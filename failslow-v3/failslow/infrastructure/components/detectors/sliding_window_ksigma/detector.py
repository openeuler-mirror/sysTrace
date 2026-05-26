"""
Implementation of the Sliding Window K-Sigma detector with robust statistics.

This module implements a streaming anomaly detector that processes multi-dimensional
time series data (e.g., data from multiple ranks at the same time step). It uses
a sliding window approach with robust statistics (median-MAD) to detect anomalies.

The detector supports:
- slow_cal mode: Detects low value anomalies (e.g., slow calculations)
- slow_launch mode: Detects high value anomalies (e.g., slow launches)
- both mode: Detects both low and high value anomalies

Key features:
- Robust median-MAD estimation (ignores outlier dimensions)
- Variable window size that grows when no anomalies detected
- Window reset when too many ranks show anomalies simultaneously
- Confidence scoring that penalizes multi-rank anomalies
- Consecutive anomaly grouping with threshold filtering
"""
import logging
import os
import re
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from failslow.infrastructure.framework.registration import DetectorRegistry
from failslow.domain.interfaces.detector import IBatchDetector, IStatefulDetector
from failslow.domain.models import DetectionResult, AnomalyInfo, AnomalyType, DetectorInput
from .schema import SlidingWindowKSigmaParams


class WindowData:
    """
    Sliding window data manager supporting multi-dimensional data.

    Maintains a 2D window of shape (time_steps, num_ranks) and provides
    robust statistics estimation using median-MAD with outlier dimension rejection.
    """

    def __init__(
        self,
        init_window_size: int,
        window_increase_ratio: float = 0.5,
        k: float = 2.5,
    ):
        """
        Initialize the window data manager.

        Args:
            init_window_size: Initial window size (look_back parameter).
            window_increase_ratio: Ratio to increase window size when exceeding capacity.
            k: K-sigma coefficient for thresholding.
        """
        self.init_window_size = init_window_size
        self.window_size = float(init_window_size)
        self.k = k
        self.window_increase_ratio = window_increase_ratio
        self.window_data: Optional[np.ndarray] = None
        self.obs_cnt = 0
        self.obs_sizes: Deque[int] = deque()

    def reset_window_size(self) -> None:
        """Reset window size to initial value and ensure capacity."""
        self.window_size = float(self.init_window_size)
        self._ensure_window_size(window_increase_ratio=0)

    def update_obs(self, obs: np.ndarray) -> None:
        """
        Add a new observation (all ranks at a single time step).

        Args:
            obs: 1D array of shape (num_ranks,) containing values for all ranks.
        """
        obs = obs.flatten()
        self.obs_cnt += 1
        self.obs_sizes.append(len(obs))

        if self.window_data is not None:
            self.window_data = np.vstack([self.window_data, obs.reshape((1, -1))])
        else:
            self.window_data = obs.reshape((1, -1))

        self._ensure_window_size(window_increase_ratio=self.window_increase_ratio)

    def _ensure_window_size(self, window_increase_ratio: float) -> None:
        """Ensure window size doesn't exceed capacity, growing if needed."""
        while self.obs_cnt > int(self.window_size):
            self.window_data = self.window_data[1:]
            self.obs_sizes.popleft()
            self.obs_cnt -= 1
            self.window_size += window_increase_ratio

    def valid(self) -> bool:
        """Check if there's enough data for detection."""
        return self.obs_cnt >= int(self.window_size // 2)

    def full_by_init_size(self) -> bool:
        """Check if window is full (reached initial window size)."""
        return self.obs_cnt >= self.init_window_size

    def robust_median_mad(self) -> Tuple[float, float, np.ndarray]:
        """
        Robust median and MAD estimation with outlier dimension rejection.

        Steps:
        1. Compute median for each column (dimension/rank), then take median of those.
        2. Compute absolute deviations of each column median from the main median.
        3. Drop the columns with largest deviations (assumed to be outliers).
        4. Compute final median and MAD from remaining columns.

        Returns:
            Tuple of (final_median, sigma_hat, kept_indices)
        """
        arr = self.window_data
        T, N = arr.shape
        drop_data_length = 1 if N <= 3 else 2

        # Step 1: Column medians, then median of those
        col_medians = np.median(arr, axis=0)
        main_median = np.median(col_medians)

        # Step 2: Absolute deviations from main median
        deviations = np.abs(col_medians - main_median)

        # Step 3: Drop columns with largest deviations
        sorted_indices = np.argsort(deviations)
        kept_indices = np.sort(sorted_indices[:-drop_data_length])

        # Step 4: Final median and MAD on kept columns
        selected_data = arr[:, kept_indices].flatten()
        final_median = np.median(selected_data)
        mad = np.median(np.abs(selected_data - final_median))
        sigma = mad * 1.4826

        return final_median, sigma, kept_indices

    def get_median_sigma_by_col(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Get per-column median and sigma estimates.

        Returns:
            Tuple of (median_by_col, sigma_by_col) arrays of shape (num_ranks,)
        """
        window_data = self.window_data
        lb_by_col = np.quantile(window_data, 0.02, axis=0)
        ub_by_col = np.quantile(window_data, 0.98, axis=0)
        median_by_col = (ub_by_col + lb_by_col) / 2
        sigma_by_col = (ub_by_col - lb_by_col) / 2 / self.k
        return median_by_col, sigma_by_col

    def get_ub_lb(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Get upper and lower bounds arrays.

        Returns:
            Tuple of (upper_bound, lower_bound) arrays of shape (num_ranks,)
        """
        median, sigma_hat, kept_dims = self.robust_median_mad()
        median_by_col, sigma_hat_by_col = self.get_median_sigma_by_col()
        median = np.median(median_by_col)
        sigma_hat = sigma_hat * np.ones(len(sigma_hat_by_col))
        upper_limit = median + self.k * sigma_hat
        lower_limit = median - self.k * sigma_hat
        return upper_limit, lower_limit


class SlidingWindowKSigmaDetector(DetectorRegistry, IBatchDetector, IStatefulDetector):
    """
    Sliding Window K-Sigma anomaly detector with robust statistics.

    This detector processes multi-rank data and detects anomalies using
    a sliding window approach with robust median-MAD statistics. It supports
    both slow_cal (low value) and slow_launch (high value) anomaly detection.

    Implements:
        - IBatchDetector: For batch/offline detection on 2D arrays
        - IStatefulDetector: For state persistence and checkpointing

    For streaming (online) detection, use the separate stream_detect() method.
    """

    COMPONENT_NAME = "sliding_window_ksigma"

    def __init__(self, params: SlidingWindowKSigmaParams = None, **kwargs):
        if params is not None:
            self._params = params
        else:
            self._params = SlidingWindowKSigmaParams(**kwargs)

        # Core parameters
        self._k = self._params.k
        self._look_back = self._params.look_back
        self._metric_key = "t_exec_ns"  # Fixed metric key for StepMetrics.kernels
        self._slow_type = self._params.slow_type

        # Window parameters
        self._use_variable_window = self._params.use_variable_window
        self._window_increase_ratio = self._params.window_increase_ratio

        # Preprocessing parameters
        self._smooth_size = self._params.smooth_size
        self._filter_extreme_values = self._params.filter_extreme_values
        self._extreme_quantile = self._params.extreme_quantile

        # Detection parameters
        self._anom_threshold = self._params.anom_threshold
        self._change_conf = self._params.change_conf
        self._keep_last = self._params.keep_last
        self._alert_conf_thresh = self._params.alert_conf_thresh
        self._conf_score_decay = self._params.conf_score_decay
        self._deviation_ratio_thresh = self._params.deviation_ratio_thresh

        # Debug
        self._enable_debug = self._params.enable_debug_logging

        # Visualization
        self._plt_save_path = self._params.plt_save_path

        # State
        self._window_data: Optional[WindowData] = None
        self._step_count = 0
        self._anom_mark_buffer: List[np.ndarray] = []
        self._obs_buffer: List[np.ndarray] = []

        # Metadata buffer for rank_id tracking
        self._rank_ids: List[int] = []
        self._timestamps: List[int] = []

        # Logger
        self._logger = logging.getLogger(__name__)
        if self._enable_debug:
            self._logger.setLevel(logging.DEBUG)

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def reset(self) -> None:
        """Reset the detector state."""
        self._window_data = None
        self._step_count = 0
        self._anom_mark_buffer = []
        self._obs_buffer = []
        self._rank_ids = []
        self._timestamps = []

    def get_state(self) -> Dict[str, Any]:
        """
        Get the current detector state for persistence.

        Returns:
            Dict containing all internal state needed to resume detection.
        """
        state = {
            "step_count": self._step_count,
            "anom_mark_buffer": [arr.tolist() for arr in self._anom_mark_buffer],
            "obs_buffer": [arr.tolist() for arr in self._obs_buffer],
            "rank_ids": self._rank_ids,
            "timestamps": self._timestamps,
        }
        if self._window_data is not None:
            state["window_data"] = {
                "window_data": self._window_data.window_data.tolist() if self._window_data.window_data is not None else None,
                "obs_cnt": self._window_data.obs_cnt,
                "window_size": self._window_data.window_size,
                "init_window_size": self._window_data.init_window_size,
                "window_increase_ratio": self._window_data.window_increase_ratio,
                "k": self._window_data.k,
            }
        return state

    def set_state(self, state: Dict[str, Any]) -> None:
        """
        Restore detector state from a previously saved state.

        Args:
            state: Dict containing previously saved state.
        """
        self._step_count = state.get("step_count", 0)
        self._anom_mark_buffer = [np.array(arr) for arr in state.get("anom_mark_buffer", [])]
        self._obs_buffer = [np.array(arr) for arr in state.get("obs_buffer", [])]
        self._rank_ids = state.get("rank_ids", [])
        self._timestamps = state.get("timestamps", [])
        
        window_state = state.get("window_data")
        if window_state is not None:
            self._window_data = WindowData(
                init_window_size=window_state.get("init_window_size", self._look_back),
                window_increase_ratio=window_state.get("window_increase_ratio", self._window_increase_ratio),
                k=window_state.get("k", self._k),
            )
            if window_state.get("window_data") is not None:
                self._window_data.window_data = np.array(window_state["window_data"])
            self._window_data.obs_cnt = window_state.get("obs_cnt", 0)
            self._window_data.window_size = window_state.get("window_size", float(self._look_back))

    def detect(
        self,
        data: Union[np.ndarray, "DetectorInput"],
        context: Optional[Dict[str, Any]] = None,
    ) -> np.ndarray:
        """
        Detect anomalies in batch mode (offline detection).

        This method processes 2D arrays (time_len, num_ranks) and returns
        anomaly labels. For streaming (online) detection, use stream_detect().

        Args:
            data: Either a np.ndarray of shape (time_len, num_ranks) or
                  a DetectorInput containing values and metadata
            context: Optional runtime context for forward extensibility.
                     Can contain:
                     - 'timestamps': np.ndarray of window start times (ms)
                     - 'sensitivity': float override for detection sensitivity
                     - 'callbacks': Dict of named callbacks

        Returns:
            np.ndarray of shape (time_len, num_ranks) with 0=normal, 1=anomaly
        """
        if isinstance(data, DetectorInput):
            values = data.values
            # Use timestamps from context if not in DetectorInput
            if context is None and data.timestamps is not None:
                context = {'timestamps': data.timestamps}
        else:
            values = np.asarray(data, dtype=float)

        if values.ndim != 2:
            raise ValueError(
                f"Batch detection requires 2D array (time_len, num_ranks), "
                f"got {values.ndim}D. For streaming detection, use stream_detect()."
            )

        return self.detect_batch(values, context=context)

    def stream_detect(
        self,
        data: Union[np.ndarray, "DetectorInput"],
        context: Optional[Dict[str, Any]] = None,
    ) -> List["DetectionResult"]:
        """
        Detect anomalies in streaming mode (online detection).

        This method processes single time steps (1D arrays) and returns
        detection results immediately. For batch/offline detection,
        use detect() instead.

        Args:
            data: Either a 1D np.ndarray of shape (num_ranks,) or
                  a DetectorInput containing values and metadata
            context: Optional runtime context for forward extensibility.
                     Can contain:
                     - 'timestamp': int representing current time (ms)
                     - 'sensitivity': float override for detection sensitivity
                     - 'callbacks': Dict of named callbacks

        Returns:
            List of DetectionResult for any detected anomalies at this step
        """
        if isinstance(data, DetectorInput):
            values = data.values.flatten()
            rank_ids = data.rank_ids
            node_ips = data.node_ips
        else:
            values = np.asarray(data, dtype=float).flatten()
            rank_ids = list(range(len(values)))
            node_ips = ["unknown"] * len(values)

        return self._detect_streaming(values, rank_ids, node_ips, context=context)

    def _detect_streaming(
        self,
        values: np.ndarray,
        rank_ids: List[int],
        node_ips: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> List["DetectionResult"]:
        
        self._step_count += 1
        N = len(values)
        
        # Initialize window if needed
        if self._window_data is None:
            self._window_data = WindowData(
                init_window_size=self._look_back,
                window_increase_ratio=self._window_increase_ratio,
                k=self._k,
            )
            self._num_ranks = N
        
        # Store observation for later analysis
        self._obs_buffer.append(values.copy())
        self._rank_ids = rank_ids
        self._timestamps.append(self._step_count)
        
        # Check if window is ready
        if not self._window_data.valid():
            self._logger.debug("Step %d: window not valid yet, detection skipped", self._step_count)
            self._window_data.update_obs(values)
            self._anom_mark_buffer.append(np.zeros(N, dtype=float))
            return []
        
        if not self._window_data.full_by_init_size() and not self._use_variable_window:
            self._logger.debug("Step %d: window not full yet, detection skipped", self._step_count)
            self._window_data.update_obs(values)
            self._anom_mark_buffer.append(np.zeros(N, dtype=float))
            return []
        
        # Perform detection
        upper_limit, lower_limit = self._window_data.get_ub_lb()
        median = np.median((upper_limit + lower_limit) / 2)
        diff = upper_limit - lower_limit + 1e-6
        
        # Compute deviation
        deviation = (values - (upper_limit + lower_limit) / 2) / (diff / 2 + 1e-6)
        
        # Mark anomalies based on slow_type
        # slow_cal: detect only low value anomalies (deviation < -1)
        # slow_launch: detect only high value anomalies (deviation > 1)
        # both: detect both directions
        if self._slow_type == "slow_cal":
            obs_anom_mark = np.where(deviation < -1, -1.0, 0)
        elif self._slow_type == "slow_launch":
            obs_anom_mark = np.where(deviation > 1, 1.0, 0)
        else:  # both
            obs_anom_mark = np.where(
                deviation > 1,
                1.0,
                np.where(deviation < -1, -1.0, 0),
            )

        # Log ratio filter: value must deviate from median by deviation_ratio_thresh
        if self._slow_type != "both":
            deviation_log = values / (np.median(median) + 1e-6) + 1e-6
            deviation_log = np.log10(deviation_log)
            deviation_log = np.abs(deviation_log)
            deviation_log_ratio = deviation_log - np.log10(self._deviation_ratio_thresh)
            obs_anom_mark *= deviation_log_ratio > 0
        
        abs_obs_anom_mark = np.abs(obs_anom_mark)
        
        # Check for over-half anomalies (uniform change, reset window)
        if np.sum(abs_obs_anom_mark) > self._change_conf * N:
            self._logger.debug("Step %d: reset window size by over-half anomalies", self._step_count)
            self._window_data.reset_window_size()
            median_val = np.median(obs_anom_mark[obs_anom_mark != 0])
            obs_anom_mark -= median_val
            obs_anom_mark = np.where(
                obs_anom_mark > 0,
                1.0,
                np.where(obs_anom_mark < 0, -1.0, 0),
            )
            abs_obs_anom_mark = np.abs(obs_anom_mark)
        
        # Store anomaly mark for postprocessing
        self._anom_mark_buffer.append(obs_anom_mark.copy())
        
        # Update window
        self._window_data.update_obs(values)
        
        # Generate detection results for this step
        results = []
        for rank_idx in range(N):
            if abs_obs_anom_mark[rank_idx] > 0:
                direction = "high" if obs_anom_mark[rank_idx] > 0 else "low"
                anomaly_info = AnomalyInfo(
                    anomaly_type=AnomalyType.FAIL_SLOW,
                    anomaly_details=[{
                        "direction": direction,
                        "deviation": float(deviation[rank_idx]),
                        "value": float(values[rank_idx]),
                        "upper_limit": float(upper_limit[rank_idx]),
                        "lower_limit": float(lower_limit[rank_idx]),
                    }],
                )
                result = DetectionResult(
                    detector_name=self.name,
                    anomaly_info=anomaly_info,
                    metadata={
                        "rank_id": rank_ids[rank_idx],
                        "node_ip": node_ips[rank_idx],
                        "step_id": self._step_count,
                    },
                )
                results.append(result)
        
        return results

    def detect_batch(
        self,
        data: np.ndarray,
        context: Optional[Dict[str, Any]] = None,
    ) -> np.ndarray:
        """
        Detect anomalies using offline batch processing.

        Accepts multi-dimensional time series data (time_len, num_ranks) and performs
        full offline anomaly detection with preprocessing, sliding window detection,
        and postprocessing.

        Args:
            data: np.ndarray of shape (time_len, num_ranks) containing time series data
            context: Optional runtime context for forward extensibility.
                     Can contain:
                     - 'timestamps': np.ndarray of window start times (ms)
                     - 'sensitivity': float override for detection sensitivity
                     - 'callbacks': Dict of named callbacks

        Returns:
            np.ndarray of shape (time_len, num_ranks) with 0=normal, 1=anomaly
        """
        self._logger.info(
            "SlidingWindowKSigmaDetector.detect_batch called with data shape: %s", data.shape
        )

        # Extract context parameters (for future use)
        # Currently context is reserved for forward extensibility
        if context is not None:
            self._logger.debug("detect_batch received context with keys: %s", list(context.keys()))

        # Convert to numpy array and validate
        data = np.asarray(data, dtype=float)
        if data.ndim != 2:
            raise ValueError("data must be 2D array (time_len, num_ranks)")

        # 保存原始数据用于preprocess阶段画图
        data_original = data.copy()

        T, N = data.shape
        self._logger.info(f"sliding_window_ksigma: T={T}, N={N}")

        # Initialize return values and intermediate buffers
        ret_values = np.zeros((T, N), dtype=int)
        anom_mark = np.zeros((T, N), dtype=float)
        continuous_anom_mark = np.zeros((T, N), dtype=int)
        anom_mark_count = np.zeros((T, N), dtype=int) + 1e-6  # avoid div by zero

        # ========== PREPROCESS PLOTTING ==========
        self.plot_preprocess_data(data_original, column_list=None)

        # ========== PREPROCESSING ==========

        # 1. Extreme value filtering (99th/1st percentile clipping)
        if self._filter_extreme_values:
            ub = np.nanpercentile(data, 99)
            lb = np.nanpercentile(data, 1)
            self._logger.info(f"filter extreme values, ub: {ub}, lb: {lb}")
            data[data > ub] = np.nan
            data[data < lb] = np.nan

        # 2. Smoothing per rank (pandas rolling mean)
        for rank in range(N):
            rank_data = data[:, rank].copy()
            # Interpolate to fill NaN values
            s = pd.Series(rank_data)
            s = s.interpolate(method="nearest")
            s = s.interpolate(method="linear")
            rank_data = s.to_numpy()
            # Apply rolling mean smoothing
            tmp_df = pd.DataFrame(rank_data, columns=["value"])
            tmp_df["smoothed"] = (
                tmp_df["value"]
                .rolling(window=self._smooth_size, min_periods=1, center=True)
                .mean()
            )
            data[:, rank] = tmp_df["smoothed"].to_numpy()

        # 3. Remove trailing NaN rows
        while data.shape[0] > 0:
            last_row = data[-1, :]
            if np.sum(np.isnan(last_row)) > N / 2:
                data = data[:-1, :]
                T -= 1
            else:
                break
        self._logger.info(
            f"After removing trailing NaN rows, data shape: {data.shape}"
        )

        if T == 0:
            self._logger.warning("All data filtered out, returning zeros")
            return ret_values

        # 4. Offset normalization (median centering + offset)
        nan_before_norm = np.sum(np.isnan(data))
        offset = np.nanmin(data)
        data -= np.nanmedian(data, axis=1, keepdims=True)
        data += 1e-6
        data -= np.nanmin(data)
        data += offset
        nan_after_norm = np.sum(np.isnan(data))
        self._logger.info(f"After offset normalization: nan_count={nan_after_norm}")

        # ========== SLIDING WINDOW DETECTION ==========

        window_data = WindowData(
            init_window_size=self._look_back,
            window_increase_ratio=self._window_increase_ratio,
            k=self._k,
        )

        for pos in range(T):
            obs = data[pos, :]

            if not window_data.valid():
                self._logger.debug("pos:%d, window not valid yet, detection skipped", pos)
                window_data.update_obs(obs)
                continue
            if not window_data.full_by_init_size() and not self._use_variable_window:
                self._logger.debug("pos:%d, window not full yet, detection skipped", pos)
                window_data.update_obs(obs)
                continue

            upper_limit, lower_limit = window_data.get_ub_lb()
            median = np.median((upper_limit + lower_limit) / 2)
            diff = upper_limit - lower_limit + 1e-6  # avoid div by zero

            # Compute deviation
            deviation = (obs - (upper_limit + lower_limit) / 2) / (diff / 2 + 1e-6)
            deviation_abs = np.abs(deviation)
            deviation_exp = np.exp(deviation_abs - np.max(deviation_abs))

            deviation_weights = deviation_abs / (np.sum(deviation_abs) + 1e-6)
            deviation *= deviation_weights

            # Mark anomalies based on slow_type
            # slow_cal: detect only low value anomalies (deviation < -1)
            # slow_launch: detect only high value anomalies (deviation > 1)
            # both: detect both directions
            if self._slow_type == "slow_cal":
                obs_anom_mark = np.where(deviation < -1, -1.0, 0)
            elif self._slow_type in ("slow_launch", "slow_host"):
                obs_anom_mark = np.where(deviation > 1, 1.0, 0)
            else:
                obs_anom_mark = np.where(
                    deviation > 1,
                    1.0,
                    np.where(deviation < -1, -1.0, 0),
                )

            # Log ratio filter: value must deviate from median by deviation_ratio_thresh
            if self._slow_type != "both":
                deviation_log = obs / (np.median(median) + 1e-6) + 1e-6
                deviation_log = np.log10(deviation_log)
                deviation_log = np.abs(deviation_log)
                deviation_log_ratio = deviation_log - np.log10(self._deviation_ratio_thresh)
                obs_anom_mark *= deviation_log_ratio > 0

            # if self._enable_debug:
            #     self._logger.debug(
            #         (
            #             f"detect pos:%d with windowsize=%d"
            #             "\n =>val: %s"
            #             "\n => ub: %s"
            #             "\n => lb: %s"
            #             "\n => deviation: %s"
            #             "\n => anom_mark: %s"
            #         ),
            #         pos,
            #         window_data.window_size,
            #         obs.tolist(),
            #         upper_limit,
            #         lower_limit,
            #         weighted_deviation.tolist(),
            #         obs_anom_mark.tolist(),
            #     )

            anom_mark[pos, :] = obs_anom_mark
            abs_obs_anom_mark = np.abs(obs_anom_mark)

            # Check for over-half anomalies (uniform change, reset window)
            if np.sum(abs_obs_anom_mark) > self._change_conf * N:
                self._logger.debug("reset window size by over-half anomalies in pos %d", pos)
                window_data.reset_window_size()
                # Correct
                median_val = np.median(obs_anom_mark[obs_anom_mark != 0])
                obs_anom_mark -= median_val
                obs_anom_mark = np.where(
                    obs_anom_mark > 0,
                    1.0,
                    np.where(obs_anom_mark < 0, -1.0, 0),
                )
                abs_obs_anom_mark = np.abs(obs_anom_mark)
                self._logger.debug("  => %s", obs_anom_mark.tolist())

            # Track continuous anomalies
            anom_mark_count[pos, :] += abs_obs_anom_mark

            if pos == 0:
                continuous_anom_mark[pos, :] = obs_anom_mark
            elif pos < T - 1:
                continuous_anom_mark[pos, :] = (
                    continuous_anom_mark[pos - 1, :] * abs_obs_anom_mark + obs_anom_mark
                )

            window_data.update_obs(obs)

        # ========== POSTPROCESSING ==========

        # 1. Confidence score decay: penalize multi-rank anomalies
        # x = number of anomalous ranks at each time step
        x = np.sum(np.abs(anom_mark), axis=1)
        row_confidence = np.exp(-self._conf_score_decay * (x - 1) / N)
        anom_mark = anom_mark * row_confidence.reshape((-1, 1))

        # 2. Consecutive anomaly grouping with thresholds
        # Only keep anomalies that form continuous sequences exceeding thresholds
        for rank_id in range(N):
            idx = 0
            while idx < T:
                if anom_mark[idx, rank_id] != 0:
                    curr_label = anom_mark[idx, rank_id]
                    count = 1
                    j = idx + 1
                    conf_cum = anom_mark[idx, rank_id]
                    while j < T and anom_mark[j, rank_id] * curr_label > 0:
                        conf_cum += anom_mark[j, rank_id]
                        count += 1
                        j += 1

                    self._logger.info(
                        "[rank %d]check possible anomaly from %d to %d (total %s), count=%d, conf_cum=%.4f",
                        rank_id,
                        idx,
                        j - 1,
                        T,
                        count,
                        conf_cum,
                    )

                    # Apply threshold criteria:
                    # - cumulative confidence must exceed alert_conf_thresh
                    # - consecutive count must exceed anom_threshold
                    # - sequence must be connected to the tail (keep_last ratio)
                    if (
                        np.abs(conf_cum) >= self._alert_conf_thresh
                        and count >= self._anom_threshold
                        and j >= T * (1 - self._keep_last)
                    ):
                        ret_values[idx:j, rank_id] = 1

                    idx = j
                else:
                    idx += 1

        self._logger.info(f"Detection complete. Anomalies found: {np.sum(ret_values)}")

        self.plot_multi_dim_multi_rank_data(data, ret_values, column_list=None)

        return ret_values

    def plot_multi_dim_multi_rank_data(
        self,
        data: np.ndarray,
        anomaly_labels: np.ndarray = None,
        column_list: list = None,
    ) -> None:
        """
        绘制多维度多节点数据可视化图

        Args:
            data: 2D array (time_len, obj_num)
            anomaly_labels: 异常标签矩阵，1表示异常点
            column_list: 真实的 rank 编号列表
        """
        if not self._plt_save_path:
            return

        if data.ndim != 2:
            raise ValueError("data must be 2D array (time_len, obj_num)")

        T, N = data.shape

        if column_list is None:
            column_list = list(range(N))

        if anomaly_labels is None:
            anomaly_labels = np.zeros((T, N), dtype=int)

        plt.figure(figsize=(14, 8))

        cmap = plt.get_cmap('tab20')

        # 绘制正常数据线
        for rank_idx in range(min(N, 20)):
            actual_rank = column_list[rank_idx] if rank_idx < len(column_list) else rank_idx
            plt.plot(
                range(T),
                data[:, rank_idx],
                label=f"Rank {actual_rank}",
                color=cmap(rank_idx % 20),
                alpha=0.7,
                linewidth=1.0,
            )

        # 绘制异常点标记
        for rank_idx in range(N):
            actual_rank = column_list[rank_idx] if rank_idx < len(column_list) else rank_idx
            anomaly_mask = anomaly_labels[:, rank_idx] == 1
            if np.any(anomaly_mask):
                anomaly_times = np.where(anomaly_mask)[0]
                anomaly_values = data[anomaly_times, rank_idx]
                plt.scatter(
                    anomaly_times,
                    anomaly_values,
                    c='red',
                    s=100,
                    marker='x',
                    linewidths=2,
                    zorder=10,
                    label=f"Rank {actual_rank} Anomaly" if rank_idx < 5 else None,
                )

        plt.title("Multi-Dim Multi-Rank Data Visualization (with Anomaly Markers)")
        plt.xlabel("Time Index")
        plt.ylabel("Values")

        if N <= 10:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize='small')
        elif N <= 20:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", ncol=2, fontsize='small')
        else:
            plt.legend(
                [plt.Line2D([0], [0], color='gray', lw=1),
                 plt.Line2D([0], [0], marker='x', color='red', linestyle='None', markersize=8)],
                ['Normal', 'Anomaly'],
                loc='upper right'
            )

        plt.grid(True, linestyle='--', alpha=0.5)
        plt.tight_layout()

        # 保存图片
        save_dir = self._plt_save_path
        if not save_dir.endswith("/"):
            save_dir += "/"

        os.makedirs(save_dir, exist_ok=True)

        # 找到已有的文件最大编号
        existing_files = [
            f for f in os.listdir(save_dir)
            if f.startswith("multi_dim_multi_rank_plot_") and f.endswith(".png")
        ]

        max_index = 0
        for filename in existing_files:
            match = re.search(r"multi_dim_multi_rank_plot_(\d+)\.png", filename)
            if match:
                index = int(match.group(1))
                max_index = max(max_index, index)

        next_index = max_index + 1
        indexed_path = os.path.join(
            save_dir, f"multi_dim_multi_rank_plot_{next_index}.png"
        )
        plt.savefig(indexed_path, dpi=300, bbox_inches="tight")
        self._logger.info(f"Plot saved to {indexed_path}")
        plt.close()

    def plot_preprocess_data(
        self,
        data: np.ndarray,
        column_list: list = None,
    ) -> None:
        """
        绘制预处理前的原始数据可视化图，保存到preprocess子文件夹

        Args:
            data: 2D array (time_len, obj_num) 原始数据
            column_list: 真实的 rank 编号列表
        """
        if not self._plt_save_path:
            return

        if data.ndim != 2:
            raise ValueError("data must be 2D array (time_len, obj_num)")

        T, N = data.shape

        if column_list is None:
            column_list = list(range(N))

        plt.figure(figsize=(14, 8))

        cmap = plt.get_cmap('tab20')

        # 绘制正常数据线
        for rank_idx in range(min(N, 20)):
            actual_rank = column_list[rank_idx] if rank_idx < len(column_list) else rank_idx
            plt.plot(
                range(T),
                data[:, rank_idx],
                label=f"Rank {actual_rank}",
                color=cmap(rank_idx % 20),
                alpha=0.7,
                linewidth=1.0,
            )

        plt.title("Preprocess - Raw Input Data Visualization")
        plt.xlabel("Time Index")
        plt.ylabel("Values")

        if N <= 10:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize='small')
        elif N <= 20:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", ncol=2, fontsize='small')
        else:
            plt.legend(
                [plt.Line2D([0], [0], color='gray', lw=1)],
                ['Normal'],
                loc='upper right'
            )

        plt.grid(True, linestyle='--', alpha=0.5)
        plt.tight_layout()

        # 保存图片到 preprocess 子文件夹
        save_dir = self._plt_save_path
        if not save_dir.endswith("/"):
            save_dir += "/"
        save_dir = os.path.join(save_dir, "preprocess")

        os.makedirs(save_dir, exist_ok=True)

        # 找到已有的文件最大编号
        existing_files = [
            f for f in os.listdir(save_dir)
            if f.startswith("preprocess_plot_") and f.endswith(".png")
        ]

        max_index = 0
        for filename in existing_files:
            match = re.search(r"preprocess_plot_(\d+)\.png", filename)
            if match:
                index = int(match.group(1))
                max_index = max(max_index, index)

        next_index = max_index + 1
        indexed_path = os.path.join(
            save_dir, f"preprocess_plot_{next_index}.png"
        )
        plt.savefig(indexed_path, dpi=300, bbox_inches="tight")
        self._logger.info(f"Preprocess plot saved to {indexed_path}")
        plt.close()
