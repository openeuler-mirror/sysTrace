"""
Degradation K-Sigma Robust detector.

Per-rank time-series degradation detection using sliding window with
robust median and Median Absolute Deviation (MAD). Each rank is monitored
independently against its own historical baseline. The robust statistics
make this detector resistant to outliers.
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

from failslow.domain.interfaces.detector import IStreamDetector, IStatefulDetector
from failslow.domain.models import AnomalyInfo, AnomalyType, DetectionResult, DetectorInput
from failslow.infrastructure.framework.registration import DetectorRegistry
from .schema import DegradationKSigmaRobustParams

logger = logging.getLogger(__name__)

_MAD_TO_SIGMA_FACTOR = 1.4826


class _WindowState:
    """Per-rank sliding window state with robust median/MAD computation."""

    def __init__(self, window_size: int, window_increase_ratio: float, eps: float):
        self.window_data: Deque[float] = deque()
        self.count: int = 0
        self.window_size: float = float(window_size)
        self.init_window_size: int = window_size
        self.window_increase_ratio: float = window_increase_ratio
        self.eps: float = eps
        self.index_counter: int = 0

    def update(self, obs: float) -> None:
        self.index_counter += 1
        self.window_data.append(obs)
        self.count += 1
        self._ensure_window_size()

    def _ensure_window_size(self) -> None:
        while self.count > int(self.window_size):
            self.window_data.popleft()
            self.count -= 1
            self.window_size += self.window_increase_ratio

    def get_mu_sigma(self) -> Tuple[float, float]:
        if self.count == 0:
            return 0.0, self.eps
        data = np.array(self.window_data)
        mu = float(np.median(data))
        mad = float(np.median(np.abs(data - mu)))
        sigma = mad * _MAD_TO_SIGMA_FACTOR + self.eps
        return mu, sigma

    def is_ready(self, use_variable_window: bool) -> bool:
        if self.count < 2:
            return False
        if use_variable_window:
            return self.count >= max(2, int(self.window_size // 2))
        return self.count >= self.init_window_size

    def reset_window_size(self) -> None:
        self.window_size = float(self.init_window_size)


class _AlertState:
    """Per-rank alert confirmation state."""

    def __init__(self):
        self.signal: int = 0
        self.first_degradation_index: Optional[int] = None
        self.last_degradation_index: Optional[int] = None
        self.report_enabled: bool = True


class DegradationKSigmaRobustDetector(DetectorRegistry, IStreamDetector, IStatefulDetector):
    """
    Per-rank degradation detector using sliding window with robust median/MAD.

    Each rank is monitored independently against its own historical baseline.
    Uses median and MAD (Median Absolute Deviation) for robust estimation
    that is resistant to outliers. An anomaly is flagged when a value falls
    outside the k-sigma band AND the relative deviation exceeds
    anomaly_degree_thr. Alerts are confirmed only after min_consecutive
    consecutive anomaly signals in the same direction.
    """

    COMPONENT_NAME = "degradation_ksigma_robust"

    def __init__(self, params: Optional[DegradationKSigmaRobustParams] = None, **kwargs):
        if params is not None:
            if isinstance(params, dict):
                self._params = DegradationKSigmaRobustParams(**params)
            else:
                self._params = params
        else:
            self._params = DegradationKSigmaRobustParams(**kwargs)

        self._rank_windows: Dict[int, _WindowState] = {}
        self._rank_alerts: Dict[int, _AlertState] = {}
        self._plot_data: Dict[int, List[float]] = {}

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def reset(self) -> None:
        self._rank_windows.clear()
        self._rank_alerts.clear()
        self._plot_data.clear()

    def _plot_and_save(self) -> None:
        if not self._plot_data:
            return

        logger.debug(f"[_plot_and_save] _plot_data keys: {list(self._plot_data.keys())}")
        for rank_id, values in self._plot_data.items():
            logger.debug(f"[_plot_and_save] rank {rank_id}: len={len(values)}, shape={np.shape(values)}")

        T = max(len(v) for v in self._plot_data.values()) if self._plot_data else 0
        N = len(self._plot_data)

        plt.figure(figsize=(14, 8))
        cmap = plt.get_cmap('tab20')

        for idx, rank_id in enumerate(sorted(self._plot_data.keys())):
            plt.plot(
                range(len(self._plot_data[rank_id])),
                self._plot_data[rank_id],
                label=f"Rank {rank_id}",
                color=cmap(idx % 20),
                alpha=0.7,
                linewidth=1.0,
            )

        plt.title("Degradation Detection - Per-Rank Time Series")
        plt.xlabel("Time Index")
        plt.ylabel("Values")

        if N <= 10:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize='small')
        elif N <= 20:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", ncol=2, fontsize='small')
        else:
            plt.legend(loc='upper right')

        plt.grid(True, linestyle='--', alpha=0.5)
        plt.tight_layout()

        save_dir = self._params.plt_save_path
        if not save_dir.endswith("/"):
            save_dir += "/"

        os.makedirs(save_dir, exist_ok=True)

        existing_files = [
            f for f in os.listdir(save_dir)
            if f.startswith("degradation_plot_") and f.endswith(".png")
        ]

        max_index = 0
        for filename in existing_files:
            match = re.search(r"degradation_plot_(\d+)\.png", filename)
            if match:
                max_index = max(max_index, int(match.group(1)))

        indexed_path = os.path.join(save_dir, f"degradation_plot_{max_index + 1}.png")
        plt.savefig(indexed_path, dpi=300, bbox_inches="tight")
        logger.info(f"Plot saved to {indexed_path}")
        plt.close()

    def detect(
        self,
        data: Union[np.ndarray, DetectorInput],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DetectionResult]:
        # Clear plot data at start of each detect call to avoid stale data from previous runs
        self._plot_data.clear()

        if isinstance(data, DetectorInput):
            values = data.values
            rank_ids = data.rank_ids
        else:
            values = np.asarray(data, dtype=float)
            rank_ids = list(range(values.shape[1])) if values.ndim == 2 else list(range(len(values)))

        logger.debug(f"[detect] values.shape={values.shape}, rank_ids={rank_ids}, values.ndim={values.ndim}")

        timestamp = None
        if context is not None:
            timestamp = context.get("timestamp")

        results = []

        if values.ndim == 2:
            # 2D data: (num_timesteps, num_ranks) - offline batch mode
            # For each rank, accumulate all timestep values, then detect once with full series
            for rank_idx, rank_id in enumerate(rank_ids):
                rank_values = values[:, rank_idx]
                logger.debug(f"[detect] 2D mode: rank {rank_id}, rank_values.shape={rank_values.shape}, converting to list len={len(rank_values.tolist())}")
                self._plot_data[rank_id] = rank_values.tolist()

                # Detect on all observations for this rank at once
                rank_results = self._detect_single_rank(rank_id, rank_values, timestamp)
                results.extend(rank_results)
        else:
            # 1D data - process one at a time for streaming/online mode
            logger.debug(f"[detect] 1D mode: values.shape={values.shape}, rank_ids={rank_ids}")
            for val, rank_id in zip(values, rank_ids):
                rank_results = self._detect_single_rank(rank_id, float(val), timestamp)
                results.extend(rank_results)

                if rank_id not in self._plot_data:
                    self._plot_data[rank_id] = []
                self._plot_data[rank_id].append(float(val))

        if self._params.plt_save_path:
            self._plot_and_save()

        return results

    def _detect_single_rank(
        self,
        rank_id: int,
        obs: Union[float, np.ndarray],
        timestamp: Optional[int],
    ) -> List[DetectionResult]:
        if rank_id not in self._rank_windows:
            self._rank_windows[rank_id] = _WindowState(
                window_size=self._params.window_size,
                window_increase_ratio=self._params.window_increase_ratio,
                eps=self._params.eps,
            )
            self._rank_alerts[rank_id] = _AlertState()

        # Handle batch mode (numpy array) vs streaming mode (single float)
        is_batch = isinstance(obs, np.ndarray)
        values_to_process = obs.flatten() if is_batch else np.array([obs])

        results = []
        for idx, val in enumerate(values_to_process):
            window = self._rank_windows[rank_id]
            alert = self._rank_alerts[rank_id]

            current_index = window.index_counter + 1

            if not window.is_ready(self._params.use_variable_window):
                window.update(float(val))
                continue

            if not alert.report_enabled:
                window.update(float(val))
                continue

            mu, sigma = window.get_mu_sigma()

            upper_bound = mu + self._params.k_sigma * sigma
            lower_bound = mu - self._params.k_sigma * sigma

            signal = 0
            if val > upper_bound and self._params.detect_rise:
                degree = abs(val - mu) / (abs(mu) + self._params.eps)
                if degree >= self._params.anomaly_degree_thr:
                    signal = 1
            elif val < lower_bound and self._params.detect_drop:
                degree = abs(val - mu) / (abs(mu) + self._params.eps)
                if degree >= self._params.anomaly_degree_thr:
                    signal = -1

            if signal == 0:
                alert.signal = 0
                alert.first_degradation_index = None
                alert.last_degradation_index = None
                window.update(float(val))
                continue

            if alert.signal != signal:
                alert.signal = signal
                alert.first_degradation_index = current_index
                alert.last_degradation_index = current_index
            else:
                alert.last_degradation_index = current_index

            consecutive_count = alert.last_degradation_index - alert.first_degradation_index + 1

            if consecutive_count < self._params.min_consecutive:
                window.update(float(val))
                continue

            alert.report_enabled = False

            direction = "rise" if signal > 0 else "drop"
            anomaly_info = AnomalyInfo(
                is_anomaly=True,
                anomaly_type=AnomalyType.FAIL_SLOW,
                anomaly_details=[{
                    "direction": direction,
                    "rank_id": rank_id,
                    "observed_value": float(val),
                    "median": mu,
                    "mad_sigma": sigma,
                    "upper_bound": upper_bound,
                    "lower_bound": lower_bound,
                    "anomaly_degree": abs(val - mu) / (abs(mu) + self._params.eps),
                    "first_degradation_index": alert.first_degradation_index,
                    "last_degradation_index": alert.last_degradation_index,
                }],
            )

            metadata = {
                "rank_id": rank_id,
                "detector_type": "degradation_ksigma_robust",
            }
            if timestamp is not None:
                metadata["timestamp"] = timestamp

            results.append(DetectionResult(
                detector_name=self.name,
                anomaly_info=anomaly_info,
                metadata=metadata,
            ))

            window.update(float(val))

        return results

    def get_state(self) -> Dict[str, Any]:
        state = {}
        for rank_id, window in self._rank_windows.items():
            alert = self._rank_alerts.get(rank_id)
            state[str(rank_id)] = {
                "window_data": list(window.window_data),
                "count": window.count,
                "window_size": window.window_size,
                "index_counter": window.index_counter,
                "alert_signal": alert.signal if alert else 0,
                "alert_first_idx": alert.first_degradation_index if alert else None,
                "alert_last_idx": alert.last_degradation_index if alert else None,
                "alert_report_enabled": alert.report_enabled if alert else True,
            }
        return state

    def set_state(self, state: Dict[str, Any]) -> None:
        self._rank_windows.clear()
        self._rank_alerts.clear()
        for rank_id_str, rank_state in state.items():
            rank_id = int(rank_id_str)
            window = _WindowState(
                window_size=self._params.window_size,
                window_increase_ratio=self._params.window_increase_ratio,
                eps=self._params.eps,
            )
            window.window_data = deque(rank_state.get("window_data", []))
            window.count = rank_state.get("count", 0)
            window.window_size = rank_state.get("window_size", float(self._params.window_size))
            window.index_counter = rank_state.get("index_counter", 0)
            self._rank_windows[rank_id] = window

            alert = _AlertState()
            alert.signal = rank_state.get("alert_signal", 0)
            alert.first_degradation_index = rank_state.get("alert_first_idx")
            alert.last_degradation_index = rank_state.get("alert_last_idx")
            alert.report_enabled = rank_state.get("alert_report_enabled", True)
            self._rank_alerts[rank_id] = alert
