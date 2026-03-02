"""
Degradation K-Sigma Naive detector.

Per-rank time-series degradation detection using sliding window with
population mean and standard deviation. Each rank is monitored independently
against its own historical baseline.
"""

import logging
import math
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

import numpy as np

from failslow.domain.interfaces.detector import IStreamDetector, IStatefulDetector
from failslow.domain.models import AnomalyInfo, AnomalyType, DetectionResult, DetectorInput
from failslow.infrastructure.framework.registration import DetectorRegistry
from .schema import DegradationKSigmaNaiveParams

logger = logging.getLogger(__name__)


class _WindowState:
    """Per-rank sliding window state with incremental mean/std computation."""

    def __init__(self, window_size: int, window_increase_ratio: float, eps: float):
        self.window_data: Deque[float] = deque()
        self.window_sum: float = 0.0
        self.window_sum_sqr: float = 0.0
        self.count: int = 0
        self.window_size: float = float(window_size)
        self.init_window_size: int = window_size
        self.window_increase_ratio: float = window_increase_ratio
        self.eps: float = eps
        self.index_counter: int = 0

    def update(self, obs: float) -> None:
        self.index_counter += 1
        self.window_data.append(obs)
        self.window_sum += obs
        self.window_sum_sqr += obs * obs
        self.count += 1
        self._ensure_window_size()

    def _ensure_window_size(self) -> None:
        while self.count > int(self.window_size):
            removed = self.window_data.popleft()
            self.window_sum -= removed
            self.window_sum_sqr -= removed * removed
            self.count -= 1
            self.window_size += self.window_increase_ratio

    def get_mu_sigma(self) -> Tuple[float, float]:
        if self.count == 0:
            return 0.0, self.eps
        mu = self.window_sum / self.count
        variance = self.window_sum_sqr / self.count - mu * mu
        sigma = math.sqrt(max(variance, 0.0)) + self.eps
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


class DegradationKSigmaNaiveDetector(DetectorRegistry, IStreamDetector, IStatefulDetector):
    """
    Per-rank degradation detector using sliding window with population mean/std.

    Each rank is monitored independently against its own historical baseline.
    An anomaly is flagged when a value falls outside the k-sigma band AND
    the relative deviation exceeds anomaly_degree_thr. Alerts are confirmed
    only after min_consecutive consecutive anomaly signals in the same direction.
    """

    COMPONENT_NAME = "degradation_ksigma_naive"

    def __init__(self, params: Optional[DegradationKSigmaNaiveParams] = None, **kwargs):
        if params is not None:
            if isinstance(params, dict):
                self._params = DegradationKSigmaNaiveParams(**params)
            else:
                self._params = params
        else:
            self._params = DegradationKSigmaNaiveParams(**kwargs)

        self._rank_windows: Dict[int, _WindowState] = {}
        self._rank_alerts: Dict[int, _AlertState] = {}

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def reset(self) -> None:
        self._rank_windows.clear()
        self._rank_alerts.clear()

    def detect(
        self,
        data: Union[np.ndarray, DetectorInput],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DetectionResult]:
        if isinstance(data, DetectorInput):
            values = data.values.flatten()
            rank_ids = data.rank_ids
        else:
            values = np.asarray(data, dtype=float).flatten()
            rank_ids = list(range(len(values)))

        timestamp = None
        if context is not None:
            timestamp = context.get("timestamp")

        results = []
        for i, (val, rank_id) in enumerate(zip(values, rank_ids)):
            rank_results = self._detect_single_rank(rank_id, float(val), timestamp)
            results.extend(rank_results)

        return results

    def _detect_single_rank(
        self,
        rank_id: int,
        obs: float,
        timestamp: Optional[int],
    ) -> List[DetectionResult]:
        if rank_id not in self._rank_windows:
            self._rank_windows[rank_id] = _WindowState(
                window_size=self._params.window_size,
                window_increase_ratio=self._params.window_increase_ratio,
                eps=self._params.eps,
            )
            self._rank_alerts[rank_id] = _AlertState()

        window = self._rank_windows[rank_id]
        alert = self._rank_alerts[rank_id]

        window.update(obs)

        if not window.is_ready(self._params.use_variable_window):
            return []

        if not alert.report_enabled:
            return []

        mu, sigma = window.get_mu_sigma()

        upper_bound = mu + self._params.k_sigma * sigma
        lower_bound = mu - self._params.k_sigma * sigma

        signal = 0
        if obs > upper_bound and self._params.detect_rise:
            degree = abs(obs - mu) / (abs(mu) + self._params.eps)
            if degree >= self._params.anomaly_degree_thr:
                signal = 1
        elif obs < lower_bound and self._params.detect_drop:
            degree = abs(obs - mu) / (abs(mu) + self._params.eps)
            if degree >= self._params.anomaly_degree_thr:
                signal = -1

        if signal == 0:
            alert.signal = 0
            alert.first_degradation_index = None
            alert.last_degradation_index = None
            return []

        if alert.signal != signal:
            alert.signal = signal
            alert.first_degradation_index = window.index_counter
            alert.last_degradation_index = window.index_counter
        else:
            alert.last_degradation_index = window.index_counter

        consecutive_count = alert.last_degradation_index - alert.first_degradation_index + 1

        if consecutive_count < self._params.min_consecutive:
            return []

        alert.report_enabled = False

        direction = "rise" if signal > 0 else "drop"
        anomaly_info = AnomalyInfo(
            is_anomaly=True,
            anomaly_type=AnomalyType.FAIL_SLOW,
            anomaly_details=[{
                "direction": direction,
                "rank_id": rank_id,
                "observed_value": obs,
                "mean": mu,
                "std": sigma,
                "upper_bound": upper_bound,
                "lower_bound": lower_bound,
                "anomaly_degree": abs(obs - mu) / (abs(mu) + self._params.eps),
                "first_degradation_index": alert.first_degradation_index,
                "last_degradation_index": alert.last_degradation_index,
            }],
        )

        metadata = {
            "rank_id": rank_id,
            "detector_type": "degradation_ksigma_naive",
        }
        if timestamp is not None:
            metadata["timestamp"] = timestamp

        return [DetectionResult(
            detector_name=self.name,
            anomaly_info=anomaly_info,
            metadata=metadata,
        )]

    def get_state(self) -> Dict[str, Any]:
        state = {}
        for rank_id, window in self._rank_windows.items():
            alert = self._rank_alerts.get(rank_id)
            state[str(rank_id)] = {
                "window_data": list(window.window_data),
                "window_sum": window.window_sum,
                "window_sum_sqr": window.window_sum_sqr,
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
            window.window_sum = rank_state.get("window_sum", 0.0)
            window.window_sum_sqr = rank_state.get("window_sum_sqr", 0.0)
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
