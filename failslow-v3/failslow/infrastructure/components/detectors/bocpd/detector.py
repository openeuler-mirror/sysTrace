"""
Implementation of the BOCPD (Bayesian Online Change Point Detection) detector.
"""
import logging
from abc import ABC, ABCMeta, abstractmethod
from typing import Any, Dict, List, Optional, Union

import numpy as np
from scipy import stats

from failslow.infrastructure.framework.registration import DetectorRegistry
from failslow.domain.interfaces.detector import IStepMetricsStreamDetector, IStatefulDetector
from failslow.domain.models import StepMetrics, DetectionResult, AnomalyInfo, AnomalyType
from .schema import BocpdParams

logger = logging.getLogger(__name__)


class DistributionMeta(ABCMeta):
    """Distribution type registry metaclass."""
    registry: Dict[str, type] = {}

    def __new__(mcls, name: str, bases: tuple, namespace: dict, **kwargs):
        cls = super().__new__(mcls, name, bases, namespace)
        if not any(
            hasattr(attr, "__isabstractmethod__") and attr.__isabstractmethod__
            for attr in namespace.values()
        ):
            DistributionMeta.registry[name] = cls
        return cls


class ProbabilityRecord(ABC, metaclass=DistributionMeta):
    """Base class for probability distribution records."""

    @staticmethod
    @abstractmethod
    def update(obs: Union[float, np.ndarray]) -> None:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_probability(obs: Union[float, np.ndarray]) -> np.ndarray:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def egress_point(num: int) -> None:
        raise NotImplementedError()


class Probability1d(ProbabilityRecord):
    """1D probability distribution record."""

    @staticmethod
    @abstractmethod
    def update(obs: float) -> None:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_probability(obs: float) -> np.ndarray:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def egress_point(num: int) -> None:
        raise NotImplementedError()


class GaussianProb1d(Probability1d):
    """Gaussian distribution probability estimation."""

    def __init__(self, init_sigma2: float = 1.0):
        self._init_sigma2 = init_sigma2
        self._sumX: np.ndarray = np.array([])
        self._sumX_sqr: np.ndarray = np.array([])
        self._N: np.ndarray = np.array([])

    def update(self, obs: float) -> None:
        self._sumX = np.append(self._sumX + obs, obs)
        self._sumX_sqr = np.append(self._sumX_sqr + obs * obs, obs * obs)
        self._N = np.append(self._N + 1, 1)

    def get_probability(self, obs: float) -> np.ndarray:
        mu = self._sumX / self._N
        sigma = np.sqrt(
            (self._sumX_sqr / self._N) - np.square(self._sumX / self._N) + self._init_sigma2
        )
        prob = stats.norm.pdf(obs, mu, sigma)
        return prob

    def egress_point(self, num: int) -> None:
        self._sumX = self._sumX[num:]
        self._sumX_sqr = self._sumX_sqr[num:]
        self._N = self._N[num:]


class StudentTProb1d(Probability1d):
    """Student-t distribution probability estimation."""

    def __init__(self) -> None:
        self._alphaAll: np.ndarray = np.array([])
        self._betaAll: np.ndarray = np.array([])
        self._countAll: np.ndarray = np.array([])
        self._muAll: np.ndarray = np.array([])

    def update(self, obs: float) -> None:
        self._betaAll = np.append(
            self._countAll + self._countAll / (self._countAll + 1) * np.square(obs - self._muAll) / 2,
            1,
        )
        self._muAll = np.append((self._muAll * self._countAll + obs) / (self._countAll + 1), obs)
        self._countAll = np.append(self._countAll + 1, 1)
        self._alphaAll = np.append(self._alphaAll + 0.5, 0.5)

    def get_probability(self, obs: float) -> np.ndarray:
        mean = self._muAll
        freedom = 2 * self._alphaAll
        precision = self._alphaAll * self._countAll / (self._countAll + 1) / self._betaAll
        prob = stats.t.pdf(obs, loc=mean, df=freedom, scale=precision)
        return prob

    def egress_point(self, num: int) -> None:
        self._alphaAll = self._alphaAll[num:]
        self._countAll = self._countAll[num:]
        self._muAll = self._muAll[num:]
        self._betaAll = self._betaAll[num:]


class LinearProb1d(Probability1d):
    """Linear model probability estimation.

    X - a*i - b ~ N(0, sigma)
    """

    def __init__(self, init_sigma2: float = 10.0):
        self._init_sigma2 = init_sigma2
        self._sumIX: np.ndarray = np.array([])
        self._sumI: np.ndarray = np.array([])
        self._sumI_sqr: np.ndarray = np.array([])
        self._sumX: np.ndarray = np.array([])
        self._sumX_sqr: np.ndarray = np.array([])
        self._N: np.ndarray = np.array([])

    def get_a(self) -> np.ndarray:
        return (self._N * self._sumIX - self._sumI * self._sumX) / (
            self._N * self._sumI_sqr - np.square(self._sumI) + 1e-30
        )

    def get_b(self, a: np.ndarray = None) -> np.ndarray:
        if a is None:
            a = self.get_a()
        return (self._sumX - a * self._sumI) / self._N

    def get_sigma(self, a: np.ndarray = None, b: np.ndarray = None) -> np.ndarray:
        if a is None:
            a = self.get_a()
        if b is None:
            b = self.get_b(a)
        sigma_sqr = (
            self._sumX_sqr
            + self._N * np.square(b)
            + np.square(a) * self._sumI_sqr
            + 2 * a * b * self._sumI
            - 2 * a * self._sumIX
            - 2 * b * self._sumX
            + self._init_sigma2
        )
        return np.sqrt(sigma_sqr)

    def update(self, obs: float) -> None:
        self._sumIX = np.append(self._sumIX + self._N * obs, 0)
        self._sumI = np.append(self._sumI + self._N, 0)
        self._sumI_sqr = np.append(self._sumI_sqr + np.square(self._N), 0)
        self._sumX = np.append(self._sumX + obs, obs)
        obs_sqr = obs * obs
        self._sumX_sqr = np.append(self._sumX_sqr + obs_sqr, obs_sqr)
        self._N = np.append(self._N + 1, 1)

    def get_probability(self, obs: float) -> np.ndarray:
        a = self.get_a()
        b = self.get_b(a)
        sigma = self.get_sigma(a, b)
        mu = obs - a * self._N - b
        probs = stats.norm.pdf(0, mu, sigma) + 1e-10
        return probs

    def egress_point(self, num: int) -> None:
        self._sumIX = self._sumIX[num:]
        self._sumI = self._sumI[num:]
        self._sumI_sqr = self._sumI_sqr[num:]
        self._sumX = self._sumX[num:]
        self._sumX_sqr = self._sumX_sqr[num:]
        self._N = self._N[num:]


class LinearProb1dWithRunLengthBonus(LinearProb1d):
    """Linear probability estimation with run length bonus."""

    def get_probability(self, obs: float) -> np.ndarray:
        probs = super().get_probability(obs)
        capped_N = np.minimum(self._N, 100)
        bonus = 1.01**capped_N
        probs *= bonus
        return probs


class BOCPDStream:
    """Bayesian Online Changepoint Detection streaming implementation."""

    def __init__(
        self,
        distribution: str = "LinearProb1dWithRunLengthBonus",
        hazard_lambda: float = 500,
        ignore_prop_lb: float = 1e-4,
        egress_distance: int = 10,
        record_probs: bool = False,
        enable_crop_acceleration: bool = True,
    ):
        self._P_r_t: np.ndarray = np.ones(0, dtype=np.float64)
        self._dist: Probability1d = DistributionMeta.registry[distribution]()
        logger.debug("Initialized BOCPDStream with distribution: %s", distribution)

        self._h_lambda = hazard_lambda
        self._ignore_prop_lb = ignore_prop_lb
        self._egress_distance = egress_distance
        self._probs: np.ndarray = np.ones(0, dtype=np.float64)
        self.obs: np.ndarray = np.zeros(0, dtype=np.float64)
        self._record_probs = record_probs
        self._enable_crop_acceleration = enable_crop_acceleration
        self._previous_rt: int = 0

    def update(self, obs: Union[float, np.ndarray]) -> bool:
        """
        Update the detector with a new observation.

        Returns:
            True if a changepoint was detected, False otherwise.
        """
        R = len(self._P_r_t)
        if R == 0:
            self._P_r_t = np.ones(1, dtype=np.float64)
            if self._record_probs:
                self._probs = np.ones((1, 1), dtype=np.float64)
            self._dist.update(obs)
            self.obs = np.append(self.obs, obs)
            self._previous_rt = 0
            return False

        prob_all_r = self._dist.get_probability(obs)
        assert len(prob_all_r) == R

        if self._record_probs:
            OBS_N, MAX_R = self._probs.shape
            if R > MAX_R:
                self._probs = np.hstack([self._probs, np.zeros((OBS_N, R - MAX_R))])
                MAX_R = R
            self._probs = np.vstack([self._probs, np.zeros((1, MAX_R))])
            self._probs[-1, :R] = np.flip(prob_all_r)

        H = 1 / self._h_lambda

        grow_prop = self._P_r_t * prob_all_r * (1 - H)
        change_prop = np.sum(self._P_r_t * prob_all_r * H)

        self._P_r_t = np.append(grow_prop, change_prop)
        prob_sum = np.sum(self._P_r_t)
        if prob_sum > 0:
            self._P_r_t /= prob_sum
        else:
            self._P_r_t = np.ones(len(self._P_r_t), dtype=np.float64) / len(self._P_r_t)

        self._dist.update(obs)
        self.obs = np.append(self.obs, obs)

        current_rt = self.get_rt()
        changepoint_detected = current_rt < self._previous_rt - self._egress_distance
        self._previous_rt = current_rt

        if self._enable_crop_acceleration:
            cdf_rt = np.cumsum(self._P_r_t)
            remove_n: int = np.count_nonzero(cdf_rt < self._ignore_prop_lb) - self._egress_distance
            if remove_n > 0:
                self._dist.egress_point(remove_n)
                self._P_r_t = self._P_r_t[remove_n:]
                self.obs = self.obs[remove_n:]

        return changepoint_detected

    def get_rt(self) -> int:
        """Get current run length estimate (mode of posterior)."""
        return len(self._P_r_t) - 1 - np.argmax(self._P_r_t)

    def get_P_rt(self) -> np.ndarray:
        """Get run length probability distribution."""
        return self._P_r_t

    def get_probs(self) -> np.ndarray:
        """Get all probability records."""
        return self._probs


class BocpdDetector(DetectorRegistry, IStepMetricsStreamDetector, IStatefulDetector):
    """
    BOCPD (Bayesian Online Change Point Detection) streaming detector.

    Detects changepoints in time series data using Bayesian online changepoint
    detection with configurable probability distributions.
    
    Implements:
        - IStepMetricsStreamDetector: For streaming detection on StepMetrics
        - IStatefulDetector: For state persistence and checkpointing
    """
    COMPONENT_NAME = "bocpd"

    def __init__(self, params: BocpdParams = None, **kwargs):
        if params is not None:
            self._params = params
        else:
            self._params = BocpdParams(**kwargs)
        
        self._hazard_lambda = int(1.0 / self._params.hazard) if self._params.hazard > 0 else 500
        self._stream = BOCPDStream(
            distribution=self._params.distribution,
            hazard_lambda=self._hazard_lambda,
            ignore_prop_lb=self._params.ignore_prop_lb,
            egress_distance=self._params.egress_distance,
            record_probs=self._params.record_probs,
            enable_crop_acceleration=self._params.enable_crop_acceleration,
        )
        self._metric_key = self._params.metric_key
        self._changepoint_threshold = self._params.changepoint_threshold
        self._step_count = 0
        self._last_run_length = 0

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def detect(self, data: List[StepMetrics]) -> List[DetectionResult]:
        """
        Detect changepoints in a batch of step metrics.

        Processes each StepMetrics sequentially, detecting changepoints
        using Bayesian online change point detection.
        """
        results = []
        for step_metrics in data:
            self._step_count += 1
            metric_value = self._extract_metric(step_metrics)

            if metric_value is None:
                continue

            changepoint_detected = self._stream.update(metric_value)
            current_run_length = self._stream.get_rt()

            if changepoint_detected:
                result = DetectionResult(
                    detector_name=self.name,
                    anomaly_info=AnomalyInfo(
                        is_anomaly=True,
                        anomaly_type=AnomalyType.FAIL_SLOW,
                        anomaly_count=1,
                        anomaly_details=[
                            {
                                "run_length": current_run_length,
                                "previous_run_length": self._last_run_length,
                                "threshold": self._changepoint_threshold,
                            }
                        ],
                        start_time=step_metrics.start_time_ns,
                        end_time=step_metrics.end_time_ns,
                    ),
                    confidence=min(1.0, self._last_run_length / 100.0),
                    metadata={
                        "metric_key": self._metric_key,
                        "metric_value": metric_value,
                        "run_length": current_run_length,
                    },
                )
                results.append(result)

            self._last_run_length = current_run_length

        return results

    def reset(self) -> None:
        """Reset the detector state."""
        self._stream = BOCPDStream(
            distribution=self._params.distribution,
            hazard_lambda=self._hazard_lambda,
            ignore_prop_lb=self._params.ignore_prop_lb,
            egress_distance=self._params.egress_distance,
            record_probs=self._params.record_probs,
            enable_crop_acceleration=self._params.enable_crop_acceleration,
        )
        self._step_count = 0
        self._last_run_length = 0

    def get_state(self) -> Dict[str, Any]:
        """
        Get the current detector state for persistence.

        Returns:
            Dict containing all internal state needed to resume detection.
        """
        return {
            "step_count": self._step_count,
            "last_run_length": self._last_run_length,
            "metric_key": self._metric_key,
            "changepoint_threshold": self._changepoint_threshold,
        }

    def set_state(self, state: Dict[str, Any]) -> None:
        """
        Restore detector state from a previously saved state.

        Args:
            state: Dict containing previously saved state.
        """
        self._step_count = state.get("step_count", 0)
        self._last_run_length = state.get("last_run_length", 0)
        self._metric_key = state.get("metric_key", self._metric_key)
        self._changepoint_threshold = state.get("changepoint_threshold", self._changepoint_threshold)

    def _extract_metric(self, step_metrics: StepMetrics) -> Optional[float]:
        """
        Extract the metric value from StepMetrics based on the configured metric_key.

        Args:
            step_metrics: The step metrics to extract from.

        Returns:
            The metric value or None if extraction fails.
        """
        if not step_metrics.kernels:
            return None

        if self._metric_key == "t_exec_ns":
            values = [k.t_exec_ns for k in step_metrics.kernels if k.t_exec_ns > 0]
            return float(np.mean(values)) if values else None
        elif self._metric_key == "t_delta_ns":
            values = [k.t_delta_ns for k in step_metrics.kernels if k.t_delta_ns > 0]
            return float(np.mean(values)) if values else None
        elif self._metric_key == "t3_ns":
            values = [k.t3_ns for k in step_metrics.kernels if k.t3_ns > 0]
            return float(np.mean(values)) if values else None
        elif self._metric_key == "t4_ns":
            values = [k.t4_ns for k in step_metrics.kernels if k.t4_ns > 0]
            return float(np.mean(values)) if values else None
        else:
            return None
