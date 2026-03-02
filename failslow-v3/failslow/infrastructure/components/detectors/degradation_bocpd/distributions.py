"""
Probability distribution models for BOCPD (Bayesian Online Changepoint Detection).

Implements vectorized distribution models where each instance maintains
sufficient statistics arrays for ALL run lengths simultaneously. This is
the core design pattern from the original BOCPD algorithm.
"""

import logging
from abc import ABC, ABCMeta, abstractmethod
from typing import Dict, List, Type

import numpy as np
from scipy.stats import norm, t as t_dist

logger = logging.getLogger(__name__)


class DistributionMeta(ABCMeta):
    """Registry metaclass for probability distribution models."""
    registry: Dict[str, Type["ProbabilityRecord"]] = {}

    def __new__(mcs, name, bases, namespace, **kwargs):
        cls = super().__new__(mcs, name, bases, namespace, **kwargs)
        if not any(
            hasattr(v, "__isabstractmethod__") and v.__isabstractmethod__
            for v in namespace.values()
        ):
            mcs.registry[name] = cls
        return cls


class ProbabilityRecord(ABC, metaclass=DistributionMeta):
    """Abstract base class for probability distribution models."""

    @abstractmethod
    def update(self, obs: float) -> None:
        raise NotImplementedError()

    @abstractmethod
    def get_probability(self, obs: float) -> np.ndarray:
        raise NotImplementedError()

    @abstractmethod
    def egress_point(self, num: int) -> None:
        raise NotImplementedError()


class GaussianProb1d(ProbabilityRecord):
    """Gaussian distribution with conjugate prior (vectorized for all run lengths)."""

    def __init__(self, init_sigma2: float = 1.0, **kwargs):
        self.init_sigma2 = init_sigma2
        self._sumX = np.array([], dtype=np.float64)
        self._sumX_sqr = np.array([], dtype=np.float64)
        self._N = np.array([], dtype=np.float64)

    def update(self, obs: float) -> None:
        self._sumX = np.append(self._sumX + obs, obs)
        obs_sqr = obs * obs
        self._sumX_sqr = np.append(self._sumX_sqr + obs_sqr, obs_sqr)
        self._N = np.append(self._N + 1, 1)

    def get_probability(self, obs: float) -> np.ndarray:
        if len(self._N) == 0:
            return np.array([1.0])
        mu = self._sumX / self._N
        sigma2 = self._sumX_sqr / self._N - np.square(mu) + self.init_sigma2
        sigma = np.sqrt(np.maximum(sigma2, 1e-12))
        return norm.pdf(obs, mu, sigma)

    def egress_point(self, num: int) -> None:
        self._sumX = self._sumX[num:]
        self._sumX_sqr = self._sumX_sqr[num:]
        self._N = self._N[num:]


class StudentTProb1d(ProbabilityRecord):
    """Student-t distribution with conjugate Normal-Gamma prior (vectorized)."""

    def __init__(self, init_sigma2: float = 1.0, **kwargs):
        self.init_sigma2 = init_sigma2
        self._alpha = np.array([], dtype=np.float64)
        self._beta = np.array([], dtype=np.float64)
        self._count = np.array([], dtype=np.float64)
        self._mu = np.array([], dtype=np.float64)

    def update(self, obs: float) -> None:
        delta = obs - self._mu
        new_count = self._count + 1
        new_mu = np.where(self._count > 0, self._mu + delta / new_count, obs)
        new_alpha = self._alpha + 0.5
        new_beta = np.where(self._count > 0, self._beta + delta * (obs - new_mu) / 2.0, self.init_sigma2 / 2.0)

        self._alpha = np.append(new_alpha, 1.0)
        self._beta = np.append(new_beta, self.init_sigma2 / 2.0)
        self._count = np.append(new_count, 0.0)
        self._mu = np.append(new_mu, obs)

    def get_probability(self, obs: float) -> np.ndarray:
        if len(self._count) == 0:
            return np.array([1.0])
        df = 2 * self._alpha
        loc = self._mu
        scale = np.sqrt(self._beta * (self._count + 1) / (self._alpha * np.maximum(self._count, 1)))
        return t_dist.pdf(obs, df=df, loc=loc, scale=scale)

    def egress_point(self, num: int) -> None:
        self._alpha = self._alpha[num:]
        self._beta = self._beta[num:]
        self._count = self._count[num:]
        self._mu = self._mu[num:]


class LinearProb1d(ProbabilityRecord):
    """Linear regression model: X = a*i + b + noise (vectorized for all run lengths)."""

    def __init__(self, init_sigma2: float = 10.0, **kwargs):
        self.init_sigma2 = init_sigma2
        self._sumIX = np.array([], dtype=np.float64)
        self._sumI = np.array([], dtype=np.float64)
        self._sumI_sqr = np.array([], dtype=np.float64)
        self._sumX = np.array([], dtype=np.float64)
        self._sumX_sqr = np.array([], dtype=np.float64)
        self._N = np.array([], dtype=np.float64)

    def update(self, obs: float) -> None:
        self._sumIX = np.append(self._sumIX + self._N * obs, 0)
        self._sumI = np.append(self._sumI + self._N, 0)
        self._sumI_sqr = np.append(self._sumI_sqr + np.square(self._N), 0)
        self._sumX = np.append(self._sumX + obs, obs)
        obs_sqr = obs * obs
        self._sumX_sqr = np.append(self._sumX_sqr + obs_sqr, obs_sqr)
        self._N = np.append(self._N + 1, 1)

    def get_probability(self, obs: float) -> np.ndarray:
        if len(self._N) == 0:
            return np.array([1.0])
        a = (self._N * self._sumIX - self._sumI * self._sumX) / (
            self._N * self._sumI_sqr - np.square(self._sumI) + 1e-30
        )
        b = (self._sumX - a * self._sumI) / self._N
        idx = len(self._N)
        pred = a * idx + b
        sigma2 = self._sumX_sqr / self._N - np.square(self._sumX / self._N) + self.init_sigma2
        sigma = np.sqrt(np.maximum(sigma2, 1e-12))
        return norm.pdf(obs, pred, sigma)

    def egress_point(self, num: int) -> None:
        self._sumIX = self._sumIX[num:]
        self._sumI = self._sumI[num:]
        self._sumI_sqr = self._sumI_sqr[num:]
        self._sumX = self._sumX[num:]
        self._sumX_sqr = self._sumX_sqr[num:]
        self._N = self._N[num:]


class LinearProbRobust(ProbabilityRecord):
    """Linear model with Huber loss for robust variance estimation (vectorized)."""

    def __init__(self, init_sigma2: float = 10.0, huber_delta: float = 1.0, **kwargs):
        self.init_sigma2 = init_sigma2
        self.huber_delta = huber_delta
        self._sumIX = np.array([], dtype=np.float64)
        self._sumI = np.array([], dtype=np.float64)
        self._sumI_sqr = np.array([], dtype=np.float64)
        self._sumX = np.array([], dtype=np.float64)
        self._sumX_sqr = np.array([], dtype=np.float64)
        self._N = np.array([], dtype=np.float64)
        self._residuals: List[float] = []

    def update(self, obs: float) -> None:
        self._sumIX = np.append(self._sumIX + self._N * obs, 0)
        self._sumI = np.append(self._sumI + self._N, 0)
        self._sumI_sqr = np.append(self._sumI_sqr + np.square(self._N), 0)
        self._sumX = np.append(self._sumX + obs, obs)
        obs_sqr = obs * obs
        self._sumX_sqr = np.append(self._sumX_sqr + obs_sqr, obs_sqr)
        self._N = np.append(self._N + 1, 1)
        a = (self._N * self._sumIX - self._sumI * self._sumX) / (
            self._N * self._sumI_sqr - np.square(self._sumI) + 1e-30
        )
        b = (self._sumX - a * self._sumI) / self._N
        idx = len(self._N)
        pred = a[-1] * (idx - 1) + b[-1]
        residual = obs - pred
        self._residuals.append(residual)

    def _get_robust_sigma(self) -> float:
        if len(self._residuals) < 2:
            return np.sqrt(self.init_sigma2)
        residuals = np.array(self._residuals)
        delta = self.huber_delta
        abs_r = np.abs(residuals)
        huber_loss = np.where(
            abs_r <= delta, 0.5 * residuals ** 2, delta * (abs_r - 0.5 * delta)
        )
        sigma2 = np.mean(huber_loss) + self.init_sigma2
        return np.sqrt(sigma2)

    def get_probability(self, obs: float) -> np.ndarray:
        if len(self._N) == 0:
            return np.array([1.0])
        a = (self._N * self._sumIX - self._sumI * self._sumX) / (
            self._N * self._sumI_sqr - np.square(self._sumI) + 1e-30
        )
        b = (self._sumX - a * self._sumI) / self._N
        idx = len(self._N)
        pred = a * idx + b
        sigma = self._get_robust_sigma()
        return norm.pdf(obs, pred, sigma) + 1e-10

    def egress_point(self, num: int) -> None:
        self._sumIX = self._sumIX[num:]
        self._sumI = self._sumI[num:]
        self._sumI_sqr = self._sumI_sqr[num:]
        self._sumX = self._sumX[num:]
        self._sumX_sqr = self._sumX_sqr[num:]
        self._N = self._N[num:]
        self._residuals = self._residuals[num:]


class LinearProb1dWithRunLengthBonus(LinearProb1d):
    """Linear model with run-length bonus to bias toward longer run lengths."""

    def __init__(self, init_sigma2: float = 10.0, run_length_bonus: float = 1.001, **kwargs):
        super().__init__(init_sigma2=init_sigma2, **kwargs)
        self._run_length_bonus = run_length_bonus

    def get_probability(self, obs: float) -> np.ndarray:
        probs = super().get_probability(obs)
        capped_N = np.minimum(self._N, 100)
        bonus = self._run_length_bonus ** capped_N
        return probs * bonus


class BVARProb1d(ProbabilityRecord):
    """Bayesian Vector Auto-Regression (stub)."""

    def update(self, obs: float) -> None:
        pass

    def get_probability(self, obs: float) -> np.ndarray:
        return np.array([1.0])

    def egress_point(self, num: int) -> None:
        pass


class BOCPDStream:
    """
    Core BOCPD (Bayesian Online Changepoint Detection) algorithm.

    Maintains a probability distribution over run lengths P(r_t) and
    updates it incrementally as new observations arrive. Uses vectorized
    distribution models for efficient computation.
    """

    def __init__(
        self,
        distribution: str = "LinearProb1dWithRunLengthBonus",
        hazard: float = 0.002,
        ignore_prop_lb: float = 1e-4,
        egress_distance: int = 10,
        record_probs: bool = False,
        enable_crop_acceleration: bool = True,
        init_sigma2: float = 10.0,
        huber_delta: float = 1.0,
        run_length_bonus: float = 1.001,
    ):
        self._hazard = hazard
        self._ignore_prop_lb = ignore_prop_lb
        self._egress_distance = egress_distance
        self._record_probs = record_probs
        self._enable_crop_acceleration = enable_crop_acceleration

        dist_cls = DistributionMeta.registry.get(distribution)
        if dist_cls is None:
            raise ValueError(
                f"Unknown distribution: {distribution}. "
                f"Available: {list(DistributionMeta.registry.keys())}"
            )

        kwargs = {"init_sigma2": init_sigma2}
        if distribution == "LinearProbRobust":
            kwargs["huber_delta"] = huber_delta
        if distribution == "LinearProb1dWithRunLengthBonus":
            kwargs["run_length_bonus"] = run_length_bonus

        self._dist = dist_cls(**kwargs)
        self._P_r_t = np.ones(0, dtype=np.float64)
        self._total_obs_count: int = 0
        self._cropped_count: int = 0

    def update(self, obs: float) -> int:
        """
        Process a new observation and return the most probable run length.

        Args:
            obs: New observation value.

        Returns:
            Most probable run length after processing this observation.
        """
        self._total_obs_count += 1
        R = len(self._P_r_t)

        if R == 0:
            self._P_r_t = np.ones(1, dtype=np.float64)
            self._dist.update(obs)
            return 0

        prob_all_r = self._dist.get_probability(obs)
        assert len(prob_all_r) == R, f"prob_all_r length {len(prob_all_r)} != R {R}"

        H = self._hazard

        growth_probs = self._P_r_t * prob_all_r * (1 - H)
        change_prob = np.sum(self._P_r_t * prob_all_r * H)

        self._P_r_t = np.append(growth_probs, change_prob)
        total = np.sum(self._P_r_t)
        if total > 0:
            self._P_r_t /= total

        self._dist.update(obs)

        if self._enable_crop_acceleration:
            cdf_rt = np.cumsum(self._P_r_t)
            remove_n = (
                np.count_nonzero(cdf_rt < self._ignore_prop_lb) - self._egress_distance
            )
            if remove_n > 0:
                self._dist.egress_point(remove_n)
                self._P_r_t = self._P_r_t[remove_n:]
                self._cropped_count += remove_n

        rt = len(self._P_r_t) - 1 - np.argmax(self._P_r_t) + self._cropped_count
        return rt

    def get_rt(self) -> int:
        """Get the most probable run length."""
        return len(self._P_r_t) - 1 - np.argmax(self._P_r_t)

    def get_total_obs_count(self) -> int:
        return self._total_obs_count
