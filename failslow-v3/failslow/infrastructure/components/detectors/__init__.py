"""
Detector components for the FailSlow application.
"""
from .sliding_window_ksigma import SlidingWindowKSigmaDetector
from .bocpd import BocpdDetector
from .composite import CompositeDetector
from .degradation_ksigma_naive import DegradationKSigmaNaiveDetector
from .degradation_ksigma_robust import DegradationKSigmaRobustDetector
from .degradation_bocpd import DegradationBocpdDetector

__all__ = [
    "SlidingWindowKSigmaDetector",
    "BocpdDetector",
    "CompositeDetector",
    "DegradationKSigmaNaiveDetector",
    "DegradationKSigmaRobustDetector",
    "DegradationBocpdDetector",
]
