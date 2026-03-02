"""
BOCPD (Bayesian Online Change Point Detection) detector.
"""
from .detector import BocpdDetector
from .schema import BocpdParams

__all__ = [
    "BocpdDetector",
    "BocpdParams",
]
