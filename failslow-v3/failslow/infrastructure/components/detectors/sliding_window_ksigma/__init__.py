"""
Sliding Window K-Sigma detector.
"""
from .detector import SlidingWindowKSigmaDetector
from .schema import SlidingWindowKSigmaParams

__all__ = [
    "SlidingWindowKSigmaDetector",
    "SlidingWindowKSigmaParams",
]
