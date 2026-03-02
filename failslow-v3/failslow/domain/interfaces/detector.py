"""
Detector interface definitions.

This module re-exports detector interfaces from the detector/ subpackage
for backward compatibility.

For new code, prefer importing directly from the detector subpackage:
    from failslow.domain.interfaces.detector import IDetector, IStreamDetector

Available interfaces:
    - IDetector: Base interface for all detectors
    - IStreamDetector: For streaming detection returning DetectionResult
    - IBatchDetector: For batch detection on numpy arrays
    - IStatefulDetector: For detectors with persistent state
    - IStepMetricsStreamDetector: For streaming detection on StepMetrics
"""

from .detector.base import IDetector
from .detector.stream import IStreamDetector
from .detector.batch import IBatchDetector
from .detector.stateful import IStatefulDetector
from .detector.step_metrics_stream import IStepMetricsStreamDetector

__all__ = [
    "IDetector",
    "IStreamDetector",
    "IBatchDetector",
    "IStatefulDetector",
    "IStepMetricsStreamDetector",
]
