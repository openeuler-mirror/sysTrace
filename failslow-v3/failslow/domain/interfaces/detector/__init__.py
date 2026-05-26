"""Detector interfaces for the FailSlow application.

This module provides a hierarchy of detector interfaces:
- IDetector: Base interface for all detectors
- IStreamDetector: For streaming (single-point) detection returning DetectionResult
- IBatchDetector: For batch detection on numpy arrays
- IStatefulDetector: For detectors with persistent state
- IStepMetricsStreamDetector: For streaming detection on StepMetrics
- IFusionStrategy: For fusing results from multiple detectors

Usage:
    from failslow.domain.interfaces.detector import IDetector, IStreamDetector
    
    class MyStreamDetector(IStreamDetector, IStatefulDetector):
        @property
        def name(self) -> str:
            return "my_detector"
        
        def detect(self, data) -> List[DetectionResult]:
            # Implementation for streaming detection
            pass
        
        def reset(self) -> None:
            # Reset state
            pass
        
        def get_state(self) -> Dict[str, Any]:
            # Get state for persistence
            pass
        
        def set_state(self, state: Dict[str, Any]) -> None:
            # Restore state
            pass
"""

from .base import IDetector
from .stream import IStreamDetector
from .batch import IBatchDetector
from .stateful import IStatefulDetector
from .step_metrics_stream import IStepMetricsStreamDetector
from .fusion import (
    IFusionStrategy,
    TimeSpaceFusionStrategy,
    OrFusionStrategy,
    AndFusionStrategy,
)

__all__ = [
    "IDetector",
    "IStreamDetector",
    "IBatchDetector",
    "IStatefulDetector",
    "IStepMetricsStreamDetector",
    "IFusionStrategy",
    "TimeSpaceFusionStrategy",
    "OrFusionStrategy",
    "AndFusionStrategy",
]

__all__ = [
    "IDetector",
    "IStreamDetector",
    "IBatchDetector",
    "IStatefulDetector",
    "IStepMetricsStreamDetector",
]
