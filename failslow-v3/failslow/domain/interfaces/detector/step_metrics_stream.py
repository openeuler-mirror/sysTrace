"""Step metrics stream detector interface."""
from abc import abstractmethod
from typing import TYPE_CHECKING, List

from .base import IDetector

if TYPE_CHECKING:
    from ...models import StepMetrics, DetectionResult


class IStepMetricsStreamDetector(IDetector):
    """
    Interface for streaming detectors that process StepMetrics directly.
    
    This interface is for detectors that work with raw StepMetrics data
    rather than pre-aggregated numpy arrays. Useful for detectors that
    need access to individual kernel metrics or metadata.
    
    This is a specialized interface for detectors like BocpdDetector that
    process StepMetrics streams and produce DetectionResult objects.
    """
    
    @abstractmethod
    def detect(self, data: List["StepMetrics"]) -> List["DetectionResult"]:
        """
        Process a list of StepMetrics and return detection results.
        
        Args:
            data: List of StepMetrics from multiple ranks at a time point
        
        Returns:
            List of DetectionResult for any detected anomalies
        """
        raise NotImplementedError()
