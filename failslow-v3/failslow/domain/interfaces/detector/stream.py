"""Stream detector interface for single-step detection."""
from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import numpy as np

from .base import IDetector

if TYPE_CHECKING:
    from ...models import DetectorInput, DetectionResult


class IStreamDetector(IDetector):
    """
    Interface for streaming detectors that process single-step data.

    This interface is for detectors that work in a streaming fashion,
    processing one time step at a time and returning detection results
    immediately.

    This is useful for online monitoring scenarios where data arrives
    step by step and immediate feedback is needed.

    The optional context parameter allows forward extensibility without
    modifying the interface signature.
    """

    @abstractmethod
    def detect(
        self,
        data: Union[np.ndarray, "DetectorInput"],
        context: Optional[Dict[str, Any]] = None,
    ) -> List["DetectionResult"]:
        """
        Process a single time step of data.

        Args:
            data: Either a 1D np.ndarray of shape (num_ranks,) or
                  a DetectorInput containing values and metadata
            context: Optional runtime context for forward extensibility.
                     Can contain:
                     - 'timestamp': int representing current time (ms)
                     - 'sensitivity': float override for detection sensitivity
                     - 'callbacks': Dict of named callbacks
                     - Any other runtime parameters

        Returns:
            List of DetectionResult for any detected anomalies at this step
        """
        raise NotImplementedError()
