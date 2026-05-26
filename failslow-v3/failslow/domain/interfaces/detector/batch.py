"""Batch detector interface."""
from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

import numpy as np

from .base import IDetector

if TYPE_CHECKING:
    from ...models import DetectorInput


class IBatchDetector(IDetector):
    """
    Interface for batch detectors.

    Batch detectors process entire datasets at once, suitable for
    offline analysis scenarios where all data is available.

    The optional context parameter allows forward extensibility without
    modifying the interface signature - callers can pass runtime
    information like timestamps, callbacks, or sensitivity overrides.
    """

    @abstractmethod
    def detect(
        self,
        data: Union[np.ndarray, "DetectorInput"],
        context: Optional[Dict[str, Any]] = None,
    ) -> np.ndarray:
        """
        Process a batch of data.

        Args:
            data: Either a np.ndarray of shape (time_len, num_ranks) or
                  a DetectorInput containing values and metadata
            context: Optional runtime context for forward extensibility.
                     Can contain:
                     - 'timestamps': np.ndarray of window start times (ms)
                     - 'sensitivity': float override for detection sensitivity
                     - 'callbacks': Dict of named callbacks
                     - Any other runtime parameters

        Returns:
            np.ndarray of shape (time_len, num_ranks) with 0=normal, 1=anomaly
        """
        raise NotImplementedError()
