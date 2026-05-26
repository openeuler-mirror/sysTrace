"""Base detector interface."""
from abc import ABC, abstractmethod


class IDetector(ABC):
    """
    Base interface for all detectors.
    
    All detectors must implement this interface, which provides:
    - name property for identification
    - reset method for state reset
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Get the detector name.
        
        Returns:
            str: Unique identifier for this detector
        """
        raise NotImplementedError()
    
    @abstractmethod
    def reset(self) -> None:
        """
        Reset the detector's internal state.
        
        Called when starting a new detection session or after
        significant changes in the data stream.
        """
        raise NotImplementedError()
