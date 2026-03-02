"""Stateful detector interface."""
from abc import abstractmethod
from typing import Any, Dict

from .base import IDetector


class IStatefulDetector(IDetector):
    """
    Interface for stateful detectors.
    
    Stateful detectors maintain internal state that can be saved
    and restored, useful for checkpointing and resuming detection.
    """
    
    @abstractmethod
    def get_state(self) -> Dict[str, Any]:
        """
        Get the current detector state.
        
        Returns:
            Dict containing all internal state needed to resume detection
        """
        raise NotImplementedError()
    
    @abstractmethod
    def set_state(self, state: Dict[str, Any]) -> None:
        """
        Restore detector state.
        
        Args:
            state: Dict containing previously saved state
        """
        raise NotImplementedError()
