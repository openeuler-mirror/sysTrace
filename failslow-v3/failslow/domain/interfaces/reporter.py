"""
Defines the abstract interface for alert reporters.
"""
from abc import ABC, abstractmethod
from ..models import Alert

class IAlertReporter(ABC):
    """
    Alert reporter interface.

    Defines a unified interface for alert reporters.
    """
    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the reporter."""
        raise NotImplementedError()

    @abstractmethod
    def report(self, alert: Alert) -> bool:
        """
        Sends an alert.

        Args:
            alert: The alert object.

        Returns:
            True if the alert was sent successfully, False otherwise.
        """
        raise NotImplementedError()

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the reporter is available."""
        raise NotImplementedError()

    @abstractmethod
    def convert_to_alert(self, result: "DetectionResult") -> Alert:
        """Converts a DetectionResult into a reportable Alert."""
        raise NotImplementedError()
