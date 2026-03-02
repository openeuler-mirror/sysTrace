"""
Defines the abstract interface for data sources.
"""
from abc import ABC, abstractmethod
from typing import Iterator
from ..models import StepMetrics

class IDataSource(ABC):
    """
    Data source interface.

    Defines a unified interface for data sources, supporting connecting,
    disconnecting, and reading data.
    """
    @abstractmethod
    def connect(self) -> None:
        """Establishes a connection to the data source."""
        raise NotImplementedError()

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnects from the data source."""
        raise NotImplementedError()

    @abstractmethod
    def is_connected(self) -> bool:
        """Checks if a connection is established."""
        raise NotImplementedError()

    @abstractmethod
    def read(self) -> Iterator[StepMetrics]:
        """Reads data and returns a StepMetrics iterator."""
        raise NotImplementedError()
