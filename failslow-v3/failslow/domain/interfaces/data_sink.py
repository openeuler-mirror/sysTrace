"""
Defines the abstract interface for data sinks.

Data sinks are responsible for persisting raw StepMetrics data to durable storage.
Unlike reporters (which handle alerts), data sinks handle raw metrics persistence.
"""
from abc import ABC, abstractmethod
from typing import List

from ..models import StepMetrics


class IDataSink(ABC):
    """
    Data sink interface for persisting raw metrics data.

    Used in online mode to asynchronously persist incoming StepMetrics
    before they are processed by the detection pipeline.
    """

    @abstractmethod
    def write(self, step_metrics_list: List[StepMetrics]) -> None:
        """
        Write a batch of StepMetrics data (non-blocking, async).

        Args:
            step_metrics_list: List of StepMetrics to persist.
        """
        raise NotImplementedError()

    @abstractmethod
    def flush(self) -> None:
        """Flush buffered data to ensure all data is persisted."""
        raise NotImplementedError()

    @abstractmethod
    def close(self) -> None:
        """Close the sink and release all resources."""
        raise NotImplementedError()
