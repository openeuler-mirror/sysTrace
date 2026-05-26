"""
Defines the abstract interface for metric extractors.
"""
from abc import ABC, abstractmethod
from typing import List, TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from ..models import StepMetrics, DetectorInput


class IMetricExtractor(ABC):
    """
    Metric Extractor interface. 从 StepMetrics 提取特定 metric。
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the extractor name."""
        raise NotImplementedError()

    @abstractmethod
    def extract(self, data: List["StepMetrics"]) -> "DetectorInput":
        """
        从 StepMetrics 提取 metric 值。

        Args:
            data: List[StepMetrics]

        Returns:
            DetectorInput: 包含 values, rank_ids, node_ips
        """
        raise NotImplementedError()
