"""
Metric extractor for degradation detection.

Extracts step duration (end_time_ns - start_time_ns) from StepMetrics.
"""
import numpy as np
from typing import List, TYPE_CHECKING

from failslow.infrastructure.framework.registration import MetricExtractorRegistry
from failslow.domain.interfaces.metric_extractor import IMetricExtractor
from failslow.domain.models import DetectorInput

if TYPE_CHECKING:
    from failslow.domain.models import StepMetrics


class DegradationMetricExtractor(MetricExtractorRegistry, IMetricExtractor):
    """
    Metric extractor for degradation detection.

    Extracts step duration (end_time_ns - start_time_ns) from StepMetrics.
    """

    COMPONENT_NAME = "degradation_extractor"

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def extract(self, data: List["StepMetrics"]) -> DetectorInput:
        """
        Extract step duration from StepMetrics.

        Args:
            data: List[StepMetrics]

        Returns:
            DetectorInput with values = end_time_ns - start_time_ns for each rank
        """
        values = []
        rank_ids = []
        node_ips = []

        for step in data:
            values.append(step.end_time_ns - step.start_time_ns)
            rank_ids.append(step.rank_id)
            node_ips.append(step.node_ip)

        return DetectorInput(
            values=np.array(values),
            rank_ids=rank_ids,
            node_ips=node_ips,
        )
