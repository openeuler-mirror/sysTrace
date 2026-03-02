"""
Metric extractor for slow_launch detection.

Extracts kernel launch time (t3_ns - t2_ns) from StepMetrics.
"""
import numpy as np
from typing import List, TYPE_CHECKING

from failslow.infrastructure.framework.registration import MetricExtractorRegistry
from failslow.domain.interfaces.metric_extractor import IMetricExtractor
from failslow.domain.models import DetectorInput

if TYPE_CHECKING:
    from failslow.domain.models import StepMetrics


class SlowLaunchMetricExtractor(MetricExtractorRegistry, IMetricExtractor):
    """
    Metric extractor for slow_launch detection.

    Extracts kernel launch time (t3_ns - t2_ns) from StepMetrics.
    """

    COMPONENT_NAME = "slow_launch_extractor"

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def extract(self, data: List["StepMetrics"]) -> DetectorInput:
        """
        Extract launch time from StepMetrics.

        Args:
            data: List[StepMetrics]

        Returns:
            DetectorInput with values = t3_ns - t2_ns for each kernel (expanded, not mean'd).
            Each kernel becomes a separate entry, allowing the preprocessor to handle
            aggregation across time windows consistently with v1 behavior.
        """
        values = []
        rank_ids = []
        node_ips = []

        for step in data:
            if step.kernels:
                for kernel in step.kernels:
                    diff = kernel.t3_ns - kernel.t2_ns
                    values.append(diff)
                    rank_ids.append(step.rank_id)
                    node_ips.append(step.node_ip)
            else:
                values.append(np.nan)
                rank_ids.append(step.rank_id)
                node_ips.append(step.node_ip)

        return DetectorInput(
            values=np.array(values),
            rank_ids=rank_ids,
            node_ips=node_ips,
        )
