"""
Configuration schema for the Step Aggregator preprocessor.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from ..time_window_aggregator.schema import AggregationFunction, SmoothingSettings


class StepMetricOverrideConfig(BaseModel):
    """Per-operator aggregation override configuration for step aggregator."""

    steps_per_group: Optional[int] = Field(
        default=None, description="Override steps per group for this operator"
    )
    aggregation_functions: Optional[List[AggregationFunction]] = None
    smoothing: Optional[SmoothingSettings] = None
    filter_extreme_values: Optional[bool] = None
    extreme_quantile_upper: Optional[float] = None
    extreme_quantile_lower: Optional[float] = None


class StepAggregatorParams(BaseModel):
    """
    Parameters for the StepAggregatorPreprocessor.
    """

    steps_per_group: int = Field(
        default=1,
        ge=1,
        description="几个 step 聚合一次。例如 steps_per_group=10 时，step 0-9 聚合为一个数据点。",
    )
    filter_extreme_values: bool = Field(
        default=False,
        description="Whether to filter out extreme values before aggregation.",
    )
    extreme_quantile_upper: float = Field(0.95, ge=0, le=1)
    extreme_quantile_lower: float = Field(0.05, ge=0, le=1)
    aggregation_functions: List[AggregationFunction] = Field(
        default=[AggregationFunction(function="mean")],
        description="List of functions to apply during aggregation.",
    )
    smoothing: SmoothingSettings = Field(
        default_factory=SmoothingSettings,
        description="Settings for smoothing the aggregated data.",
    )
    metric_configs: Dict[str, StepMetricOverrideConfig] = Field(
        default_factory=dict,
        description="Per-operator aggregation configuration. Key is operator name. "
        "When OpNameFilter selects an operator, this config is used if available.",
    )
