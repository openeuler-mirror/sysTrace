"""
Configuration schema for the Time Window Aggregator preprocessor.
"""
from typing import Dict, Literal, List, Optional
from pydantic import BaseModel, Field

class SmoothingSettings(BaseModel):
    """Configuration for data smoothing."""
    function: Literal["mean", "median", "gaussian"] = "mean"
    window_size: int = Field(10, gt=1)


class MetricOverrideConfig(BaseModel):
    """Per-operator aggregation override configuration."""
    time_window_seconds: Optional[float] = Field(default=None, description="Override window duration")
    aggregation_functions: Optional[List["AggregationFunction"]] = None
    smoothing: Optional[SmoothingSettings] = None
    filter_extreme_values: Optional[bool] = None
    extreme_quantile_upper: Optional[float] = None
    extreme_quantile_lower: Optional[float] = None

class PercentileParams(BaseModel):
    """Parameters for percentile aggregation."""
    q: float = Field(default=80.0, ge=0, le=100, description="Percentile quantile (0-100)")


class AggregationFunction(BaseModel):
    """Configuration for a single aggregation function."""
    function: Literal["mean", "median", "sum", "max", "min", "std", "count", "p99", "percentile"] = "mean"
    func_params: Optional[PercentileParams] = Field(default=None, description="Parameters for the aggregation function")

class TimeWindowAggregatorParams(BaseModel):
    """
    Parameters for the TimeWindowAggregatorPreprocessor.
    """
    time_window_seconds: float = Field(
        default=1.0,
        gt=0,
        description="The duration of the time window in seconds."
    )
    drop_head_seconds: float = Field(
        default=0.0,
        ge=0,
        description="丢弃数据开头的时长（秒），用于跳过训练初始化预热阶段"
    )
    drop_tail_seconds: float = Field(
        default=0.0,
        ge=0,
        description="丢弃数据末尾的时长（秒），用于跳过训练收尾阶段"
    )
    filter_extreme_values: bool = Field(
        default=False,
        description="Whether to filter out extreme values before aggregation."
    )
    extreme_quantile_upper: float = Field(0.95, ge=0, le=1)
    extreme_quantile_lower: float = Field(0.05, ge=0, le=1)
    aggregation_functions: List[AggregationFunction] = Field(
        default=[AggregationFunction(function="mean")],
        description="List of functions to apply during aggregation."
    )
    smoothing: SmoothingSettings = Field(
        default_factory=SmoothingSettings,
        description="Settings for smoothing the aggregated data."
    )
    metric_configs: Dict[str, MetricOverrideConfig] = Field(
        default_factory=dict,
        description="Per-operator aggregation configuration. Key is operator name (e.g., 'HcclAllreduce'). "
                    "When OpNameFilter selects an operator, this config is used if available."
    )
