"""
Configuration schemas for preprocessors.
"""

from typing import Literal, Union

from pydantic import BaseModel, Field

from ..components.preprocessors.time_window_aggregator.schema import (
    TimeWindowAggregatorParams,
)
from ..components.preprocessors.op_name_filter.schema import OpNameFilterParams
from ..components.preprocessors.step_aggregator.schema import StepAggregatorParams


# --- Config Union ---
class TimeWindowAggregatorConfig(BaseModel):
    type: Literal["time_window_aggregator"]
    enabled: bool = True
    params: TimeWindowAggregatorParams = Field(
        default_factory=TimeWindowAggregatorParams
    )


class OpNameFilterConfig(BaseModel):
    type: Literal["op_name_filter"]
    enabled: bool = True
    params: OpNameFilterParams = Field(default_factory=OpNameFilterParams)


class StepAggregatorConfig(BaseModel):
    type: Literal["step_aggregator"]
    enabled: bool = True
    params: StepAggregatorParams = Field(default_factory=StepAggregatorParams)


# This is the type that will be used in TaskConfig.
PreprocessorConfig = Union[
    TimeWindowAggregatorConfig, OpNameFilterConfig, StepAggregatorConfig
]
