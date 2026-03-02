"""
Configuration schemas for metric extractors.
"""
from typing import Literal, Union

from pydantic import BaseModel


class SlowCalcExtractorConfig(BaseModel):
    """Configuration for slow_calc metric extractor."""
    type: Literal["slow_calc_extractor"]
    enabled: bool = True


class SlowLaunchExtractorConfig(BaseModel):
    """Configuration for slow_launch metric extractor."""
    type: Literal["slow_launch_extractor"]
    enabled: bool = True


class DegradationExtractorConfig(BaseModel):
    """Configuration for degradation metric extractor."""
    type: Literal["degradation_extractor"]
    enabled: bool = True


class SlowHostExtractorConfig(BaseModel):
    """Configuration for slow_host metric extractor."""
    type: Literal["slow_host_extractor"]
    enabled: bool = True


MetricExtractorConfig = Union[
    SlowCalcExtractorConfig,
    SlowLaunchExtractorConfig,
    DegradationExtractorConfig,
    SlowHostExtractorConfig,
]
