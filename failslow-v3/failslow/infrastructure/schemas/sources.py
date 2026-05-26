"""
Configuration schemas for data sources.
"""
from typing import Union, Literal
from pydantic import BaseModel

# Import the actual params from the component
from ..components.sources.local_csv.schema import LocalCsvParams
from ..components.sources.degradation_step_csv.schema import DegradationStepCsvParams


# --- Config Union ---
class LocalCsvSourceConfig(BaseModel):
    type: Literal["local_csv"]
    params: LocalCsvParams


class DegradationStepCsvSourceConfig(BaseModel):
    type: Literal["degradation_step_csv"]
    params: DegradationStepCsvParams


# This is the type that will be used in TaskConfig.
DataSourceConfig = Union[LocalCsvSourceConfig, DegradationStepCsvSourceConfig]
