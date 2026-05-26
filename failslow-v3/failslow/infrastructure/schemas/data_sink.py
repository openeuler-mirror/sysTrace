"""
Configuration schemas for data sinks.
"""
from typing import Union, Literal
from pydantic import BaseModel, Field

from ..components.sinks.local_csv.schema import LocalCsvDataSinkParams


class LocalCsvDataSinkConfig(BaseModel):
    type: Literal["local_csv"] = "local_csv"
    enabled: bool = True
    params: LocalCsvDataSinkParams = Field(default_factory=LocalCsvDataSinkParams)


DataSinkConfig = Union[LocalCsvDataSinkConfig]
