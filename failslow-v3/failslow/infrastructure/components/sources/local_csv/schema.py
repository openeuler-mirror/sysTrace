"""
Configuration schema for the Local CSV Data Source component.
"""
from typing import Literal
from pydantic import BaseModel, Field


class LocalCsvParams(BaseModel):
    """
    Parameters for configuring the LocalCsvDataSource.

    This Pydantic model provides strict, type-safe validation for all
    configuration parameters at application startup.
    """
    directory_path: str = Field(
        ...,
        description="Path to the directory containing the CSV files."
    )
    format: Literal["hccl", "nccl", "auto"] = Field(
        default="auto",
        description="The format of the CSV data. 'auto' will detect based on filename or content."
    )
    strict_mode: bool = Field(
        default=False,
        description="If True, any parsing error will raise an exception. If False, errors are logged and the file is skipped."
    )
    max_workers: int = Field(
        default=1,
        ge=1,
        description="Maximum number of threads for parallel CSV file parsing. Default 1 (serial)."
    )
