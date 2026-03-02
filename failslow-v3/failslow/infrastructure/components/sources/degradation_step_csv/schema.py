"""
Configuration schema for the Degradation Step CSV Data Source component.
"""
from pydantic import BaseModel, Field


class DegradationStepCsvParams(BaseModel):
    """
    Parameters for configuring the DegradationStepCsvDataSource.

    Reads step-level CSV files with columns:
    step_id, step_start_time, step_end_time, step_exec_time
    """
    directory_path: str = Field(
        ...,
        description="Path to directory with step time CSVs"
    )
    file_pattern: str = Field(
        default="training_step_time_*.csv",
        description="Glob pattern for files to read"
    )
    max_workers: int = Field(
        default=1,
        ge=1,
        description="Maximum number of threads for parallel CSV file parsing. Default 1 (serial)."
    )