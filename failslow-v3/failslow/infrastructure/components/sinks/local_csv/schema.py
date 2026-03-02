"""
Configuration schema for LocalCsvDataSink.
"""
from pydantic import BaseModel, Field


class LocalCsvDataSinkParams(BaseModel):
    output_directory: str = Field(
        default="./data_sink_output",
        description="Directory path for output CSV files.",
    )
    format: str = Field(
        default="nccl",
        description="Output CSV format. Supported: 'nccl' (hccl_activity-*.csv), 'hccl' (mspti-marker-*.csv).",
    )
