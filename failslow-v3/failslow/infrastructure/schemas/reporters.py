"""
Configuration schemas for alert reporters.
"""
from typing import Union, Literal
from pydantic import BaseModel, Field

# --- Parameter Schemas ---
class BaseReporterParams(BaseModel):
    """Base model for all reporter parameters."""
    pass

class LoggerParams(BaseReporterParams):
    """Parameters for the LoggerAlertReporter."""
    level: str = Field("WARNING", description="The logging level to use for alerts.")

class FileParams(BaseReporterParams):
    """Parameters for the FileAlertReporter."""
    output_path: str = Field("./alerts", description="Directory to save alert files.")
    format: str = Field("json", description="Output format (json or text).")

from ..components.reporters.file.schema import FileAlertReporterParams

# --- Config Union ---
class LoggerReporterConfig(BaseModel):
    type: Literal["console"]
    enabled: bool = True
    params: LoggerParams = Field(default_factory=LoggerParams)

class FileReporterConfig(BaseModel):
    type: Literal["file"]
    enabled: bool = True
    params: FileAlertReporterParams = Field(default_factory=FileAlertReporterParams)

# This is the type that will be used in TaskConfig.
AlertReporterConfig = Union[LoggerReporterConfig, FileReporterConfig]
