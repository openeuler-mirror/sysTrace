"""
Configuration schema for the File Alert Reporter.
"""
from pydantic import BaseModel, Field

class FileAlertReporterParams(BaseModel):
    """
    Parameters for the FileAlertReporter.
    """
    output_path: str = Field(
        default="./alerts.json", 
        description="Path to the output file where alerts will be written."
    )
    format: str = Field(
        default="json",
        description="Output format (currently only 'json' is supported)."
    )
