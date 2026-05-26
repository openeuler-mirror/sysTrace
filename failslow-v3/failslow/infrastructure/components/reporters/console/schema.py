"""
Configuration schema for the ConsoleAlertReporter.
"""
from pydantic import BaseModel, Field

class ConsoleParams(BaseModel):
    """Parameters for the ConsoleAlertReporter."""
    level: str = Field("INFO", description="The logging level to use for alerts.")
