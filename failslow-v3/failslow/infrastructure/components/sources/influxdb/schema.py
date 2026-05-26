"""
Configuration schema for the InfluxDBDataSource.
"""
from pydantic import BaseModel, Field

class InfluxDBParams(BaseModel):
    """Parameters for the InfluxDBDataSource."""
    url: str = Field(..., description="URL of the InfluxDB v2 instance.")
    token: str = Field(..., description="Authentication token for InfluxDB v2.")
    org: str = Field(..., description="Organization name in InfluxDB v2.")
    bucket: str = Field(..., description="Bucket to query from.")
    measurement: str = Field(..., description="Measurement to query from.")
    start: str = Field("-1h", description="Start time for the query.")
