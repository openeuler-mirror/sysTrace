"""
Root configuration schema for the FailSlow application.
"""
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

# These will be replaced by more specific types later
from .detectors import DetectorConfig
from .metric_extractors import MetricExtractorConfig
from .sources import DataSourceConfig
from .reporters import AlertReporterConfig
from .preprocessors import PreprocessorConfig
from .data_sink import DataSinkConfig


class HCCLRestoreConfig(BaseModel):
    """Configuration for HCCL domain restoration (TP/DP/PP groups)."""
    enabled: bool = Field(default=True, description="Whether to enable HCCL domain restoration.")
    tp_groups: List[List[int]] = Field(default_factory=list, description="Tensor Parallelism groups.")
    dp_groups: List[List[int]] = Field(default_factory=list, description="Data Parallelism groups.")
    pp_groups: List[List[int]] = Field(default_factory=list, description="Pipeline Parallelism groups.")


class MultiNodeConfig(BaseModel):
    """Configuration for multi-node detection server."""

    enabled: bool = Field(default=False, description="Whether to enable multi-node detection server.")
    server_host: str = Field(default="0.0.0.0", description="Server listen address.")
    server_port: int = Field(default=8765, description="Server listen port.")
    expected_nodes: Dict[str, int] = Field(
        default_factory=dict,
        description="Expected node configuration. Key is node IP, value is number of ranks on that node.",
    )


class TaskConfig(BaseModel):
    """Configuration for a single detection task."""
    task_name: str = Field(default="gpu_fail_slow_detection", description="A unique name for the task.")
    task_type: Literal["slow_calc", "slow_launch", "slow_comm", "slow_host", "degradation"] = Field(
        default="slow_calc",
        description="Task type: slow_calc (compute slow), slow_launch (launch slow), slow_host (host slow), slow_comm (communication slow), or degradation (performance degradation)",
    )
    enable_group_detection: bool = Field(
        default=False,
        description="Whether to enable HCCL group-based detection. When enabled, detection is performed within each TP/DP/PP group separately."
    )
    detect_interval_seconds: float = Field(
        default=5.0,
        description="Minimum interval (seconds) between consecutive detections in online mode. Set to 0 for no throttling."
    )
    hccl_restore: Optional[HCCLRestoreConfig] = Field(default=None, description="HCCL domain restoration configuration (TP/DP/PP groups).")
    data_source: Optional[DataSourceConfig] = Field(default=None, description="Data source for offline mode. If None, online mode is used.")
    data_sink: Optional[DataSinkConfig] = Field(default=None, description="Data sink for online mode persistence. If None, no data persistence.")
    metric_extractors: List[MetricExtractorConfig] = Field(default_factory=list)
    preprocessors: List[PreprocessorConfig] = Field(default_factory=list)
    detectors: List[DetectorConfig] = Field(default_factory=list)
    alert_reporters: List[AlertReporterConfig] = Field(default_factory=list)


class FailSlowConfig(BaseModel):
    """The root configuration model for the entire application."""
    tasks: List[TaskConfig] = Field(default_factory=list)
    logging: Dict[str, Any] = Field(default=lambda: {"level": "INFO"})
    config_path: Optional[str] = None
