"""Output data models for the FailSlow application domain.

These models represent output data structures used for detection results and alerts.
They are pure data containers with no logic, forming part of the stable core of
the onion architecture.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .enums import AnomalyType


@dataclass
class AnomalyInfo:
    """
    Contains detailed information about a detected anomaly.
    """
    is_anomaly: bool = False
    anomaly_type: AnomalyType = AnomalyType.NORMAL
    anomaly_count: int = 0
    anomaly_details: List[Dict[str, Any]] = field(default_factory=list)
    start_time: int = 0
    end_time: int = 0


@dataclass
class DetectionResult:
    """
    Represents the output of a single detector run.
    """
    detector_name: str
    anomaly_info: AnomalyInfo
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """
    Represents a final, reportable alert generated from a detection result.
    与 v2 格式对齐的报警结构。
    """
    anomaly_type: str
    severity: str = "warning"
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """返回 v2 格式的字符串表示"""
        return str({
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "details": self.details,
        })


__all__ = [
    "AnomalyInfo",
    "DetectionResult",
    "Alert",
]
