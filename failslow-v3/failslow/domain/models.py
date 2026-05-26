"""Core data models for the FailSlow application domain.

These models represent the fundamental entities and data structures used throughout the
system. They are pure data containers with no logic, forming the stable core of
the onion architecture.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np


@dataclass
class CommGroup:
    """通信组数据结构"""
    comm_name: str
    group_ranks: List[int]


@dataclass
class HCCLDomain:
    """HCCL Domain 信息，包含 TP/DP 分组"""
    tp_groups: List[List[int]] = field(default_factory=list)
    dp_groups: List[List[int]] = field(default_factory=list)
    comm_groups: List[CommGroup] = field(default_factory=list)
    rank_to_group: Dict[int, str] = field(default_factory=dict)  # rank_id -> comm_name


class TaskType(Enum):
    """任务类型枚举"""
    SLOW_CALC = "slow_calc"      # 计算慢检测
    SLOW_LAUNCH = "slow_launch"  # 下发慢检测
    DEGRADATION = "degradation"  # 劣化感知


@dataclass
class DetectorInput:
    """Detector 输入数据结构"""
    values: np.ndarray                    # shape (num_ranks,)
    rank_ids: List[int]                   # 对应的 rank_id 列表
    node_ips: List[str]                    # 对应的 node_ip 列表
    hccl_domain: Optional[HCCLDomain] = None  # HCCL Domain 信息（TP/DP 分组）


@dataclass
class KernelType:
    """
    Represents the performance metrics of a single kernel execution.
    """
    name: str
    t1_ns: int
    t2_ns: int
    t_delta_ns: float
    t_exec_ns: float
    t3_ns: int
    t4_ns: int


@dataclass
class StepMetrics:
    """
    Represents all performance metrics collected for a single step from a single rank.
    """
    start_time_ns: int
    end_time_ns: int
    step: int
    rank_id: int
    local_rank_id: int
    node_ip: str
    node_port: int
    kernels: List[KernelType]


class AnomalyType(Enum):
    """Enumeration of possible anomaly types detected by the system."""
    NORMAL = "normal"
    FAIL_SLOW = "fail_slow"
    HBM_LEAK = "hbm_leak"
    HANG = "hang"
    COMM_SLOW = "comm_slow"
    CAL_SLOW = "cal_slow"
    LAUNCH_SLOW = "launch_slow"


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
    "KernelType",
    "StepMetrics",
    "AnomalyType",
    "AnomalyInfo",
    "DetectionResult",
    "Alert",
    "TaskType",
    "DetectorInput",
    "HCCLDomain",
    "CommGroup",
]
