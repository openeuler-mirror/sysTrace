"""Input data models for the FailSlow application domain.

These models represent input data structures used for metric collection and detection.
They are pure data containers with no logic, forming part of the stable core of
the onion architecture.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

from .domain_objects import CommGroup, HCCLDomain


@dataclass
class KernelType:
    """
    Represents the performance metrics of a single kernel execution.
    """
    name: str
    t1_ns: int
    t2_ns: int
    t_delta_ns: float  # Kernel launch delay (t3_ns - t2_ns)
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


@dataclass
class DetectorInput:
    """Detector 输入数据结构

    这个 dataclass 使用固定字段 + context 扩展字段的模式来平衡类型安全和前向拓展性。
    固定字段保证静态类型检查的收益，context 字段允许运行时扩展而无需修改签名。
    """
    values: np.ndarray
    rank_ids: List[int]
    node_ips: List[str]
    hccl_domain: Optional[HCCLDomain] = None
    timestamps: Optional[np.ndarray] = None  # 每个时间窗口的起始时间戳 (ms)
    # 前向扩展字段：用于传递运行时上下文信息（如 sensitivity、callbacks 等）
    # 使用 Dict 而不是具体字段，以便未来新增参数而无需修改 dataclass 定义
    context: Optional[Dict[str, Any]] = field(default_factory=dict)


__all__ = [
    "KernelType",
    "StepMetrics",
    "DetectorInput",
]
