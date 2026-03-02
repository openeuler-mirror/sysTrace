"""Domain objects for communication and topology structures.

These dataclasses represent the fundamental domain objects related to
communication groups and HCCL domain topology information.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class CommGroup:
    """通信组数据结构"""
    comm_name: str
    group_ranks: List[int]


@dataclass
class HCCLDomain:
    """
    HCCL Domain 信息，包含 TP/DP/PP 分组。
    
    Attributes:
        tp_groups: Tensor Parallelism 分组列表，每个分组是一个 rank 列表
        dp_groups: Data Parallelism 分组列表，每个分组是一个 rank 列表
        pp_groups: Pipeline Parallelism 分组列表，每个分组是一个 rank 列表
        comm_groups: 通信组列表
        rank_to_group: rank 到通信组名称的映射
        world_size: 总 rank 数
    """
    tp_groups: List[List[int]] = field(default_factory=list)
    dp_groups: List[List[int]] = field(default_factory=list)
    pp_groups: List[List[int]] = field(default_factory=list)
    comm_groups: List[CommGroup] = field(default_factory=list)
    rank_to_group: Dict[int, str] = field(default_factory=dict)
    world_size: int = 0


__all__ = [
    "CommGroup",
    "HCCLDomain",
]
