"""Enumeration types for the FailSlow application domain.

This module contains all enumeration types used throughout the system.
These enums define the core categories and types that the system works with.
"""

from enum import Enum


class TaskType(Enum):
    """任务类型枚举"""
    SLOW_CALC = "slow_calc"
    SLOW_LAUNCH = "slow_launch"
    SLOW_COMM = "slow_comm"
    DEGRADATION = "degradation"
    SLOW_HOST = "slow_host"


class AnomalyType(Enum):
    """Enumeration of possible anomaly types detected by the system."""
    NORMAL = "normal"
    FAIL_SLOW = "fail_slow"
    HBM_LEAK = "hbm_leak"
    HANG = "hang"
    COMM_SLOW = "comm_slow"
    CAL_SLOW = "calc_slow"
    LAUNCH_SLOW = "launch_slow"


__all__ = [
    "TaskType",
    "AnomalyType",
]
