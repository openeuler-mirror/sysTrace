"""
failslow.util 模块

提供统一的工具函数，包括日志、数据处理、时间转换等。
"""
from failslow.util.logging import get_logger, setup_logging

__all__ = [
    "get_logger",
    "setup_logging",
]
