"""
统一的日志配置和管理工具。

提供统一的日志配置接口，避免在每个模块中重复创建 logger。
"""
import logging
from typing import Optional


THIRD_PARTY_LOGGERS = [
    "matplotlib",
    "matplotlib.font",
    "matplotlib.ticker",
    "matplotlib.backends",
    "PIL",
    "PIL.Image",
    "numpy",
    "numpy.core",
    "pandas",
    "sklearn",
    "scipy",
    "influxdb_client",
]


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    获取配置好的 logger。

    Args:
        name: logger 名称，通常使用 __name__
        level: 日志级别（可选），如 "DEBUG", "INFO", "WARNING", "ERROR"

    Returns:
        配置好的 logger 实例

    Example:
        >>> from failslow.util.logging import get_logger
        >>> logger = get_logger(__name__)
        >>> logger.info("Application started")
    """
    logger = logging.getLogger(name)

    if level:
        logger.setLevel(getattr(logging, level.upper()))

    return logger


def setup_logging(level: str = "INFO") -> None:
    """
    统一配置应用日志。

    Args:
        level: 日志级别，如 "DEBUG", "INFO", "WARNING", "ERROR"

    Example:
        >>> setup_logging("INFO")
    """
    level = level.upper()

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
    )

    for lib_logger in THIRD_PARTY_LOGGERS:
        logging.getLogger(lib_logger).setLevel(logging.WARNING)


__all__ = [
    "get_logger",
    "setup_logging",
    "THIRD_PARTY_LOGGERS",
]
