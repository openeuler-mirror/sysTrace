from abc import ABC, abstractmethod, ABCMeta
from pydantic import BaseModel
from typing import Callable
from failslow.util.logging_utils import get_default_logger


logger = get_default_logger(__name__)


class DegradationAlert(BaseModel):
    timestamp: int
    severity: str = "critical"
    description: str
    details: dict = {}

    model_config = {"extra": "allow"}


class DetectorConfig(BaseModel):
    model_config = {"extra": "allow"}


class DetectorConfigDefault(DetectorConfig):
    config: dict = {}


class OnlineDegradationDetectorMeta(ABCMeta):
    """用于注册在线劣化检测器的元类"""

    registry = {}

    def __new__(cls, name, bases, attrs):
        new_class = super().__new__(cls, name, bases, attrs)
        # 除了存在abstractmethod的方法外，其他类都注册
        if not any(
            hasattr(attr, "__isabstractmethod__") and attr.__isabstractmethod__
            for attr in attrs.values()
        ):
            cls.registry[name] = new_class
        return new_class


class OnlineDegradationDetector(ABC, metaclass=OnlineDegradationDetectorMeta):
    def __init__(self, config: dict):
        self.config = self.__config_type__()(**config)
        # 默认不处理告警
        self.alert_report_func: Callable[[DegradationAlert], None] = lambda *_: None

    @abstractmethod
    def __config_type__(self) -> type[DetectorConfig]:
        """返回对应的配置类型"""
        raise NotImplementedError()

    @abstractmethod
    def update(self, obs, timestamp=None):
        """在线更新检测器状态，data为新到达的数据"""
        raise NotImplementedError()

    def set_alert_reporter(self, alert_report_func: Callable[[DegradationAlert], None]):
        """设置告警报告器"""
        self.alert_report_func = alert_report_func


def get_available_detectors() -> list[str]:
    """获取可用的在线劣化检测器类型列表"""
    return list(OnlineDegradationDetectorMeta.registry.keys())

def create_detector(detector_type: str, config: dict) -> OnlineDegradationDetector:
    """根据类型名称创建对应的在线劣化检测器实例"""
    detector_class = OnlineDegradationDetectorMeta.registry.get(detector_type)
    if not detector_class:
        error_msg = f"Unknown detector type: {detector_type}, available types: {list(OnlineDegradationDetectorMeta.registry.keys())}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    return detector_class(config)


__all__ = [
    "OnlineDegradationDetector",
    "DetectorConfig",
    "DegradationAlert",
    "create_detector",
]
