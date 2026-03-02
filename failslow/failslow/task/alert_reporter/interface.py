"""AlertReporter接口及工厂实现"""

from abc import ABC, ABCMeta, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


@dataclass
class AlertBase:
    def __str__(self) -> str:
        return str(asdict(self))


@dataclass
class AlertReporterConfig:
    reporter_type: str = field(default="LoggerAlertReporter")
    config: dict = field(default_factory=dict)


class AlertReporterMeta(ABCMeta):
    registy: dict[str, "AlertReporterBase"] = {}

    def __new__(mcs, name, bases, namespace):
        """记录所有非抽象的AlertReporter子类"""
        cls = super().__new__(mcs, name, bases, namespace)
        if not getattr(cls, "__abstractmethods__", False):
            mcs.registy[name] = cls
        return cls


class AlertReporterBase(ABC, metaclass=AlertReporterMeta):

    @abstractmethod
    def report_alert(self, alert: dict) -> None:
        raise NotImplementedError


class BufferedAlertReporterBase(AlertReporterBase):
    @abstractmethod
    def get_all_alerts(self) -> list[dict]:
        raise NotImplementedError


class AlertReporterFactory:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @staticmethod
    def create_reporter(
        alert_reporter_config: AlertReporterConfig,
    ) -> AlertReporterBase:
        reporter_cls = AlertReporterMeta.registy.get(
            alert_reporter_config.reporter_type
        )
        if not reporter_cls:
            raise ValueError(
                f"Unknown reporter type: {alert_reporter_config.reporter_type} (available: {list(AlertReporterMeta.registy.keys())})"
            )
        logger.info("create reporter: %s", reporter_cls.__name__)
        return reporter_cls(alert_reporter_config.config)
