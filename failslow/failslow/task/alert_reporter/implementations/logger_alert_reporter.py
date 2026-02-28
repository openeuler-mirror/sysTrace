"""常用的AlertReporter"""

from failslow.task.alert_reporter.interface import BufferedAlertReporterBase
from failslow.util.logging_utils import get_default_logger
from queue import Queue
import logging
from dataclasses import dataclass

@dataclass
class LoggerAlertReporterConfig:
    """Logger alert reporter configuration."""
    logger_name: str = __name__
    log_path: str = None
    logger_level: str = "INFO"
    buffer_size: int = 1000

class LoggerAlertReporter(BufferedAlertReporterBase):
    """打印到Logger的AlertReporter实现"""

    def __init__(self, config: dict):
        """
        Args: config: dict, 配置字典
        """
        super().__init__()
        self.config = LoggerAlertReporterConfig(**config)
        self.logger: logging.Logger = get_default_logger(self.config.logger_name, self.config.log_path)
        self.logger.setLevel(self.config.logger_level)
        self._alerts = Queue(maxsize=self.config.buffer_size)

    def report_alert(self, alert: dict) -> None:
        self.logger.warning(f"Alert reported: {alert}")
        self._alerts.put(alert)

    def get_all_alerts(self) -> list[dict]:
        return list(self._alerts.queue)
