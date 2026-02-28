"""常用的AlertReporter"""

from failslow.task.alert_reporter.interface import BufferedAlertReporterBase
from failslow.util.logging_utils import get_default_logger
from queue import Queue
import logging
from dataclasses import dataclass
import json
import os
logger = get_default_logger(__name__)

@dataclass
class FileAlertReporterConfig:
    """File alert reporter configuration."""
    file_path: str
    buffer_size: int = 1000

class FileAlertReporter(BufferedAlertReporterBase):
    """打印到Logger的AlertReporter实现"""

    def __init__(self, config: dict):
        """
        Args: config: dict, 配置字典
        """
        super().__init__()
        self.config = FileAlertReporterConfig(**config)
        self._alerts = Queue(maxsize=self.config.buffer_size)
        os.makedirs(os.path.dirname(self.config.file_path), exist_ok=True)

    def report_alert(self, alert: dict) -> None:
        logger.info("Reporting alert: %s to file %s", alert, self.config.file_path)
        with open(self.config.file_path, "a") as f:
            json.dump(alert, f, indent=2)
            f.write("\n")
        self._alerts.put(alert)

    def get_all_alerts(self) -> list[dict]:
        return list(self._alerts.queue)
