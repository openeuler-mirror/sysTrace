"""
Implementation of an alert reporter that prints alerts to the console.
"""
import logging
import sys
from typing import Optional

from failslow.infrastructure.framework.registration import ReporterRegistry
from failslow.domain.models import Alert, DetectionResult
from .schema import ConsoleParams

logger = logging.getLogger(__name__)


class ConsoleAlertReporter(ReporterRegistry):
    """
    Alert reporter that outputs alerts to the console (stdout/stderr).

    Uses the standard output stream to print formatted alert information.
    """
    COMPONENT_NAME = "console"

    def __init__(self, params: ConsoleParams = None, **kwargs):
        if params is not None:
            self._params = params
        else:
            self._params = ConsoleParams(**kwargs)
        
        self._level = getattr(logging, self._params.level.upper(), logging.INFO)
        self._is_available = True

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def report(self, alert: Alert) -> bool:
        """
        Report an alert by printing it to the console.

        Args:
            alert: The alert to report.

        Returns:
            True if the alert was reported successfully, False otherwise.
        """
        if not self._is_available:
            return False

        try:
            output = self._format_alert(alert)
            if self._level >= logging.ERROR:
                print(output, file=sys.stderr)
            else:
                print(output)
            return True
        except Exception as e:
            logger.error("Failed to report alert to console: %s", e)
            return False

    def is_available(self) -> bool:
        """Check if the reporter is available."""
        return self._is_available

    def convert_to_alert(self, result: DetectionResult) -> Alert:
        """Convert DetectionResult to Alert (v2 format)."""
        anomaly_info = result.anomaly_info
        severity = "warning" if anomaly_info.is_anomaly else "info"

        # 从 metadata 构建 v2 格式的 details
        abnormal_ranks = result.metadata.get("abnormal_ranks", [])
        abnormal_ips = result.metadata.get("abnormal_ips", [])
        anomaly_time_ranges = result.metadata.get("anomaly_time_ranges", [])
        detect_type = result.metadata.get("detect_type", "SPACE")

        return Alert(
            anomaly_type=anomaly_info.anomaly_type.value,
            severity=severity,
            details={
                "abnormal_ranks": abnormal_ranks,
                "abnormal_ips": abnormal_ips,
                "anomaly_time_ranges": anomaly_time_ranges,
                "detect_type": detect_type,
            },
        )

    def _format_alert(self, alert: Alert) -> str:
        """Format an alert for console output (v2 style)."""
        return f"Alert sent to console: {alert}"
