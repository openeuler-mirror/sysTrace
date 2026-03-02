"""
Implementation of an alert reporter that writes alerts to a file.
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional

from failslow.infrastructure.framework.registration import ReporterRegistry
from failslow.domain.models import Alert, DetectionResult
from .schema import FileAlertReporterParams

logger = logging.getLogger(__name__)


class FileAlertReporter(ReporterRegistry):
    """
    Alert reporter that writes alerts to a JSON or text file.

    Supports appending to the file for continuous logging of alerts.
    """
    COMPONENT_NAME = "file"

    def __init__(self, params: FileAlertReporterParams = None, **kwargs):
        if params is not None:
            self._params = params
        else:
            self._params = FileAlertReporterParams(**kwargs)
        
        self._output_path = self._params.output_path
        self._format = self._params.format.lower()
        self._is_available = self._ensure_output_dir()
        self._file_handle = None

    def _ensure_output_dir(self) -> bool:
        """Ensure the output directory exists."""
        try:
            output_path = Path(self._output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logger.error("Failed to create output directory: %s", e)
            return False

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def report(self, alert: Alert) -> bool:
        """
        Report an alert by writing it to the file.

        Args:
            alert: The alert to report.

        Returns:
            True if the alert was reported successfully, False otherwise.
        """
        if not self._is_available:
            return False

        try:
            if self._format == "json":
                return self._write_json(alert)
            else:
                return self._write_text(alert)
        except Exception as e:
            logger.error("Failed to report alert to file: %s", e)
            return False

    def _write_json(self, alert: Alert) -> bool:
        """Write alert as JSON (v2 format)."""
        try:
            alert_dict = {
                "anomaly_type": alert.anomaly_type,
                "severity": alert.severity,
                "details": alert.details,
            }

            with open(self._output_path, "a") as f:
                f.write(json.dumps(alert_dict) + "\n")
            return True
        except Exception as e:
            logger.error("Failed to write JSON alert: %s", e)
            return False

    def _write_text(self, alert: Alert) -> bool:
        """Write alert as plain text (v2 format)."""
        try:
            with open(self._output_path, "a") as f:
                f.write(str(alert) + "\n")
            return True
        except Exception as e:
            logger.error("Failed to write text alert: %s", e)
            return False

    def is_available(self) -> bool:
        """Check if the reporter is available."""
        return self._is_available

    def convert_to_alert(self, result: DetectionResult) -> Alert:
        """Convert DetectionResult to Alert (v2 format)."""
        anomaly_info = result.anomaly_info
        severity = "warning" if anomaly_info.is_anomaly else "info"

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
