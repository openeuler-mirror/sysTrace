"""
Node Agent - collects local data and pushes to the central DetectionServer.

Supports two data collection modes:
1. CSV file mode: reads local CSV files incrementally and pushes data
2. Callback mode: accepts StepMetrics via push_step_metrics and forwards to server

Supports both NCCL and HCCL format CSV files.
Designed for NPU training scenarios where data accumulates on disk over time.

Usage (CSV mode):
    python -m failslow.entrypoints.multi_node_agent \
        --server-url http://10.2.44.100:8765 \
        --data-dir /path/to/local/csv \
        --node-ip 10.2.44.104
"""

import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import List, Optional, Union

from failslow.domain.models import StepMetrics
from failslow.infrastructure.components.sources.degradation_step_csv.source import (
    DegradationStepCsvDataSource,
)
from failslow.infrastructure.components.sources.local_csv.source import (
    LocalCsvDataSource,
)
from failslow.infrastructure.services.serialization import (
    serialize_step_metrics_list,
)

logger = logging.getLogger(__name__)


class NodeAgent:
    """
    Node agent that collects local data and pushes to the central DetectionServer.

    In CSV mode, it auto-detects the CSV format and incrementally reads
    local CSV files via the appropriate data source:
    - Degradation format (step_id, step_start_time, step_end_time, step_exec_time)
      -> DegradationStepCsvDataSource
    - NCCL/HCCL format -> LocalCsvDataSource
    """

    def __init__(
        self,
        server_url: str,
        node_ip: str,
        data_dir: Optional[str] = None,
        data_format: str = "auto",
        data_source: str = "auto",
        interval: float = 1.0,
        max_retries: int = 3,
        retry_delay: float = 5.0,
        request_timeout: float = 30.0,
    ):
        self._server_url = server_url.rstrip("/")
        self._node_ip = node_ip
        self._data_dir = data_dir
        self._data_format = data_format
        self._data_source_type = data_source
        self._interval = interval
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._request_timeout = request_timeout

        self._data_source: Optional[Union[LocalCsvDataSource, DegradationStepCsvDataSource]] = None
        self._running = False
        self._total_pushed = 0
        self._total_failed = 0

    def start(self):
        """Start the agent loop."""
        self._running = True
        logger.info(
            "NodeAgent started: server=%s, node_ip=%s, data_dir=%s, "
            "data_format=%s, interval=%.1fs",
            self._server_url,
            self._node_ip,
            self._data_dir,
            self._data_format,
            self._interval,
        )

        self._check_server_health()

        if self._data_dir:
            self._data_source = self._create_data_source()
            self._csv_loop()
        else:
            logger.error("No data_dir specified, nothing to do")
            return

    def stop(self):
        """Stop the agent loop."""
        self._running = False
        logger.info(
            "NodeAgent stopped: total_pushed=%d, total_failed=%d",
            self._total_pushed,
            self._total_failed,
        )

    def push_step_metrics(self, step_metrics_list: List[StepMetrics]) -> bool:
        """
        Push a batch of StepMetrics to the server.

        Can be called directly (callback mode) or internally (CSV mode).
        Returns True if push succeeded.
        """
        if not step_metrics_list:
            return True

        payload = serialize_step_metrics_list(step_metrics_list)
        body = json.dumps(payload).encode("utf-8")

        for attempt in range(1, self._max_retries + 1):
            try:
                req = urllib.request.Request(
                    f"{self._server_url}/api/v1/step_metrics",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._request_timeout) as resp:
                    if resp.status == 200:
                        self._total_pushed += len(step_metrics_list)
                        logger.debug(
                            "Pushed %d step_metrics to server (attempt %d)",
                            len(step_metrics_list),
                            attempt,
                        )
                        return True
                    else:
                        logger.warning(
                            "Server returned status %d (attempt %d/%d)",
                            resp.status,
                            attempt,
                            self._max_retries,
                        )
            except urllib.error.URLError as e:
                logger.warning(
                    "Failed to push data (attempt %d/%d): %s",
                    attempt,
                    self._max_retries,
                    e,
                )
            except Exception as e:
                logger.error(
                    "Unexpected error pushing data (attempt %d/%d): %s",
                    attempt,
                    self._max_retries,
                    e,
                )

            if attempt < self._max_retries:
                time.sleep(self._retry_delay)

        self._total_failed += len(step_metrics_list)
        logger.error(
            "Failed to push %d step_metrics after %d attempts",
            len(step_metrics_list),
            self._max_retries,
        )
        return False

    def _check_server_health(self):
        """Check if the server is reachable."""
        for attempt in range(1, 4):
            try:
                req = urllib.request.Request(f"{self._server_url}/api/v1/health")
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if resp.status == 200:
                        logger.info("Server health check passed")
                        return
            except Exception as e:
                logger.warning(
                    "Server health check failed (attempt %d/3): %s", attempt, e
                )
            time.sleep(2.0)

        logger.warning("Server health check failed, will retry on push")

    def _create_data_source(self):
        """
        Create the appropriate data source based on the data_source_type setting.

        - "auto": auto-detect CSV format by scanning files in the data directory.
        - "degradation": directly create DegradationStepCsvDataSource.
        - "local_csv": directly create LocalCsvDataSource.
        - No CSV files (auto mode) -> returns None (loop retries).
        """
        if self._data_source_type == "degradation":
            logger.info(
                "Using DegradationStepCsvDataSource (explicitly configured)"
            )
            return DegradationStepCsvDataSource(
                directory_path=self._data_dir,
                file_pattern="*.csv",
            )

        if self._data_source_type == "local_csv":
            logger.info(
                "Using LocalCsvDataSource with format=%s (explicitly configured)",
                self._data_format,
            )
            return LocalCsvDataSource(
                directory_path=self._data_dir, format=self._data_format
            )

        # auto mode: detect format from CSV files
        try:
            csv_files = sorted(
                f for f in os.listdir(self._data_dir) if f.endswith(".csv")
            )
        except FileNotFoundError:
            logger.warning(
                "Data directory not yet available: %s, will retry",
                self._data_dir,
            )
            return None

        if csv_files:
            first_file = os.path.join(self._data_dir, csv_files[0])
            if DegradationStepCsvDataSource.is_degradation_format(first_file):
                logger.info(
                    "Detected degradation CSV format, using DegradationStepCsvDataSource"
                )
                return DegradationStepCsvDataSource(
                    directory_path=self._data_dir,
                    file_pattern="*.csv",
                )

        if not csv_files:
            logger.warning(
                "No CSV files found in %s, will retry",
                self._data_dir,
            )
            return None

        logger.info(
            "Using LocalCsvDataSource with format=%s", self._data_format
        )
        return LocalCsvDataSource(
            directory_path=self._data_dir, format=self._data_format
        )

    def _csv_loop(self):
        """Incrementally read CSV files and push new data to server."""
        while self._running:
            try:
                if self._data_source is None:
                    self._data_source = self._create_data_source()
                    if self._data_source is None:
                        time.sleep(self._interval)
                        continue
                new_metrics = self._data_source.read_incremental()
                if new_metrics:
                    logger.info(
                        "Scanned %d new step_metrics from %s",
                        len(new_metrics),
                        self._data_dir,
                    )
                    success = self.push_step_metrics(new_metrics)
                    if not success:
                        logger.warning(
                            "Failed to push %d step_metrics, will retry next scan",
                            len(new_metrics),
                        )

                time.sleep(self._interval)

            except Exception as e:
                logger.error("Error in CSV loop: %s", e)
                time.sleep(self._interval)
