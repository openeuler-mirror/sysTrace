"""
Detection Server - central node for multi-node slow node detection.

Receives StepMetrics data from remote node agents via HTTP
and forwards them into Task for interval-based processing.

Two deployment scenarios:
1. GPU training: external distributed logic collects data from all nodes,
   then pushes to this server via HTTP POST.
2. NPU training: each node's agent reads local CSV files and pushes data
   to this server; the server also supports pulling files via rsync.

Usage:
    python -m failslow.entrypoints.multi_node_server --config config/config.json
"""

import json
import logging
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Set

from failslow.domain.models import StepMetrics
from failslow.infrastructure.services.serialization import (
    deserialize_step_metrics_payload,
)
from failslow.task.task import Task

logger = logging.getLogger(__name__)


class _RequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the detection server."""

    server_ref = None

    def do_POST(self):
        if self.path == "/api/v1/step_metrics":
            self._handle_step_metrics()
        elif self.path == "/api/v1/health":
            self._handle_health()
        else:
            self._send_json(404, {"status": "error", "message": "Not found"})

    def do_GET(self):
        if self.path == "/api/v1/health":
            self._handle_health()
        elif self.path == "/api/v1/status":
            self._handle_status()
        else:
            self._send_json(404, {"status": "error", "message": "Not found"})

    def _handle_step_metrics(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body)

            node_ip, step_metrics_list = deserialize_step_metrics_payload(payload)

            if not step_metrics_list:
                self._send_json(
                    400, {"status": "error", "message": "Empty step_metrics_list"}
                )
                return

            detection_server = self.server_ref
            if detection_server is not None:
                detection_server.on_data_received(node_ip, step_metrics_list)

            self._send_json(
                200,
                {
                    "status": "ok",
                    "received_count": len(step_metrics_list),
                    "message": f"Data received from {node_ip}, {len(step_metrics_list)} ranks",
                },
            )

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error("Failed to parse request body: %s", e)
            self._send_json(
                400, {"status": "error", "message": f"Invalid request: {e}"}
            )
        except Exception as e:
            logger.error("Error handling step_metrics request: %s", e)
            self._send_json(500, {"status": "error", "message": f"Internal error: {e}"})

    def _handle_health(self):
        self._send_json(200, {"status": "ok"})

    def _handle_status(self):
        detection_server = self.server_ref
        if detection_server is None:
            self._send_json(200, {"status": "unknown"})
            return
        status = detection_server.get_status()
        self._send_json(200, status)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        logger.debug("HTTP %s", format % args)


class DetectionServer:
    """
    Central detection server for multi-node slow node detection.

    Receives StepMetrics data from remote agents and forwards them into Task.
    Detection timing is controlled by task config detect_interval_seconds.
    """

    def __init__(
        self,
        config_path: str,
        host: str = "0.0.0.0",
        port: int = 8765,
        expected_nodes: Optional[Dict[str, int]] = None,
    ):
        self._config_path = config_path
        self._host = host
        self._port = port
        self._expected_nodes = expected_nodes or {}

        self._task = Task(config_path=config_path)
        logger.info(
            "DetectionServer: task=%s, type=%s",
            self._task.name,
            self._task.task_type,
        )

        self._detect_interval_seconds = self._task._detect_interval_seconds
        self._received_nodes: Set[str] = set()
        self._last_received_at: Dict[str, float] = {}
        self._data_lock = threading.Lock()

        self._running = False
        self._http_server: Optional[HTTPServer] = None

        self._total_received = 0
        self._total_detections = 0
        self._start_time: Optional[float] = None

    def start(self):
        """Start the HTTP server and detection loop."""
        self._running = True
        self._start_time = time.time()

        _RequestHandler.server_ref = self
        self._http_server = HTTPServer((self._host, self._port), _RequestHandler)

        http_thread = threading.Thread(
            target=self._http_server.serve_forever, daemon=True
        )
        http_thread.start()
        logger.info(
            "DetectionServer HTTP listening on %s:%d",
            self._host,
            self._port,
        )

        if self._expected_nodes:
            logger.info(
                "Expected nodes: %s (monitoring only, detection timing uses task config)",
                self._expected_nodes,
            )
        else:
            logger.info("No expected_nodes configured")

        logger.info("Detection timing is controlled by task config detect_interval_seconds")

        try:
            while self._running:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Received KeyboardInterrupt, shutting down...")
            self.shutdown()

    def shutdown(self):
        """Gracefully shutdown the server."""
        self._running = False
        if self._http_server:
            self._http_server.shutdown()
        if self._task:
            self._task.shutdown()
        logger.info("DetectionServer shutdown complete")

    def on_data_received(self, node_ip: str, step_metrics_list: List[StepMetrics]):
        """Handle received data from a remote node agent."""
        mismatched_ranks = sorted(
            {
                sm.rank_id
                for sm in step_metrics_list
                if sm.node_ip and sm.node_ip != node_ip
            }
        )
        if mismatched_ranks:
            logger.warning(
                "Normalizing StepMetrics node_ip to sender %s for ranks=%s",
                node_ip,
                mismatched_ranks,
            )
            for step_metrics in step_metrics_list:
                step_metrics.node_ip = node_ip

        with self._data_lock:
            self._received_nodes.add(node_ip)
            self._last_received_at[node_ip] = time.time()
            self._total_received += len(step_metrics_list)

        ranks = sorted(set(sm.rank_id for sm in step_metrics_list))
        logger.info(
            "Data received from %s: %d step_metrics, ranks=%s",
            node_ip,
            len(step_metrics_list),
            ranks,
        )

        self._task.on_recv_all_step(step_metrics_list)
        self._total_detections += 1

    def get_status(self) -> Dict:
        """Return current server status."""
        with self._data_lock:
            if self._detect_interval_seconds <= 0:
                received_nodes = sorted(self._received_nodes)
            else:
                cutoff = time.time() - self._detect_interval_seconds
                received_nodes = sorted(
                    node_ip
                    for node_ip, last_seen in self._last_received_at.items()
                    if last_seen >= cutoff
                )

        missing_nodes = sorted(set(self._expected_nodes.keys()) - set(received_nodes))
        uptime = time.time() - self._start_time if self._start_time else 0

        return {
            "status": "running" if self._running else "stopped",
            "uptime_seconds": round(uptime, 1),
            "expected_nodes": self._expected_nodes,
            "received_nodes": received_nodes,
            "missing_nodes": missing_nodes,
            "buffered_step_metrics": 0,
            "total_received": self._total_received,
            "total_detections": self._total_detections,
        }
