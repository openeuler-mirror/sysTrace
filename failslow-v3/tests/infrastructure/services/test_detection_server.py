import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))

from failslow.domain.models import StepMetrics
from failslow.infrastructure.services import detection_server


class FakeTask:
    def __init__(self, config_path):
        self.config_path = config_path
        self.name = "fake-task"
        self.task_type = "fake-type"
        self._detect_interval_seconds = 30.0
        self.received_batches = []

    def on_recv_all_step(self, step_metrics_list):
        self.received_batches.append(step_metrics_list)

    def shutdown(self):
        pass


def _step(node_ip="10.0.0.1", rank_id=0, step=1):
    return StepMetrics(
        start_time_ns=0,
        end_time_ns=1,
        step=step,
        rank_id=rank_id,
        local_rank_id=rank_id,
        node_ip=node_ip,
        node_port=0,
        kernels=[],
    )


def test_on_data_received_forwards_immediately_without_expected_nodes(monkeypatch):
    monkeypatch.setattr(detection_server, "Task", FakeTask)
    server = detection_server.DetectionServer(
        config_path="config.json",
        expected_nodes={},
    )

    batch = [_step(node_ip="10.0.0.1")]
    server.on_data_received("10.0.0.1", batch)

    assert server._task.received_batches == [batch]


def test_status_marks_expected_node_missing_after_interval(monkeypatch):
    now = 100.0

    def fake_time():
        return now

    monkeypatch.setattr(detection_server, "Task", FakeTask)
    monkeypatch.setattr(detection_server.time, "time", fake_time)

    server = detection_server.DetectionServer(
        config_path="config.json",
        expected_nodes={"10.0.0.1": 1, "10.0.0.2": 1},
    )

    server.on_data_received("10.0.0.1", [_step(node_ip="10.0.0.1")])

    status = server.get_status()
    assert status["received_nodes"] == ["10.0.0.1"]
    assert status["missing_nodes"] == ["10.0.0.2"]

    now = 131.0
    status = server.get_status()
    assert status["received_nodes"] == []
    assert status["missing_nodes"] == ["10.0.0.1", "10.0.0.2"]
