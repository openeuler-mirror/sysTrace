import pathlib
import queue
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from failslow.domain.models import StepMetrics, TaskType
from failslow.task.task import Task


def make_step(step: int, rank_id: int, duration_ms: float) -> StepMetrics:
    start_time_ns = step * 1_000
    end_time_ns = start_time_ns + int(duration_ms * 1_000_000)
    return StepMetrics(
        start_time_ns=start_time_ns,
        end_time_ns=end_time_ns,
        step=step,
        rank_id=rank_id,
        local_rank_id=rank_id,
        node_ip="10.0.0.1",
        node_port=0,
        kernels=[],
    )


class FakeDetector:
    def __init__(self):
        self.reset_calls = 0
        self.seen_batches = []

    def reset(self):
        self.reset_calls += 1

    def observe(self, batch):
        self.seen_batches.append([list(row) for row in batch])


class FakePreprocessor:
    def __init__(self):
        self.reset_calls = 0

    def reset(self):
        self.reset_calls += 1


class FakePipeline:
    def __init__(self, detectors, preprocessors):
        self.detectors = detectors
        self.preprocessors = preprocessors
        self.processed_batches = []

    def _process_step(self, step_metrics_list, task_type, task_name):
        self.processed_batches.append(list(step_metrics_list))
        ordered_steps = sorted(step_metrics_list, key=lambda step: (step.step, step.rank_id))
        batch = [
            [[(step.end_time_ns - step.start_time_ns) / 1_000_000.0] for step in ordered_steps]
        ][0]
        for detector in self.detectors:
            detector.observe(batch)


def build_task(task_type: TaskType) -> Task:
    task = object.__new__(Task)
    task._task_name = f"{task_type.value}-task"
    task._task_type = task_type
    task._data_queue = queue.Queue()
    task._step_cache = []
    task._pipeline = FakePipeline([FakeDetector()], [FakePreprocessor()])
    return task


def test_degradation_task_replays_full_history_through_fresh_pipeline_state():
    task = build_task(TaskType.DEGRADATION)

    first_batch = [make_step(step=1, rank_id=0, duration_ms=10.0)]
    second_batch = [make_step(step=2, rank_id=0, duration_ms=12.0)]

    task._do_detection(first_batch)
    first_state = task._pipeline.detectors[0].seen_batches[-1]

    task._do_detection(second_batch)
    second_state = task._pipeline.detectors[0].seen_batches[-1]

    assert task._pipeline.processed_batches == [first_batch, first_batch + second_batch]
    assert first_state == [[10.0]]
    assert second_state == [[10.0], [12.0]]
    assert task._pipeline.detectors[0].reset_calls == 2
    assert task._pipeline.preprocessors[0].reset_calls == 2


def test_non_degradation_task_keeps_detector_state_between_detection_cycles():
    task = build_task(TaskType.SLOW_CALC)

    first_batch = [make_step(step=1, rank_id=0, duration_ms=10.0)]
    second_batch = [make_step(step=2, rank_id=0, duration_ms=12.0)]

    task._do_detection(first_batch)
    task._do_detection(second_batch)

    assert task._pipeline.detectors[0].reset_calls == 0
    assert task._pipeline.preprocessors[0].reset_calls == 0
    assert task._pipeline.processed_batches == [first_batch, second_batch]
