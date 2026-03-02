import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[4]))

from failslow.domain.models import StepMetrics, TaskType
from failslow.infrastructure.components.preprocessors.step_aggregator.preprocessor import (
    StepAggregatorPreprocessor,
)


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


def test_online_process_returns_only_new_groups():
    pre = StepAggregatorPreprocessor(steps_per_group=1)
    pre.set_data_source(None)

    first = [make_step(step=1, rank_id=0, duration_ms=10.0)]
    second = [make_step(step=2, rank_id=0, duration_ms=12.0)]

    out1 = pre.process(first, task_type=TaskType.DEGRADATION)
    out2 = pre.process(second, task_type=TaskType.DEGRADATION)

    assert out1.shape == (1, 1)
    assert out2.shape == (1, 1)
    assert out1[:, 0].tolist() == [10.0]
    assert out2[:, 0].tolist() == [12.0]


def test_online_process_keeps_unfinished_group_until_complete():
    pre = StepAggregatorPreprocessor(steps_per_group=2)
    pre.set_data_source(None)

    out1 = pre.process(
        [make_step(step=1, rank_id=0, duration_ms=10.0)],
        task_type=TaskType.DEGRADATION,
    )
    out2 = pre.process(
        [make_step(step=2, rank_id=0, duration_ms=14.0)],
        task_type=TaskType.DEGRADATION,
    )

    assert out1.size == 0
    assert out2.shape == (1, 1)
    assert out2[:, 0].tolist() == [12.0]
