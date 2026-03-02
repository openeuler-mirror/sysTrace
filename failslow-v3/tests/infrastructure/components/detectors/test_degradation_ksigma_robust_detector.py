import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[4]))

from failslow.domain.models import StepMetrics, TaskType
from failslow.infrastructure.components.detectors.degradation_ksigma_robust.detector import (
    DegradationKSigmaRobustDetector,
)
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


def test_ksigma_online_path_consumes_each_group_once():
    pre = StepAggregatorPreprocessor(steps_per_group=1)
    pre.set_data_source(None)
    detector = DegradationKSigmaRobustDetector(
        window_size=2,
        min_consecutive=1,
        use_variable_window=False,
    )

    out1 = pre.process(
        [make_step(step=1, rank_id=0, duration_ms=10.0)],
        task_type=TaskType.DEGRADATION,
    )
    detector.detect(out1)

    out2 = pre.process(
        [make_step(step=2, rank_id=0, duration_ms=12.0)],
        task_type=TaskType.DEGRADATION,
    )
    detector.detect(out2)

    state = detector.get_state()
    assert out2.shape == (1, 1)
    assert state["0"]["index_counter"] == 2


def test_ksigma_batch_mode_detects_all_ranks_with_sustained_rise():
    values = np.array(
        [
            [1351.227276, 1272.134921, 1354.439454, 1331.235401],
            [1285.431491, 1256.516025, 1329.238105, 1186.995085],
            [1168.164878, 1143.629863, 1206.13875, 1084.105355],
            [1080.11101, 1058.594302, 1113.428807, 1006.719158],
            [1012.151397, 992.883136, 1041.713602, 946.75126],
            [955.389257, 937.995611, 982.014107, 896.552701],
            [537.88274, 565.081086, 611.40831, 463.80851],
            [537.429165, 564.851672, 611.26602, 463.499815],
            [537.276629, 564.53267, 611.179016, 463.259101],
            [537.042344, 564.174375, 610.984476, 463.109366],
            [536.040639, 563.799306, 610.82008, 462.578951],
            [740.32525, 759.145995, 752.48433, 676.62319],
            [1009.327104, 1025.970177, 1021.224146, 945.127215],
            [1271.705821, 1295.842859, 1283.439957, 1207.21153],
            [1551.533661, 1576.681379, 1563.513176, 1487.598504],
            [1834.837422, 1846.710801, 1846.979834, 1770.668953],
            [2105.99406, 2124.707125, 2032.454474, 1995.680754],
            [2383.057679, 2404.439209, 2309.639746, 2272.689535],
            [2666.340759, 2686.311228, 2592.77662, 2556.148723],
            [2935.452931, 2954.054782, 2861.967057, 2824.912818],
            [3218.011103, 3226.195937, 3143.954234, 3107.185496],
        ],
        dtype=float,
    )
    detector = DegradationKSigmaRobustDetector(
        window_size=10,
        k_sigma=2.0,
        anomaly_degree_thr=0.05,
        use_variable_window=True,
        window_increase_ratio=0.5,
        eps=1e-6,
        min_consecutive=6,
        detect_rise=True,
        detect_drop=False,
    )

    results = detector.detect(values)

    assert sorted(result.metadata["rank_id"] for result in results) == [0, 1, 2, 3]


def test_ksigma_batch_mode_reports_current_observation_indices():
    detector = DegradationKSigmaRobustDetector(
        window_size=4,
        k_sigma=1.0,
        anomaly_degree_thr=0.1,
        use_variable_window=False,
        window_increase_ratio=0.0,
        eps=1e-6,
        min_consecutive=2,
        detect_rise=True,
        detect_drop=False,
    )

    results = detector.detect(np.array([[10.0], [10.0], [10.0], [10.0], [20.0], [20.0]]))

    assert len(results) == 1
    details = results[0].anomaly_info.anomaly_details[0]
    assert details["first_degradation_index"] == 5
    assert details["last_degradation_index"] == 6
