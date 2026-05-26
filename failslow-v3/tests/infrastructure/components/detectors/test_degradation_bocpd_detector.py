import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[4]))

from failslow.infrastructure.components.detectors.degradation_bocpd.detector import (
    DegradationBocpdDetector,
)


def test_detect_skips_non_finite_values_without_polluting_state():
    detector = DegradationBocpdDetector(min_consecutive=2)
    values = np.array([[11.0, np.nan], [12.0, 13.0]], dtype=float)

    detector.detect(values)
    state = detector.get_state()

    assert state["0"]["observations"] == [11.0, 12.0]
    assert state["1"]["observations"] == [13.0]


def test_detect_reports_all_ranks_for_delayed_rise_confirmation():
    detector = DegradationBocpdDetector(
        distribution="StudentTProb1d",
        hazard=0.002,
        min_consecutive=6,
        detect_rise=True,
        detect_drop=False,
        plt_save_path=None,
    )
    base = np.array(
        [1300.0, 1200.0, 1100.0, 1000.0, 400.0, 400.0, 400.0, 400.0]
        + [2200.0] * 8,
        dtype=float,
    )
    values = np.column_stack(
        [
            base,
            base + np.array([20.0, 20.0, 10.0, 10.0] + [0.0] * 4 + [100.0] * 8),
            base - np.array([20.0, 20.0, 10.0, 10.0] + [0.0] * 4 + [100.0] * 8),
        ]
    )

    results = detector.detect(values)

    assert [result.metadata["rank_id"] for result in results] == [0, 1, 2]
