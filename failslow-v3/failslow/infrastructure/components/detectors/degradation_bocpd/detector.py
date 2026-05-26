"""
Degradation BOCPD detector.

Per-rank time-series degradation detection using Bayesian Online
Changepoint Detection (BOCPD). Each rank is monitored independently
for changepoints in its performance metrics.
"""

import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from failslow.domain.interfaces.detector import IStreamDetector, IStatefulDetector
from failslow.domain.models import (
    AnomalyInfo,
    AnomalyType,
    DetectionResult,
    DetectorInput,
)
from failslow.infrastructure.framework.registration import DetectorRegistry
from .schema import DegradationBocpdParams
from .distributions import BOCPDStream

logger = logging.getLogger(__name__)


@dataclass
class _CandidateRecord:
    first_index: int
    last_index: int
    degradation_pos: int


class _RankState:
    """Per-rank BOCPD state."""

    def __init__(self, params: DegradationBocpdParams):
        self.stream = BOCPDStream(
            distribution=params.distribution,
            hazard=params.hazard,
            ignore_prop_lb=params.ignore_prop_lb,
            egress_distance=params.egress_distance,
            record_probs=params.record_probs,
            enable_crop_acceleration=params.enable_crop_acceleration,
            init_sigma2=params.init_sigma2,
            huber_delta=params.huber_delta,
            run_length_bonus=params.run_length_bonus,
        )
        self.total_obs_count: int = 0
        self.last_degradation_pos: Optional[int] = None
        self.candidates: List[_CandidateRecord] = []
        self.change_point2cumsum: pd.DataFrame = pd.DataFrame(columns=["cumsum"])
        self.observations: List[float] = []


class DegradationBocpdDetector(DetectorRegistry, IStreamDetector, IStatefulDetector):
    """
    Per-rank degradation detector using Bayesian Online Changepoint Detection.

    Each rank is monitored independently for changepoints. A changepoint
    indicates a shift in the underlying distribution of the metric.
    Alerts are confirmed after min_consecutive consecutive observations
    report the same changepoint position.
    """

    COMPONENT_NAME = "degradation_bocpd"

    def __init__(self, params: Optional[DegradationBocpdParams] = None, **kwargs):
        if params is not None:
            if isinstance(params, dict):
                self._params = DegradationBocpdParams(**params)
            else:
                self._params = params
        else:
            self._params = DegradationBocpdParams(**kwargs)

        self._rank_states: Dict[int, _RankState] = {}
        self._plot_data: Dict[int, List[float]] = {}
        self._changepoint_records: Dict[int, List[Tuple[int, str]]] = {}

    @property
    def name(self) -> str:
        return self.COMPONENT_NAME

    def reset(self) -> None:
        self._rank_states.clear()
        self._plot_data.clear()
        self._changepoint_records.clear()

    def _plot_and_save(self) -> None:
        if not self._plot_data:
            return

        logger.debug(
            f"[_plot_and_save] _plot_data keys: {list(self._plot_data.keys())}"
        )
        for rank_id, values in self._plot_data.items():
            logger.debug(
                f"[_plot_and_save] rank {rank_id}: len={len(values)}, shape={np.shape(values)}"
            )

        N = len(self._plot_data)

        plt.figure(figsize=(14, 8))
        cmap = plt.get_cmap("tab20")

        for idx, rank_id in enumerate(sorted(self._plot_data.keys())):
            plt.plot(
                range(len(self._plot_data[rank_id])),
                self._plot_data[rank_id],
                label=f"Rank {rank_id}",
                color=cmap(idx % 20),
                alpha=0.7,
                linewidth=1.0,
            )

        for rank_id, cps in self._changepoint_records.items():
            if rank_id not in self._plot_data:
                continue
            for cp_index, direction in cps:
                if cp_index < 0 or cp_index >= len(self._plot_data[rank_id]):
                    continue
                cp_value = self._plot_data[rank_id][cp_index]
                color = "red" if direction == "rise" else "blue"
                plt.axvline(
                    x=cp_index, color=color, linestyle="--", alpha=0.5, linewidth=0.8
                )
                plt.plot(
                    cp_index, cp_value, marker="v", color=color, markersize=8, alpha=0.8
                )

        plt.title("Degradation Detection (BOCPD) - Per-Rank Time Series")
        plt.xlabel("Time Index")
        plt.ylabel("Values")

        if N <= 10:
            plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize="small")
        elif N <= 20:
            plt.legend(
                bbox_to_anchor=(1.05, 1), loc="upper left", ncol=2, fontsize="small"
            )
        else:
            plt.legend(loc="upper right")

        plt.grid(True, linestyle="--", alpha=0.5)
        plt.tight_layout()

        save_dir = self._params.plt_save_path
        if not save_dir.endswith("/"):
            save_dir += "/"

        os.makedirs(save_dir, exist_ok=True)

        existing_files = [
            f
            for f in os.listdir(save_dir)
            if f.startswith("degradation_bocpd_plot_") and f.endswith(".png")
        ]

        max_index = 0
        for filename in existing_files:
            match = re.search(r"degradation_bocpd_plot_(\d+)\.png", filename)
            if match:
                max_index = max(max_index, int(match.group(1)))

        indexed_path = os.path.join(
            save_dir, f"degradation_bocpd_plot_{max_index + 1}.png"
        )
        plt.savefig(indexed_path, dpi=300, bbox_inches="tight")
        logger.info(f"Plot saved to {indexed_path}")
        plt.close()

    def detect(
        self,
        data: Union[np.ndarray, DetectorInput],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DetectionResult]:
        self._plot_data.clear()
        self._changepoint_records.clear()

        if isinstance(data, DetectorInput):
            values = data.values
            rank_ids = data.rank_ids
        else:
            values = np.asarray(data, dtype=float)
            rank_ids = (
                list(range(values.shape[1]))
                if values.ndim == 2
                else list(range(len(values)))
            )

        timestamp = None
        if context is not None:
            timestamp = context.get("timestamp")

        results = []
        if values.ndim == 2:
            for rank_idx, rank_id in enumerate(rank_ids):
                rank_values = values[:, rank_idx]
                self._plot_data[rank_id] = rank_values.tolist()
                for val in rank_values:
                    rank_results = self._detect_single_rank(
                        rank_id, float(val), timestamp
                    )
                    results.extend(rank_results)
        else:
            values_flat = values.flatten()
            for i, (val, rank_id) in enumerate(zip(values_flat, rank_ids)):
                rank_results = self._detect_single_rank(rank_id, float(val), timestamp)
                results.extend(rank_results)

                if rank_id not in self._plot_data:
                    self._plot_data[rank_id] = []
                self._plot_data[rank_id].append(float(val))

        if self._params.plt_save_path:
            self._plot_and_save()

        return results

    def _detect_single_rank(
        self,
        rank_id: int,
        obs: float,
        timestamp: Optional[int],
    ) -> List[DetectionResult]:
        if not np.isfinite(obs):
            return []

        if rank_id not in self._rank_states:
            self._rank_states[rank_id] = _RankState(self._params)

        state = self._rank_states[rank_id]
        state.total_obs_count += 1
        state.observations.append(obs)

        rt = state.stream.update(obs)
        total_count = state.stream.get_total_obs_count()
        degradation_pos = total_count - rt - 1

        if degradation_pos < 0:
            return []

        if state.last_degradation_pos is None:
            state.last_degradation_pos = degradation_pos
            state.candidates.append(
                _CandidateRecord(
                    first_index=state.total_obs_count,
                    last_index=state.total_obs_count,
                    degradation_pos=degradation_pos,
                )
            )
            return []

        if degradation_pos == state.last_degradation_pos:
            if state.candidates:
                state.candidates[-1].last_index = state.total_obs_count
        else:
            state.last_degradation_pos = degradation_pos
            state.candidates.append(
                _CandidateRecord(
                    first_index=state.total_obs_count,
                    last_index=state.total_obs_count,
                    degradation_pos=degradation_pos,
                )
            )

        if not state.candidates:
            return []

        latest = state.candidates[-1]
        consecutive_count = latest.last_index - latest.first_index + 1

        if consecutive_count < self._params.min_consecutive:
            return []

        if degradation_pos >= len(state.observations):
            return []

        post_cp_observations = state.observations[degradation_pos:]
        state.change_point2cumsum.loc[degradation_pos, "cumsum"] = float(
            np.sum(post_cp_observations)
        )

        cumsum = state.change_point2cumsum.loc[degradation_pos, "cumsum"]
        count_since_cp = len(post_cp_observations)
        if count_since_cp <= 0:
            return []

        avg_since_cp = cumsum / count_since_cp

        if degradation_pos > 0:
            pre_obs = state.observations[:degradation_pos]
            if pre_obs:
                avg_before_cp = np.mean(pre_obs)
            else:
                avg_before_cp = avg_since_cp
        else:
            avg_before_cp = avg_since_cp

        direction = None
        if avg_since_cp > avg_before_cp and self._params.detect_rise:
            direction = "rise"
        elif avg_since_cp < avg_before_cp and self._params.detect_drop:
            direction = "drop"

        if direction is None:
            return []

        state.candidates.clear()
        state.last_degradation_pos = None

        # 重置 BOCPD 流状态，回放变点之后的观测值，避免同一变点被重复检测
        post_cp_observations = state.observations[degradation_pos:]
        state.stream = BOCPDStream(
            distribution=self._params.distribution,
            hazard=self._params.hazard,
            ignore_prop_lb=self._params.ignore_prop_lb,
            egress_distance=self._params.egress_distance,
            record_probs=self._params.record_probs,
            enable_crop_acceleration=self._params.enable_crop_acceleration,
            init_sigma2=self._params.init_sigma2,
            huber_delta=self._params.huber_delta,
            run_length_bonus=self._params.run_length_bonus,
        )
        state.total_obs_count = 0
        state.observations = []
        state.change_point2cumsum = pd.DataFrame(columns=["cumsum"])
        for obs in post_cp_observations:
            state.stream.update(obs)
            state.total_obs_count += 1
            state.observations.append(obs)

        if rank_id not in self._changepoint_records:
            self._changepoint_records[rank_id] = []
        self._changepoint_records[rank_id].append((degradation_pos, direction))

        anomaly_info = AnomalyInfo(
            is_anomaly=True,
            anomaly_type=AnomalyType.FAIL_SLOW,
            anomaly_details=[
                {
                    "direction": direction,
                    "rank_id": rank_id,
                    "changepoint_index": degradation_pos,
                    "avg_before_changepoint": float(avg_before_cp),
                    "avg_after_changepoint": float(avg_since_cp),
                    "relative_change": float(
                        (avg_since_cp - avg_before_cp) / (abs(avg_before_cp) + 1e-9)
                    ),
                    "first_detection_index": latest.first_index,
                    "last_detection_index": latest.last_index,
                }
            ],
        )

        metadata = {
            "rank_id": rank_id,
            "detector_type": "degradation_bocpd",
            "distribution": self._params.distribution,
        }
        if timestamp is not None:
            metadata["timestamp"] = timestamp

        return [
            DetectionResult(
                detector_name=self.name,
                anomaly_info=anomaly_info,
                metadata=metadata,
            )
        ]

    def get_state(self) -> Dict[str, Any]:
        state = {}
        for rank_id, rank_state in self._rank_states.items():
            state[str(rank_id)] = {
                "total_obs_count": rank_state.total_obs_count,
                "observations": rank_state.observations,
                "last_degradation_pos": rank_state.last_degradation_pos,
                "candidates": [
                    {
                        "first_index": c.first_index,
                        "last_index": c.last_index,
                        "degradation_pos": c.degradation_pos,
                    }
                    for c in rank_state.candidates
                ],
                "change_point2cumsum": rank_state.change_point2cumsum.to_dict(),
            }
        return state

    def set_state(self, state: Dict[str, Any]) -> None:
        self._rank_states.clear()
        for rank_id_str, rank_state in state.items():
            rank_id = int(rank_id_str)
            new_state = _RankState(self._params)
            new_state.total_obs_count = rank_state.get("total_obs_count", 0)
            new_state.observations = rank_state.get("observations", [])
            new_state.last_degradation_pos = rank_state.get("last_degradation_pos")

            for obs in new_state.observations:
                new_state.stream.update(obs)

            new_state.candidates = [
                _CandidateRecord(
                    first_index=c["first_index"],
                    last_index=c["last_index"],
                    degradation_pos=c["degradation_pos"],
                )
                for c in rank_state.get("candidates", [])
            ]

            cp2cumsum_dict = rank_state.get("change_point2cumsum", {})
            if cp2cumsum_dict:
                new_state.change_point2cumsum = pd.DataFrame(cp2cumsum_dict)
            else:
                new_state.change_point2cumsum = pd.DataFrame(columns=["cumsum"])

            self._rank_states[rank_id] = new_state
