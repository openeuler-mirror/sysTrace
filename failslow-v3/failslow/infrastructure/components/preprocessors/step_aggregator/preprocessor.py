"""
Implementation of the Step Aggregator preprocessor.

This preprocessor aggregates StepMetrics by step number across ranks,
returning np.ndarray format for detectors.

Output format: (num_groups, num_ranks) where num_groups = ceil(num_steps / steps_per_group)
"""
import logging
from typing import Dict, List, Optional

import numpy as np
from scipy.ndimage import gaussian_filter1d

from failslow.domain.models import KernelType, StepMetrics, TaskType
from failslow.infrastructure.framework.registration import PreprocessorRegistry

from .schema import StepAggregatorParams

logger = logging.getLogger(__name__)


class StepAggregatorPreprocessor(PreprocessorRegistry):
    """
    Preprocessor that aggregates StepMetrics by step number,
    outputting np.ndarray for detectors.

    Output format: (num_groups, num_ranks)
    """

    COMPONENT_NAME = "step_aggregator"

    def __init__(self, params: StepAggregatorParams = None, **kwargs):
        if params is not None:
            p = params
        else:
            p = StepAggregatorParams(**kwargs)

        self._steps_per_group = p.steps_per_group
        self._filter_extreme = p.filter_extreme_values
        self._extreme_lower = p.extreme_quantile_lower
        self._extreme_upper = p.extreme_quantile_upper
        self._agg_functions = p.aggregation_functions
        self._smoothing = p.smoothing
        self._metric_configs = p.metric_configs
        self._current_task_type: Optional[TaskType] = None
        self._raw_cache: List[StepMetrics] = []
        self._process_called_since_flush: bool = False
        self._step_timestamps: List[float] = []
        self._output_rank_ids: List[int] = []
        self._output_node_ips: List[str] = []
        self._data_source = None
        self._emitted_group_count: int = 0
        self._target_op: Optional[str] = None
        self._override_applied: bool = False

    def _clear_output_rank_metadata(self) -> None:
        self._output_rank_ids = []
        self._output_node_ips = []

    def _set_output_rank_metadata(
        self,
        rank_ids: List[int],
        rank_id_to_node_ip: Dict[int, str],
    ) -> None:
        self._output_rank_ids = list(rank_ids)
        self._output_node_ips = [
            rank_id_to_node_ip.get(rank_id, "unknown") for rank_id in rank_ids
        ]

    def set_data_source(self, data_source) -> None:
        """Set data source for auto-detection of offline/online mode."""
        self._data_source = data_source

    def set_target_op(self, target_op: str) -> None:
        """
        Set the target operator name and apply per-operator config if available.

        Called by pipeline after OpNameFilter determines the target operator.
        """
        self._target_op = target_op
        self._apply_metric_override(target_op)

    def _apply_metric_override(self, op_name: str) -> None:
        """Apply per-operator configuration override if available."""
        if not op_name or not self._metric_configs:
            return

        override = self._metric_configs.get(op_name)
        if override is None:
            logger.debug(
                "No metric override found for operator '%s', using default config",
                op_name,
            )
            return

        logger.info(
            "Applying metric override for operator '%s': steps_per_group=%s",
            op_name,
            override.steps_per_group,
        )

        if override.steps_per_group is not None:
            self._steps_per_group = override.steps_per_group
        if override.aggregation_functions is not None:
            self._agg_functions = override.aggregation_functions
        if override.smoothing is not None:
            self._smoothing = override.smoothing
        if override.filter_extreme_values is not None:
            self._filter_extreme = override.filter_extreme_values
        if override.extreme_quantile_upper is not None:
            self._extreme_upper = override.extreme_quantile_upper
        if override.extreme_quantile_lower is not None:
            self._extreme_lower = override.extreme_quantile_lower

        self._override_applied = True

    def get_target_op(self) -> Optional[str]:
        """Return the current target operator name."""
        return self._target_op

    def process(
        self, data: List[StepMetrics], task_type: Optional[TaskType] = None
    ) -> np.ndarray:
        """
        Aggregate StepMetrics by step number.

        Args:
            data: List of StepMetrics
            task_type: Optional task type for task-specific aggregation

        Returns:
            np.ndarray: shape (num_groups, num_ranks)
        """
        self._current_task_type = task_type
        self._raw_cache.extend(data)
        self._process_called_since_flush = True

        if self._data_source is None:
            return self._process_online_cache()
        return self._process_cache()

    def _process_online_cache(self) -> np.ndarray:
        """Emit only newly completed groups while keeping online history cached."""
        step_ids = sorted({sm.step for sm in self._raw_cache})
        complete_step_count = (len(step_ids) // self._steps_per_group) * self._steps_per_group
        if complete_step_count == 0:
            self._step_timestamps = []
            return np.array([])

        ready_steps = set(step_ids[:complete_step_count])
        ready_metrics = [sm for sm in self._raw_cache if sm.step in ready_steps]
        self._raw_cache = [sm for sm in self._raw_cache if sm.step not in ready_steps]

        cached_metrics = self._raw_cache
        self._raw_cache = ready_metrics
        try:
            return self._process_cache()
        finally:
            self._raw_cache = cached_metrics

    def _process_cache(self) -> np.ndarray:
        """
        Process the raw cache by grouping data by step and rank,
        then aggregating multiple steps into groups.

        Returns:
            np.ndarray: shape (num_groups, num_ranks)
        """
        if not self._raw_cache:
            self._clear_output_rank_metadata()
            return np.array([])

        step_groups: Dict[int, List[StepMetrics]] = {}
        for sm in self._raw_cache:
            step_groups.setdefault(sm.step, []).append(sm)

        sorted_steps = sorted(step_groups.keys())
        if not sorted_steps:
            return np.array([])

        all_rank_ids = sorted(set(sm.rank_id for sm in self._raw_cache))
        num_ranks = len(all_rank_ids)
        rank_id_to_idx = {rid: idx for idx, rid in enumerate(all_rank_ids)}
        rank_id_to_node_ip = {}
        for sm in self._raw_cache:
            if sm.rank_id not in rank_id_to_node_ip:
                rank_id_to_node_ip[sm.rank_id] = sm.node_ip
        self._set_output_rank_metadata(all_rank_ids, rank_id_to_node_ip)

        all_step_values = []
        for step_id in sorted_steps:
            step_data = step_groups[step_id]
            for sm in step_data:
                if self._current_task_type == TaskType.DEGRADATION:
                    all_step_values.append((sm.end_time_ns - sm.start_time_ns) / 1_000_000.0)
                else:
                    for kernel in sm.kernels:
                        all_step_values.append(
                            self._get_value_for_task_type(kernel, self._current_task_type)
                        )

        lower_bound = None
        upper_bound = None
        if self._filter_extreme and len(all_step_values) > 2:
            lower_bound = np.quantile(all_step_values, self._extreme_lower)
            upper_bound = np.quantile(all_step_values, self._extreme_upper)

        num_steps = len(sorted_steps)
        step_values = np.full((num_steps, num_ranks), np.nan)
        step_timestamps = []

        for step_idx, step_id in enumerate(sorted_steps):
            step_data = step_groups[step_id]
            min_start_time = float("inf")
            ranks_in_step = set()

            for sm in step_data:
                if sm.start_time_ns < min_start_time:
                    min_start_time = sm.start_time_ns
                rank_idx = rank_id_to_idx.get(sm.rank_id)
                if rank_idx is None:
                    continue

                ranks_in_step.add(sm.rank_id)
                if self._current_task_type == TaskType.DEGRADATION:
                    value = (sm.end_time_ns - sm.start_time_ns) / 1_000_000.0
                    if lower_bound is not None and upper_bound is not None:
                        if value < lower_bound or value > upper_bound:
                            value = np.nan
                    if not np.isnan(value):
                        step_values[step_idx, rank_idx] = value
                else:
                    values = []
                    for kernel in sm.kernels:
                        value = self._get_value_for_task_type(
                            kernel, self._current_task_type
                        )
                        if lower_bound is not None and upper_bound is not None:
                            if value <= lower_bound or value >= upper_bound:
                                continue
                        values.append(value)

                    if values:
                        step_values[step_idx, rank_idx] = self._aggregate_values(values)

            step_timestamps.append(min_start_time / 1_000_000.0)

            missing_ranks = set(all_rank_ids) - ranks_in_step
            if missing_ranks:
                logger.warning(
                    "Step %d missing data for ranks: %s",
                    step_id,
                    sorted(missing_ranks),
                )

        num_groups = (num_steps + self._steps_per_group - 1) // self._steps_per_group
        result = np.full((num_groups, num_ranks), np.nan)
        self._step_timestamps = []

        for group_idx in range(num_groups):
            start_step_idx = group_idx * self._steps_per_group
            end_step_idx = min(start_step_idx + self._steps_per_group, num_steps)

            group_data = step_values[start_step_idx:end_step_idx, :]

            for rank_idx in range(num_ranks):
                rank_values = group_data[:, rank_idx]
                valid_values = rank_values[~np.isnan(rank_values)]
                if len(valid_values) > 0:
                    result[group_idx, rank_idx] = self._aggregate_values(
                        valid_values.tolist()
                    )

            group_start_time = step_timestamps[start_step_idx]
            self._step_timestamps.append(group_start_time)

        if self._smoothing and self._smoothing.window_size > 1:
            for col_idx in range(result.shape[1]):
                col_data = result[:, col_idx]
                valid_mask = ~np.isnan(col_data)
                if np.sum(valid_mask) > 1:
                    smoothed = self._smooth_series(col_data)
                    result[:, col_idx] = smoothed

        logger.info(
            "Step aggregation: num_steps=%d, steps_per_group=%d, num_groups=%d, "
            "num_ranks=%d, extreme_filter=%s, target_op=%s",
            num_steps,
            self._steps_per_group,
            num_groups,
            num_ranks,
            self._filter_extreme,
            self._target_op,
        )

        return result

    def _get_value_for_task_type(
        self, kernel: KernelType, task_type: Optional[TaskType]
    ) -> float:
        """Calculate the value to aggregate based on task type."""
        if task_type == TaskType.SLOW_LAUNCH:
            value_ns = kernel.t3_ns - kernel.t2_ns
        elif task_type == TaskType.SLOW_CALC:
            value_ns = kernel.t4_ns - kernel.t3_ns
        else:
            value_ns = kernel.t_exec_ns
        return value_ns / 1_000_000.0

    def _aggregate_values(self, values: List[float]) -> float:
        """Aggregate a list of values using the configured aggregation function."""
        if not values:
            return np.nan

        primary_func = (
            self._agg_functions[0].function if self._agg_functions else "mean"
        )

        if primary_func == "percentile":
            q = (
                self._agg_functions[0].func_params.q
                if self._agg_functions and self._agg_functions[0].func_params
                else 80
            )
            return float(np.percentile(values, q))
        elif primary_func == "mean":
            return float(np.mean(values))
        elif primary_func == "median":
            return float(np.median(values))
        elif primary_func == "max":
            return float(np.max(values))
        elif primary_func == "min":
            return float(np.min(values))
        elif primary_func == "sum":
            return float(np.sum(values))
        elif primary_func == "p99":
            return float(np.percentile(values, 99))
        else:
            return float(np.mean(values))

    def _smooth_series(self, series: np.ndarray) -> np.ndarray:
        """Apply smoothing to a series, handling NaN values."""
        valid_mask = ~np.isnan(series)
        if np.sum(valid_mask) <= 1:
            return series

        valid_indices = np.where(valid_mask)[0]
        valid_values = series[valid_indices]

        if self._smoothing.function == "gaussian":
            smoothed_valid = gaussian_filter1d(
                valid_values, sigma=self._smoothing.window_size / 6, mode="nearest"
            )
        elif self._smoothing.function == "mean":
            import pandas as pd

            smoothed_valid = (
                pd.Series(valid_values)
                .rolling(window=self._smoothing.window_size, min_periods=1, center=True)
                .mean()
                .values
            )
        elif self._smoothing.function == "median":
            import pandas as pd

            smoothed_valid = (
                pd.Series(valid_values)
                .rolling(window=self._smoothing.window_size, min_periods=1, center=True)
                .median()
                .values
            )
        else:
            smoothed_valid = valid_values

        result = series.copy()
        result[valid_indices] = smoothed_valid
        return result

    def get_step_timestamps(self) -> np.ndarray:
        """Return timestamps (ms) for each group."""
        return (
            np.array(self._step_timestamps) if self._step_timestamps else np.array([])
        )

    def get_window_timestamps(self) -> np.ndarray:
        """Alias for get_step_timestamps() for pipeline compatibility."""
        return self.get_step_timestamps()

    def get_output_rank_ids(self) -> List[int]:
        return list(self._output_rank_ids)

    def get_output_node_ips(self) -> List[str]:
        return list(self._output_node_ips)

    def flush(self) -> Optional[np.ndarray]:
        """
        Flush remaining data.

        If process() was already called, returns None to avoid duplicate data.
        Otherwise processes the cache and clears it.
        """
        if not self._raw_cache:
            return None

        if self._process_called_since_flush:
            self._process_called_since_flush = False
            return None

        result = self._process_cache()
        self._raw_cache.clear()
        self._step_timestamps.clear()
        return result if result.size > 0 else None

    def reset(self) -> None:
        """Reset all buffers and accumulated data."""
        self._raw_cache.clear()
        self._step_timestamps.clear()
        self._clear_output_rank_metadata()
        self._process_called_since_flush = False
        self._emitted_group_count = 0
