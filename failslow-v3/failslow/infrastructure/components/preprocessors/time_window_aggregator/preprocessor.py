"""
Implementation of the Time Window Aggregator preprocessor.

This preprocessor aggregates StepMetrics by rank over time windows,
returning np.ndarray format for detectors.

Migrated from v2:
- Extreme value filtering: rank-level global filtering (not per-window)
- Data smoothing: after aggregation (not within window)
- Output format: (num_windows, num_ranks)
"""
import logging
from typing import Dict, List, Tuple, Iterator, Optional

import numpy as np
import pandas as pd
from scipy.ndimage import gaussian_filter1d

from failslow.infrastructure.framework.registration import PreprocessorRegistry
from failslow.domain.models import StepMetrics, KernelType, TaskType
from .schema import TimeWindowAggregatorParams, AggregationFunction, MetricOverrideConfig

logger = logging.getLogger(__name__)


class TimeWindowAggregatorPreprocessor(PreprocessorRegistry):
    """
    Preprocessor that aggregates StepMetrics into time windows,
    outputting np.ndarray for detectors.
    
    Output format: (num_windows, num_ranks)
    """
    COMPONENT_NAME = "time_window_aggregator"

    def __init__(self, params: TimeWindowAggregatorParams = None, **kwargs):
        if params is not None:
            p = params
        else:
            p = TimeWindowAggregatorParams(**kwargs)

        self._window_seconds = p.time_window_seconds
        self._window_ns = int(p.time_window_seconds * 1e9)
        self._drop_head_seconds = p.drop_head_seconds
        self._drop_tail_seconds = p.drop_tail_seconds
        self._filter_extreme = p.filter_extreme_values
        self._extreme_lower = p.extreme_quantile_lower
        self._extreme_upper = p.extreme_quantile_upper
        self._agg_functions = p.aggregation_functions
        self._smoothing = p.smoothing
        self._metric_configs = p.metric_configs
        self._metric_override: Optional[MetricOverrideConfig] = None
        self._buffers: Dict[int, List[StepMetrics]] = {}
        self._window_start_ns: Dict[int, int] = {}
        self._pending_results: List[Tuple[int, float]] = []
        self._current_task_type: Optional[TaskType] = None
        self._window_timestamps: List[float] = []
        self._accumulated_windows: List[Tuple[int, Dict[int, float]]] = []
        self._accumulated_global_min_time: Optional[int] = None
        self._all_rank_ids: List[int] = []
        self._output_rank_ids: List[int] = []
        self._output_node_ips: List[str] = []
        # Unified raw cache: accumulates ALL raw input across calls
        self._raw_cache: List[StepMetrics] = []
        # Track if process() was called since last flush/reset
        self._process_called_since_flush: bool = False
        # Data source reference for auto-detection of offline/online mode
        self._data_source = None

    def _clear_output_rank_metadata(self) -> None:
        self._output_rank_ids = []
        self._output_node_ips = []

    def _set_output_rank_metadata(
        self,
        rank_ids: List[int],
        rank_groups: Dict[int, List[StepMetrics]],
    ) -> None:
        self._output_rank_ids = list(rank_ids)
        self._output_node_ips = [
            rank_groups[rank_id][0].node_ip if rank_groups.get(rank_id) else "unknown"
            for rank_id in rank_ids
        ]

    def set_data_source(self, data_source) -> None:
        """Set data source for auto-detection of offline/online mode."""
        self._data_source = data_source

    def set_target_op(self, op_name: str) -> None:
        """
        Set the target operator for per-operator config lookup.

        Called by OpNameFilterPreprocessor after it selects an operator.

        Args:
            op_name: The selected operator name (e.g., 'HcclAllreduce')
        """
        override = self._find_metric_override(op_name)
        if override:
            self._metric_override = override
            # Apply override values
            if override.time_window_seconds is not None:
                self._window_seconds = override.time_window_seconds
                self._window_ns = int(override.time_window_seconds * 1e9)
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
            logger.info("Using per-operator config for '%s': window=%s, agg=%s",
                        op_name,
                        override.time_window_seconds,
                        override.aggregation_functions)
        else:
            self._metric_override = None
            logger.debug("No per-operator config found for '%s', using global config", op_name)

    def _find_metric_override(self, op_name: str) -> Optional[MetricOverrideConfig]:
        """
        Find metric override config for the given operator name.

        Matching logic:
        1. Exact match (e.g., 'HcclAllreduce')
        2. Base name match (e.g., 'HcclAllreduce_launch' -> 'HcclAllreduce')

        Args:
            op_name: The operator name to look up

        Returns:
            MetricOverrideConfig if found, None otherwise
        """
        # 1. Exact match
        if op_name in self._metric_configs:
            return self._metric_configs[op_name]

        # 2. Base name match (e.g., "HcclAllreduce_launch" -> "HcclAllreduce")
        if "_launch" in op_name:
            base_name = op_name.split("_launch")[0]
            if base_name in self._metric_configs:
                return self._metric_configs[base_name]

        return None

    def _get_time_column_attr(self, task_type: Optional[TaskType]) -> str:
        """Get the time column attribute name for windowing based on task type."""
        if task_type == TaskType.SLOW_LAUNCH:
            return "t2_ns"
        elif task_type == TaskType.SLOW_CALC:
            return "t3_ns"
        else:
            return "start_time_ns"

    def _get_kernel_time_attr(self, step: StepMetrics, attr: str) -> int:
        """Get time attribute from first kernel in step, fallback to step.start_time_ns."""
        if not step.kernels:
            return step.start_time_ns
        kernel = step.kernels[0]
        return getattr(kernel, attr, step.start_time_ns)

    def _apply_drop_head_seconds(self, steps: List[StepMetrics], task_type: Optional[TaskType]) -> List[StepMetrics]:
        """过滤掉开头 drop_head_seconds 时间范围内的数据"""
        if self._drop_head_seconds <= 0 or not steps:
            return steps

        drop_ns = self._drop_head_seconds * 1e9
        time_attr = self._get_time_column_attr(task_type)

        min_time = float('inf')
        for step in steps:
            step_time = self._get_kernel_time_attr(step, time_attr)
            if step_time < min_time:
                min_time = step_time

        filtered_steps = []
        for step in steps:
            step_time = self._get_kernel_time_attr(step, time_attr)
            if step_time >= min_time + drop_ns:
                filtered_steps.append(step)

        logger.info("drop_head_seconds=%.2f (using %s): filtered %d steps, kept %d steps",
                    self._drop_head_seconds, time_attr, len(steps) - len(filtered_steps), len(filtered_steps))
        return filtered_steps

    def _apply_drop_tail_seconds(self, steps: List[StepMetrics], task_type: Optional[TaskType]) -> List[StepMetrics]:
        """过滤掉末尾 drop_tail_seconds 时间范围内的数据"""
        if self._drop_tail_seconds <= 0 or not steps:
            return steps

        drop_ns = self._drop_tail_seconds * 1e9
        time_attr = self._get_time_column_attr(task_type)

        max_time = float('-inf')
        for step in steps:
            step_time = self._get_kernel_time_attr(step, time_attr)
            if step_time > max_time:
                max_time = step_time

        filtered_steps = []
        for step in steps:
            step_time = self._get_kernel_time_attr(step, time_attr)
            if step_time <= max_time - drop_ns:
                filtered_steps.append(step)

        logger.info("drop_tail_seconds=%.2f (using %s): filtered %d steps, kept %d steps",
                    self._drop_tail_seconds, time_attr, len(steps) - len(filtered_steps), len(filtered_steps))
        return filtered_steps

    def _get_value_for_task_type(self, kernel: KernelType, task_type: Optional[TaskType]) -> float:
        """Calculate the value to aggregate based on task type."""
        if task_type == TaskType.SLOW_LAUNCH:
            value_ns = kernel.t3_ns - kernel.t2_ns
        elif task_type == TaskType.SLOW_CALC:
            value_ns = kernel.t4_ns - kernel.t3_ns
        elif task_type == TaskType.SLOW_HOST:
            value_ns = kernel.t2_ns - kernel.t1_ns
        else:
            value_ns = kernel.t_exec_ns
        return value_ns / 1_000_000.0

    def process(self, data: List[StepMetrics], task_type: Optional[TaskType] = None) -> np.ndarray:
        """
        接收一批 StepMetrics，按 rank 分组后进行时间窗口聚合。

        Args:
            data: 当前 batch 内所有 rank 的 StepMetrics
            task_type: Optional task type for task-specific aggregation behavior

        Returns:
            np.ndarray:
                - 离线模式: shape (num_windows, num_ranks)
                - 在线模式: shape (num_ranks,)
        """
        self._current_task_type = task_type

        if self._drop_head_seconds > 0:
            data = self._apply_drop_head_seconds(data, task_type)

        if self._drop_tail_seconds > 0:
            data = self._apply_drop_tail_seconds(data, task_type)

        if self._is_offline_mode():
            return self._process_offline(data)
        else:
            return self._process_online(data)

    def _is_offline_mode(self) -> bool:
        """Auto-detect offline mode based on data source availability.

        Offline mode: has data_source (batch processing via run_offline())
        Online mode: no data_source (streaming via Task)
        """
        return self._data_source is not None

    def _process_offline(self, data: List[StepMetrics]) -> np.ndarray:
        """
        离线模式：一次性聚合所有数据，输出 2D 数组 (num_windows, num_ranks)。

        迁移 v2 功能：
        1. 使用全局窗口对齐（与 v2 保持一致）
        2. 极值过滤改为 rank 内全局过滤
        3. 数据平滑改为聚合后
        4. 输出格式改为 (num_windows, num_ranks)
        5. 过滤负窗口数据（与 v2 的 window > 0 保持一致）
        """
        rank_groups: Dict[int, List[StepMetrics]] = {}
        for step in data:
            rank_groups.setdefault(step.rank_id, []).append(step)

        rank_ids_sorted = sorted(rank_groups.keys())
        self._set_output_rank_metadata(rank_ids_sorted, rank_groups)
        time_attr = self._get_time_column_attr(self._current_task_type)

        steps_sorted_by_rank: Dict[int, List[StepMetrics]] = {}
        global_min_time = float('inf')

        for rank_id in rank_ids_sorted:
            steps = rank_groups[rank_id]
            steps_sorted_by_rank[rank_id] = steps  # Use data as-is, already sorted

            if not steps:
                continue

            first_time = self._get_kernel_time_attr(steps[0], time_attr)
            if first_time < global_min_time:
                global_min_time = first_time

        if global_min_time == float('inf'):
            global_min_time = 0

        rank_results: Dict[int, List[float]] = {}
        min_windows = float('inf')
        max_windows = 0

        for rank_id in rank_ids_sorted:
            steps_sorted = steps_sorted_by_rank.get(rank_id, [])

            if not steps_sorted:
                continue

            all_kernel_values = []
            for step in steps_sorted:
                for kernel in step.kernels:
                    value = self._get_value_for_task_type(kernel, self._current_task_type)
                    all_kernel_values.append(value)

            lower_bound = None
            upper_bound = None
            if self._filter_extreme and len(all_kernel_values) > 2:
                lower_bound = np.quantile(all_kernel_values, self._extreme_lower)
                upper_bound = np.quantile(all_kernel_values, self._extreme_upper)

            windows: Dict[int, List[float]] = {}

            for step in steps_sorted:
                step_time = self._get_kernel_time_attr(step, time_attr)
                window_idx = int((step_time - global_min_time) // self._window_ns)

                if window_idx < 0:
                    continue

                for kernel in step.kernels:
                    value = self._get_value_for_task_type(kernel, self._current_task_type)

                    if lower_bound is not None and upper_bound is not None:
                        if value <= lower_bound or value >= upper_bound:
                            continue

                    windows.setdefault(window_idx, []).append(value)

            window_values = []
            for window_idx in windows.keys():
                values = windows[window_idx]
                agg_value = self._aggregate_values(values)
                window_values.append(agg_value)

            rank_results[rank_id] = window_values
            num_windows = len(window_values)
            min_windows = min(min_windows, num_windows)
            max_windows = max(max_windows, num_windows)

        if not rank_results:
            self._clear_output_rank_metadata()
            return np.array([])

        num_ranks = len(rank_ids_sorted)
        final_num_windows = min_windows if min_windows != float('inf') else 0
        result = np.zeros((final_num_windows, num_ranks))

        for col_idx, rank_id in enumerate(rank_ids_sorted):
            window_values = rank_results.get(rank_id, [])
            result[:, col_idx] = window_values[:final_num_windows]

        if self._smoothing and self._smoothing.window_size > 1:
            for col_idx in range(result.shape[1]):
                result[:, col_idx] = self._smooth_series(result[:, col_idx])

        self._window_timestamps = []
        for window_idx in range(final_num_windows):
            window_start_ns = global_min_time + window_idx * self._window_ns
            window_start_ms = window_start_ns / 1_000_000.0
            self._window_timestamps.append(window_start_ms)

        logger.info(
            "Offline aggregation: min_windows=%d, max_windows=%d, num_ranks=%d, "
            "global_min_time=%d ns, window_size=%d ns",
            min_windows, max_windows, num_ranks, global_min_time, self._window_ns
        )

        return result

    def _aggregate_values(self, values: List[float]) -> float:
        """简单聚合，不在窗口内平滑或过滤"""
        if not values:
            return 0.0

        primary_func = self._agg_functions[0].function if self._agg_functions else "mean"

        if primary_func == "percentile":
            q = self._agg_functions[0].func_params.q if self._agg_functions and self._agg_functions[0].func_params else 80
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
        """对聚合结果序列进行平滑（v2 方式）"""
        if self._smoothing.function == "gaussian":
            return gaussian_filter1d(series, sigma=self._smoothing.window_size / 6, mode="nearest")
        elif self._smoothing.function == "mean":
            return pd.Series(series).rolling(
                window=self._smoothing.window_size, min_periods=1, center=True
            ).mean().values
        elif self._smoothing.function == "median":
            return pd.Series(series).rolling(
                window=self._smoothing.window_size, min_periods=1, center=True
            ).median().values
        else:
            return series

    def get_window_timestamps(self) -> np.ndarray:
        """返回每个时间窗口的起始时间戳 (ms)。"""
        return np.array(self._window_timestamps) if self._window_timestamps else np.array([])

    def get_output_rank_ids(self) -> List[int]:
        return list(self._output_rank_ids)

    def get_output_node_ips(self) -> List[str]:
        return list(self._output_node_ips)

    def _process_online(self, data: List[StepMetrics]) -> np.ndarray:
        """
        在线模式：使用统一缓存处理所有数据。

        每次调用时：
        1. 将新数据追加到 _raw_cache（统一缓存，跨调用累积）
        2. 处理整个 _raw_cache 进行时间窗口聚合
        3. 对完整数据集应用极值过滤
        4. 返回聚合结果供检测器使用

        Args:
            data: 当前 batch 内所有 rank 的 StepMetrics

        Returns:
            np.ndarray: shape (num_windows, num_ranks)
        """
        # Append all incoming data to unified raw cache
        self._raw_cache.extend(data)

        # Update all_rank_ids from new data
        for step in data:
            if step.rank_id not in self._all_rank_ids:
                self._all_rank_ids.append(step.rank_id)

        if not self._raw_cache:
            return np.array([])

        # Mark that process() was called - flush() should not return duplicate data
        self._process_called_since_flush = True

        return self._process_unified_cache()

    def _process_unified_cache(self) -> np.ndarray:
        """
        Process the entire unified raw cache for time window aggregation.

        This method:
        1. Groups _raw_cache by rank_id
        2. Applies extreme filtering on full rank data (quantile-based)
        3. Assigns each step to time window
        4. Filters negative windows
        5. Aggregates values per window
        6. Builds result array with min_windows alignment across ranks
        7. Applies smoothing if enabled
        """
        time_attr = self._get_time_column_attr(self._current_task_type)

        # Group by rank_id
        rank_groups: Dict[int, List[StepMetrics]] = {}
        for step in self._raw_cache:
            rank_groups.setdefault(step.rank_id, []).append(step)

        rank_ids_sorted = sorted(rank_groups.keys())
        self._set_output_rank_metadata(rank_ids_sorted, rank_groups)

        # Determine global_min_time from first step of first rank
        global_min_time = float('inf')
        for rank_id in rank_ids_sorted:
            steps = rank_groups[rank_id]
            if steps:
                first_time = self._get_kernel_time_attr(steps[0], time_attr)
                if first_time < global_min_time:
                    global_min_time = first_time

        if global_min_time == float('inf'):
            global_min_time = 0

        # Compute extreme bounds per rank on FULL dataset before windowing
        rank_extreme_bounds: Dict[int, Tuple[Optional[float], Optional[float]]] = {}
        for rank_id in rank_ids_sorted:
            steps = rank_groups[rank_id]
            all_kernel_values = []
            for step in steps:
                for kernel in step.kernels:
                    value = self._get_value_for_task_type(kernel, self._current_task_type)
                    all_kernel_values.append(value)

            lower_bound = None
            upper_bound = None
            if self._filter_extreme and len(all_kernel_values) > 2:
                lower_bound = np.quantile(all_kernel_values, self._extreme_lower)
                upper_bound = np.quantile(all_kernel_values, self._extreme_upper)
            rank_extreme_bounds[rank_id] = (lower_bound, upper_bound)

        # Assign steps to windows and apply extreme filtering per rank
        rank_window_data: Dict[int, Dict[int, List[float]]] = {}

        for rank_id in rank_ids_sorted:
            steps = rank_groups[rank_id]
            lower_bound, upper_bound = rank_extreme_bounds[rank_id]

            windows: Dict[int, List[float]] = {}

            for step in steps:
                step_time = self._get_kernel_time_attr(step, time_attr)
                window_idx = int((step_time - global_min_time) // self._window_ns)

                if window_idx < 0:
                    continue

                for kernel in step.kernels:
                    value = self._get_value_for_task_type(kernel, self._current_task_type)

                    if lower_bound is not None and upper_bound is not None:
                        if value <= lower_bound or value >= upper_bound:
                            continue

                    windows.setdefault(window_idx, []).append(value)

            rank_window_data[rank_id] = windows

        # Aggregate values per window per rank
        rank_results: Dict[int, List[float]] = {}
        min_windows = float('inf')
        max_windows = 0

        for rank_id in rank_ids_sorted:
            windows = rank_window_data[rank_id]
            window_values = []
            for window_idx in sorted(windows.keys()):
                values = windows[window_idx]
                agg_value = self._aggregate_values(values)
                window_values.append(agg_value)

            rank_results[rank_id] = window_values
            num_windows = len(window_values)
            min_windows = min(min_windows, num_windows)
            max_windows = max(max_windows, num_windows)

        if not rank_results:
            self._clear_output_rank_metadata()
            return np.array([])

        num_ranks = len(rank_ids_sorted)
        final_num_windows = min_windows if min_windows != float('inf') else 0

        if final_num_windows == 0:
            self._clear_output_rank_metadata()
            return np.array([])

        result = np.zeros((final_num_windows, num_ranks))

        for col_idx, rank_id in enumerate(rank_ids_sorted):
            window_values = rank_results.get(rank_id, [])
            result[:, col_idx] = window_values[:final_num_windows]

        # Apply smoothing if enabled
        if self._smoothing and self._smoothing.window_size > 1:
            for col_idx in range(result.shape[1]):
                result[:, col_idx] = self._smooth_series(result[:, col_idx])

        # Update window timestamps
        self._window_timestamps = []
        for window_idx in range(final_num_windows):
            window_start_ns = global_min_time + window_idx * self._window_ns
            self._window_timestamps.append(window_start_ns / 1_000_000.0)

        logger.info(
            "Online unified cache aggregation: min_windows=%d, max_windows=%d, num_ranks=%d, "
            "global_min_time=%d ns, window_size=%d ns, cached_steps=%d",
            min_windows, max_windows, num_ranks, int(global_min_time), self._window_ns, len(self._raw_cache)
        )

        return result

    def flush(self) -> Optional[np.ndarray]:
        """
        Flush remaining data in the unified raw cache and return aggregated result.

        In online mode with unified caching, flush() handles the final drain when
        online detection ends. If process() was already called and returned complete
        windows, flush() returns None to avoid duplicate data.

        After flush(), the cache is cleared to allow fresh processing on restart.

        Returns:
            np.ndarray: shape (num_windows, num_ranks), or None if no data to flush
        """
        if not self._raw_cache:
            return None

        # If process() was already called and returned data, flush() should not
        # return duplicate data - but we also should NOT clear the cache because
        # the data was validly processed and we want to accumulate across calls
        if self._process_called_since_flush:
            # Just reset the flag, don't clear cache - data accumulates across calls
            self._process_called_since_flush = False
            return None

        # Process the remaining cache data (this is the drain case where
        # process() was never called or was called with no data)
        result = self._process_unified_cache()

        # Clear the raw cache after flushing
        self._raw_cache.clear()

        # Also clear other buffers to prevent duplicate returns
        self._buffers.clear()
        self._accumulated_windows.clear()

        return result if result.size > 0 else None

    def reset(self) -> None:
        """Reset all buffers and accumulated data."""
        self._buffers.clear()
        self._window_start_ns.clear()
        self._pending_results.clear()
        self._accumulated_windows.clear()
        self._accumulated_global_min_time = None
        self._all_rank_ids.clear()
        self._clear_output_rank_metadata()
        self._window_timestamps.clear()
        self._raw_cache.clear()
        self._process_called_since_flush = False
