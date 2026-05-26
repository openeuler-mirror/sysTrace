"""
Defines the core detection pipeline for the application.
"""

import logging
from typing import List, Optional, Tuple

import numpy as np

from ..domain.interfaces.data_source import IDataSource
from ..domain.interfaces.data_sink import IDataSink
from ..domain.interfaces.detector import IDetector
from ..domain.interfaces.metric_extractor import IMetricExtractor
from ..domain.interfaces.preprocessor import IPreprocessor
from ..domain.interfaces.reporter import IAlertReporter
from ..domain.models import (
    AnomalyInfo,
    AnomalyType,
    DetectionResult,
    DetectorInput,
    StepMetrics,
    TaskType,
)
from ..domain.models.domain_objects import HCCLDomain

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """
    Orchestrates the entire detection process from data loading to alerting.

    Supports:
    - Global detection (all ranks together)
    - Group detection (by TP/DP/PP groups)
    """

    def __init__(
        self,
        data_source: Optional[IDataSource],
        preprocessors: List[IPreprocessor],
        detectors: List[IDetector],
        reporters: List[IAlertReporter],
        metric_extractors: Optional[List[IMetricExtractor]] = None,
        enable_group_detection: bool = False,
        task_type: Optional[TaskType] = None,
        hccl_domain: Optional[HCCLDomain] = None,
        data_sink: Optional[IDataSink] = None,
    ):
        self.data_source = data_source
        self.preprocessors = preprocessors
        self.detectors = detectors
        self.reporters = reporters
        self.metric_extractors = metric_extractors or []
        self.enable_group_detection = enable_group_detection
        self.task_type = task_type
        self._hccl_domain = hccl_domain
        self._data_sink = data_sink

        # Pass data_source to preprocessors for auto-detection of offline/online mode
        for preprocessor in self.preprocessors:
            if hasattr(preprocessor, "set_data_source"):
                preprocessor.set_data_source(self.data_source)

        logger.info(
            f"Pipeline initialized with {len(preprocessors)} preprocessors, "
            f"{len(detectors)} detectors, {len(self.metric_extractors)} metric extractors, "
            f"enable_group_detection={enable_group_detection}"
        )

    def run_detect(self, data: np.ndarray) -> Tuple[np.ndarray, str]:
        """
        Run detection on aggregated data.

        Args:
            data: np.ndarray of shape (time_len, num_ranks)

        Returns:
            Tuple of (anomaly_labels, detect_type):
            - anomaly_labels: np.ndarray of shape (time_len, num_ranks) with 0=normal, 1=anomaly
            - detect_type: str indicating detection type ("TIME", "SPACE", "TIME_AND_SPACE")
        """
        all_results = np.zeros((0, 0))
        detect_type = "TIME"

        for detector in self.detectors:
            result = detector.detect(data)
            if isinstance(result, tuple):
                result, detect_type = result

            # Handle stream detectors that return List[DetectionResult]
            if isinstance(result, list):
                # Stream detector returns DetectionResult list - convert to 2D anomaly labels
                all_results = self._convert_stream_results_to_anomaly_labels(
                    result, data.shape if hasattr(data, 'shape') else (0, 0)
                )
                break

            if all_results.size == 0:
                all_results = result
            else:
                all_results = np.logical_or(all_results, result).astype(int)

        return all_results, detect_type

    def _convert_stream_results_to_anomaly_labels(
        self,
        detection_results: List,
        data_shape: Tuple[int, int],
    ) -> np.ndarray:
        """Convert stream detector results to 2D anomaly labels array.

        Supports two metadata formats:
        1. Group-detection format: metadata['abnormal_ranks'] (list) +
           metadata['anomaly_time_ranges'] (list of {start, end})
        2. Stream-detector format: metadata['rank_id'] (single int) +
           anomaly_info.anomaly_details[*]['first_degradation_index'/'last_degradation_index']
           or 'first_detection_index'/'last_detection_index' (1-based counters)
        """
        if not detection_results:
            return np.zeros(data_shape, dtype=int)

        anomaly_labels = np.zeros(data_shape, dtype=int)

        for result in detection_results:
            if not hasattr(result, 'metadata'):
                continue

            abnormal_ranks = result.metadata.get('abnormal_ranks', [])
            anomaly_time_ranges = list(result.metadata.get('anomaly_time_ranges', []))

            # Fallback: single rank_id from stream detectors (degradation_ksigma_robust, etc.)
            if not abnormal_ranks:
                rank_id = result.metadata.get('rank_id')
                if rank_id is not None:
                    abnormal_ranks = [rank_id]

            # Fallback: extract time range from anomaly_info.anomaly_details
            if not anomaly_time_ranges:
                anomaly_info = getattr(result, 'anomaly_info', None)
                if anomaly_info is not None:
                    details = getattr(anomaly_info, 'anomaly_details', None) or []
                    for detail in details:
                        # degradation detectors use 1-based index_counter
                        first_idx = detail.get('first_degradation_index') or detail.get('first_detection_index')
                        last_idx = detail.get('last_degradation_index') or detail.get('last_detection_index')
                        if first_idx is not None and last_idx is not None:
                            # Convert 1-based to 0-based array indices
                            anomaly_time_ranges.append({
                                'start': max(0, int(first_idx) - 1),
                                'end': max(0, int(last_idx) - 1),
                            })

            for rank_id in abnormal_ranks:
                for time_range in anomaly_time_ranges:
                    start = time_range.get('start', 0)
                    end = time_range.get('end', start)
                    for t in range(start, end + 1):
                        if 0 <= t < data_shape[0] and 0 <= rank_id < data_shape[1]:
                            anomaly_labels[t, rank_id] = 1

        return anomaly_labels

    def reset(self) -> None:
        """Reset all detectors."""
        for detector in self.detectors:
            detector.reset()

    def _get_anomaly_type_for_task(self, task_type: TaskType) -> Optional[AnomalyType]:
        """Map task type to the alert anomaly type exposed to users."""
        if task_type == TaskType.SLOW_CALC:
            return AnomalyType.CAL_SLOW
        if task_type == TaskType.SLOW_LAUNCH:
            return AnomalyType.LAUNCH_SLOW
        if task_type == TaskType.SLOW_COMM:
            return AnomalyType.COMM_SLOW
        if task_type == TaskType.DEGRADATION:
            return AnomalyType.FAIL_SLOW
        return None

    def _normalize_anomaly_types(
        self,
        detection_results: List[DetectionResult],
        task_type: TaskType,
    ) -> List[DetectionResult]:
        """Ensure reported anomalies use the task-specific user-facing type."""
        anomaly_type = self._get_anomaly_type_for_task(task_type)
        if anomaly_type is None:
            return detection_results

        for result in detection_results:
            result.anomaly_info.anomaly_type = anomaly_type

        return detection_results

    def _get_target_groups(
        self,
        hccl_domain: HCCLDomain,
        task_type: TaskType,
    ) -> List[List[int]]:
        """
        根据 HCCL 域和任务类型获取目标检测分组。

        优先级：tp_group > dp_group
        判断标准：分组配置存在且每个组的 size > 1（与 v1/v2 的 tp_size > 1 语义一致）
        对于 SLOW_COMM 任务：pp_group > tp_group > dp_group

        Args:
            hccl_domain: HCCL 通信域信息
            task_type: 任务类型

        Returns:
            目标分组列表，每个分组是一个 rank 列表
        """
        tp_groups = hccl_domain.tp_groups or []
        dp_groups = hccl_domain.dp_groups or []
        pp_groups = hccl_domain.pp_groups or []

        has_valid_tp = bool(tp_groups) and all(len(g) > 1 for g in tp_groups)
        has_valid_dp = bool(dp_groups) and all(len(g) > 1 for g in dp_groups)
        has_valid_pp = bool(pp_groups) and all(len(g) > 1 for g in pp_groups)

        if task_type == TaskType.SLOW_COMM:
            if has_valid_pp:
                logger.info("Using PP groups for SLOW_COMM task: %s", pp_groups)
                return pp_groups
            if has_valid_tp:
                logger.info("Using TP groups for SLOW_COMM task: %s", tp_groups)
                return tp_groups
            if has_valid_dp:
                logger.info("Using DP groups for SLOW_COMM task: %s", dp_groups)
                return dp_groups
            logger.info("No valid groups, using all ranks as one group")
            return [list(range(hccl_domain.world_size))]

        if has_valid_tp:
            logger.info("Using TP groups: %s", tp_groups)
            return tp_groups
        if has_valid_dp:
            logger.info("Using DP groups: %s", dp_groups)
            return dp_groups
        logger.info("No valid groups, using all ranks as one group")
        return [list(range(hccl_domain.world_size))]

    def _extract_group_data(
        self,
        detector_input: DetectorInput,
        group_ranks: List[int],
    ) -> Tuple[np.ndarray, List[int], List[str]]:
        """
        从检测输入中提取指定分组的数据。

        Args:
            detector_input: 检测输入
            group_ranks: 分组中的 rank 列表

        Returns:
            Tuple of (group_values, group_rank_ids, group_node_ips)
        """
        rank_indices = []
        group_rank_ids = []
        group_node_ips = []

        for rank in group_ranks:
            if rank in detector_input.rank_ids:
                idx = detector_input.rank_ids.index(rank)
                rank_indices.append(idx)
                group_rank_ids.append(rank)
                if idx < len(detector_input.node_ips):
                    group_node_ips.append(detector_input.node_ips[idx])

        if not rank_indices:
            return np.array([]), [], []

        group_values = detector_input.values[:, rank_indices]
        return group_values, group_rank_ids, group_node_ips

    def _detect_by_groups(
        self,
        detector_input: DetectorInput,
        task_type: TaskType,
        task_name: str,
    ) -> List[DetectionResult]:
        """
        按 HCCL 分组执行检测。

        Args:
            detector_input: 检测输入数据
            task_type: 任务类型
            task_name: 任务名称

        Returns:
            所有分组的检测结果列表
        """
        all_results = []

        if not self.enable_group_detection or detector_input.hccl_domain is None:
            return self._detect_globally(detector_input, task_name)

        target_groups = self._get_target_groups(
            detector_input.hccl_domain,
            task_type,
        )

        for group_ranks in target_groups:
            group_values, group_rank_ids, group_node_ips = self._extract_group_data(
                detector_input, group_ranks
            )

            if group_values.size == 0:
                logger.debug(f"Skipping empty group: {group_ranks}")
                continue

            logger.debug(f"Detecting group {group_ranks}: shape={group_values.shape}")

            results, _ = self.run_detect(group_values)

            group_results = self._convert_to_detection_results(
                results,
                DetectorInput(
                    values=group_values,
                    rank_ids=group_rank_ids,
                    node_ips=group_node_ips,
                    timestamps=detector_input.timestamps,
                ),
                task_name,
            )

            for result in group_results:
                result.metadata["group_ranks"] = group_ranks
                all_results.append(result)

        return all_results

    def _detect_globally(
        self,
        detector_input: DetectorInput,
        task_name: str,
    ) -> List[DetectionResult]:
        """
        执行全局检测（所有 rank 一起）。

        Args:
            detector_input: 检测输入数据
            task_name: 任务名称

        Returns:
            检测结果列表
        """
        results, _ = self.run_detect(detector_input.values)
        return self._convert_to_detection_results(results, detector_input, task_name)

    def _get_aggregated_rank_metadata(
        self,
        step_metrics_list: List[StepMetrics],
        num_ranks: int,
        metadata_preprocessor: Optional[IPreprocessor] = None,
    ) -> Tuple[List[int], List[str]]:
        if metadata_preprocessor is not None:
            get_rank_ids = getattr(metadata_preprocessor, "get_output_rank_ids", None)
            get_node_ips = getattr(metadata_preprocessor, "get_output_node_ips", None)
            if callable(get_rank_ids) and callable(get_node_ips):
                rank_ids = list(get_rank_ids())
                node_ips = list(get_node_ips())
                if len(rank_ids) == num_ranks and len(node_ips) == num_ranks:
                    return rank_ids, node_ips

        rank_to_node_ip = {}
        for step in step_metrics_list:
            if step.rank_id not in rank_to_node_ip:
                rank_to_node_ip[step.rank_id] = step.node_ip

        rank_ids = sorted(rank_to_node_ip)
        node_ips = [rank_to_node_ip[rank_id] for rank_id in rank_ids]
        return rank_ids, node_ips

    def _process_step(
        self,
        step_metrics_list: List[StepMetrics],
        task_type: TaskType,
        task_name: str,
    ) -> None:
        """
        Internal: Process a single step's data through the full pipeline.

        Handles:
        1. MetricExtractor: Extract metrics from StepMetrics
        2. Preprocessor: Aggregate/filter data
        3. Detector: Detect anomalies (with group detection if enabled)
        4. Reporter: Send alerts (via _report_anomalies)

        All processing done internally. No return value.
        """
        if self._data_sink is not None:
            self._data_sink.write(step_metrics_list)

        detector_input: Optional[DetectorInput] = None
        for extractor in self.metric_extractors:
            detector_input = extractor.extract(step_metrics_list)
            break

        if detector_input is None:
            return

        if detector_input.hccl_domain is None:
            if self.data_source is not None:
                detector_input.hccl_domain = getattr(
                    self.data_source, "hccl_domain", None
                )
            if detector_input.hccl_domain is None and self._hccl_domain is not None:
                detector_input.hccl_domain = self._hccl_domain

        if task_type in (TaskType.SLOW_CALC, TaskType.SLOW_LAUNCH, TaskType.SLOW_HOST, TaskType.DEGRADATION):
            aggregated_values = None
            metadata_preprocessor = None

            for preprocessor in self.preprocessors:
                result = preprocessor.process(step_metrics_list, task_type=task_type)
                if result is not None:
                    aggregated_values = result
                    if getattr(result, "ndim", 1) == 2:
                        metadata_preprocessor = preprocessor
                if hasattr(preprocessor, "get_target_op"):
                    target_op = preprocessor.get_target_op()
                    if target_op:
                        for subsequent in self.preprocessors:
                            if subsequent is not preprocessor and hasattr(
                                subsequent, "set_target_op"
                            ):
                                subsequent.set_target_op(target_op)

            for preprocessor in self.preprocessors:
                flushed = preprocessor.flush()
                if flushed is not None and len(flushed) > 0:
                    if aggregated_values is not None and aggregated_values.ndim == 2:
                        aggregated_values = np.concatenate(
                            [aggregated_values, flushed], axis=0
                        )
                        if metadata_preprocessor is None and getattr(flushed, "ndim", 1) == 2:
                            metadata_preprocessor = preprocessor
                    elif aggregated_values is not None and len(aggregated_values) > 0:
                        aggregated_values = np.concatenate([aggregated_values, flushed])
                    else:
                        aggregated_values = flushed
                        if getattr(flushed, "ndim", 1) == 2:
                            metadata_preprocessor = preprocessor

            if aggregated_values is not None:
                detector_input.values = aggregated_values

                if aggregated_values.ndim == 2:
                    rank_ids, node_ips = self._get_aggregated_rank_metadata(
                        step_metrics_list,
                        aggregated_values.shape[1],
                        metadata_preprocessor,
                    )
                    detector_input.rank_ids = rank_ids
                    detector_input.node_ips = node_ips

                for preprocessor in self.preprocessors:
                    if hasattr(preprocessor, "get_window_timestamps"):
                        detector_input.timestamps = preprocessor.get_window_timestamps()
                        break

        if detector_input.values is None or len(detector_input.values) == 0:
            logger.debug(
                "[%s] No data after aggregation, skipping detection", task_name
            )
            return

        detection_results = self._detect_by_groups(detector_input, task_type, task_name)
        detection_results = self._normalize_anomaly_types(detection_results, task_type)

        self._report_anomalies(detection_results)

    def _convert_to_detection_results(
        self,
        anomaly_labels: np.ndarray,
        detector_input: DetectorInput,
        task_name: str,
    ) -> List[DetectionResult]:
        """
        聚合模式：将所有异常 rank 聚合成一个 DetectionResult。
        """
        results = []
        if anomaly_labels is None or np.sum(anomaly_labels) == 0:
            return results

        time_len, num_ranks = anomaly_labels.shape
        timestamps = (
            detector_input.timestamps
            if detector_input.timestamps is not None
            else np.arange(time_len)
        )

        anomaly_time_ranges = []
        abnormal_rank_ids = []
        abnormal_node_ips = []

        first_anomaly_ts = None
        last_anomaly_ts = None

        for t in range(time_len):
            for rank_idx in range(num_ranks):
                if anomaly_labels[t, rank_idx] == 1:
                    rank_id = (
                        detector_input.rank_ids[rank_idx]
                        if rank_idx < len(detector_input.rank_ids)
                        else rank_idx
                    )
                    node_ip = (
                        detector_input.node_ips[rank_idx]
                        if rank_idx < len(detector_input.node_ips)
                        else "unknown"
                    )

                    if rank_id not in abnormal_rank_ids:
                        abnormal_rank_ids.append(rank_id)
                        abnormal_node_ips.append(node_ip)

                    anomaly_ts = timestamps[t] if t < len(timestamps) else t
                    if first_anomaly_ts is None:
                        first_anomaly_ts = anomaly_ts
                    last_anomaly_ts = anomaly_ts

        if abnormal_rank_ids:
            if first_anomaly_ts is not None and last_anomaly_ts is not None:
                anomaly_time_ranges.append(
                    {
                        "start": int(first_anomaly_ts),
                        "end": int(last_anomaly_ts),
                    }
                )

            anomaly_info = AnomalyInfo(
                is_anomaly=True,
                anomaly_type=AnomalyType.FAIL_SLOW,
                anomaly_count=len(abnormal_rank_ids),
                start_time=int(first_anomaly_ts) if first_anomaly_ts else 0,
                end_time=int(last_anomaly_ts) if last_anomaly_ts else 0,
            )

            result = DetectionResult(
                detector_name=task_name,
                anomaly_info=anomaly_info,
                metadata={
                    "abnormal_ranks": abnormal_rank_ids,
                    "abnormal_ips": abnormal_node_ips,
                    "anomaly_time_ranges": anomaly_time_ranges,
                    "detect_type": "SPACE",
                },
            )
            results.append(result)

        return results

    def _report_anomalies(self, detection_results: List[DetectionResult]) -> None:
        """
        Send alerts via all configured reporters.

        Args:
            detection_results: List of detection results to report
        """
        if not detection_results:
            logger.info("No anomalies detected.")
            return
        for reporter in self.reporters:
            if not reporter.is_available():
                logger.warning("Reporter %s is not available, skipping", reporter.name)
                continue

            for result in detection_results:
                try:
                    alert = reporter.convert_to_alert(result)
                    success = reporter.report(alert)
                    if success:
                        logger.info(
                            "Alert sent via %s for ranks %s",
                            reporter.name,
                            result.metadata.get("abnormal_ranks"),
                        )
                    else:
                        logger.warning("Failed to send alert via %s", reporter.name)
                except Exception as e:
                    logger.error("Error reporting via %s: %s", reporter.name, e)

    def run_offline(self, task_type: TaskType, task_name: str) -> List[DetectionResult]:
        """
        Execute detection pipeline in offline mode.

        Reads all data from configured data_source, processes it in one batch,
        and returns all detection results.

        Args:
            task_type: Type of detection task
            task_name: Name of the task for logging

        Returns:
            List of all DetectionResult from the pipeline run

        Raises:
            RuntimeError: If no data_source is configured
        """
        if self.data_source is None:
            raise RuntimeError(
                "No data_source configured. Use online mode with external data."
            )

        logger.info("Detection pipeline started (offline mode).")
        self.data_source.connect()
        all_results: List[DetectionResult] = []

        try:
            all_steps: List[StepMetrics] = []
            for step_metrics in self.data_source.read():
                all_steps.append(step_metrics)

            if all_steps:
                self._process_step(
                    all_steps,
                    task_type=task_type,
                    task_name=task_name,
                )

        finally:
            self.data_source.disconnect()
            logger.info("Detection pipeline finished.")

        return all_results
