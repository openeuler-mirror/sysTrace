"""
Task module - top-level interface for external clients.

External clients interact with Task, not DetectionPipeline directly.
Task encapsulates a DetectionPipeline and provides a unified interface.

Reference: failslow/failslow/task/custom_v1/custom_v1.py
"""
import json
import logging
import os
import queue
import threading
import time
from typing import List

from ..domain.models import DetectionResult, StepMetrics, TaskType
from ..application.pipeline import DetectionPipeline
from ..infrastructure.framework.registration import (
    ComponentFactory,
    DataSourceRegistry,
    PreprocessorRegistry,
    DetectorRegistry,
    ReporterRegistry,
    MetricExtractorRegistry,
    DataSinkRegistry,
)
from ..infrastructure.framework.configuration import ConfigLoader
from ..infrastructure.schemas.root import FailSlowConfig

logger = logging.getLogger(__name__)


class ITask:
    """Task interface - top level interface for external clients."""

    @property
    def name(self) -> str:
        raise NotImplementedError()

    def on_recv_single_step(self, step_metrics: StepMetrics) -> None:
        raise NotImplementedError()

    def on_recv_all_step(self, step_metrics_list: List[StepMetrics]) -> None:
        raise NotImplementedError()

    def reset(self) -> None:
        raise NotImplementedError()


class Task(ITask):
    """
    Task implementation that encapsulates a DetectionPipeline.

    External clients only need to provide config path.
    All internal components (pipeline, task_name, task_type) are built from config.

    Reference: failslow/failslow/task/custom_v1/custom_v1.py
    """

    def __init__(self, config_path: str = None):
        if not config_path:
            config_path = self._default_config_path()

        self._config_path = config_path
        self._config = self._load_config(config_path)

        task_config = self._config.tasks[0]
        self._task_name = task_config.task_name
        self._task_type = TaskType(task_config.task_type)
        self._enable_group_detection = task_config.enable_group_detection
        self._detect_interval_seconds = task_config.detect_interval_seconds

        self._pipeline = self._create_pipeline()

        self._last_detect_time = 0.0
        self._step_cache: List[StepMetrics] = []

        self._data_queue = queue.Queue()
        self._running = True
        self._processor_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._processor_thread.start()
        logger.info(
            "[%s] Task initialized (async_mode, detect_interval=%.1fs)",
            self._task_name,
            self._detect_interval_seconds,
        )

    def _default_config_path(self) -> str:
        """Get default config path."""
        return os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "..",
            "config",
            "config.v3.json",
        )

    def _load_config(self, config_path: str) -> FailSlowConfig:
        """Load and parse configuration from file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")

        try:
            with open(config_path, "r") as f:
                config_data = json.load(f)

            source_factory = ComponentFactory(DataSourceRegistry)
            preprocessor_factory = ComponentFactory(PreprocessorRegistry)
            detector_factory = ComponentFactory(DetectorRegistry)
            reporter_factory = ComponentFactory(ReporterRegistry)
            metric_extractor_factory = ComponentFactory(MetricExtractorRegistry)
            data_sink_factory = ComponentFactory(DataSinkRegistry)

            config_loader = ConfigLoader(
                source_factory=source_factory,
                preprocessor_factory=preprocessor_factory,
                detector_factory=detector_factory,
                reporter_factory=reporter_factory,
                metric_extractor_factory=metric_extractor_factory,
                data_sink_factory=data_sink_factory,
            )

            return config_loader.load_from_dict(config_data)

        except (json.JSONDecodeError, Exception) as e:
            raise RuntimeError(f"Failed to load config from {config_path}: {e}")

    def _create_pipeline(self) -> DetectionPipeline:
        """Create DetectionPipeline from config."""
        task_config = self._config.tasks[0]

        hccl_domain = None
        hccl_restore = getattr(task_config, 'hccl_restore', None)
        if hccl_restore and hccl_restore.enabled:
            from failslow.domain.models import HCCLDomain
            all_ranks = set()
            for g in (hccl_restore.tp_groups or []):
                all_ranks.update(g)
            for g in (hccl_restore.dp_groups or []):
                all_ranks.update(g)
            for g in (hccl_restore.pp_groups or []):
                all_ranks.update(g)
            hccl_domain = HCCLDomain(
                tp_groups=hccl_restore.tp_groups or [],
                dp_groups=hccl_restore.dp_groups or [],
                pp_groups=hccl_restore.pp_groups or [],
                world_size=len(all_ranks) if all_ranks else 0,
            )
            logger.info(
                "[%s] hccl_domain loaded: tp_groups=%s, dp_groups=%s, pp_groups=%s, world_size=%d",
                self._task_name,
                hccl_domain.tp_groups,
                hccl_domain.dp_groups,
                hccl_domain.pp_groups,
                hccl_domain.world_size,
            )

        data_sink = getattr(task_config, 'data_sink', None)

        pipeline = DetectionPipeline(
            data_source=None,
            preprocessors=task_config.preprocessors,
            detectors=task_config.detectors,
            reporters=task_config.alert_reporters,
            metric_extractors=task_config.metric_extractors,
            enable_group_detection=self._enable_group_detection,
            task_type=self._task_type,
            hccl_domain=hccl_domain,
            data_sink=data_sink,
        )

        return pipeline

    @property
    def name(self) -> str:
        return self._task_name

    @property
    def task_type(self) -> TaskType:
        return self._task_type

    def on_recv_single_step(self, step_metrics: StepMetrics) -> None:
        """
        Receive single step metrics from one rank.

        Note: This method is deprecated. Use on_recv_all_step instead.
        """
        pass

    def on_recv_all_step(self, step_metrics_list: List[StepMetrics]) -> None:
        """
        Online mode entry point.

        Puts data into queue and returns immediately (non-blocking).
        Detection is executed asynchronously in background thread.
        """
        self._data_queue.put(step_metrics_list)

    def _process_loop(self) -> None:
        """Background processing loop for async mode."""
        step_cache: List[StepMetrics] = []

        while self._running:
            current_time = time.time()
            try:
                step_metrics_list = self._data_queue.get(timeout=0.1)
                step_cache.extend(step_metrics_list)

                if self._detect_interval_seconds <= 0:
                    if step_cache:
                        self._do_detection(step_cache)
                        step_cache = []
                elif current_time - self._last_detect_time >= self._detect_interval_seconds:
                    self._do_detection(step_cache)
                    self._last_detect_time = current_time
                    step_cache = []

            except queue.Empty:
                if step_cache and self._detect_interval_seconds <= 0:
                    self._do_detection(step_cache)
                    step_cache = []
                elif current_time - self._last_detect_time >= self._detect_interval_seconds:
                    self._do_detection(step_cache)
                    self._last_detect_time = current_time
                    step_cache = []
                continue

    def _do_detection(self, step_cache: List[StepMetrics]) -> None:
        """Execute detection with given data."""
        if not step_cache:
            return

        detection_steps = self._prepare_detection_steps(step_cache)
        self._reset_pipeline_for_degradation_replay()

        queue_size = self._data_queue.qsize()
        num_windows_before = self._get_accumulated_windows_count()

        logger.info(
            "[%s] Executing detection: queue_size=%d, cached_steps=%d, num_windows_before=%d",
            self._task_name,
            queue_size,
            len(step_cache),
            num_windows_before,
        )

        self._pipeline._process_step(
            detection_steps,
            task_type=self._task_type,
            task_name=self._task_name,
        )

        num_windows_after = self._get_accumulated_windows_count()
        logger.info(
            "[%s] Detection complete: num_windows_after=%d (added %d windows)",
            self._task_name,
            num_windows_after,
            num_windows_after - num_windows_before,
        )

    def _prepare_detection_steps(
        self, step_cache: List[StepMetrics]
    ) -> List[StepMetrics]:
        """Build the batch to process for the current detection cycle."""
        if self._task_type != TaskType.DEGRADATION:
            return step_cache

        self._step_cache.extend(step_cache)
        return list(self._step_cache)

    def _reset_pipeline_for_degradation_replay(self) -> None:
        """Rebuild degradation pipeline state from accumulated history each cycle."""
        if self._task_type != TaskType.DEGRADATION:
            return

        for preprocessor in self._pipeline.preprocessors:
            if hasattr(preprocessor, "reset"):
                preprocessor.reset()

        for detector in self._pipeline.detectors:
            detector.reset()

    def _get_accumulated_windows_count(self) -> int:
        """Get the number of accumulated windows from preprocessors."""
        for preprocessor in self._pipeline.preprocessors:
            if hasattr(preprocessor, '_accumulated_windows'):
                return len(preprocessor._accumulated_windows)
        return 0

    def shutdown(self) -> None:
        """Gracefully shutdown the async processor thread."""
        logger.info("[%s] Shutting down async processor...", self._task_name)
        self._running = False
        if hasattr(self, '_processor_thread'):
            self._processor_thread.join(timeout=5.0)
        if self._pipeline._data_sink is not None:
            self._pipeline._data_sink.close()
        logger.info("[%s] Async processor shutdown complete", self._task_name)

    def reset(self) -> None:
        """Reset task state."""
        self._pipeline.reset()
        self._last_detect_time = 0.0
        self._step_cache = []
        while not self._data_queue.empty():
            try:
                self._data_queue.get_nowait()
            except queue.Empty:
                break
