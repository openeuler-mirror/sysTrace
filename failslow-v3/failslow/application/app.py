"""
Defines the main Application service that orchestrates the detection tasks.
"""
import logging
from typing import List

from ..infrastructure.schemas.root import FailSlowConfig
from ..task.task_factory import TaskFactory
from ..domain.models import TaskType, HCCLDomain
from .pipeline import DetectionPipeline

logger = logging.getLogger(__name__)


class Application:
    """
    The main application service.

    It takes a fully hydrated configuration object, builds a detection pipeline
    for each task defined in it, and then runs them.

    Supports two modes:
    - Offline mode: data_source is configured, pipeline.run_offline() reads data and processes it
    - Online mode: data_source is None, external clients call Task.on_recv_all_step()
    """

    def __init__(self, config: FailSlowConfig):
        self._config = config
        self._pipelines: List[DetectionPipeline] = []

    def start(self):
        """
        Initializes all pipelines and runs offline mode tasks.
        Online mode tasks are left ready for external clients to call.
        """
        logger.info("Starting FailSlow application")
        if not self._config.tasks:
            logger.warning("No tasks configured. Application will exit.")
            return

        for task_config in self._config.tasks:
            logger.info(f"Setting up task: '{task_config.task_name}'")
            try:
                hccl_domain = None
                hccl_restore = getattr(task_config, 'hccl_restore', None)
                if hccl_restore and hccl_restore.enabled:
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
                        "hccl_domain loaded: tp_groups=%s, dp_groups=%s, pp_groups=%s, world_size=%d",
                        hccl_domain.tp_groups,
                        hccl_domain.dp_groups,
                        hccl_domain.pp_groups,
                        hccl_domain.world_size,
                    )

                if task_config.data_source is not None:
                    pipeline = DetectionPipeline(
                        data_source=task_config.data_source,
                        preprocessors=task_config.preprocessors,
                        detectors=task_config.detectors,
                        reporters=task_config.alert_reporters,
                        metric_extractors=task_config.metric_extractors,
                        enable_group_detection=getattr(task_config, 'enable_group_detection', False),
                        task_type=TaskType(task_config.task_type),
                        hccl_domain=hccl_domain,
                    )
                    self._pipelines.append(pipeline)

                    logger.info(f"Running offline mode for task: '{task_config.task_name}'")
                    pipeline.run_offline(
                        task_type=TaskType(task_config.task_type),
                        task_name=task_config.task_name,
                    )
                else:
                    task = TaskFactory.create(self._config.config_path)
                    logger.info(f"Task ready for online mode: '{task_config.task_name}'")

            except Exception as e:
                logger.error(f"Failed to create pipeline for task '{task_config.task_name}': {e}", exc_info=True)

        logger.info("All tasks completed. Shutting down.")

    def get_task(self, task_name: str):
        """Get a task by name for online mode access."""
        return TaskFactory.get(task_name)
