"""
Configuration loading and validation service.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from ..schemas.root import FailSlowConfig, TaskConfig
from .registration import ComponentFactory

logger = logging.getLogger(__name__)


class ConfigLoader:
    """
    Loads, validates, and builds the full application configuration from a file.
    It dynamically instantiates all necessary components (sources, detectors, etc.)
    using their respective factories.
    """

    def __init__(
        self,
        source_factory: ComponentFactory,
        preprocessor_factory: ComponentFactory,
        detector_factory: ComponentFactory,
        reporter_factory: ComponentFactory,
        metric_extractor_factory: ComponentFactory,
        data_sink_factory: ComponentFactory = None,
    ):
        self._source_factory = source_factory
        self._preprocessor_factory = preprocessor_factory
        self._detector_factory = detector_factory
        self._reporter_factory = reporter_factory
        self._metric_extractor_factory = metric_extractor_factory
        self._data_sink_factory = data_sink_factory

    def load_from_file(self, config_path: Path) -> FailSlowConfig:
        """
        Loads a JSON configuration file, validates it against Pydantic schemas,
        and instantiates all components.
        """
        logger.info(f"Loading configuration from: {config_path}")
        if not config_path.is_file():
            raise FileNotFoundError(f"Configuration file not found at {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}") from e

        config_data['_config_path'] = str(config_path)
        return self.load_from_dict(config_data)

    def load_from_dict(self, config_data: Dict[str, Any]) -> FailSlowConfig:
        """
        Loads configuration from a dictionary, validates it against Pydantic schemas,
        and instantiates all components.
        """
        config_path = config_data.get('_config_path')
        fs_config = FailSlowConfig(**config_data)
        fs_config.config_path = config_path

        hydrated_tasks = []
        for task_config in fs_config.tasks:
            hydrated_tasks.append(self._hydrate_task(task_config))

        fs_config.tasks = hydrated_tasks
        logger.info("Configuration loaded and all components instantiated successfully.")
        return fs_config

    def _hydrate_task(self, task_config: TaskConfig) -> TaskConfig:
        """Instantiates the components for a single task."""
        if task_config.data_source is not None:
            task_config.data_source = self._source_factory.create(
                task_config.data_source.type,
                **task_config.data_source.params.dict()
            )

        task_config.metric_extractors = [
            self._metric_extractor_factory.create(m.type)
            for m in task_config.metric_extractors if m.enabled
        ]

        task_config.preprocessors = [
            self._preprocessor_factory.create(p.type, **p.params.dict())
            for p in task_config.preprocessors if p.enabled
        ]

        task_config.detectors = [
            self._create_detector_recursive(d.dict())
            for d in task_config.detectors if d.enabled
        ]

        task_config.alert_reporters = [
            self._reporter_factory.create(r.type, **r.params.dict())
            for r in task_config.alert_reporters if r.enabled
        ]

        if task_config.data_sink is not None and task_config.data_sink.enabled:
            if self._data_sink_factory is not None:
                task_config.data_sink = self._data_sink_factory.create(
                    task_config.data_sink.type,
                    **task_config.data_sink.params.dict(),
                )
            else:
                logger.warning("data_sink configured but no data_sink_factory provided")
        elif task_config.data_sink is not None and not task_config.data_sink.enabled:
            task_config.data_sink = None
        
        return task_config

    def _create_detector_recursive(self, detector_config: Dict[str, Any]) -> Any:
        """
        Recursively create a detector, handling nested detectors for CompositeDetector.
        
        Args:
            detector_config: Dictionary with 'type' and 'params' keys
            
        Returns:
            Instantiated detector component
        """
        detector_type = detector_config.get("type")
        params = detector_config.get("params", {})
        
        if detector_type == "composite":
            return self._create_composite_detector(params)
        else:
            return self._detector_factory.create(detector_type, **params)

    def _create_composite_detector(self, params: Dict[str, Any]) -> Any:
        """
        Create a CompositeDetector with nested time and space detectors.
        
        Args:
            params: CompositeDetectorParams as a dictionary
            
        Returns:
            CompositeDetector instance
        """
        time_detector = None
        space_detector = None
        
        time_detector_config = params.get("time_detector")
        if time_detector_config:
            time_detector = self._create_detector_recursive(time_detector_config)
        
        space_detector_config = params.get("space_detector")
        if space_detector_config:
            space_detector = self._create_detector_recursive(space_detector_config)
        
        return self._detector_factory.create(
            "composite",
            time_detector=time_detector,
            space_detector=space_detector,
            **{k: v for k, v in params.items() if k not in ("time_detector", "space_detector")}
        )
