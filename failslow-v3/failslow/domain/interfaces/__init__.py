"""Domain interfaces."""
from .detector import (
    IDetector,
    IStreamDetector,
    IBatchDetector,
    IStatefulDetector,
    IStepMetricsStreamDetector,
)
from .metric_extractor import IMetricExtractor
from .preprocessor import IPreprocessor
from .reporter import IAlertReporter
from .data_source import IDataSource
from .data_sink import IDataSink

__all__ = [
    "IDetector",
    "IStreamDetector",
    "IBatchDetector",
    "IStatefulDetector",
    "IStepMetricsStreamDetector",
    "IMetricExtractor",
    "IPreprocessor",
    "IAlertReporter",
    "IDataSource",
    "IDataSink",
]
