"""
This file ensures that all component modules are imported, which allows them
to be automatically registered in their respective registries via the
ComponentRegistryMeta metaclass.
"""

# Import all known components here
from .sources.degradation_step_csv.source import DegradationStepCsvDataSource
from .sources.local_csv.source import LocalCsvDataSource
from .detectors.bocpd.detector import BocpdDetector
from .detectors.sliding_window_ksigma.detector import SlidingWindowKSigmaDetector
from .reporters.console.reporter import ConsoleAlertReporter
from .preprocessors.time_window_aggregator.preprocessor import TimeWindowAggregatorPreprocessor
from .preprocessors.op_name_filter.preprocessor import OpNameFilterPreprocessor
from .reporters.file.reporter import FileAlertReporter
from .metric_extractors.slow_calc_extractor import SlowCalcMetricExtractor
from .metric_extractors.slow_launch_extractor import SlowLaunchMetricExtractor
from .metric_extractors.degradation_extractor import DegradationMetricExtractor
from .sinks.local_csv.sink import LocalCsvDataSink
from .detectors.degradation_ksigma_naive.detector import DegradationKSigmaNaiveDetector
from .detectors.degradation_ksigma_robust.detector import DegradationKSigmaRobustDetector
from .detectors.degradation_bocpd.detector import DegradationBocpdDetector
