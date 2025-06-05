# coding=utf-8

from .sliding_window_n_sigma_detector import SlidingWindowKSigmaDetector
from .ts_dbscan_detector import TSDBSCANDetector

time_node_detectors = {
    "TSDBSCANDetector": TSDBSCANDetector,
    "SlidingWindowKSigmaDetector": SlidingWindowKSigmaDetector
}
