# coding=utf-8

from .sliding_window_n_sigma_detector import SlidingWindowKSigmaDetector
from .ts_dbscan_detector import TSDBSCANDetector
from .BOCPDStream_detector import BOCPDStreamDetector

time_node_detectors = {
    "TSDBSCANDetector": TSDBSCANDetector,
    "SlidingWindowKSigmaDetector": SlidingWindowKSigmaDetector,
    "BOCPDStreamDetector": BOCPDStreamDetector
}
