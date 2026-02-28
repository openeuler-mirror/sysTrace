# coding=utf-8

from sklearn.cluster import DBSCAN
from .sliding_window_dbscan import SlidingWindowDBSCAN
from .outlier_data_detector import OuterDataDetector
from .sliding_window_ksigma import SlidingWindowKSigma

space_node_detectors = {
    "OuterDataDetector": OuterDataDetector,
    "SlidingWindowDBSCAN": SlidingWindowDBSCAN,
    "SlidingWindowKSigma": SlidingWindowKSigma
}
