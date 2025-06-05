# coding=utf-8

from sklearn.cluster import DBSCAN
from .sliding_window_dbscan import SlidingWindowDBSCAN
from .outlier_data_detector import OuterDataDetector

space_node_detectors = {
    "OuterDataDetector": OuterDataDetector,
    "SlidingWindowDBSCAN": SlidingWindowDBSCAN,
}
