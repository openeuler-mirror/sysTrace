# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：linear_detector.py
Create Date: 2024/8/1 15:06
Notes:
"""
import numpy as np
from collections import Counter
from sklearn.cluster import DBSCAN
from sklearn.linear_model import LinearRegression
from typing import List

from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


class LinearDetector():
    def __init__(self, cfg=None):
        self.detector = None
        self.thr = cfg.get("linear_detector_thr", 0.1)

    def min_max_processing(self, ts_data):
        if np.min(ts_data) == np.max(ts_data):
            ret = ts_data - np.min(ts_data)
            return ret

        ret = (ts_data - np.min(ts_data)) / (np.max(ts_data) - np.min(ts_data) + 1e-5)
        return ret

    def filter_outlier(self, x: np.ndarray, raw_data: np.ndarray) -> List[np.ndarray]:
        eps = 0.01
        sample = 5
        dbscan = DBSCAN(eps=eps, min_samples=sample)

        raw_data = raw_data.reshape(-1, 1)
        dbscan.fit(raw_data)
        predictions = dbscan.fit_predict(raw_data)
        cluster_counts = Counter(predictions)
        most_common_cluster = cluster_counts.most_common(1)[0][0]
        processed_clusters = np.where(predictions == most_common_cluster, True, False)

        filtered_data = raw_data.flatten()[processed_clusters]
        x = x[processed_clusters]

        return [x, filtered_data]

    def fit(self, data: np.ndarray):
        pre_data = self.min_max_processing(data)
        x = np.arange(pre_data.size)

        x, filtered_data = self.filter_outlier(x, pre_data)
        x = self.min_max_processing(x)
        filtered_data = self.min_max_processing(filtered_data)

        logger.info(f"linear input {x.shape} and output {filtered_data.shape}.")
        x = x.reshape(-1, 1)
        filtered_data = filtered_data.reshape(-1, 1)

        model = LinearRegression()
        model.fit(x, filtered_data)
        weight = model.coef_.flatten()[0]
        bias = model.intercept_[0]
        logger.info(f"linear model y=ax+b, weight: {weight}, bias:{bias}.")

        self.detector = {"weight": weight, "bias": bias}

    def get_anomaly_info(self, rank: int) -> dict:
        anomaly_info = {
            "rank": rank,
            "linear_weight": self.detector.get("weight", None),
            "linear_detector_threshold": self.thr
        }
        anomaly_info[
            "rule"] = f"if linear_weight:{anomaly_info.get('linear_weight')} is larger than linear_detector_threshold: {anomaly_info.get('linear_detector_threshold')}, time series is anomaly, else is normal."
        return anomaly_info

    def detect(self):
        weight = self.detector.get("weight", None)
        if weight and weight > self.thr:
            logger.info(f"linear weight: {weight}, status is anomaly.")
            return True
        else:
            logger.info(f"linear weight: {weight}, status is normal.")
            return False


def main():
    data = np.ones(360) * 1650
    data[200:250] -= 800
    data[100:150] += 400

    data2 = np.arange(360) * 1650
    data2[200:250] -= 800

    noise = np.random.rand(360) * 180
    data2 = data2 + noise

    detector = LinearDetector(cfg={})
    detector.fit(data)
    detector.detect()


if __name__ == "__main__":
    main()
