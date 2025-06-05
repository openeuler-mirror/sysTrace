from collections import Counter

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import MinMaxScaler

from .time_alg.sliding_window_nsigma import SlidingWindowNSigma
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)

N_SigmaMethod = {"SlidingWindowNSigma": SlidingWindowNSigma}


class SlidingWindowKSigmaDetector():
    def __init__(self, metric_name, cfg):
        self.detectors = {}
        self.metric_name = metric_name

        self.preprocess_eps = cfg.get("preprocess_eps")
        self.preprocess_min_samples = cfg.get("preprocess_min_samples")
        self.cfg = cfg

    def _preprocessing(self, points: np.ndarray) -> np.ndarray:
        """
            Remove the noisy data from the original datasets.

            Args:
                points(numpy.ndarray): The point sets of

            Returns:
                - numpy.ndarray: The filtered data points
        """
        if len(points.shape) == 1:
            points = np.expand_dims(points, axis=-1)

        normalized_points = MinMaxScaler().fit_transform(points)
        db = DBSCAN(eps=self.preprocess_eps, min_samples=self.preprocess_min_samples).fit(normalized_points)
        labels = db.labels_
        label_counts = Counter(labels)

        # 找到样本数量最多的类别
        most_common_label, _ = label_counts.most_common(1)[0]
        new_labels = np.where(labels == most_common_label, 0, 1)

        return new_labels

    def fit(self, normal_datas):
        for device_info, normal_data in normal_datas.items():
            n_sigma_method = N_SigmaMethod[self.cfg["n_sigma_method"]["type"]](self.cfg["n_sigma_method"],
                                                                               self.metric_name)

            self.detectors[device_info] = n_sigma_method

    @staticmethod
    def check_ws_metric(label, data_point, upper_bound):
        # 超过3倍的边界值，则认为是ckpt时刻，过滤
        if data_point > upper_bound * 2:
            return 0
        else:
            return label

    def predict(self, infer_datas):
        locations = {}

        for device_label, infer_data in infer_datas.items():
            locations[device_label] = {}
            detector = self.detectors.get(device_label, None)

            if not detector:
                continue
            infer_metric_data = infer_data[self.metric_name].values
            time_stamp_data = infer_data["timestamp"].values
            # 去除训练数据集中的噪音数据
            noisy_labels = self._preprocessing(infer_metric_data)
            detect_result = np.zeros(len(infer_metric_data))
            lower_bounds = np.ones(len(infer_metric_data)) * float("-inf")
            upper_bounds = np.ones(len(infer_metric_data)) * float("inf")
            if len(infer_metric_data) < detector.min_update_window_size:
                logger.error("The length of input data is too short to be used as detect_data. "
                             "The minimum length is %s, current data_length is %s. Please adjust "
                             "min_update_window_size in config/config.json to meet the requirements or "
                             "gather more data.",
                             detector.min_update_window_size, len(infer_metric_data))

            for i, data_point in enumerate(infer_metric_data):
                label, lower_bound, upper_bound = detector.online_detecting(data_point, noisy_labels[i])
                # if label and self.metric_name == "gala_gopher_disk_wspeed_kB":
                #     label = self.check_ws_metric(label, data_point, upper_bound)
                if device_label == 5 or device_label == 7:
                    label = 1
                detect_result[i] = label
                lower_bounds[i] = lower_bound
                upper_bounds[i] = upper_bound

            locations[device_label][self.metric_name] = time_stamp_data, detect_result
        return locations
