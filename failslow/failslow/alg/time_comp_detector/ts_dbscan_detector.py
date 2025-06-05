import numpy as np

from .time_alg.ts_dbscan import TSDBSCAN


class TSDBSCANDetector:
    def __init__(self, metric_names, cfg):
        self.detectors = {}
        self.metric_names = metric_names

        self.k_thr = cfg.get("k_thr", 0.02)
        self.smooth_win = cfg.get("smooth_win", 4)
        self.cfg = cfg

    def check_smooth(self, infer_data):
        data_size = len(infer_data)
        if data_size < self.smooth_win:
            smooth_win = data_size // 2
        else:
            smooth_win = self.smooth_win

        return smooth_win

    def fit(self, normal_datas):
        for node_id, normal_data in normal_datas.items():
            node_detector = {}
            for metric_name in self.metric_names:
                ts_dbscan_detector = TSDBSCAN(cfg=self.cfg)
                node_detector[metric_name] = {"detector": ts_dbscan_detector}

            self.detectors[node_id] = node_detector

    def predict(self, infer_datas):
        anomaly_nodes_info = {}
        anomaly_nodes_location = {}
        locations = {}
        for node_id, infer_data in infer_datas.items():
            locations[node_id] = {}
            node_detector = self.detectors[node_id]

            for metric_name in self.metric_names:
                detector_info = node_detector.get(metric_name, {})
                if not detector_info:
                    continue

                detector = detector_info["detector"]
                # 数据平滑
                smooth_win = self.check_smooth(infer_data)
                infer_metric_data = infer_data[metric_name].rolling(window=smooth_win).mean().bfill().ffill().values
                detect_result = detector.detect(infer_metric_data)
                locations[node_id][metric_name] = detect_result
                anomlay_sum = np.sum(detect_result)

                if anomlay_sum > len(infer_metric_data) * self.k_thr:
                    anomaly_nodes_info.setdefault(node_id, []).append(metric_name)
                    anomaly_nodes_location.setdefault(node_id, []).append(detect_result)

        valid_metrics = []
        anomaly_nodes = []

        # 返回时间有异常的节点和
        for anomaly_node, metircs_list in anomaly_nodes_info.items():
            valid_metrics += metircs_list
            anomaly_nodes.append(anomaly_node)

        return anomaly_nodes, valid_metrics, locations
