from collections import Counter

import numpy as np
from sklearn.cluster import DBSCAN


class TSDBSCAN:
    def __init__(self, cfg):
        self.eps = cfg.get("eps", 0.03)
        self.min_samples = cfg.get("min_samples", 5)
        self.detect_type = cfg.get("detect_type", "bi_bound")

    def detect(self, ts_data):
        ts_data = self.min_max_processing(ts_data)
        clf = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        # Reshape data to be compatible with sklearn's input format
        ts_data_reshaped = ts_data.reshape(-1, 1)
        # 训练模型
        clf.fit(ts_data_reshaped)

        # 预测数据点的标签，1表示异常，-1表示正常，这里我们需要转换为0和1
        predictions = clf.fit_predict(ts_data_reshaped)
        cluster_counts = Counter(predictions)

        # 找出数量最多的类别
        most_common_cluster = cluster_counts.most_common(1)[0][0]

        # 重标记：数量最多的类别为0，其他类别及-1（噪声）为1
        processed_clusters = np.where(predictions == most_common_cluster, 0, 1)

        if self.detect_type == "bi_bound":
            return processed_clusters

        normal_data_avg = np.mean(ts_data[np.where(processed_clusters == 0)])

        if self.detect_type == "upper_bound":
            for i in np.where(processed_clusters == 1)[0]:
                if ts_data[i] < normal_data_avg:
                    processed_clusters[i] = 0
        elif self.detect_type == "lower_bound":
            for i in np.where(processed_clusters == 1)[0]:
                if ts_data[i] > normal_data_avg:
                    processed_clusters[i] = 0

        return processed_clusters

    @staticmethod
    def min_max_processing(ts_data):
        if np.min(ts_data) == np.max(ts_data):
            ret = ts_data - np.min(ts_data)
            return ret

        ret = (ts_data - np.min(ts_data)) / (np.max(ts_data) - np.min(ts_data) + 1e-5)
        return ret


if __name__ == "__main__":
    data = np.ones(360) * 1650
    data[200:250] -= 800

    data[100:150] += 400

    cfg_test = {"eps": 0.03,
           "min_samples": 5,
           "smooth_win": 4,
           "k_thr": 0.02,
           "detect_type": "upper_bound"}

    detector = TSDBSCAN(cfg_test)

    label = detector.detect(data)
