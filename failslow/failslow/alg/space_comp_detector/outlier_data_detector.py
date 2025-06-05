import numpy as np
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


def one_hot_encode(labels, num_classes):
    """
    将整数标签转换为one-hot编码的向量。

    参数:
    labels -- 标签数组，形状为 (n_samples,)
    num_classes -- 类别的总数

    返回:
    one_hot -- one-hot编码的数组，形状为 (n_samples, num_classes)
    """
    # 初始化一个形状为 [n_samples, num_classes] 的零数组
    one_hot = np.zeros((labels.size, num_classes), dtype=np.bool_)
    # 将对应标签的位置设为1
    one_hot[np.arange(labels.size), labels] = True
    return one_hot


EPS = 1e-8
LABEL_DICT = {}


class OuterDataDetector():
    def __init__(self, cfg):
        # 不同数据中，从小到大排列，最大间距占所有间距的比例
        self.first_gap_rate = cfg.get("first_gap_rate")
        # 不同数据中，从大到小排列，第二个间距达到第一个间距的某个比例,视为有效的间距
        self.second_gap_rate = cfg.get("second_gap_rate")
        # 一组数据所有值小于某个值时集体不捡
        self.base_threshold = cfg.get("base_threshold")
        # 判断为异常的一组数据与判断为正常的一组数据相比,均值较大的需要超过均值较小的若干倍率,视为异常的一组才被认为时异常.
        self.discrete_rate = cfg.get("discrete_rate")
        # 判断为异常的一组数据与判断为正常的一组数据相比, 判断为异常值的一组数据需要在判断为正常值的(mean-n*std, mean+n*std)区间外
        self.nsigma_coefficient = cfg.get("nsigma_coefficient")
        # 离散的的点占总的点的数量小于此比例时不报告警
        self.discrete_point_suppression_ratio = cfg.get("discrete_point_suppression_ratio")
        # 其他类别异常点数量不超过所有异常点数量时
        self.non_major_anomaly_suppression = cfg.get("non_major_anomaly_suppression")
        self.args = (self.first_gap_rate, self.second_gap_rate, self.discrete_rate, self.nsigma_coefficient)

    def detect(self, test_data: np.ndarray):
        global LABEL_DICT
        labels = np.zeros_like(test_data)
        un_detected_data = set()
        un_detected_data_indexes = []
        for index, single_data in enumerate(test_data.tolist()):
            if np.any(np.array(single_data) > self.base_threshold):
                sorted_data = sorted(single_data)
                abnormal_values = LABEL_DICT.get((tuple(sorted_data), self.args), [])
                for single_abnormal in abnormal_values:
                    labels[index][single_data == single_abnormal] = 1
                if not abnormal_values:
                    un_detected_data_indexes.append(index)
                    un_detected_data.add(tuple(single_data))
        if len(un_detected_data) > 0:
            data = np.sort(np.array(tuple(un_detected_data)), axis=-1)
            diff_data = np.diff(data, axis=-1)
            max_index = np.argmax(diff_data, axis=-1)
            max_one_hot = one_hot_encode(max_index, diff_data.shape[-1])
            first_gap_choose = diff_data[max_one_hot] / (np.sum(diff_data, axis=-1) + EPS) > self.first_gap_rate
            diff_data_copy = np.copy(diff_data)
            diff_data_copy[max_one_hot] = -1
            second_index = np.argmax(diff_data_copy, axis=-1)
            second_one_hot = one_hot_encode(second_index, diff_data_copy.shape[-1])
            second_gap_choose = diff_data[max_one_hot] / (diff_data[second_one_hot] + EPS) < 1 + self.second_gap_rate
            index1s = diff_data == diff_data[max_one_hot][..., None]
            index2s = diff_data == diff_data[second_one_hot][..., None]
            gap_dict = {}
            for i, (index1, index2, has_first_gap, has_second_gap) in enumerate(zip(index1s.tolist(), index2s.tolist(),
                                                                                    first_gap_choose.tolist(),
                                                                                    second_gap_choose.tolist())):
                gap_dict.setdefault(i, [])
                if has_first_gap:
                    first_gaps = np.arange(diff_data.shape[-1])[index1].tolist()
                    if len(first_gaps) == 1:
                        gap_dict.get(i).extend(first_gaps)
                        if has_second_gap:
                            gap_dict.get(i).extend(np.arange(diff_data.shape[-1])[index2].tolist())
            for i, gaps in gap_dict.items():
                abnormal = self._single_detector(sorted_single_data=tuple(data[i]), gaps=tuple(gaps))
                LABEL_DICT[(tuple(data[i]), self.args)] = abnormal
            for index in un_detected_data_indexes:
                single_data = test_data[index]
                sorted_data = sorted(single_data)
                for single_abnormal in LABEL_DICT[(tuple(sorted_data), self.args)]:
                    labels[index][single_data == single_abnormal] = 1
        labels = self._alarm_suppression(labels)
        return labels

    def _alarm_suppression(self, labels):
        # 告警抑制,抑制离散点
        for index, label in enumerate(labels.T):
            kernel = np.array([-1, 1, -1])
            convolution_result = np.convolve(label, kernel, mode='same')
            discrete_points = np.where(convolution_result == 1)[0]
            if len(discrete_points) <= self.discrete_point_suppression_ratio * len(label):
                labels[discrete_points, index] = 0
        # 有一个device异常比较多的情况,主要报这一个
        abnormal_point_count = np.sum(labels, axis=0)
        non_major_anomaly_rate = 1 - np.max(abnormal_point_count) / (np.sum(abnormal_point_count) + EPS)
        logger.info("non_major_anomaly_rate:%s", non_major_anomaly_rate)
        if non_major_anomaly_rate < self.non_major_anomaly_suppression:
            max_index = np.argmax(abnormal_point_count)
            labels[:, max_index] = np.array(np.sum(labels, axis=-1) > 0, dtype=np.int32)
            labels[:, :max_index] = 0
            labels[:, max_index + 1:] = 0
        return labels

    def _single_detector(self, sorted_single_data, gaps):
        if len(gaps) == 1 or len(gaps) > 2:
            data_parts = (sorted_single_data[:gaps[0] + 1], sorted_single_data[gaps[0] + 1:])
        elif len(gaps) == 2:
            data_parts = (
                sorted_single_data[:min(gaps) + 1], sorted_single_data[min(gaps) + 1:max(gaps) + 1],
                sorted_single_data[max(gaps):])
        else:
            data_parts = ()
        if data_parts:
            part1, part2 = data_parts[0], data_parts[-1]
            if len(part1) == len(part2):
                return []
            if len(part1) < len(part2):
                abnormal = part1
                normal = part2
            else:
                abnormal = part2
                normal = part1
            m_abnormal, m_normal = np.mean(abnormal), np.mean(normal)
            std_normal, std_part2 = np.std(normal), np.std(sorted_single_data)
            flag1 = max(m_abnormal, m_normal) / (min(m_abnormal, m_normal) + EPS) > self.discrete_rate
            flag2 = (m_abnormal < m_normal - self.nsigma_coefficient * std_normal or
                     m_abnormal > m_normal + self.nsigma_coefficient * std_normal)
            if flag1 and flag2:
                return abnormal
        return []
