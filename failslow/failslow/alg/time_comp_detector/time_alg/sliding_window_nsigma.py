from typing import Tuple

import numpy as np
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


class SlidingWindowNSigma(object):
    def __init__(self, cfg: dict, metric_name):
        self.training_window_size = cfg.get("training_window_size")
        self.min_update_window_size = cfg.get("min_update_window_size")
        self.min_std_val = cfg.get("min_std_val")
        self.metric_name = metric_name

        self.bias = cfg.get("bias")
        self.abs_bias = cfg.get("abs_bias")
        self.nsigma_coefficient = cfg.get("nsigma_coefficient")
        self.training_buffer = []
        self.cursion = 0
        self.lower_bound = None
        self.upper_bound = None
        self.mean = None

        self.detect_type = cfg.get("detect_type")

        # 设置专家阈值
        self.min_expert_lower_bound = cfg.get("min_expert_lower_bound", None)
        self.max_expert_lower_bound = cfg.get("max_expert_lower_bound", None)
        self.min_expert_upper_bound = cfg.get("min_expert_upper_bound", None)
        self.max_expert_upper_bound = cfg.get("max_expert_upper_bound", None)

    # 实现boxplot算法
    def nsigma(self, np_data: list) -> Tuple[float, float, float]:
        # 去掉一个最大值，去掉一个最小值之后计算标准差以及均值
        if len(np_data) >= 10:
            np_data = sorted(np_data)
            np_data = np_data[1:-1]
        else:
            logger.warning("[%s]Data length is not long enough for training, you got %s", self.metric_name,
                           len(np_data))
        mean = np.mean(np_data)
        std = np.std(np_data)

        if std == 0:
            std = self.min_std_val

        nsigma_upper_bound = mean + self.nsigma_coefficient * std
        nsigma_lower_bound = mean - self.nsigma_coefficient * std
        if self.abs_bias:
            upper_offset = max(self.bias * nsigma_upper_bound, self.abs_bias)
            lower_offset = max(self.bias * nsigma_lower_bound, self.abs_bias)
        else:
            upper_offset = self.bias * nsigma_upper_bound
            lower_offset = self.bias * nsigma_lower_bound

        upper_bound = nsigma_upper_bound + upper_offset
        lower_bound = nsigma_lower_bound - lower_offset

        # 将阈值下限圈定在min_expert_lower_bound 和 max_expert_lower_bound之间
        if self.max_expert_lower_bound is not None:
            lower_bound = min(self.max_expert_lower_bound, lower_bound)

        if self.min_expert_lower_bound is not None:
            lower_bound = max(self.min_expert_lower_bound, lower_bound)

        # 将阈值上限圈定在min_expert_lower_bound 和 max_expert_lower_bound之间
        if self.min_expert_upper_bound is not None:
            upper_bound = max(self.min_expert_upper_bound, upper_bound)

        if self.max_expert_upper_bound is not None:
            upper_bound = min(self.max_expert_upper_bound, upper_bound)
        logger.debug("[%s] expert range: max_el:%s min_el:%s min_eu:%s max_el:%s.", self.metric_name,
                     self.max_expert_lower_bound, self.min_expert_lower_bound, self.min_expert_upper_bound,
                     self.max_expert_upper_bound)
        logger.debug("[%s] Nsigma calculation: mean %s", self.metric_name, (mean, nsigma_upper_bound, upper_bound,))
        return mean, lower_bound, upper_bound

    def train(self):
        if len(self.training_buffer) < self.min_update_window_size:
            logger.info("Not enough data for training, current data_numbe"
                        "r:%s, except %s", len(self.training_buffer), self.min_update_window_size)
            return

        self.mean, self.lower_bound, self.upper_bound = self.nsigma(self.training_buffer)

    def add_training_data(self, data):
        if len(self.training_buffer) < self.training_window_size:
            self.training_buffer.append(data)
            self.cursion += 1
        else:
            self.cursion = (self.cursion + 1) % self.training_window_size
            self.training_buffer[self.cursion] = data

    def online_detecting(self, data_point, noisy_label=0):
        if len(self.training_buffer) < self.min_update_window_size:
            if noisy_label == 0:
                self.add_training_data(data_point)

            return 0, self.lower_bound, self.upper_bound
        self.train()
        logger.debug("[%s] training buffer %s.", self.metric_name, self.training_buffer)
        logger.debug("[%s] datapoint:%s, lower_bound:%s, upper_bound:%s", self.metric_name, data_point,
                     self.lower_bound, self.upper_bound)
        if self.detect_type == 'lower_bound':
            if data_point < self.lower_bound:
                return 1, self.lower_bound, self.upper_bound
            else:
                self.add_training_data(data_point)
                return 0, self.lower_bound, self.upper_bound

        elif self.detect_type == "upper_bound":
            if data_point >= self.upper_bound:
                return 1, self.lower_bound, self.upper_bound
            else:
                self.add_training_data(data_point)
                return 0, self.lower_bound, self.upper_bound
        else:
            if data_point > self.upper_bound or data_point < self.lower_bound:
                return 1, self.lower_bound, self.upper_bound
            else:
                self.add_training_data(data_point)
                return 0, self.lower_bound, self.upper_bound
