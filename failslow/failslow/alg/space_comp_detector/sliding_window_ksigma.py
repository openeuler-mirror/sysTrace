import logging
import math
from collections import Counter, deque

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field
from scipy.ndimage import gaussian_filter1d
from scipy.stats import norm

from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


class ModelConfig(BaseModel):
    look_back: int = Field(
        20, description="Number of past time steps to consider for anomaly detection"
    )
    look_forward: int = Field(
        1, description="Number of future time steps to consider for anomaly detection"
    )
    use_variable_window: bool = Field(
        False, description="Whether to allow detection before window is full"
    )
    window_increase_ratio: float = Field(
        0.5, description="Ratio to increase window size when no anomaly is detected"
    )
    k: float = Field(2.5, description="Number of standard deviations for thresholding")
    anom_threshold: int = Field(
        5, description="Minimum consecutive anomalies to confirm an anomaly"
    )
    change_conf: float = Field(
        0.4, description="Proportion threshold to ignore uniform changes"
    )

    filter_early_ratio: float = Field(
        0.25, description="Ratio of early data to filter out"
    )


class SlidingWindowKSigmaRaw:
    def __init__(self, cfg=None):
        if isinstance(cfg, dict):
            self._config = ModelConfig(**cfg) if cfg else ModelConfig()
        else:
            self._config = ModelConfig()

    def detect(self, test_data: np.ndarray):
        """
        Detect anomalies where a single dimension (object) deviates from the rest
        over a sliding time window. If, within the sliding window ending at time t,
        an object's recent behavior forms a small/noise cluster by DBSCAN, the
        object at time t is marked as anomalous.

        Args:
            test_data: np.ndarray, shape (time_len, obj_num)
        Returns:
            ret_values: np.ndarray, shape (time_len, obj_num), 0-normal, 1-anomaly
        """
        logger.info(
            "SlidingWindowKSigma.detect called with data shape: %s", test_data.shape
        )
        logger.info(
            "test_data sample with nan number: %s",
            np.isnan(test_data[:, :]).sum(axis=0),
        )
        data = np.asarray(test_data)
        data[np.isnan(data)] = np.inf
        if data.ndim != 2:
            raise ValueError("test_data must be 2D array (time_len, obj_num)")

        T, N = data.shape
        ret_values = np.zeros((T, N), dtype=int)
        anom_mark = np.zeros((T, N), dtype=int)
        anom_mark_count = np.zeros((T, N), dtype=int) + 1e-6  # 避免除0

        for pos in range(T):
            # 用 [pos-lookback, pos] 检测 [pos+1, pos+lookforward]
            # [start, pos] 检测 [pos+1, end]

            if pos < self._config.look_back:  # 滑窗没有填满，等填满才检测
                continue
            if pos > T - self._config.look_forward - 1:  # look forward 超出边界
                continue
            start = max(0, pos - self._config.look_back)
            end = min(T, pos + self._config.look_forward + 1)

            # 用[start, pos] 检测 [pos+1, end] 的异常
            data = test_data[start : pos + 1, :].flatten()
            median = np.median(data)  # 不用mean，更鲁棒，避免outlier影响
            # 更鲁棒的sigma, 避免被极端值影响
            mad = np.median(np.abs(data - median)) + 1e-6  # 避免除0
            madn = mad * 1.4826  # ppf(0.75) = pdf(0.75)的反函数，约等于0.6745
            sigma_hat = madn

            # 改为用60分位数和40分位数推测sigma值
            # upper_limit = np.percentile(data, 60) + self._config.k * (np.percentile(data, 60) - np.percentile(data, 40))
            # lower_limit = np.percentile(data, 40) - self._config.k * (np.percentile(data, 60) - np.percentile(data, 40))
            q40, q60 = np.quantile(data, [0.4, 0.6])
            sigma_hat = (q60 - q40) / (norm.ppf(0.6) - norm.ppf(0.4))
            upper_limit = median + self._config.k * sigma_hat
            lower_limit = median - self._config.k * sigma_hat

            look_forward_data = test_data[pos + 1 : end, :]
            # 用1, 0, -1标记 <lower_limit , 之间, > upper_limit 的点
            deviation = (look_forward_data - median) / (sigma_hat + 1e-6)
            anom_mark_forward = np.where(
                deviation > self._config.k,
                1,
                np.where(deviation < -self._config.k, -1, 0),
            )
            # 注意如果大多数点取值都一样，那么就忽略掉（可能是一起变化的）
            # 例如：一行中有  1, 1, 1, 1, 1, 1, 0, 1, -1
            #           转为 0, 0, 0, 0, 0, 0,-1, 0, -1
            # 处理：对anom_mark_forward每一行，如果超出一定比例以上的是1,-1，则对取值为该主流值的点置0
            for rank_id in range(anom_mark_forward.shape[0]):
                for tgt in [-1, 1]:
                    idx = np.where(anom_mark_forward[rank_id, :] == tgt)[0]
                    if len(idx) > N * self._config.change_conf:
                        anom_mark_forward[rank_id, :] -= tgt
                        # 规整到 -1, 1
                        anom_mark_forward[rank_id, :] = np.where(
                            anom_mark_forward[rank_id, :] > 0,
                            1,
                            np.where(anom_mark_forward[rank_id, :] < 0, -1, 0),
                        )
            # """
            logger.debug(
                "pos:%d, median:%.2f, %s <= [%s] madn:%f lb:%f ub:%f\nraw:%s",
                pos,
                median,
                anom_mark_forward.flatten().tolist(),
                ",".join([f"{e:.2f}" for e in deviation.flatten().tolist()]),
                madn,
                lower_limit,
                upper_limit,
                look_forward_data.flatten().tolist(),
            )  # """

            anom_mark[pos + 1 : end, :] += anom_mark_forward
            anom_mark_count[pos + 1 : end, :] += np.ones_like(anom_mark_forward)

        # self.plot_raw_mark(anom_mark, anom_mark_count)

        # 最终判定：如果某个点被标记的次数超过一半，则认为是异常
        anom_mark = np.nan_to_num(anom_mark, nan=0)
        anom_mark = anom_mark / anom_mark_count
        # 根据平均值 -0.5 和 0.5 进行阈值划分为 -1,0,1
        anom_mark = np.where(anom_mark > 0.5, 1, np.where(anom_mark < -0.5, -1, 0))
        anom_mark[: int(T * self._config.filter_early_ratio), :] = (
            0  # 过滤掉前面一部分数据
        )
        # logger.info(f"anom_mark: {anom_mark}")
        # 连续x个点为同类异常，才认为是异常
        # 某一张卡(对应一列)：  0 0 0 0 0 0 1 1 1 1 1 1 1 1 0 0 0 0 → 有一段连续的异常
        # 某一张卡(对应一列)：  0 0 0 0 0 0 1 0 0 1 1 0 1 0 0 0 0 0 → 全部被筛掉
        for rank_id in range(N):
            idx = 0
            while idx < T:
                if anom_mark[idx, rank_id] != 0:
                    curr_label = anom_mark[idx, rank_id]
                    count = 1
                    j = idx + 1
                    while j < T and anom_mark[j, rank_id] == curr_label:
                        count += 1
                        j += 1
                    if count >= self._config.anom_threshold:
                        ret_values[idx:j, rank_id] = 1
                    idx = j
                else:
                    idx += 1
        # anom_mark = np.abs(anom_mark)
        # logger.debug(f"ret_values: %s", ret_values)
        return ret_values


class WindowData:
    """由此控制如何维护滑窗数据"""

    def __init__(
        self, init_window_size: int, window_increase_ratio: float = 0.2, k: float = 3.0
    ):
        self.init_window_size = init_window_size
        self.window_size = init_window_size
        self.k = k
        self.window_increase_ratio = window_increase_ratio
        self.window_data = None
        self.obs_cnt = 0
        self.obs_sizes = deque()

    def reset_window_size(self):
        self.window_size = self.init_window_size
        self._ensure_window_size(window_increase_ratio=0)

    def update_obs(self, obs: np.ndarray):
        obs = obs.flatten()
        self.obs_cnt += 1
        self.obs_sizes.append(len(obs))

        self.window_data = (
            np.vstack([self.window_data, obs.reshape((1, -1))])
            if self.window_data is not None
            else obs.reshape((1, -1))
        )

        # logger.info(f"WindowData update_obs: obs_cnt={self.obs_cnt}, window_size={self.window_size}, current_data_size={len(self.window_data)}")
        self._ensure_window_size(window_increase_ratio=self.window_increase_ratio)

    def _ensure_window_size(self, window_increase_ratio: float = 0):
        while self.obs_cnt > self.window_size:
            self.window_data = self.window_data[1:]
            self.obs_sizes.popleft()
            self.obs_cnt -= 1
            self.window_size += window_increase_ratio

    def quantile_continuity_threshold(self, x, alphas, tau_r=0.5, gamma=0.02):
        x = np.asarray(x)
        n = len(x)

        qs = np.quantile(x, alphas)
        Ns = []
        Ds = []

        for i in range(len(qs) - 1):
            Ni = np.sum((x >= qs[i]) & (x < qs[i + 1]))
            Ns.append(Ni)
            Ds.append(Ni / ((alphas[i + 1] - alphas[i]) * n + 1e-8))

        Rs = np.array(Ds[1:]) / (np.array(Ds[:-1]) + 1e-8)

        for k, r in enumerate(Rs):
            tail_mass = sum(Ns[k + 1 :]) / n
            if r < tau_r and tail_mass < gamma:
                return qs[k + 1]

        return qs[-1]

    def estimate_q(self, x, src1, src2, tgt, min_scale=1e-6):
        q25, q40 = np.quantile(x, [src1, src2])
        scale = max(q40 - q25, min_scale)

        slope = scale / (src2 - src1)
        q02 = q25 - slope * (src1 - tgt)
        return q02

    def get_mu(self) -> float:
        """获取均值"""
        if self.obs_cnt == 0:
            return 0.0
        return np.median(self.window_data)

    def get_sigma(self) -> float:
        """每个维度自己计算"""
        sigma = [
            np.median(np.abs(col - np.median(col))) * 1.4826
            for col in self.window_data.T
        ]
        return np.array(sigma)

    def robust_median_mad(self, arr):
        """
        对 TxN 的 ndarray arr 执行以下步骤：
        1. 粗略计算每列（维度）的中位数，再对这些中位数取中位数作为“主要 median”。
        2. 计算每一列中位数与主要 median 的绝对偏差。
        3. 剔除偏差最大的两个维度（列）。
        4. 在剩下的 N-2 列上，将所有数据 flatten 后计算最终的 median 和 MAD，
        并由此估计 mu（用 median）和 sigma（用 MAD * 1.4826）。

        参数:
            arr (np.ndarray): shape (T, N)，T 是样本数，N 是维度数。

        返回:
            mu (float): 最终稳健估计的中心（median）
            sigma (float): 最终稳健估计的标准差（基于 MAD）
            kept_dims (np.ndarray): 保留下来的维度索引
        """
        assert arr.ndim == 2, "arr 必须是二维数组 (T, N)"
        T, N = arr.shape
        drop_data_length = 1 if N <= 3 else 2

        # Step 1: 粗略计算每列的中位数，再求这些中位数的中位数（主要 median）
        col_medians = np.median(arr, axis=0)  # shape (N,)
        main_median = np.median(col_medians)  # scalar

        # Step 2: 计算各维度中位数到 main_median 的绝对偏差
        deviations = np.abs(col_medians - main_median)  # shape (N,)

        # Step 3: 剔除偏差最大的两个维度
        # 获取排序后的索引，取前 N-drop_data_length 个（即剔除最后两个最大偏差的）
        sorted_indices = np.argsort(deviations)
        kept_indices = sorted_indices[:-drop_data_length]  # 剔除最大的两个
        # 可选：如果想确保顺序不变，可以 sort(kept_indices)，但非必须
        kept_indices = np.sort(kept_indices)

        # Step 4: 在保留的维度上计算最终的 median 和 MAD
        selected_data = arr[
            :, kept_indices
        ].flatten()  # shape (T * (N-drop_data_length),)
        final_median = np.median(selected_data)
        mad = np.median(np.abs(selected_data - final_median))
        # 使用标准正态分布下 MAD 与 sigma 的关系：sigma ≈ MAD * 1.4826
        sigma = mad * 1.4826

        return final_median, sigma, kept_indices

    def get_core_dims(self):
        """计算主要的几个维度"""
        median_by_col = np.median(self.window_data, axis=0)

        lb_by_col = np.quantile(self.window_data, 0.05, axis=0)
        ub_by_col = np.quantile(self.window_data, 0.95, axis=0)
        sort_index = np.argsort(median_by_col)
        center_index = sort_index[(len(median_by_col) - 1) // 2]
        ub = np.max(ub_by_col[center_index:])
        lb = 2 * np.median(median_by_col) - ub
        # 要求：lb_by_col[i],ub_by_col[i]至少75%在[lb, ub] 之间
        coverage = [
            np.sum((self.window_data[:, i] >= lb) * (self.window_data[:, i] <= ub))
            / len(self.window_data)
            for i in range(len(median_by_col))
        ]
        coverage = [float(c) for c in coverage]

        core_dims = [i for i, c in enumerate(coverage) if c >= 0.6]

        logger.debug(
            ("\ncore_dims: %s" "\nub_by_col: %s" "\nlb_by_col: %s" "\n coverage: %s"),
            core_dims,
            ub_by_col,
            lb_by_col,
            coverage,
        )

        return lb, ub

    def get_median_sigma_by_col(self, window_data):
        # TODO: SELECT One
        median_by_col = np.median(window_data, axis=0)
        mad_by_col = np.median(np.abs(window_data - median_by_col), axis=0)
        sigma_by_col = mad_by_col * 1.4826

        # 新的写法
        lb_by_col = np.quantile(window_data, 0.02, axis=0)
        ub_by_col = np.quantile(window_data, 0.98, axis=0)

        median_by_col = (ub_by_col + lb_by_col) / 2
        sigma_by_col = (ub_by_col - lb_by_col) / 2 / self.k

        return median_by_col, sigma_by_col

    def get_ub_lb(self):
        """获取上下界"""
        # median, sigma_hat, kept_dims = self.robust_median_mad(self.window_data)

        median, sigma_hat, kept_dims = self.robust_median_mad(self.window_data)
        median_by_col, sigma_hat_by_col = self.get_median_sigma_by_col(self.window_data)
        median = np.median(median_by_col)
        # sigma_hat = np.median(np.abs(median - self.window_data)) * 1.4826
        # sigma_hat = np.median(sigma_hat_by_col)
        sigma_hat = sigma_hat * np.ones(len(sigma_hat_by_col))

        upper_limit = median + self.k * sigma_hat
        lower_limit = median - self.k * sigma_hat
        return upper_limit, lower_limit
        # """

    def valid(self) -> bool:
        """检查是否有足够数据"""
        return self.obs_cnt >= self.window_size // 2

    def full_by_init_size(self) -> bool:
        """检查窗口是否满"""
        return self.obs_cnt >= self.init_window_size


class SlidingWindowKSigmaRobustConfig(BaseModel):
    smooth_size: int = Field(10, description="Window size for smoothing the data")
    look_back: int = Field(
        8, description="Number of past time steps to consider for anomaly detection"
    )
    use_variable_window: bool = Field(
        True, description="Whether to allow detection before window is full"
    )
    window_increase_ratio: float = Field(
        0.5, description="Ratio to increase window size when no anomaly is detected"
    )
    k: float = Field(2.5, description="Number of standard deviations for thresholding")
    anom_threshold: int = Field(
        5, description="Minimum consecutive anomalies to confirm an anomaly"
    )
    change_conf: float = Field(
        0.5, description="Proportion threshold to ignore uniform changes"
    )
    keep_last: float = Field(0.2, description="Ratio of anomaly tail data")
    alert_conf_thresh: float = Field(4.0, description="Threshold for alert confidence")
    conf_score_decay: float = Field(
        5, description="Decay factor for confidence score calculation"
    )
    deviation_ratio_thresh: float = Field(
        1.01, description="Threshold for deviation ratio to consider anomaly"
    )
    plt_save_path: str = Field(
        "/home/sysTrace/mspti/", description="Path to save the plot image"
    )


class SlidingWindowKSigmaRobust:
    def __init__(self, cfg=None):
        if isinstance(cfg, dict):
            self._config: SlidingWindowKSigmaRobustConfig = (
                SlidingWindowKSigmaRobustConfig(**cfg)
                if cfg
                else SlidingWindowKSigmaRobustConfig()
            )
        else:
            self._config: SlidingWindowKSigmaRobustConfig = (
                SlidingWindowKSigmaRobustConfig()
            )

    def plot_multi_dim_multi_rank_data(self, data):
        if data.ndim != 2:
            raise ValueError("data must be 2D array (time_len, obj_num)")
        
        T, N = data.shape
        
        # 创建图形
        plt.figure(figsize=(12, 8))
        
        # 为每个rank/维度绘制一条线
        for rank_idx in range(min(N, 20)):  # 限制最多绘制20条线，避免图表过于拥挤
            plt.plot(range(T), data[:, rank_idx], label=f'Rank {rank_idx}', alpha=0.7)
        
        plt.title('Multi-Dim Multi-Rank Data Visualization')
        plt.xlabel('Time')
        plt.ylabel('Values')
        
        # 如果rank数量不多，显示图例；否则隐藏以避免遮挡主要内容
        if N <= 10:
            plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        elif N <= 20:
            # 如果rank数量较多，只显示部分图例
            plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', ncol=2)
        
        plt.tight_layout()
        
        # 如果提供了保存路径，则保存图片
        if self._config.plt_save_path:
            import os
            import re
            
            # 确保路径以/结尾
            save_dir = self._config.plt_save_path
            if not save_dir.endswith('/'):
                save_dir += '/'
            
            # 创建目录（如果不存在）
            os.makedirs(save_dir, exist_ok=True)
            
            # 查找目录下所有以.png结尾的文件
            existing_files = [f for f in os.listdir(save_dir) if f.startswith('multi_dim_multi_rank_plot_') and f.endswith('.png')]
            
            # 提取文件名中的数字索引
            max_index = 0
            for filename in existing_files:
                # 匹配文件名中的数字，例如 multi_dim_multi_rank_plot_5.png
                match = re.search(r'multi_dim_multi_rank_plot_(\d+)\.png', filename)
                if match:
                    index = int(match.group(1))
                    max_index = max(max_index, index)
            
            # 下一个索引是最大索引+1，如果没有匹配到则为1
            next_index = max_index + 1
            indexed_path = os.path.join(save_dir, f'multi_dim_multi_rank_plot_{next_index}.png')
            plt.savefig(indexed_path, dpi=300, bbox_inches='tight')
            logger.info(f"Plot saved to {indexed_path}")

    def detect(self, test_data: np.ndarray):
        """
        Detect anomalies where a single dimension (object) deviates from the rest
        over a sliding time window. If, within the sliding window ending at time t,
        an object's recent behavior forms a small/noise cluster by DBSCAN, the
        object at time t is marked as anomalous.

        Args:
            test_data: np.ndarray, shape (time_len, obj_num)
        Returns:
            ret_values: np.ndarray, shape (time_len, obj_num), 0-normal, 1-anomaly
        """

        logger.info(
            "SlidingWindowKSigmaRobust.detect called with data shape: %s",
            test_data.shape,
        )
        logger.info(
            "test_data sample with nan number: %s",
            np.isnan(test_data[:, :]).sum(axis=0),
        )
        data = np.asarray(test_data)

        if data.ndim != 2:
            raise ValueError("test_data must be 2D array (time_len, obj_num)")

        T, N = data.shape

        ret_values = np.zeros((T, N), dtype=int)
        anom_mark = np.zeros((T, N), dtype=float)
        continuous_anom_mark = np.zeros((T, N), dtype=int)
        anom_mark_count = np.zeros((T, N), dtype=int) + 1e-6  # 避免除0

        # 筛掉过高点和过低点
        ub = np.nanpercentile(data, 99)
        lb = np.nanpercentile(data, 1)
        logger.info(f"filter extreme values, ub: {ub}, lb: {lb}")
        data[data > ub] = np.nan
        data[data < lb] = np.nan

        # 数据平滑：
        for rank in range(N):
            # 填充
            rank_data = data[:, rank].copy()
            s = pd.Series(rank_data)
            s = s.interpolate(
                method="nearest"
            )  # 可选 'polynomial', 'spline', 'nearest' 等
            s = s.interpolate(method="linear")  # 线性插值填补剩余的nan
            rank_data = s.to_numpy()
            # 滤波
            WINDOW_SIZE = self._config.smooth_size
            tmp_df = pd.DataFrame(rank_data, columns=["value"])
            tmp_df["smoothed"] = (
                tmp_df["value"]
                .rolling(window=WINDOW_SIZE, min_periods=1, center=True)
                .mean()
            )
            # tmp_df["smoothed"] = gaussian_filter1d(tmp_df["value"], sigma=WINDOW_SIZE / 6, mode='nearest')
            smoothed_data = tmp_df["smoothed"].to_numpy()
            """padded_data = np.pad(rank_data, (WINDOW_SIZE // 2, WINDOW_SIZE // 2), mode='edge')
            smoothed_data = np.array([
                np.mean(padded_data[i:i + WINDOW_SIZE]) 
                for i in range(len(rank_data))
            ])"""
            data[:, rank] = smoothed_data

        # 除去末尾行的nan: 如果最后一行过半为nan，则删除最后一行，循环检查直到没有过半为nan的行
        while data.shape[0] > 0:
            last_row = data[-1, :]
            if np.sum(np.isnan(last_row)) > N / 2:
                data = data[:-1, :]
                T -= 1
            else:
                break
        logger.info(
            f"After removing trailing NaN rows, data shape: {data.shape} (from {test_data.shape})"
        )

        # 预处理
        offset = np.min(data)
        data -= np.median(data, axis=1, keepdims=True)
        data += 1e-6
        data -= np.min(data)
        data += offset

        # for debug
        # self.plot_multi_dim_multi_rank_data(data)

        window_data = WindowData(
            init_window_size=self._config.look_back,
            window_increase_ratio=self._config.window_increase_ratio,
            k=self._config.k,
        )
        for pos in range(T):
            obs = data[pos, :]
            if not window_data.valid():
                logger.debug("pos:%d, window not valid yet, detection skipped", pos)
                window_data.update_obs(obs)
                continue
            if (
                not window_data.full_by_init_size()
                and not self._config.use_variable_window
            ):
                logger.debug("pos:%d, window not full yet, detection skipped", pos)
                window_data.update_obs(obs)
                continue
            upper_limit, lower_limit = window_data.get_ub_lb()
            median = np.median((upper_limit + lower_limit) / 2)
            diff = upper_limit - lower_limit + 1e-6  # 避免除0

            # 计算偏离
            deviation = (obs - (upper_limit + lower_limit) / 2) / (diff / 2 + 1e-6)
            deviation_abs = np.abs(deviation)
            deviation_exp = np.exp(deviation_abs - np.max(deviation_abs))

            deviation_weights = deviation_abs / (np.sum(deviation_abs) + 1e-6)
            deviation *= deviation_weights
            # 异常分数根据偏离程度给与权重补正
            obs_anom_mark = np.where(
                deviation > 1,
                1.0,
                np.where(deviation < -1, -1.0, 0),
            )
            # 小于中值的1/t 或者 大于中值的t倍
            deviation_log = obs / (np.median(median) + 1e-6) + 1e-6
            deviation_log = np.log10(deviation_log)
            deviation_log = np.abs(deviation_log)
            deviation_log_ratio = deviation_log - np.log10(
                self._config.deviation_ratio_thresh
            )
            obs_anom_mark *= deviation_log_ratio > 0
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    (
                        f"detect pos:%d with windowsize=%d"
                        "\n =>val: %s"
                        "\n => ub: %s"
                        "\n => lb: %s"
                        "\n => deviation: %s"
                        "\n => deviation_log: %s"
                        "\n => deviation_log_ratio: %s"
                        "\n => anom_mark: %s"
                    ),
                    pos,
                    window_data.window_size,
                    obs.tolist(),
                    upper_limit,
                    lower_limit,
                    deviation.tolist(),
                    deviation_log.tolist(),
                    deviation_log_ratio.tolist(),
                    obs_anom_mark.tolist(),
                )

            anom_mark[pos, :] = obs_anom_mark
            abs_obs_anom_mark = np.abs(obs_anom_mark)
            # 超出一半，需要注意窗口重置
            if np.sum(abs_obs_anom_mark) > self._config.change_conf * N:

                logger.debug("reset window size by over-half anomalies in pos %d", pos)
                window_data.reset_window_size()
                # 修正
                median = np.median(obs_anom_mark[obs_anom_mark != 0])
                obs_anom_mark -= median
                obs_anom_mark = np.where(
                    obs_anom_mark > 0,
                    1.0,
                    np.where(obs_anom_mark < 0, -1.0, 0),
                )
                abs_obs_anom_mark = np.abs(obs_anom_mark)
                logger.debug("  => %s", obs_anom_mark.tolist())

            # 如果存在持续异常，进行窗口大小重置
            anom_mark_count[pos, :] += abs_obs_anom_mark

            if pos == 0:
                continuous_anom_mark[pos, :] = obs_anom_mark
            elif pos < T - 1:
                # 1/-1
                continuous_anom_mark[pos, :] = (
                    continuous_anom_mark[pos - 1, :] * abs_obs_anom_mark + obs_anom_mark
                )
            # if np.abs(continuous_anom_mark[pos, :]).sum() > self._config.anom_threshold:
            # logger.debug("reset window size by continuous anomalies in pos %d", pos)
            # window_data.reset_window_size()

            window_data.update_obs(obs)
        # 最终筛选仅保留
        # 仅仅保留与最后self._config.keep_last比例数据中的的异常点相连的异常点
        # 连续x个点为同类异常，才认为是异常
        # 某一张卡(对应一列)：  0 0 0 0 0 0 1 1 1 1 1 1 1 1 0 0 0 0 → 有一段连续的异常
        # 某一张卡(对应一列)：  0 0 0 0 0 0 1 0 0 1 1 0 1 0 0 0 0 0 → 全部被筛掉

        # 某一行异常点越多，异常置信度越低（不会多卡一起故障）
        # N卡(x=N)一起故障，则得分只增加很小很小 y=exp(-decay_factor*(N-1)/N)
        # 单卡(x=1)故障得分最高，为 y=1
        # N/2卡(x=N/2)一起故障，得分为 y=exp(-decay_factor*(N/2-1)/N) = exp(-decay_factor/2 + decay_factor/(2N))
        x = np.sum(np.abs(anom_mark), axis=1)
        row_confidence = np.exp(-self._config.conf_score_decay * (x - 1) / N)
        # row_confidence =  ( N+1. - x) / N
        anom_mark = anom_mark * row_confidence.reshape((-1, 1))
        for rank_id in range(N):
            idx = 0
            while idx < T:
                if anom_mark[idx, rank_id] != 0:
                    curr_label = anom_mark[idx, rank_id]
                    count = 1
                    j = idx + 1
                    conf_cum = anom_mark[idx, rank_id]
                    while j < T and anom_mark[j, rank_id] * curr_label > 0:
                        conf_cum += anom_mark[j, rank_id]
                        count += 1
                        j += 1
                    logger.info(
                        "[rank %d]check possible anomaly from %d to %d (total %s), count=%d, conf_cum=%.4f",
                        rank_id,
                        idx,
                        j - 1,
                        T,
                        count,
                        conf_cum,
                    )
                    if (
                        np.abs(conf_cum) >= self._config.alert_conf_thresh
                        and count >= self._config.anom_threshold
                        and j >= T * (1 - self._config.keep_last)
                    ):
                        ret_values[idx:j, rank_id] = 1
                    idx = j
                else:
                    idx += 1

        return ret_values


SlidingWindowKSigma = SlidingWindowKSigmaRobust


# Demo / test logic moved to the dedicated pytest in
# failslow/tests/alg/space_comp_detector/test_sliding_window_ksigma.py
