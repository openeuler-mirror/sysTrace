"""
Naive K-Sigma Sliding Window Degradation Detector.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Deque, List, Optional

import numpy as np
from pydantic import BaseModel

from failslow.util.logging_utils import get_default_logger

from ...detector import DegradationAlert, DetectorConfig, OnlineDegradationDetector
from .config import SlidingWindowKSigmaDetectorConfig

logger = get_default_logger(__name__)


class WindowState(BaseModel):
    window_size: int
    sliding_window_increase_ratio: float
    count: int = 0
    window_data: Deque[float] = deque()
    index_counter: int = 0

    def update_value(self, value: float):
        self.index_counter += 1
        self.window_data.append(value)
        self.count += 1
        if self.count > self.window_size:
            self._size_ensure()
            # 小设计：如果使用可变窗口，逐渐增大窗口大小
            self.window_size += self.sliding_window_increase_ratio

    def _size_ensure(self):
        while self.count > self.window_size:
            old = self.window_data.popleft()
            self.count -= 1

    def reset_window_size(self, size: int):
        self.window_size = int(size)
        self._size_ensure()

    def get_mu_sigma(self) -> tuple[float, float]:
        if self.count == 0:
            return 0.0, 0.0

        mu = np.median(self.window_data)
        sigma = np.median([np.abs(x - mu) for x in self.window_data]) * 1.4826
        return mu, sigma


class AlertState(BaseModel):
    signal: int = 0  # +1 rise, -1 drop, 0 no anomaly
    first_timestamp: Optional[int] = None
    first_degradation_index: Optional[int] = None
    last_degradation_index: Optional[int] = None
    report_enable: bool = True  # 用这个控制连续的告警是否重复告警


class SlidingWindowKSigmaRobust(OnlineDegradationDetector):
    """
    Simple sliding-window k-sigma online detector.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.config: SlidingWindowKSigmaDetectorConfig = self.config  # type: ignore
        self.reset()

    def reset(self):
        self.window_state = WindowState(
            window_size=self.config.algo_config.window_size,
            sliding_window_increase_ratio=self.config.algo_config.sliding_window_increase_ratio,
        )
        self.alert_state = AlertState()

    def __config_type__(self) -> type[DetectorConfig]:
        return SlidingWindowKSigmaDetectorConfig

    def update(self, obs, timestamp: Optional[int] = None):
        """Receive a new observation (numeric)."""
        cfg: SlidingWindowKSigmaDetectorConfig = self.config  # type: ignore
        logger.debug("Received new observation: %f at %.02f", obs, timestamp)
        # 如果要求填满才能开始计算
        if (not cfg.algo_config.use_variable_window) and (
            self.window_state.count < cfg.algo_config.window_size
        ):
            # wait until full window unless configured otherwise
            logger.debug(
                "Window not full (%d/%d), skipping detection",
                self.window_state.count,
                cfg.algo_config.window_size,
            )
            self.window_state.update_value(obs)
            return

        # compute population mean and std
        mean, std = self.window_state.get_mu_sigma()

        eps = cfg.algo_config.eps
        # 映射到 -1, 0, 1
        ub = mean + cfg.algo_config.k_sigma * (std + eps)
        lb = mean - cfg.algo_config.k_sigma * (std + eps)
        diviation = (obs - mean) / (std + eps)
        anom_signal = -1 if obs < lb else (1 if obs > ub else 0)

        # 计算相对异常程度
        if self.config.algo_config.anomaly_degree_thr >= 0:
            anom_degree = (abs(obs - mean) / (mean + eps)) if mean > 0 else 0
            if anom_degree < cfg.algo_config.anomaly_degree_thr:
                anom_signal = 0  # 不满足最小异常程度要求

        if (anom_signal > 0 and cfg.alert_config.detect_rise) or (
            anom_signal < 0 and cfg.alert_config.detect_drop
        ):
            # possible alert
            self._record_possible_degradation(
                self.window_state.index_counter,
                self.window_state.index_counter,
                obs,
                anom_signal,
                timestamp,
            )

        # 最后更新观测值到窗口
        self.window_state.update_value(obs)

    def _record_possible_degradation(
        self, index: int, degradation_pos: int, obs: float, signal: int, timestamp: int
    ):
        """
        记录一个可能存在的变点：
        1. 如果连续N个index都报告存在变点，那么
            1.1. 确认最开始的变点，更新last_degradation_pos为最末尾的那个，但把最开始那个index作为告警返回
            1.2. 检查变化后是上升还是下降
            1.3. 如果是上升且配置允许上升告警，或者是下降且配置允许下降告警，则产生告警
        2. 如果变点位置存在间隔，而且变化了，那么重新开始计数

        例如： 假设[5] 表示在5报告可能的异常，达到连续N=3个才确认告警
            第一种例子： [5], [6], [7], [8] -> 在7时告警变点为5，在8时告警变点为5
            第二种例子： [5], [6], [8] -> 在8位置重置计数
        """
        logger.debug("Recording possible degradation at index %d", index)
        if self.alert_state.last_degradation_index is None:
            # 第一次记录
            self.alert_state = AlertState(
                signal=signal,
                first_timestamp=timestamp,
                first_degradation_index=index,
                last_degradation_index=index,
            )
            logger.debug("First possible degradation recorded at index %d", index)
            return
        # 检查不连续情况
        if (
            index > self.alert_state.last_degradation_index + 1
            or signal != self.alert_state.signal
        ):
            # 不连续，重置计数
            logger.debug(
                "Non-consecutive degradation at index %d (last %s), resetting count",
                index,
                self.alert_state.last_degradation_index,
            )
            self.alert_state = AlertState(
                signal=signal,
                first_timestamp=timestamp,
                first_degradation_index=index,
                last_degradation_index=index,
            )
            return
        # 连续的，更新最后位置
        self.alert_state.last_degradation_index = index

        # 检查是否达到确认告警条件
        if not self.alert_state.report_enable:
            return  # 已经告警过，等待重置

        consecutive_count = (
            self.alert_state.last_degradation_index
            - self.alert_state.first_degradation_index
            + 1
        )
        if consecutive_count >= self.config.alert_config.min_consecutive:
            mean, std = self.window_state.get_mu_sigma()
            # 允许告警
            if (signal > 0 and self.config.alert_config.detect_rise) or (
                signal < 0 and self.config.alert_config.detect_drop
            ):
                alert = DegradationAlert(
                    timestamp=(
                        timestamp
                        if timestamp is not None
                        else self.alert_state.first_degradation_index
                    ),
                    description=(
                        f"Performance degradation detected at step "
                        f"{self.alert_state.first_degradation_index}"
                        f" at time {timestamp}"
                    ),
                    details={
                        "detector_type": self.__class__.__name__,
                        "degradation_type": "rise" if signal > 0 else "drop",
                        "identified_index": self.alert_state.first_degradation_index,
                        "observed_value": obs,
                        "mean": mean,
                        "std": std,
                    },
                )
                logger.info(
                    "Confirmed degradation at step %d, reporting alert at step %d (window_size=%d, mean=%.4f, std=%.4f)",
                    self.alert_state.first_degradation_index,
                    index,
                    self.window_state.window_size,
                    mean,
                    std,
                )
                # report alert
                self.alert_state.report_enable = False  # 禁止重复告警，直到重置
                self.alert_report_func(alert)
                # 窗口重置
                self.window_state.reset_window_size(self.config.algo_config.window_size)


__all__ = ["SlidingWindowKSigmaRobust"]
__all__ = ["SlidingWindowKSigmaRobust"]
__all__ = ["SlidingWindowKSigmaRobust"]
