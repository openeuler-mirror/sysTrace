"""Custom Fail Slow Detector implementation."""

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from failslow.alg.degradation_detector.detector import (
    DegradationAlert,
    DetectorConfig,
    OnlineDegradationDetector,
    create_detector,
)
from failslow.util.logging_utils import get_default_logger

from ..alert_reporter import (
    AlertReporterConfig,
    AlertReporterFactory,
    BufferedAlertReporterBase,
)
from .interface import KernelType, StepMetrics

logger = get_default_logger(__name__)


# 告警数据模型
class Alert(BaseModel):
    timestamp: int | None = None
    alert_type: str | None = None  # e.g., "hang", "slow_step"
    severity: str | None = None  # e.g., "warning", "critical"
    description: str | None = None
    details: dict | None = None

    model_config = {"extra": "allow"}


class DetectorConfig(BaseModel):
    enable: bool = Field(True, description="是否启用degradation检测功能")

    alert_reporter_config: AlertReporterConfig = AlertReporterConfig()

    class HangDetectionConfig(BaseModel):
        enable: bool = Field(True, description="是否启用hang检测功能")
        hang_check_interval: float = 5.0  # hang检查间隔，单位秒
        hang_detection_ratio: float = Field(
            2.0,
            description="用于计算hang阈值的比例因子, 当hang达到此倍率的on_recv_step时间时，则认为出现hang",
        )
        expectation_calc_sample_size: int = Field(
            100, description="用于计算expected_timestamp_interval的样本数量"
        )
        skip_steps: int = Field(default=5, description="跳过检查的step数")

    hang_detection_config: HangDetectionConfig = HangDetectionConfig()

    class DegradationDetectionConfig(BaseModel):
        detector_type: str = "BOCPDDetector"
        detector_config: dict = {}

    degradation_detection_config: DegradationDetectionConfig = (
        DegradationDetectionConfig()
    )

    alert_attrs: dict = {}

    model_config = {"extra": "allow"}


class OnlinePerformanceDegradationDetector:
    """在线性能劣化检测器实现"""

    class DetectorState(BaseModel):
        """检测器状态参数"""

        model_config = {"arbitrary_types_allowed": True}
        hang_alert_timestamp: int | None = None  # 当到达该时刻时，产生告警
        last_updated_timestamp: int = time.time_ns()  # 上次更新的数据时间戳

        past_ts: list = Field(default_factory=list)  # 历史step时延数据
        detecting_hang_flag_event: threading.Event = Field(
            default_factory=threading.Event
        )
        hang_check_interval: float = Field(default=5.0)
        expected_timestamp_interval: float | None = None

    def __init__(self, config: dict):
        """初始化在线劣化检测器
        Args:
            config (dict): 配置字典
        """
        self.config: DetectorConfig = DetectorConfig(**config)

    def initialize_detector_state(self):
        """初始化检测器状态，由外部控制调用"""
        # stop any previously running detection task
        self.stop_detect_hang()
        # reset stop flag and reinitialize state
        self.state = self.DetectorState(
            hang_check_interval=self.config.hang_detection_config.hang_check_interval,
            expected_timestamp_interval=None,
        )
        # 初始化告警器
        # TODO: 根据配置初始化不同的告警器
        self.alert_reporter: BufferedAlertReporterBase = (
            AlertReporterFactory.create_reporter(self.config.alert_reporter_config)
        )
        # 初始化劣化检测器
        self.degradation_detector: OnlineDegradationDetector = create_detector(
            self.config.degradation_detection_config.detector_type,
            self.config.degradation_detection_config.detector_config,
        )
        self.degradation_detector.set_alert_reporter(self.on_alert)
        self._detection_thread = None  # hang检测线程句柄
        if self.config.hang_detection_config.enable:
            self.start_detect_hang()

    def _detect_hang(self, flag_event: threading.Event):
        """Background runner moved to a thread so it can be cancelled/controlled by Event."""
        try:
            init_hang_check_interval = (
                self.config.hang_detection_config.hang_check_interval
            )
            if self.__timeunit == "ns":
                init_hang_check_interval *= 1e9
            while not flag_event.is_set():
                # logger.info("Hang detection awake")
                hang_alert_timestamp = self.state.hang_alert_timestamp
                if hang_alert_timestamp is None or hang_alert_timestamp <= 0:
                    # 未配置hang检测，等待一段时间后重试
                    logger.info(
                        "hang_alert_timestamp not configured; waiting for %s %s",
                        init_hang_check_interval,
                        self.__timeunit,
                    )
                    self.__sleep_func(init_hang_check_interval)
                    continue

                now = self.__get_time_record()
                if now <= hang_alert_timestamp:  # 未到达告警时间
                    next_hang_check_sleep_interval = max(
                        hang_alert_timestamp - now, init_hang_check_interval
                    )
                    logger.debug(
                        "No hang. Next hang check at %s (in %s %s).",
                        hang_alert_timestamp,
                        next_hang_check_sleep_interval,
                        self.__timeunit,
                    )
                    self.__sleep_func(next_hang_check_sleep_interval)
                    continue

                if (
                    len(self.state.past_ts)
                    <= self.config.hang_detection_config.skip_steps
                ):
                    # 数据点不足，跳过检测
                    logger.debug(
                        (
                            "Not enough data points (%d) to check hang, "
                            "need more than %d. Skipping hang detection."
                        ),
                        len(self.state.past_ts),
                        self.config.hang_detection_config.skip_steps,
                    )
                    # 等待一段时间后重试
                    self.__sleep_func(init_hang_check_interval)
                    continue

                # 检测到了hang
                logger.warning(
                    (
                        "Significant delay detected: "
                        "last update at %s, now %s (now - last_update = %s %s) "
                        "> hang_timestamp %s (now - hang_timestamp = %s %s)."
                    ),
                    self.state.last_updated_timestamp,
                    now,
                    now - self.state.last_updated_timestamp,
                    self.__timeunit,
                    hang_alert_timestamp,
                    now - hang_alert_timestamp,
                    self.__timeunit,
                )
                alert_attrs = self.config.alert_attrs.copy()
                alert_attrs.update(
                    {
                        "timestamp": now,
                        "alert_type": "hang",
                        "severity": "warning",
                        "description": f"No updates since {self.state.last_updated_timestamp}",
                        "details": {
                            "last_updated": self.state.last_updated_timestamp,
                            "now": now,
                        },
                    }
                )
                alert = Alert(**alert_attrs)
                try:
                    self.alert_reporter.report_alert(alert.model_dump())
                except Exception:
                    logger.exception("Failed to report alert")
                # 更新下一个hang告警时间点
                logger.info(
                    "Scheduling next hang check after %s %s",
                    init_hang_check_interval,
                    self.__timeunit,
                )
                self.__sleep_func(init_hang_check_interval)

        except Exception:
            logger.exception("Unexpected error in detection runner")

        logger.info("\nHang detection runner stopped.\n")

    def start_detect_hang(self):
        """
        启动一个asyncio协程，定时检查state里last_checked_timestamp
        如果距离当前时间超出一个阈值（与expected_timestamp_interval有关），则产生一个hang告警
        注意这里使用self.__sleep_func来替代asyncio.sleep，方便测试时挂钩
        """
        # avoid creating multiple concurrent threads
        if (
            getattr(self, "_detection_thread", None) is not None
            and self._detection_thread.is_alive()
        ):
            return self._detection_thread

        flag_event = self.state.detecting_hang_flag_event
        # clear the event for new run
        try:
            flag_event.clear()
        except Exception:
            # threading.Event has clear()
            pass

        self._detection_thread = threading.Thread(
            target=self._detect_hang, args=(flag_event,), daemon=True
        )
        self._detection_thread.start()
        logger.info(
            "Started hang detection thread: %s(alive=%s)",
            self._detection_thread.name,
            self._detection_thread.is_alive(),
        )
        return self._detection_thread

    def stop_detect_hang(self):
        """停止hang检测协程"""
        if not hasattr(self, "state"):
            return
        self.state.detecting_hang_flag_event.set()
        thread = getattr(self, "_detection_thread", None)
        if thread is not None and thread.is_alive():
            try:
                thread.join(timeout=1.0)
            except Exception:
                logger.exception("Failed to join detection thread")
        self._detection_thread = None

    def on_recv(self, data: StepMetrics):
        """
        收到新数据时调用，完成： 1. 更新状态以提示hang检测器 2. 检测step时延劣化
        """
        if not isinstance(data, StepMetrics):
            raise TypeError("data must be a StepMetrics instance")

        # 更新状态以提示hang检测器
        logger.debug(
            "Received StepMetrics: step=%s, rank_id=%s", data.step, data.rank_id
        )
        self.state.last_updated_timestamp = self.__get_time_record()
        self.update_hang_detection(data.step, self.state.last_updated_timestamp)

        # 这里会自动进行告警
        if data.start_time_ns is None or data.start_time_ns <= 0:
            logger.warning(
                "Received step %s with invalid start_time_ns=%s",
                data.step,
                data.start_time_ns,
            )
            return
        logger.debug(
            "[rank:%s] Received [step:%s] latency=%.02f sec(%s ns)",
            data.rank_id,
            data.step,
            (data.end_time_ns - data.start_time_ns) / 1e9,
            data.end_time_ns - data.start_time_ns,
        )
        self.degradation_detector.update(
            data.end_time_ns - data.start_time_ns, timestamp=data.end_time_ns
        )

    def update_hang_detection(self, step: int, on_recv_timestamp: float):
        """更新时间戳，以便hang检测器使用"""
        self.state.past_ts.append(
            {
                "step_index": step,
                "on_recv_timestamp": on_recv_timestamp,
            }
        )
        # 注意更新expected_timestamp_interval也是平均的on_recv时间戳间隔
        if (
            len(self.state.past_ts)
            > self.config.hang_detection_config.expectation_calc_sample_size
        ):
            self.state.past_ts.pop(0)
        if len(self.state.past_ts) > 2:
            self.expected_timestamp_interval = (
                self.state.past_ts[-1]["on_recv_timestamp"]
                - self.state.past_ts[0]["on_recv_timestamp"]
            ) / len(self.state.past_ts)
            logger.debug(
                "Updated expected_timestamp_interval to %s based on %d samples",
                self.expected_timestamp_interval,
                len(self.state.past_ts),
            )
        else:
            self.expected_timestamp_interval = (
                self.config.hang_detection_config.hang_check_interval
            )
        # 根据上一个step的时间戳和expected_timestamp_interval计算下一个hang告警时间点
        self.state.hang_alert_timestamp = on_recv_timestamp + int(
            self.expected_timestamp_interval
            * self.config.hang_detection_config.hang_detection_ratio
        )
        logger.debug(
            "Updated hang_alert_timestamp to %s based on expected interval %s",
            self.state.hang_alert_timestamp,
            self.expected_timestamp_interval,
        )

    def __get_time_record(self):
        """获取当前时间戳"""
        return int(time.time_ns())

    def __sleep_func(self, interval: float):
        """
        sleep指定时间，需要和__get_time_record配合使用
        interval: 待sleep的ns数目
        """
        time.sleep(interval / 1e9)

    @property
    def __timeunit(self):
        return "ns"

    def on_alert(self, alert: BaseModel):
        """收到外部告警时调用，可以选择性处理外部告警"""
        alert_info = {
            "alert_type": "performance_degradation",
            "severity": "warning",
            "timestamp": int(time.time()),
        }
        alert_info.update(self.config.alert_attrs)
        alert_info.update(alert.model_dump())

        self.alert_reporter.report_alert(alert_info)
        logger.info("Received external alert: %s", alert_info)

    def get_all_alerts(self) -> list[dict]:
        """获取所有已报告的告警"""
        if self.alert_reporter is None:
            return []
        return self.alert_reporter.get_all_alerts()


class OnlinePerformanceDegradationDetectorCollections:
    """
    在线劣化感知算法的集合，允许随时发送一个数据到指定的算法
    """

    def __init__(self, degradation_perception_default_config: dict):
        self.degradation_perception_default_config = (
            degradation_perception_default_config
        )
        # rank to detector map
        self.rank2degradation_detectors = {}
        # rank to last step index map (to ensure step index increasing)
        self.rank2last_step_index = {}

    def on_recv(self, step_metrics: StepMetrics):
        rank_id = step_metrics.rank_id
        if not self.degradation_perception_default_config.get("enable", False):
            logger.info(
                "Degradation detection is disabled in the configuration. skipping this step"
            )
            return

        # 丢弃重复数据
        if (
            rank_id in self.rank2last_step_index
            and step_metrics.step <= self.rank2last_step_index[rank_id]
        ):
            logger.warning(
                "Received a previously received StepMetrics(step_index=%s, rank_id=%s), but last step index is %s. Skipping.",
                step_metrics.step,
                rank_id,
                self.rank2last_step_index[rank_id],
            )
            return

        # 确保检测器存在，如果不存在则创建
        if rank_id not in self.rank2degradation_detectors:
            # 创建新的检测器
            config = {}
            config.update(self.degradation_perception_default_config)
            # 添加alert_attrs: 标记rank_id
            config.update({"alert_attrs": {"rank_id": rank_id}})
            detector: OnlinePerformanceDegradationDetector = (
                OnlinePerformanceDegradationDetector(config=config)
            )
            # 初始化检测器状态
            detector.initialize_detector_state()
            # 记录检测器
            self.rank2degradation_detectors[rank_id] = detector
        # 获取检测器并更新
        detector: OnlinePerformanceDegradationDetector = (
            self.rank2degradation_detectors[rank_id]
        )
        # 更新检测器状态
        detector.on_recv(step_metrics)

    def get_all_alerts(self):
        """获取所有已报告的告警"""
        alerts = []
        for rank_id, detector in self.rank2degradation_detectors.items():
            alerts.extend(detector.get_all_alerts())
        return alerts


__all__ = [
    "OnlinePerformanceDegradationDetector",
]
