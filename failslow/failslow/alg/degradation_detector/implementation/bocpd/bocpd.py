"""Bayesian Online Change Point Detection for degradation detection."""

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from failslow.util.logging_utils import get_default_logger

from ...detector import DegradationAlert, DetectorConfig, OnlineDegradationDetector
from .bocpd_stream import BOCPDStream
from .config import BOCPDDetectorConfig

logger = get_default_logger(__name__)


class DegradationCandidateRecord(BaseModel):
    reporter_index: int
    degradation_index: int


class BOCPDDetector(OnlineDegradationDetector):
    class State:
        last_degradation_pos: int | None = None
        total_obs_count: int = 0

        degradation_candidates: list[DegradationCandidateRecord] = []
        change_point2cumsum: pd.DataFrame = pd.DataFrame(
            columns=["index", "change_point_pos", "cumsum"]
        )

    def __init__(self, config: dict):
        super().__init__(config)
        self.config: BOCPDDetectorConfig = self.config
        self.stream = BOCPDStream(self.config.algo_config)
        self.state = self.State()

    def __config_type__(self) -> type[DetectorConfig]:
        return BOCPDDetectorConfig

    def update(self, obs: float, timestamp=None):
        """注意：一次只允许更新一个点"""
        logger.info("Received new observation: %f at %s", obs, timestamp)
        self.stream.update(obs)

        self.state.total_obs_count += 1

        if not self.state.change_point2cumsum.empty:
            self.state.change_point2cumsum["cumsum"] += obs

        # 注意当前时间点为x，stream中的run_length表示从x往回数的长度
        rt = self.stream.get_rt()
        degradation_pos = self.state.total_obs_count - 1 - rt
        # 如果此前没有，则直接设置
        if self.state.last_degradation_pos is None:
            self.state.last_degradation_pos = degradation_pos
            self.state.change_point2cumsum = pd.DataFrame(
                {
                    "index": [self.state.total_obs_count - 1],
                    "change_point_pos": [degradation_pos],
                    "cumsum": [obs],
                }
            )
            logger.debug(
                "Initialized change_point2cumsum with first degradation at pos %d",
                degradation_pos,
            )
            return
        # 如果已经有了，那么判断是否有更新，没有更新直接返回即可
        elif degradation_pos == self.state.last_degradation_pos:
            return

        # 记录可能的变点
        self._record_possible_degradation(
            self.state.total_obs_count - 1, degradation_pos, obs
        )

    def _record_possible_degradation(
        self, reporter_index: int, degradation_pos: int, obs: float
    ):
        """
        记录一个可能存在的变点：
        1. 如果连续N个index都报告存在变点，那么
            1.1. 确认最开始的变点，更新last_degradation_pos为最末尾的那个，但把最开始那个index作为告警返回
            1.2. 检查是否属于久远过滤（距离当前点很久以前的变点的切换），如果是则不报警但切换
            1.3. 检查变化后是上升还是下降
            1.4. 如果是上升且配置允许上升告警，或者是下降且配置允许下降告警，则产生告警
        2. 如果变点位置存在间隔，而且变化了，那么重新开始计数

        例如： 假设[5]3 表示在index=5时报告变点位置为3
            第一种例子： [5]3, [6]3, [7]3, [8]4 -> 报警index=5, 设置last_degradation_pos=4
            第二种例子： [5]3, [6]3, [8]5 -> 重置计数，从index=8开始计数
        """
        logger.debug(
            "Recording possible degradation at index %d (reporter index:%d)",
            degradation_pos,
            reporter_index,
        )
        report_alert_enable = (
            self.config.alert_config.detect_drop or self.config.alert_config.detect_rise
        )

        # 清理不连续的旧记录
        if self.state.degradation_candidates:
            last_record = self.state.degradation_candidates[-1]
            if abs(degradation_pos - last_record.degradation_index) > 1:
                self.state.degradation_candidates = []
        # 添加新记录
        self.state.degradation_candidates.append(
            DegradationCandidateRecord(
                reporter_index=reporter_index, degradation_index=degradation_pos
            )
        )
        self.state.change_point2cumsum = pd.concat(
            [
                self.state.change_point2cumsum,
                pd.DataFrame(
                    {
                        "index": [reporter_index],
                        "change_point_pos": [degradation_pos],
                        "cumsum": [obs],
                    }
                ),
            ],
            ignore_index=True,
        )

        # 检查长度，没达到要求直接返回
        start_index = self.state.degradation_candidates[0].reporter_index
        end_index = self.state.degradation_candidates[-1].reporter_index
        count = end_index - start_index + 1
        if count < self.config.alert_config.min_consecutive:
            return

        # 过滤过远的变点
        if (reporter_index - degradation_pos) > self.config.algo_config.h_lambda * 5:
            # 过远，允许切换但不报警
            logger.debug(
                "Degradation at pos %d at index %d is too far from current index, switching without alert",
                degradation_pos,
                reporter_index,
            )
            report_alert_enable = False
        if report_alert_enable:
            # 检查是上升还是下降，判断告警
            self.state.change_point2cumsum["cnt"] = (
                self.state.total_obs_count - self.state.change_point2cumsum["index"]
            )
            self.state.change_point2cumsum["avg"] = (
                self.state.change_point2cumsum["cumsum"]
                / self.state.change_point2cumsum["cnt"]
            )
            last_avg = self.state.change_point2cumsum[
                self.state.change_point2cumsum["change_point_pos"]
                == self.state.last_degradation_pos
            ]["avg"].values[0]
            new_avg = self.state.change_point2cumsum[
                self.state.change_point2cumsum["change_point_pos"] == degradation_pos
            ]["avg"].values[0]
            is_rise = new_avg > last_avg
            is_drop = new_avg < last_avg
            logger.debug("candidates:\n%s", self.state.degradation_candidates)
            # logger.debug("change2cumsum:\n%s", self.state.change_point2cumsum)
            logger.debug(
                "Degradation at pos %d at index %d: last_avg=%.4f, new_avg=%.4f, is_rise=%s, is_drop=%s",
                degradation_pos,
                reporter_index,
                last_avg,
                new_avg,
                is_rise,
                is_drop,
            )
            if (is_rise and self.config.alert_config.detect_rise) or (
                is_drop and self.config.alert_config.detect_drop
            ):
                reported_index = self.state.degradation_candidates[0].degradation_index

                description_msg = f"Detected degradation at step {reported_index} (by step {reporter_index})"
                alert = DegradationAlert(
                    timestamp=reported_index,
                    description=description_msg,
                    details={
                        "detector_type": self.__class__.__name__,
                        "degradation_type": "rise" if is_rise else "drop",
                        "indentified_index": reported_index,
                        "last_avg": last_avg,
                        "new_avg": new_avg,
                    },
                )
                self.alert_report_func(alert)

        # 确认变点
        logger.info(
            "Confirmed change point at index %d (type=%s), set last_degradation_pos from %s to %d",
            start_index,
            "rise" if is_rise else "drop",
            self.state.last_degradation_pos,
            end_index,
        )
        self.state.last_degradation_pos = degradation_pos
        self.state.degradation_candidates = []
        self.state.change_point2cumsum = pd.DataFrame(
            {
                "index": [end_index],
                "change_point_pos": [degradation_pos],
                "cumsum": [obs],
            }
        )


__all__ = ["BOCPDDetector"]
