"""
test performance degradation perception module with default detector
"""

import failslow.util.logging_config as logging_config
logging_config.LOG_LEVEL = "INFO"



from failslow.alg.degradation_detector import create_detector, get_available_detectors

import json
from failslow.util.logging_utils import get_default_logger
import time
import numpy as np
import random

from failslow.task.custom_v1.performance_degradation_perception import (
    OnlinePerformanceDegradationDetector,
    StepMetrics,
)
from time import sleep
import pandas as pd
import time
import datetime


logger = get_default_logger(__name__)

AVAILABLE_DETECTORS = get_available_detectors()


def get_detector_config(detector_name):
    detector = create_detector(detector_name, config={})
    config = detector.config.model_dump()
    del detector
    return config


def prepare_detector(detector_name):
    detector = create_detector(detector_name, config={})
    logger.info(
        "Prepared detector: %s with config: \n%s",
        detector_name,
        json.dumps(detector.config.model_dump(), indent=2),
    )
    return detector


def generate_synthetic_data(
    T=100,
    R=4,
    inject_target=0,
    inject_magnitude=20,
    inject_start=50,
    inject_duration=10,
):
    STEP_LATENCY = 3  # 平均每个step 3秒
    # 准备时间序列数据
    # 每个step 3 秒
    step_latencies = np.random.normal(loc=STEP_LATENCY, scale=0.2, size=(T, R))  # T steps, R ranks
    # 注入故障
    step_latencies[
        inject_start : inject_start + inject_duration, inject_target
    ] += inject_magnitude  # Inject degradation in specified rank and time range

    # 构造数据
    step_timestamps = np.cumsum(step_latencies, axis=0)
    start_timestamp = datetime.datetime.now().timestamp()
    timestamps = (start_timestamp + step_timestamps).astype(int)

    # 模拟hang：在第20个step后，inject_target rank hang 一段时间
    timestamps[20:, inject_target] += STEP_LATENCY*5000


    records = []
    for row_idx in range(timestamps.shape[0]):
        for col_idx in range(timestamps.shape[1]):
            records.append(
                {
                    "step_index": int(row_idx),
                    "timestamp": int(timestamps[row_idx, col_idx]),
                    "rank_id": int(col_idx),
                    "step_latency": float(step_latencies[row_idx, col_idx]),
                }
            )
    data = pd.DataFrame.from_records(records)
    data = data.sort_values(by=["timestamp", "rank_id"]).reset_index(drop=True)
    return data


def __test__detection_and_hang(detector_name: str):
    """
    测试逻辑：初始数据喂入可以sleep一会，然后输入数据验证hang检测和性能退化检测
    """

    # 这里简化了
    detector_config = get_detector_config(detector_name)
    # 构建数据：
    inject_target = 0
    data = generate_synthetic_data(
        T=100, R=4, inject_target=inject_target, inject_duration=20
    )

    # 构建检测器
    detector = OnlinePerformanceDegradationDetector(
        config={
            "degradation_detection_config": {
                "detector_type": detector_name,
                "detector_config": detector_config,
            },
            "hang_detection_config": {
                "hang_check_interval": 3.0,
            },
            "alert_attrs": {
                "rank_id": inject_target,
            },
        }
    )
    time_mapping = 0.001  # 真实时间和模拟时间的映射比例

    logger.info(
        "Initialized detector: %s with config: \n%s",
        detector_name,
        json.dumps(detector.config.model_dump(), indent=2),
    )
    detector.initialize_detector_state()
    detector.start_detect_hang()

    # 喂入第一批数据
    selected_rank = inject_target
    selected_data = data[data["rank_id"] == selected_rank]
    start_time = selected_data["timestamp"].min()
    end_time = selected_data["timestamp"].max()

    """
    @dataclass
    class StepMetrics:
        start_time_ns: int
        end_time_ns: int
        step: int  # step number 从0开始
        rank_id: int
        local_rank_id: int
        node_ip: str
        node_port: int
        kernels: List[KernelType]
    """
    for i, (_, row) in enumerate(selected_data.iterrows()):
        sleep((row["timestamp"] - start_time) * time_mapping)
        logger.info(f"Feeding [{row['step_index']}]{row['step_latency']}")
        step_metrics = StepMetrics(
            start_time_ns=start_time * 1e9,
            end_time_ns=row["timestamp"] * 1e9,
            step=row["step_index"],
            rank_id=row["rank_id"],
            local_rank_id=row["rank_id"],
            node_ip="",
            node_port=0,
            kernels=[],
        )
        detector.on_recv(step_metrics)
        start_time = row["timestamp"]
    
    detector.stop_detect_hang()
    all_alerts = detector.get_all_alerts()
    logger.info("Total %d alerts detected", len(all_alerts))
    logger.info(
        "Alerts: %s", json.dumps(all_alerts, indent=2)
    )


def _test_all():
    random.seed(2887)

    for i in range(1):
        for detector_name in AVAILABLE_DETECTORS[:1]:
            print("\n" * 3)
            logger.info(f"Testing detector: %s", detector_name)
            __test__detection_and_hang(detector_name=detector_name)


if __name__ == "__main__":
    """模拟在线"""
    _test_all()





