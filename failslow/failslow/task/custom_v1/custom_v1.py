# from dataloader.timeseries_dataloaders.timeseries_data import TimeSeriesData
import json
import os
from dataclasses import dataclass
from typing import Dict, List

from pydantic import BaseModel

from failslow.task.custom_v1.slow_node_locator_detector import SlowNodeLocatorDetector
from failslow.util.logging_utils import get_default_logger

from .interface import KernelType, StepMetrics, TaskInterface
from .performance_degradation_perception import (
    OnlinePerformanceDegradationDetector,
    OnlinePerformanceDegradationDetectorCollections,
)
from .slow_node_locator_detector import SlowNodeConfig

logger = get_default_logger(__name__)


class TaskConfig(BaseModel):
    task_name: str = "gpu_fail_slow_detection_naive"
    degradation_perception: dict = {}
    slow_node_locator: SlowNodeConfig


"""
TimeSeriesData:
d调用get_data获得pd.DataFrame格式的数据v
v.values()
v[d.time_column] # 时间列
v[d.value_columns] # 其他数值列有可能有多个
"""


class GPUFailSlowDetectionNaive(TaskInterface):
    def __init__(
        self,
        config_path: str = None,
    ):
        if not config_path:
            config_path = self.__default_config_path()

        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            self.config = TaskConfig(**config)
            # 将配置文件内容导出到parsed_config
            tgt_config_path = os.path.join(
                os.path.dirname(os.path.abspath(config_path)), "parsed_config.json"
            )
            with open(tgt_config_path, "w") as f:
                f.write(self.config.model_dump_json(indent=4))

            # 解析配置文件内容
        except (OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Failed to load configuration from {config_path}: {e}")

        # 初始化劣化感知集合
        self.degradation_perception_collections = (
            OnlinePerformanceDegradationDetectorCollections(
                degradation_perception_default_config=self.config.degradation_perception
            )
        )
        # 初始化慢节点定位器
        self.slow_node_locator = SlowNodeLocatorDetector(self.config.slow_node_locator)

    def __default_config_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

    def _initialize_task(self) -> None:
        """
        无需额外初始化
        """
        pass

    def on_recv_single_step(self, step_metrics: StepMetrics):
        """
        传递给算法的update接口，随收随传某一个StepMetrics
        要求：对于任意一个rank，传入的step_metrics的step_id必须严格递增，不同rank可以打乱顺序
        """
        # 用于更新劣化感知算法检测器
        self.degradation_perception_collections.on_recv(step_metrics)

    def on_recv_all_step(self, step_metrics_list: List[StepMetrics]):
        """
        传递给算法的update接口，要求每次step结束时等待所有的rank数据都收集到了再调用这个接口并且传递这个数据结构
        要求：step_metrics_list中包含所有rank的step_metrics数据，且每个rank的step_index相同，每次调用时step_index必须严格递增
        update函数中：更新检测器状态,计算更新
        """

        rank2data: dict[int, StepMetrics] = {}
        if not isinstance(step_metrics_list, list):
            logger.error(f"step_metrics_list is not a list: {type(step_metrics_list)}")
            return
        for step_metrics in step_metrics_list:
            rank2data[step_metrics.rank_id] = step_metrics

        # logger.debug(f"测试数据: {len(step_metrics_list)} 条 StepMetrics")
        # logger.debug(f"转换为字典: {len(rank2data)} 个 rank 的数据")
        if step_metrics_list:
            logger.info(
                "recv data for step %d from ranks: %s",
                step_metrics_list[0].step,
                rank2data.keys(),
            )
        self.slow_node_locator.on_recv(rank2data)
