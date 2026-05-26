"""
Defines the abstract interface for preprocessors.
"""
from abc import ABC, abstractmethod
from typing import List, TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from ..models import StepMetrics, TaskType

import numpy as np


class IPreprocessor(ABC):
    """
    Preprocessor interface. Pipeline 中 preprocessors 是必须的。

    Transforms StepMetrics into aggregated np.ndarray format for detectors.
    """

    @abstractmethod
    def process(self, data: List["StepMetrics"], task_type: Optional["TaskType"] = None) -> np.ndarray:
        """
        对输入的 StepMetrics 列表进行预处理，返回聚合后的数组。

        Args:
            data: 当前时间窗口内所有 rank 的 StepMetrics
            task_type: Optional task type for task-specific aggregation behavior

        Returns:
            np.ndarray: shape (num_ranks,)，聚合后的指标值
        """
        raise NotImplementedError()

    def flush(self) -> Optional[np.ndarray]:
        """
        冲刷缓冲区，返回尚未处理的数据。

        Returns:
            np.ndarray 或 None: 缓冲区中的聚合数据
        """
        return None
