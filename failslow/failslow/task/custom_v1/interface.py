from dataclasses import dataclass
from typing import List
from abc import ABC, abstractmethod


@dataclass
class KernelType:
    name: str
    t1_ns: int
    t2_ns: int
    t_delta_ns: float
    t_exec_ns: float
    t3_ns: int
    t4_ns: int


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


class TaskInterface(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def _initialize_task(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_recv_single_step(self, step_metrics: StepMetrics) -> None:
        """
        传递给算法的update接口，随收随传某一个StepMetrics数据结构
        """
        raise NotImplementedError
    
    @abstractmethod
    def on_recv_all_step(self, step_metrics_list: List[StepMetrics]) -> None:
        """
        传递给算法的update接口，要求每次step结束时等待所有的rank数据都收集到了再调用update接口并且传递这个数据结构
        要求：step_metrics_list中包含所有rank的step_metrics数据，且每个rank的step_index相同，每次调用时step_index必须严格递增
        update函数中
        """
        raise NotImplementedError



__all__ = ["StepMetrics", "KernelType", "TaskInterface"]





