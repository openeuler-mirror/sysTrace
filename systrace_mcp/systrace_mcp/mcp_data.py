from typing_extensions import TypedDict, List
from dataclasses import dataclass, field
from typing import List, Dict, Any

class AnomalyInfo(TypedDict):
    """劣化详细信息结构"""
    metric_name: str #是否发生性能劣化
    threshold: float
    actual_value: float
    timestamp: int

class PerceptionResult(TypedDict):
    """慢节点感知结果结构"""
    is_anomaly: bool #是否发生性能劣化
    anomaly_count_times: int #劣化次数
    anomaly_info: List[AnomalyInfo] #劣化详细信息
    start_time: int  # Unix timestamp in milliseconds 劣化开始时间
    end_time: int    # Unix timestamp in milliseconds 劣化结束时间
    anomaly_type: str  # 劣化类型
    task_id: str #服务ip
