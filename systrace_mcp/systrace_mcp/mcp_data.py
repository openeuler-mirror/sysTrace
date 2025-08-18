from typing import List, Union
from pydantic import BaseModel, Field
from enum import Enum

class ReportType(str, Enum):
    normal = "normal"
    anomaly = "anomaly"


class AnomalyInfo(BaseModel):
    """劣化详细信息结构"""
    training_step: int = Field(default=0, description="训练步骤（默认0）")
    anomaly_time: str = Field(default="", description="劣化时间（默认空字符串）")
    anomaly_degree: float = Field(default=0.0, description="劣化程度（默认0.0）")
    anomaly_training_time: str = Field(default="", description="劣化训练step时间（默认空字符串）")
    normal_training_time: str = Field(default="", description="正常训练step时间（默认空字符串）")

class AnomalyInfo2(BaseModel):
    """劣化详细信息结构"""
    detect_point: str = Field(default="", description="检测点")
    hang_minutes: str = Field(default="", description="hang的分钟数")
class PerceptionResult(BaseModel):
    """慢节点感知结果结构"""
    is_anomaly: bool = Field(default=False, description="是否发生性能劣化（默认false）")
    anomaly_count_times: int = Field(default=0, description="劣化次数（默认0）")
    # 列表类型使用 default_factory 避免 mutable 默认值问题
    anomaly_info: Union[List[AnomalyInfo],List[AnomalyInfo2]] = Field(
        default_factory=list,
        description="劣化详细信息（默认空列表）"
    )
    start_time: int = Field(default=0, description="劣化开始时间（默认0，单位毫秒）")
    end_time: int = Field(default=0, description="劣化结束时间（默认0，单位毫秒）")
    anomaly_type: str = Field(default="", description="劣化类型（默认空字符串）")
    task_id: str = Field(default="", description="服务器ip（默认空字符串）")


class DetailItem(BaseModel):
    objectId: str = Field(default="", alias="objectId", description="对象ID")
    serverIp: str = Field(default="", alias="serverIp", description="服务器IP")
    deviceInfo: str = Field(default="", alias="deviceInfo", description="设备信息")
    kpiId: str = Field(default="", alias="kpiId", description="KPI指标ID")
    methodType: str = Field(default="", alias="methodType", description="方法类型")
    kpiData: list = Field(default_factory=list, alias="kpiData", description="KPI数据列表")
    relaIds: List[int] = Field(default_factory=list, alias="relaIds", description="关联ID列表")
    omittedDevices: list = Field(default_factory=list, alias="omittedDevices", description="忽略的设备列表")


# 主模型引用嵌套模型（为所有字段添加默认值）
class AIJobDetectResult(BaseModel):
    timestamp: int = Field(default=0, description="时间戳（默认0）")
    result_code: int = Field(default=0, alias="resultCode", description="结果编码（默认0）")
    compute: bool = Field(default=False, description="计算状态（默认False）")
    network: bool = Field(default=False, description="网络状态（默认False）")
    storage: bool = Field(default=False, description="存储状态（默认False）")
    # 列表类型推荐用 default_factory=list 而非 []，避免 mutable 默认值的潜在问题
    abnormal_detail: List[DetailItem] = Field(
        default_factory=list,
        alias="abnormalDetail",
        description="异常详情列表（默认空列表）"
    )
    normal_detail: List[DetailItem] = Field(
        default_factory=list,
        alias="normalDetail",
        description="正常详情列表（默认空列表）"
    )
    error_msg: str = Field(default="", alias="errorMsg", description="错误信息（默认空字符串）")

