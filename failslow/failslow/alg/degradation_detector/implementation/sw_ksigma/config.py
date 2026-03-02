from pydantic import BaseModel, Field

from failslow.alg.degradation_detector.detector import DetectorConfig


class SlidingWindowKSigmaDetectorConfig(BaseModel):
    """检测算法配置参数"""

    model_config = {"extra": "allow"}

    window_size: int = Field(10, description="Size of the init sliding window")
    k_sigma: float = Field(
        2.0, description="Number of standard deviations for anomaly threshold"
    )
    anomaly_degree_thr: float = Field(
        0.05, description="Minimum relative anomaly degree to trigger detection"
    )
    use_variable_window: bool = Field(
        True, description="Whether to allow detection before window is full"
    )
    sliding_window_increase_ratio: float = Field(
        0.5, description="Ratio to increase window size when using variable window"
    )

    eps: float = Field(1e-6, description="Small constant to avoid division by zero")


class AlertGenerationConfig(BaseModel):
    """生成告警过滤参数"""

    model_config = {"extra": "allow"}

    min_consecutive: int = Field(
        2, description="Minimum consecutive anomaly signals to confirm an alert"
    )
    detect_rise: bool = Field(True, description="Whether to detect rising anomalies")
    detect_drop: bool = Field(False, description="Whether to detect dropping anomalies")


class SlidingWindowKSigmaDetectorConfig(DetectorConfig):
    algo_config: SlidingWindowKSigmaDetectorConfig = SlidingWindowKSigmaDetectorConfig()
    alert_config: AlertGenerationConfig = AlertGenerationConfig()

    model_config = {"extra": "ignore"}
    model_config = {"extra": "ignore"}
