from typing import Optional

from pydantic import BaseModel, Field


class DegradationKSigmaRobustParams(BaseModel):
    window_size: int = Field(10, ge=1, description="Initial sliding window size")
    k_sigma: float = Field(2.0, gt=0, description="Number of MAD-based sigma for anomaly threshold")
    anomaly_degree_thr: float = Field(0.05, ge=0, description="Minimum relative anomaly degree to trigger detection")
    use_variable_window: bool = Field(True, description="Whether to allow detection before window is full")
    window_increase_ratio: float = Field(0.5, ge=0, description="Ratio to increase window size when using variable window")
    eps: float = Field(1e-6, gt=0, description="Small constant to avoid division by zero")
    min_consecutive: int = Field(6, ge=1, description="Minimum consecutive anomaly signals to confirm an alert")
    detect_rise: bool = Field(True, description="Whether to detect rising anomalies")
    detect_drop: bool = Field(False, description="Whether to detect dropping anomalies")
    plt_save_path: Optional[str] = Field(None, description="Path to save matplotlib plot")
