"""
Configuration schema for the Sliding Window K-Sigma detector.
"""
from typing import Literal

from pydantic import BaseModel, Field


class SlidingWindowKSigmaParams(BaseModel):
    """
    Parameters for the Sliding Window K-Sigma detector.

    This detector uses a sliding window approach with robust statistics (median-MAD)
    to detect anomalies in multi-dimensional time series data. It supports both
    slow_cal (low value anomalies) and slow_launch (high value anomalies) detection modes.
    """

    #基础参数
    k: float = Field(
        default=2.5,
        gt=0,
        description="Number of standard deviations (sigma) for thresholding. "
        "Higher values require more extreme deviations to trigger anomaly detection."
    )
    look_back: int = Field(
        default=8,
        ge=2,
        description="Number of past time steps to consider for the initial window size."
    )

    #慢检测类型
    slow_type: Literal["slow_cal", "slow_launch", "slow_host", "both"] = Field(
        default="slow_cal",
        description="Slow detection type: slow_cal (detect low value anomalies), "
        "slow_launch (detect high value anomalies), slow_host (detect high value anomalies), "
        "both (detect bidirectional anomalies)."
    )

    #窗口参数
    use_variable_window: bool = Field(
        default=True,
        description="Whether to allow detection before window is full. "
        "When True, detection starts once window has at least window_size/2 data points."
    )
    window_increase_ratio: float = Field(
        default=0.5,
        ge=0,
        description="Ratio to increase window size when no anomaly is detected. "
        "Window grows by this ratio each time an observation is added beyond the current window size."
    )

    #预处理参数
    smooth_size: int = Field(
        default=10,
        ge=1,
        description="Window size for smoothing the data before detection."
    )
    filter_extreme_values: bool = Field(
        default=True,
        description="Whether to filter extreme values (values above 99th or below 1st percentile)."
    )
    extreme_quantile: float = Field(
        default=0.01,
        ge=0,
        le=0.5,
        description="Quantile threshold for extreme value filtering. "
        "Values below 1st percentile or above 99th percentile are set to NaN."
    )

    #检测参数
    anom_threshold: int = Field(
        default=5,
        ge=1,
        description="Minimum consecutive anomalies to confirm an anomaly. "
        "A sequence of this many consecutive anomalies is required to flag an anomaly."
    )
    change_conf: float = Field(
        default=0.5,
        ge=0,
        le=1,
        description="Proportion threshold to ignore uniform changes. "
        "If more than this proportion of ranks show the same anomaly direction, "
        "the window is reset (considered a uniform change, not an anomaly)."
    )
    keep_last: float = Field(
        default=0.2,
        ge=0,
        le=1,
        description="Ratio of anomaly tail data to keep. "
        "Only anomalies connected to the last keep_last proportion of data are kept."
    )
    alert_conf_thresh: float = Field(
        default=4.0,
        ge=0,
        description="Threshold for alert confidence. "
        "The cumulative confidence of an anomaly sequence must exceed this threshold."
    )
    conf_score_decay: float = Field(
        default=5.0,
        ge=0,
        description="Decay factor for confidence score calculation. "
        "Higher values give more weight to single-rank anomalies vs multi-rank anomalies."
    )
    deviation_ratio_thresh: float = Field(
        default=1.01,
        gt=0,
        description="Threshold for deviation ratio to consider anomaly. "
        "Values must deviate from median by this ratio to be considered anomalous."
    )

    #调试参数
    enable_debug_logging: bool = Field(
        default=False,
        description="Enable detailed debug logging for troubleshooting."
    )

    #可视化参数
    plt_save_path: str = Field(
        default="",
        description="Path to save the visualization plots. If empty, plots are not saved."
    )