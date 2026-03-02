"""
Configuration schemas for detectors.
"""
from __future__ import annotations

from typing import Union, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

from ..components.detectors.bocpd.schema import BocpdParams
from ..components.detectors.sliding_window_ksigma.schema import SlidingWindowKSigmaParams
from ..components.detectors.composite.schema import CompositeDetectorParams
from ..components.detectors.degradation_ksigma_naive.schema import DegradationKSigmaNaiveParams
from ..components.detectors.degradation_ksigma_robust.schema import DegradationKSigmaRobustParams
from ..components.detectors.degradation_bocpd.schema import DegradationBocpdParams


class BocpdDetectorConfig(BaseModel):
    """Configuration for BOCPD detector."""
    type: Literal["bocpd"]
    enabled: bool = True
    params: BocpdParams = Field(default_factory=BocpdParams)


class SlidingWindowKSigmaDetectorConfig(BaseModel):
    """Configuration for Sliding Window K-Sigma detector."""
    type: Literal["sliding_window_ksigma"]
    enabled: bool = True
    params: SlidingWindowKSigmaParams = Field(default_factory=SlidingWindowKSigmaParams)


class CompositeDetectorConfig(BaseModel):
    """
    Configuration for Composite detector.
    
    The Composite detector combines time-dimension and space-dimension
    detection. It can nest other detector configurations.
    
    Example:
        {
            "type": "composite",
            "enabled": true,
            "params": {
                "enable_time_detect": true,
                "enable_space_detect": true,
                "min_ranks_for_space": 2,
                "fusion_mode": "time_space",
                "time_detector": {
                    "type": "sliding_window_ksigma",
                    "params": {"k": 2.5}
                },
                "space_detector": {
                    "type": "sliding_window_ksigma",
                    "params": {"k": 3.0}
                }
            }
        }
    """
    type: Literal["composite"]
    enabled: bool = True
    params: CompositeDetectorParams = Field(default_factory=CompositeDetectorParams)


class DegradationKSigmaNaiveDetectorConfig(BaseModel):
    """Configuration for Degradation K-Sigma Naive detector."""
    type: Literal["degradation_ksigma_naive"]
    enabled: bool = True
    params: DegradationKSigmaNaiveParams = Field(default_factory=DegradationKSigmaNaiveParams)


class DegradationKSigmaRobustDetectorConfig(BaseModel):
    """Configuration for Degradation K-Sigma Robust detector."""
    type: Literal["degradation_ksigma_robust"]
    enabled: bool = True
    params: DegradationKSigmaRobustParams = Field(default_factory=DegradationKSigmaRobustParams)


class DegradationBocpdDetectorConfig(BaseModel):
    """Configuration for Degradation BOCPD detector."""
    type: Literal["degradation_bocpd"]
    enabled: bool = True
    params: DegradationBocpdParams = Field(default_factory=DegradationBocpdParams)


DetectorConfig = Union[
    BocpdDetectorConfig,
    SlidingWindowKSigmaDetectorConfig,
    CompositeDetectorConfig,
    DegradationKSigmaNaiveDetectorConfig,
    DegradationKSigmaRobustDetectorConfig,
    DegradationBocpdDetectorConfig,
]


def parse_detector_config(config_dict: Dict[str, Any]) -> DetectorConfig:
    """
    Parse a detector configuration dictionary into the appropriate config type.
    
    Args:
        config_dict: Dictionary containing detector configuration
        
    Returns:
        Parsed DetectorConfig instance
        
    Raises:
        ValueError: If detector type is unknown
    """
    detector_type = config_dict.get("type")
    
    if detector_type == "bocpd":
        return BocpdDetectorConfig(**config_dict)
    elif detector_type == "sliding_window_ksigma":
        return SlidingWindowKSigmaDetectorConfig(**config_dict)
    elif detector_type == "composite":
        return CompositeDetectorConfig(**config_dict)
    elif detector_type == "degradation_ksigma_naive":
        return DegradationKSigmaNaiveDetectorConfig(**config_dict)
    elif detector_type == "degradation_ksigma_robust":
        return DegradationKSigmaRobustDetectorConfig(**config_dict)
    elif detector_type == "degradation_bocpd":
        return DegradationBocpdDetectorConfig(**config_dict)
    else:
        raise ValueError(f"Unknown detector type: {detector_type}")
