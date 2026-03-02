"""
Configuration schema for the Composite detector.
"""
from __future__ import annotations

from typing import Literal, Optional, Dict, Any

from pydantic import BaseModel, Field


class CompositeDetectorParams(BaseModel):
    """
    Parameters for the Composite detector.
    
    The Composite detector combines time-dimension and space-dimension
    detection results using a fusion strategy.
    
    Attributes:
        enable_time_detect: Whether to enable time-dimension detection
        enable_space_detect: Whether to enable space-dimension detection
        min_ranks_for_space: Minimum number of ranks required for space detection
        fusion_mode: Fusion strategy mode
        time_detector: Configuration for the time-dimension detector (dict with 'type' and 'params')
        space_detector: Configuration for the space-dimension detector (dict with 'type' and 'params')
    """
    
    enable_time_detect: bool = Field(
        default=True,
        description="Whether to enable time-dimension detection."
    )
    
    enable_space_detect: bool = Field(
        default=True,
        description="Whether to enable space-dimension detection."
    )
    
    min_ranks_for_space: int = Field(
        default=2,
        ge=2,
        description="Minimum number of ranks required for space detection."
    )
    
    fusion_mode: Literal["time_space", "or", "and"] = Field(
        default="time_space",
        description="Fusion mode: 'time_space' (v1 logic), 'or', or 'and'."
    )
    
    time_detector: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Configuration for the time-dimension detector. "
            "Example: {'type': 'sliding_window_ksigma', 'params': {'k': 2.5}}"
        ),
    )
    
    space_detector: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Configuration for the space-dimension detector. "
            "Example: {'type': 'sliding_window_ksigma', 'params': {'k': 3.0}}"
        ),
    )
    
    class Config:
        extra = "forbid"
