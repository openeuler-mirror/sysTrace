from typing import Literal, Optional

from pydantic import BaseModel, Field


class DegradationBocpdParams(BaseModel):
    distribution: Literal[
        "GaussianProb1d",
        "StudentTProb1d",
        "LinearProb1d",
        "LinearProbRobust",
        "LinearProb1dWithRunLengthBonus",
    ] = Field(
        default="LinearProb1dWithRunLengthBonus",
        description="Probability distribution model for changepoint detection.",
    )
    hazard: float = Field(
        default=0.002,
        gt=0,
        lt=1,
        description="Hazard rate (changepoint prior probability per step).",
    )
    ignore_prop_lb: float = Field(
        default=1e-4,
        ge=0,
        description="Lower bound for crop acceleration (pruning low-probability run lengths).",
    )
    egress_distance: int = Field(
        default=10,
        ge=0,
        description="Buffer distance for crop acceleration.",
    )
    record_probs: bool = Field(
        default=False,
        description="Whether to record all probability values.",
    )
    enable_crop_acceleration: bool = Field(
        default=True,
        description="Whether to enable crop acceleration (pruning).",
    )
    run_length_bonus: float = Field(
        default=1.001,
        gt=1.0,
        le=1.05,
        description="Run-length bonus base for LinearProb1dWithRunLengthBonus. "
        "Lower values (e.g. 1.001) give milder preference for longer segments. "
        "Default 1.001 gives ~10%% bonus at N=100.",
    )
    init_sigma2: float = Field(
        default=10.0,
        gt=0,
        description="Initial variance for distribution models.",
    )
    huber_delta: float = Field(
        default=1.0,
        gt=0,
        description="Huber loss threshold for LinearProbRobust.",
    )
    min_consecutive: int = Field(
        default=3,
        ge=1,
        description="Minimum consecutive changepoint signals to confirm an alert.",
    )
    detect_rise: bool = Field(
        default=True,
        description="Whether to detect rising changepoints.",
    )
    detect_drop: bool = Field(
        default=False,
        description="Whether to detect dropping changepoints.",
    )
    plt_save_path: Optional[str] = Field(
        default=None,
        description="Path to save matplotlib plot. If None, plotting is disabled.",
    )
