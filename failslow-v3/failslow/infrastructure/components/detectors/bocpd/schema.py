"""
Configuration schema for the BocpdDetector.
"""
from typing import Literal
from pydantic import BaseModel, Field


class BocpdParams(BaseModel):
    """Parameters for the BOCPD detector."""
    distribution: Literal[
        "GaussianProb1d",
        "StudentTProb1d",
        "LinearProb1d",
        "LinearProb1dWithRunLengthBonus",
    ] = Field(
        default="LinearProb1dWithRunLengthBonus",
        description="Probability distribution for changepoint detection.",
    )
    hazard: float = Field(
        default=0.002,
        gt=0,
        lt=1,
        description="Hazard rate (1/h_lambda). Default 0.002 means changepoint probability 1/500 per step.",
    )
    ignore_prop_lb: float = Field(
        default=1e-4,
        ge=0,
        le=1,
        description="Lower bound for crop acceleration.",
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
        description="Whether to enable crop acceleration.",
    )
    metric_key: str = Field(
        default="t_exec_ns",
        description="Metric key to analyze within StepMetrics.kernels.",
    )
    changepoint_threshold: int = Field(
        default=10,
        ge=0,
        description="Run length drop threshold for changepoint detection.",
    )
