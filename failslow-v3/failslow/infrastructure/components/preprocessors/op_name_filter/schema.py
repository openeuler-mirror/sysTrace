"""
Configuration schema for the OpNameFilter preprocessor.
"""
from typing import List, Optional
from pydantic import BaseModel, Field


class OpNameFilterParams(BaseModel):
    """
    Parameters for the OpNameFilterPreprocessor.

    This preprocessor filters StepMetrics to keep only those kernels
    whose name matches the specified criteria (most frequent or exact match).
    """
    white_list: Optional[List[str]] = Field(
        default=None,
        description="List of allowed kernel names. If provided, only kernels in this list will be considered."
    )
    target_op_name: Optional[str] = Field(
        default=None,
        description="Exact kernel name to filter by. If None, the most frequent kernel name will be used."
    )