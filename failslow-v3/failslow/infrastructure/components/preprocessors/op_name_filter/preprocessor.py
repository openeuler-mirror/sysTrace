"""
Implementation of the OpNameFilter preprocessor.
"""
import logging
from collections import Counter
from typing import List, Dict, Optional

import numpy as np

from failslow.infrastructure.framework.registration import PreprocessorRegistry
from failslow.domain.models import StepMetrics, TaskType
from .schema import OpNameFilterParams


logger = logging.getLogger(__name__)


class OpNameFilterPreprocessor(PreprocessorRegistry):
    """
    Preprocessor that filters StepMetrics by kernel name.

    This preprocessor filters kernels within each StepMetrics by name,
    keeping only kernels that match the target op name (most frequent or exact match).
    """
    COMPONENT_NAME = "op_name_filter"

    def __init__(self, params: OpNameFilterParams = None, **kwargs):
        if params is not None:
            self._params = params
        else:
            self._params = OpNameFilterParams(**kwargs)
        self._name_counts: Counter = Counter()
        self._target_op: Optional[str] = None

    def process(self, data: List[StepMetrics], task_type: Optional[TaskType] = None) -> np.ndarray:
        """
        Filter StepMetrics by kernel name.

        For the first call, determines the target op name by analyzing all data.
        Then filters each StepMetrics to keep only kernels matching the target.

        Args:
            data: List of StepMetrics
            task_type: Optional task type (unused, kept for interface compatibility)

        Returns:
            np.ndarray: Array of filtered StepMetrics count per rank (for compatibility)
        """
        if not data:
            return np.array([])

        # First pass: count kernel names (if not already done)
        if not self._name_counts:
            self._name_counts = self._count_kernel_names(data)
            logger.info("Kernel name counts: %s", dict(self._name_counts))

            # Determine target op name
            self._target_op = self._determine_target_op()
            logger.info("Selected target op: %s", self._target_op)

        if self._target_op is None:
            logger.warning("No target op name selected, passing through all data")
            # Return count of steps per rank for compatibility
            return np.array([1.0] * len(data))

        # Filter kernels by target op name
        filtered_count = 0
        for step in data:
            original_count = len(step.kernels)
            step.kernels = [k for k in step.kernels if k.name == self._target_op]
            if len(step.kernels) < original_count:
                filtered_count += 1

        logger.info("Filtered %d steps with non-matching kernels", filtered_count)

        # Return count of filtered steps per rank for compatibility
        return np.array([1.0] * len(data))

    def flush(self) -> Optional[np.ndarray]:
        """
        Flush any buffered data. OpNameFilter doesn't buffer,
        so this returns None.
        """
        return None

    def _count_kernel_names(self, steps: List[StepMetrics]) -> Counter:
        """Count occurrences of each kernel name across all steps."""
        name_counts: Counter = Counter()
        for step in steps:
            for kernel in step.kernels:
                if kernel.name:
                    name_counts[kernel.name] += 1
        return name_counts

    def _determine_target_op(self) -> Optional[str]:
        """
        Determine the target kernel name to filter by.

        Returns:
            The kernel name to filter by, or None if no suitable name found.
        """
        # If explicit target is provided, use it
        if self._params.target_op_name is not None:
            if self._params.target_op_name in self._name_counts:
                return self._params.target_op_name
            logger.warning(
                "Target op '%s' not found in data. Available ops: %s",
                self._params.target_op_name,
                list(self._name_counts.keys())[:10],
            )
            return None

        # Otherwise, find most frequent (optionally constrained to white_list)
        return self._get_most_frequent_op_name()

    def _get_most_frequent_op_name(self) -> Optional[str]:
        """
        Get the most frequent kernel name, optionally constrained to white_list.

        Returns:
            The most frequent kernel name, or None if no valid name found.
        """
        if not self._name_counts:
            return None

        sorted_counts = sorted(
            self._name_counts.items(), key=lambda x: x[1], reverse=True
        )

        if not self._params.white_list:
            logger.info(
                "Selected most frequent op: %s with count %d",
                sorted_counts[0][0],
                sorted_counts[0][1],
            )
            return sorted_counts[0][0]

        # Filter by white_list
        for name, count in sorted_counts:
            if name in self._params.white_list:
                logger.info(
                    "Selected op from white list: %s with count %d",
                    name,
                    count,
                )
                return name

        logger.warning(
            "No valid op name found in white list. Available ops: %s",
            [name for name, _ in sorted_counts[:10]],
        )
        return None

    def get_target_op(self) -> Optional[str]:
        """Return the selected target op name."""
        return self._target_op
