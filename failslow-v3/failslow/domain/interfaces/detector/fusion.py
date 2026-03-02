"""
Fusion strategy interfaces and implementations for combining detection results.

This module provides strategies for fusing results from multiple detectors,
particularly for combining time-dimension and space-dimension detection results.
"""
from abc import ABC, abstractmethod
from typing import Optional, Tuple

import numpy as np


class IFusionStrategy(ABC):
    """
    Abstract interface for detection result fusion strategies.
    
    Fusion strategies combine results from multiple detectors into a single
    unified result. This is particularly useful for combining time-dimension
    and space-dimension detection results.
    """
    
    @abstractmethod
    def fuse(
        self,
        time_result: Optional[np.ndarray],
        space_result: Optional[np.ndarray],
    ) -> Tuple[np.ndarray, str]:
        """
        Fuse time and space detection results.
        
        Args:
            time_result: Time-dimension detection result with shape (time_len, num_ranks).
                        Values are 0 for normal, 1 for anomaly.
            space_result: Space-dimension detection result with shape (time_len, num_ranks).
                         Values are 0 for normal, 1 for anomaly.
        
        Returns:
            Tuple of:
                - Fused anomaly labels with shape (time_len, num_ranks)
                - detect_type: "TIME" | "SPACE" indicating which result was used
        """
        raise NotImplementedError()


class TimeSpaceFusionStrategy(IFusionStrategy):
    """
    Time-space fusion strategy based on v1 GroupAnomalyDetector.time_space_agg logic.
    
    Fusion rules (from v1 implementation):
    - If space detection has anomalies (anomaly count > 0), use space result
    - Otherwise, use time result
    
    This prioritizes space detection when available because space-dimension
    anomalies (cross-rank comparison) are more reliable for identifying
    slow nodes in distributed training scenarios.
    """
    
    def fuse(
        self,
        time_result: Optional[np.ndarray],
        space_result: Optional[np.ndarray],
    ) -> Tuple[np.ndarray, str]:
        """
        Fuse time and space detection results using v1 logic.
        
        Args:
            time_result: Time-dimension detection result
            space_result: Space-dimension detection result
        
        Returns:
            Tuple of (fused_result, detect_type)
        """
        time_available = time_result is not None and time_result.size > 0
        space_available = space_result is not None and space_result.size > 0
        
        if not time_available and not space_available:
            return np.zeros((0, 0), dtype=int), "TIME"
        
        if time_available and not space_available:
            return time_result.astype(int), "TIME"
        
        if space_available and not time_available:
            return space_result.astype(int), "SPACE"
        
        if space_result.size == 0:
            return time_result.astype(int), "TIME"
        
        space_anomaly_count = np.sum(space_result)
        
        if space_anomaly_count > 0:
            return space_result.astype(int), "SPACE"
        else:
            return time_result.astype(int), "TIME"


class OrFusionStrategy(IFusionStrategy):
    """
    OR fusion strategy - any detector flags anomaly means anomaly.
    
    This is a simple union strategy where a point is marked as anomaly
    if either time or space detection flags it.
    """
    
    def fuse(
        self,
        time_result: Optional[np.ndarray],
        space_result: Optional[np.ndarray],
    ) -> Tuple[np.ndarray, str]:
        """
        Fuse using OR logic.
        
        Args:
            time_result: Time-dimension detection result
            space_result: Space-dimension detection result
        
        Returns:
            Tuple of (fused_result, detect_type)
        """
        time_available = time_result is not None and time_result.size > 0
        space_available = space_result is not None and space_result.size > 0
        
        if not time_available and not space_available:
            return np.zeros((0, 0), dtype=int), "TIME"
        
        if time_available and not space_available:
            return time_result.astype(int), "TIME"
        
        if space_available and not time_available:
            return space_result.astype(int), "SPACE"
        
        fused = np.logical_or(time_result, space_result).astype(int)
        return fused, "TIME_AND_SPACE"


class AndFusionStrategy(IFusionStrategy):
    """
    AND fusion strategy - both detectors must flag anomaly.
    
    This is a conservative strategy where a point is only marked as anomaly
    if both time and space detection flag it.
    """
    
    def fuse(
        self,
        time_result: Optional[np.ndarray],
        space_result: Optional[np.ndarray],
    ) -> Tuple[np.ndarray, str]:
        """
        Fuse using AND logic.
        
        Args:
            time_result: Time-dimension detection result
            space_result: Space-dimension detection result
        
        Returns:
            Tuple of (fused_result, detect_type)
        """
        time_available = time_result is not None and time_result.size > 0
        space_available = space_result is not None and space_result.size > 0
        
        if not time_available and not space_available:
            return np.zeros((0, 0), dtype=int), "TIME"
        
        if time_available and not space_available:
            return time_result.astype(int), "TIME"
        
        if space_available and not time_available:
            return space_result.astype(int), "SPACE"
        
        fused = np.logical_and(time_result, space_result).astype(int)
        return fused, "TIME_AND_SPACE"
