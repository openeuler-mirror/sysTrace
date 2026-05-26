"""
Implementation of the Composite detector for time-space dual-dimension detection.

This module implements a composite detector that combines time-dimension
and space-dimension detection results using a fusion strategy.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from failslow.domain.interfaces.detector import (
    IBatchDetector,
    IDetector,
    IFusionStrategy,
    TimeSpaceFusionStrategy,
    OrFusionStrategy,
    AndFusionStrategy,
)
from failslow.infrastructure.framework.registration import DetectorRegistry
from .schema import CompositeDetectorParams


class CompositeDetector(DetectorRegistry, IBatchDetector):
    """
    Composite detector for time-space dual-dimension detection.
    
    This detector combines two sub-detectors:
    - time_detector: For time-dimension detection (longitudinal comparison)
    - space_detector: For space-dimension detection (cross-sectional comparison)
    
    Detection results are fused using a fusion strategy.
    
    Relationship with SlidingWindowKSigmaDetector:
    - CompositeDetector is a **composer** that does not implement detection algorithms itself
    - SlidingWindowKSigmaDetector is a **concrete detector** that implements detection algorithms
    - CompositeDetector can combine any two IDetector implementations
    - The same SlidingWindowKSigmaDetector class can be used for both time and space detection
    
    Example usage in config.v3.json:
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
                    "params": {"k": 2.5, "look_back": 8}
                },
                "space_detector": {
                    "type": "sliding_window_ksigma",
                    "params": {"k": 3.0, "look_back": 8}
                }
            }
        }
    """
    
    COMPONENT_NAME = "composite"
    
    def __init__(
        self,
        time_detector: Optional[IDetector] = None,
        space_detector: Optional[IDetector] = None,
        params: Optional[CompositeDetectorParams] = None,
        **kwargs,
    ):
        """
        Initialize the Composite detector.
        
        Args:
            time_detector: Detector for time-dimension detection
            space_detector: Detector for space-dimension detection
            params: Configuration parameters
            **kwargs: Additional keyword arguments for params construction
        """
        if params is not None:
            self._params = params
        else:
            self._params = CompositeDetectorParams(**kwargs)
        
        self._time_detector = time_detector
        self._space_detector = space_detector
        
        self._fusion_strategy = self._create_fusion_strategy()
        self._logger = logging.getLogger(__name__)
    
    def _create_fusion_strategy(self) -> IFusionStrategy:
        """Create fusion strategy based on configuration."""
        fusion_mode = self._params.fusion_mode
        
        if fusion_mode == "time_space":
            return TimeSpaceFusionStrategy()
        elif fusion_mode == "or":
            return OrFusionStrategy()
        elif fusion_mode == "and":
            return AndFusionStrategy()
        else:
            self._logger.warning(
                f"Unknown fusion mode '{fusion_mode}', using 'time_space'"
            )
            return TimeSpaceFusionStrategy()
    
    @property
    def name(self) -> str:
        return self.COMPONENT_NAME
    
    def reset(self) -> None:
        """Reset the detector's internal state."""
        if self._time_detector is not None:
            self._time_detector.reset()
        if self._space_detector is not None:
            self._space_detector.reset()
    
    def detect(
        self,
        data: Union[np.ndarray, "DetectorInput"],
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[np.ndarray, str]:
        """
        Perform dual-dimension detection.
        
        Args:
            data: Either a np.ndarray of shape (time_len, num_ranks) or
                  a DetectorInput containing values and metadata
            context: Optional runtime context
            
        Returns:
            Tuple of:
                - anomaly_labels: np.ndarray of shape (time_len, num_ranks)
                - detect_type: "TIME" | "SPACE" indicating which result was used
        """
        from failslow.domain.models import DetectorInput
        
        if isinstance(data, DetectorInput):
            values = data.values
        else:
            values = np.asarray(data, dtype=float)
        
        if values.ndim != 2:
            raise ValueError(
                f"CompositeDetector requires 2D array (time_len, num_ranks), "
                f"got {values.ndim}D."
            )
        
        time_len, num_ranks = values.shape
        
        time_result = None
        space_result = None
        
        if self._params.enable_time_detect and self._time_detector is not None:
            self._logger.debug(
                f"Running time detection on data shape {values.shape}"
            )
            time_result = self._time_detector.detect(values, context)
        
        if self._params.enable_space_detect and self._space_detector is not None:
            if num_ranks >= self._params.min_ranks_for_space:
                self._logger.debug(
                    f"Running space detection on data shape {values.shape}"
                )
                space_result = self._space_detector.detect(values, context)
            else:
                self._logger.info(
                    f"Skipping space detection: num_ranks ({num_ranks}) < "
                    f"min_ranks_for_space ({self._params.min_ranks_for_space})"
                )
        
        fused_result, detect_type = self._fusion_strategy.fuse(time_result, space_result)
        
        self._logger.info(
            f"Composite detection complete: detect_type={detect_type}, "
            f"anomaly_count={np.sum(fused_result)}"
        )
        
        return fused_result, detect_type
