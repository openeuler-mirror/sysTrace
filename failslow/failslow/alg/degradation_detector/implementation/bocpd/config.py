from pydantic import BaseModel, Field
 
from failslow.alg.degradation_detector.detector import DetectorConfig
from .bocpd_stream import BOCPDStreamConfig

 


class AlertGenerationConfig(BaseModel):
    min_consecutive: int = Field(3, description="Minimum consecutive change points to confirm an alert")
    detect_drop: bool = Field(False, description="Whether to detect dropping change points")
    detect_rise: bool = Field(True, description="Whether to detect rising change points")

    model_config = {"extra": "allow"}


class BOCPDDetectorConfig(DetectorConfig):
    algo_config: BOCPDStreamConfig = BOCPDStreamConfig()
    alert_config: AlertGenerationConfig = AlertGenerationConfig()

    record_obs_size: int = Field(1000, description="The number of recent observations to record for analysis")
    model_config = {"extra": "allow"}

