import numpy as np

from .time_alg.BOCPDStream import BOCPDStream
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)

BOCPDStreamMethod = {"BOCPDStream": BOCPDStream}


class BOCPDStreamDetector():
    def __init__(self, metric_name, cfg):
        self.detectors = {}
        self.metric_name = metric_name

        self.cfg = cfg

    def fit(self, normal_datas):
        for device_info, normal_data in normal_datas.items():
            BOCPDStream_method = BOCPDStreamMethod[self.cfg["BOCPDStream_method"]["type"]](self.cfg["BOCPDStream_method"],
                                                                                           self.metric_name, device_info)
            self.detectors[device_info] = BOCPDStream_method

    def predict(self, infer_datas):
        locations = {}

        for device_label, infer_data in infer_datas.items():
            locations[device_label] = {}
            detector = self.detectors.get(device_label, None)

            if not detector:
                continue
            infer_metric_data = infer_data[self.metric_name].values
            time_stamp_data = infer_data["timestamp"].values

            detect_result = detector.offline_detecting(infer_metric_data)

            locations[device_label][self.metric_name] = time_stamp_data, detect_result
        return locations