import failslow.util.logging_config as logging_config

logging_config.LOG_LEVEL = "DEBUG"

from failslow.alg.degradation_detector import create_detector, get_available_detectors

import json
from failslow.util.logging_utils import get_default_logger
import time
import numpy as np
import random

logger = get_default_logger(__name__)

AVAILABLE_DETECTORS = get_available_detectors()


def prepare_detector(detector_name):
    detector = create_detector(detector_name, config={})
    logger.info(
        "Prepared detector: %s with config: \n%s",
        detector_name,
        json.dumps(detector.config.model_dump(), indent=2),
    )
    return detector


def generate_synthetic_data():
    np.random.seed(2887)
    data = np.random.normal(loc=30.0, scale=1.0, size=300)
    # Introduce degradation
    data[100:200] += 5.0  # Simulate a rise in values
    data[200:300] -= 5.0  # Simulate a drop in values
    timestamps = data + time.time()
    return data, timestamps


def test_once(detector_name: str):

    data, timestamps = generate_synthetic_data()
    detector = prepare_detector(detector_name)

    alerts = []

    def alert_report_func(alert):
        alerts.append(alert)

    detector.set_alert_reporter(alert_report_func)

    for d in data:
        detector.update(d)

    print(
        f"Total alerts: {len(alerts)}, details:{json.dumps([alert.model_dump() for alert in alerts], indent=2)}"
    )


def test_detector():
    random.seed(2887)
    for i in range(1):
        for detector_name in AVAILABLE_DETECTORS:
            print("\n"*3)
            logger.info(f"Testing detector: %s", detector_name)
            test_once(detector_name=detector_name)


if __name__ == "__main__":
    test_detector()
