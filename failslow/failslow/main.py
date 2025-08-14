# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：main.py
Author:  
Create Date: 2025/4/21 9:36
Notes:

"""
import os
import time
import json
import traceback
from datetime import datetime, timezone

from typing import Dict
from failslow.response import AIJobDetectResult

from failslow.slow_node_detection import SlowNodeDetector
from failslow.util.logging_utils import get_default_logger
from failslow.util.constant import METRIC_CONFIG_PATH, MODEL_CONFIG_PATH, AnomalyType, TIMESTAMP_MS_NUM, HOUR_TO_SECONDS

logger = get_default_logger(__name__)


def get_slow_node_detection_time_range(model_args):
    end_time = None
    start_time = None
    with_fail_slow = model_args.get("with_fail_slow", False)
    slow_node_detection_range_times = model_args.get("slow_node_detection_range_times", [])
    # fail_slow_perception_result.json
    fail_slow_perception_path = model_args.get("fail_slow_perception_path", "/log")
    slow_node_detection_time_span_hours = model_args.get("slow_node_detection_time_span_hours", 0.5)
    if slow_node_detection_range_times:
        start_time = slow_node_detection_range_times[0]
        end_time = slow_node_detection_range_times[1]
    else:
        if with_fail_slow:
            # fail slow status, no fail no detect
            if os.path.exists(fail_slow_perception_path):
                file_slow_result_files = [file for file in os.listdir(fail_slow_perception_path) if
                                        AnomalyType.fail_slow in file]
                if file_slow_result_files:
                    file_slow_result_files.sort(reverse=True)

                    latest_slow_result_file = file_slow_result_files[0]
                    latest_slow_result_path = os.path.join(fail_slow_perception_path, latest_slow_result_file)
                    with open(latest_slow_result_path, 'r', encoding='utf-8') as reader:
                        fail_slow_result = json.load(reader)
                    start_time = fail_slow_result.get("start_time")
                    end_time = fail_slow_result.get("end_time")
        else:
            if end_time is None:
                # 若自动触发，当前时间往前推两个小时开始检测
                end_time = int(time.time() * TIMESTAMP_MS_NUM)
                time_span = int(int(slow_node_detection_time_span_hours) * HOUR_TO_SECONDS * TIMESTAMP_MS_NUM)
                start_time = end_time - time_span

    logger.info(
        f"fail slow used:" + str(with_fail_slow) + ", Start time: " + str(start_time) + ", End timestamp: " + str(
            end_time))
    return start_time, end_time


def write_anomaly_info(anomaly_info: Dict, fail_slow_perception_path: str, file_ext: str = ".json"):
    now_time = datetime.now(timezone.utc).astimezone().astimezone()
    now_timestamp = int(now_time.timestamp())
    anomaly_type = anomaly_info.get("anomaly_type", AnomalyType.fail_slow)
    fail_slow_perception_path = os.path.join(fail_slow_perception_path,
                                             f"fail_slow_perception_result_{anomaly_type}_{now_timestamp}{file_ext}")

    try:
        with open(fail_slow_perception_path, 'w', encoding='utf-8') as json_file:
            json.dump(anomaly_info, json_file, ensure_ascii=False, indent=4)
        print(f"writing result to {fail_slow_perception_path}")
    except Exception as e:
        print(f"writing result fail: {e}")


def main():
    with open(METRIC_CONFIG_PATH, 'r', encoding='utf-8') as reader:
        metric_args = json.load(reader)
    with open(MODEL_CONFIG_PATH, 'r', encoding='utf-8') as reader:
        model_args = json.load(reader)

    start_time, end_time = get_slow_node_detection_time_range(model_args)
    detector = SlowNodeDetector(metric_args, model_args, start_time, end_time)
    response: AIJobDetectResult = detector.run()
    logger.info(f"response: {response}")
    slow_node_detection_path = model_args.get("slow_node_detection_path", "/log")
    os.makedirs(slow_node_detection_path, exist_ok=True)
    slow_node_detection_file = os.path.join(slow_node_detection_path, f"slow_node_result_{response.timestamp}.json")
    with open(slow_node_detection_file, "w") as f:
        json.dump(response, f)
    logger.info("==========finished slow node result record ========")

    return response

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        response = AIJobDetectResult()
        response.error_msg = str(traceback.format_exc())
        response.report_time = str(int(time.time() * 1000))
        logger.info(json.dumps(response))
        logger.error(traceback.format_exc())
        logger.error("Slow node detection error! No Result Return")
