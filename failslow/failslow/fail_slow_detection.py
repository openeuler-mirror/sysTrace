'''
env
FAIL_SLOW_STOP: control fail slow stop
'''
import re
import json
import os
import time
from datetime import datetime, timezone
import pandas as pd
from typing import Dict

from failslow.util.constant import AnomalyType
from failslow.util.logging_utils import get_default_logger
from failslow.util.constant import MODEL_CONFIG_PATH
from failslow.dataloader.step_time_reader import StepReader

logger = get_default_logger(__name__)

def detect_step_time_anomalies(data_df: pd.DataFrame, model_args: Dict):
    """
    检测 step_time 序列中的异常值，并记录异常信息

    :param step_times: step_time 序列
    :param window_size: 计算移动平均的窗口大小
    :param threshold: 异常判断的阈值，即当前值与移动平均的差值超过多少倍标准差认为是异常
    :return: 异常信息列表，每个元素为 (异常时刻索引, 异常程度)
    """
    window_size = model_args.get("steps_window_size", 5)
    k_sigma_threshold = model_args.get("k_sigma", 2)
    anomaly_degree_thr = model_args.get("anomaly_degree_thr", 0.2)
    anomalies = []
    step_times = data_df["step_time"]
    timestamps = data_df["time"]
    # print(f"training step time: {step_times}")
    for i in range(len(step_times)):
        if i < window_size:
            continue

        moving_average = sum(step_times[i - window_size:i]) / window_size

        variance = sum((x - moving_average) ** 2 for x in step_times[i - window_size:i]) / window_size
        std_dev = variance ** 0.5

        current_anomaly = False
        current_step_time = step_times[i]

        diff = current_step_time - moving_average
        if diff > k_sigma_threshold * std_dev:
            anomaly_degree = diff / moving_average
            if anomaly_degree > anomaly_degree_thr:
                current_anomaly = True

        if current_anomaly and i + 1 < len(step_times):
            next_step_time = step_times[i + 1]
            next_diff = next_step_time - moving_average
            if next_diff > k_sigma_threshold * std_dev:
                next_anomaly_degree = next_diff / anomaly_degree_thr
                if next_anomaly_degree > anomaly_degree_thr:
                    anomalies.append(
                        {"training_step": i, "anomaly_time": timestamps[i].strftime('%Y-%m-%d %H:%M:%S'),
                         "anomaly_degree": round(anomaly_degree, 3),
                         "anomaly_training_time": f"{current_step_time}ms",
                         "normal_training_time": f"{moving_average}ms"})

    anomaly_info = {}
    if anomalies:
        anomaly_info["is_anomaly"] = True
        anomaly_info["anomaly_count_times"] = len(anomalies)
        anomaly_info["anomaly_info"] = anomalies
    else:
        anomaly_info["is_anomaly"] = False
        anomaly_info["anomaly_count_times"] = 0
        anomaly_info["anomaly_info"] = []
    anomaly_info["start_time"] = int(timestamps.iloc[0])
    anomaly_info["end_time"] = int(timestamps.iloc[len(timestamps) - 1])
    return anomaly_info


def write_anomaly_info(anomaly_info: Dict, fail_slow_perception_path: str, file_ext: str = ".json"):
    now_time = datetime.now(timezone.utc).astimezone().astimezone()
    now_timestamp = int(now_time.timestamp())
    anomaly_type = anomaly_info.get("anomaly_type", AnomalyType.fail_slow)
    fail_slow_perception_path = os.path.join(fail_slow_perception_path,
                                             f"fail_slow_perception_result_{anomaly_type}_{now_timestamp}{file_ext}")

    try:
        with open(fail_slow_perception_path, 'w', encoding='utf-8') as json_file:
            json.dump(anomaly_info, json_file, ensure_ascii=False, indent=4)
        logger.info(f"anomaly info {anomaly_info}")
        logger.info(f"writing result to {fail_slow_perception_path}")
    except Exception as e:
        logger.error(f"writing result fail: {e}")


def get_extract_func_str(log_type: str):
    extrct_func_dict = {
        "timeline": "get_step_data_from_timeline",
        "log": "get_step_data_from_training_log",
    }

    return extrct_func_dict.get(log_type, None)


def run_slow_node_perception(args: Dict):
    training_log = args.get("training_log", "./log/rank0_mindformer.log")
    fail_slow_perception_result = args.get("fail_slow_perception_path", "/log")
    os.makedirs(fail_slow_perception_result, exist_ok=True)
    log_type = args.get("log_type", "timeline")

    task_stable_step = args.get("task_stable_step", 2)  # just for first time detection
    fail_slow_span_mins = args.get("fail_slow_span_mins", 0.1)
    min_statup_detection_steps = args.get("min_startup_detection_steps", 10)
    hang_times_thr = args.get("hang_times_thr", 5)

    detecting_range_steps = [0, 0]
    first_flag = False
    hang_info = []
    next_detection_timestamp = None
    timer_flag = False

    step_reader = StepReader()
    log_extract_func = getattr(step_reader, get_extract_func_str(log_type))

    while True:
        # now_time = datetime.now(timezone.utc).astimezone().astimezone()
        # now_timestamp = now_time.timestamp()
        # if next_detection_timestamp and now_timestamp > next_detection_timestamp:
        #     print("waiting run detection.....")
        # else:
        #     continue
        # next_detection_timestamp = (now_time + timedelta(minutes=fail_slow_span_mins)).timestamp()
        if timer_flag:
            time.sleep(fail_slow_span_mins * 60)
        timer_flag = True


        data = log_extract_func(training_log)
        training_steps = len(data)
        if not training_steps:
            logger.info(f"training data is empty.")
            continue

        # if data not training, record not training times
        # remove model init process
        if training_steps == (detecting_range_steps[1]) and detecting_range_steps[1]:
            logger.info("start hang detection")

            now_time = datetime.now(timezone.utc).astimezone().astimezone()
            format_str = '%Y-%m-%d %H:%M:%S %z'
            now_time_str = now_time.strftime(format_str)
            hang_info.append(now_time_str)
            if len(hang_info) > hang_times_thr:
                # record hang
                anomaly_info = {
                    "anomaly_type": AnomalyType.hang,
                    "detect_point": hang_info,
                    "hang_minutes": fail_slow_span_mins * hang_times_thr
                }
                logger.info(f"hang detection find training process is hang at: {hang_info[0]}")
                write_anomaly_info(anomaly_info, fail_slow_perception_result)
            continue
        else:
            hang_info = []

        new_detecting_range_steps = [0, 0]
        if not detecting_range_steps[1]:
            first_flag = True
            new_detecting_range_steps[1] = training_steps
        else:
            if first_flag:
                # second time detect, start not change
                new_detecting_range_steps[0] = detecting_range_steps[0]
            else:
                new_detecting_range_steps[0] = (detecting_range_steps[0] + detecting_range_steps[1]) // 2
            first_flag = False
            new_detecting_range_steps[1] = training_steps

        range_steps = new_detecting_range_steps[1] - new_detecting_range_steps[0]
        if range_steps < min_statup_detection_steps:
            logger.warning(
                f"[Warning] detecting range step {range_steps} should larger than {min_statup_detection_steps}.")
            continue

        detecting_range_steps = new_detecting_range_steps
        if first_flag:
            detecting_range_steps[0] = task_stable_step
        logger.info(f"Detection data: {detecting_range_steps}.")
        data = data.loc[detecting_range_steps[0]: detecting_range_steps[1]].reset_index(drop=True)
        anomaly_info = detect_step_time_anomalies(data, model_args)

        anomaly_info["anomaly_type"] = AnomalyType.fail_slow
        write_anomaly_info(anomaly_info, fail_slow_perception_result)

        fail_slow_stop_flag = os.getenv('FAIL_SLOW_STOP', 'False').lower() == "true"
        if fail_slow_stop_flag:
            logger.info("User set stop fail slow detection.")
            break


if __name__ == "__main__":
    ''' 循环检测， '''
    with open(MODEL_CONFIG_PATH, 'r', encoding='utf-8') as reader:
        model_args = json.load(reader)

    run_slow_node_perception(model_args)
