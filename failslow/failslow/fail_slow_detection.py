'''
env
FAIL_SLOW_STOP: control fail slow stop
2025-07-21: add data match for L0 data covering

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

DATA_QUEUE = pd.DataFrame({'time': [], 'step_time': []})
DROP_DATA_LENGTH = 0

def detect_step_time_anomalies(data_df: pd.DataFrame, model_args: Dict):
    """
    检测 step_time 序列中的异常值，并记录异常信息

    :param step_times: step_time 序列
    :param window_size: 计算移动平均的窗口大小
    :param threshold: 异常判断的阈值，即当前值与移动平均的差值超过多少倍标准差认为是异常
    :return: 异常信息列表，每个元素为 (异常时刻索引, 异常程度)
    """
    window_size = model_args.get("steps_window_size", 10)
    k_sigma_threshold = model_args.get("k_sigma", 2)
    anomaly_degree_thr = model_args.get("anomaly_degree_thr", 0.2)
    anomalies = []
    step_times = data_df["step_time"]
    timestamps = data_df["time"]
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
                        {"training_step": i, "anomaly_time": datetime.fromtimestamp(timestamps[i]/1000).strftime('%Y-%m-%d %H:%M:%S'),
                         "anomaly_degree": round(anomaly_degree, 3),
                         "anomaly_training_time": f"{current_step_time}ms",
                         "normal_training_time": f"{moving_average}ms"})

    anomaly_info = {}
    if anomalies:
        anomaly_info["is_anomaly"] = True
        anomaly_info["anomaly_count_times"] = len(anomalies)
        anomaly_info["anomaly_info"] = anomalies
        anomaly_info["anomaly_type"] = AnomalyType.fail_slow
    else:
        anomaly_info["is_anomaly"] = False
        anomaly_info["anomaly_count_times"] = 0
        anomaly_info["anomaly_info"] = []
        anomaly_info["anomaly_type"] = AnomalyType.normal
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

def update_queue_data(data: pd.DataFrame, max_data_queue_steps: int):
    global DATA_QUEUE
    global DROP_DATA_LENGTH
    if len(DATA_QUEUE) > 0:
        history_data_length = len(DATA_QUEUE)  
        DATA_QUEUE = pd.concat([DATA_QUEUE, data], axis=0, ignore_index=True)
        if len(DATA_QUEUE) > max_data_queue_steps:
            start_data_length = min(len(data), history_data_length)
            DROP_DATA_LENGTH += start_data_length
            DATA_QUEUE = DATA_QUEUE[start_data_length:].reset_index(drop=True)
    else:
        DATA_QUEUE = data

def run_slow_node_perception(args: Dict):
    training_log = args.get("training_log", "./log/rank0_mindformer.log")
    fail_slow_perception_result = args.get("fail_slow_perception_path", "/log")
    os.makedirs(fail_slow_perception_result, exist_ok=True)
    log_type = args.get("log_type", "timeline")

    task_stable_step = args.get("task_stable_step", 2)  # just for first time detection
    fail_slow_span_mins = args.get("fail_slow_span_mins", 0.1)  # for detection interval
    max_data_queue_steps = args.get("max_data_queue_steps", 100)
    min_statup_detection_steps = args.get("min_startup_detection_steps", 10)
    hang_times_mins_thr = args.get("hang_times_mins_thr", 0.5)

    detecting_range_steps = [0, 0]
    first_flag = False
    hang_info = []
    hang_time_stamp = []
    next_detection_timestamp = None
    timer_flag = False

    step_reader = StepReader()
    log_extract_func = getattr(step_reader, get_extract_func_str(log_type))

    while True:
        if timer_flag:
            time.sleep(fail_slow_span_mins * 60)
        timer_flag = True
        data = log_extract_func(training_log)
        update_queue_data(data, max_data_queue_steps)

        training_steps = len(DATA_QUEUE)
        if not training_steps:
            logger.info(f"training data is empty.")
            continue

        # if data not training, record not training times
        # remove model init process
        # data not update
        if training_steps == (detecting_range_steps[1]) and detecting_range_steps[1] and (not step_reader.is_update):
            logger.info("start hang detection")
            now_time = datetime.now(timezone.utc).astimezone()
            now_time_stamp = now_time.timestamp()
            format_str = '%Y-%m-%d %H:%M:%S %z'
            now_time_str = now_time.strftime(format_str)
            hang_time_stamp.append(now_time_stamp)
            hang_info.append(now_time_str)
            hang_times = round((now_time_stamp - hang_time_stamp[0]) / 60, 2)
            logger.info(f"hang time min: {hang_times}")
            if hang_time_stamp and hang_times > hang_times_mins_thr:
                # record hang
                anomaly_info = {
                    "is_anomaly": True,
                    "anomaly_count_times": 1, 
                    "anomaly_info": [{
                        "detect_point": hang_info,
                        "hang_minutes": hang_times
                    }],
                    "anomaly_type": AnomalyType.hang,
                    "start_time": int(hang_time_stamp[0] * 1000),
                    "end_time": int(hang_time_stamp[1] * 1000)
                }
                logger.info(f"hang detection find training process is hang at: {hang_info[0]}")
                write_anomaly_info(anomaly_info, fail_slow_perception_result)
            continue
        else:
            hang_info = []
            hang_time_stamp = []

        new_detecting_range_steps = [0, 0]
        new_detecting_range_steps[1] = training_steps + DROP_DATA_LENGTH
        if not detecting_range_steps[1]:
            first_flag = True
        else:
            if first_flag:
                # second time detect, start not change
                new_detecting_range_steps[0] = detecting_range_steps[0]
            else:
                # main update start 
                new_detecting_range_steps[0] = (detecting_range_steps[0] + detecting_range_steps[1]) // 2
            first_flag = False
        range_steps = new_detecting_range_steps[1] - new_detecting_range_steps[0]
        if range_steps < min_statup_detection_steps:
            logger.warning(
                f"[Warning] detecting range step {range_steps} should larger than {min_statup_detection_steps}.")
            continue

        detecting_range_steps = new_detecting_range_steps
        if first_flag:
            detecting_range_steps[0] = task_stable_step
        logger.info(f"Detection data range: {detecting_range_steps}, data queue: {len(DATA_QUEUE)}, drop data length: {DROP_DATA_LENGTH}.")
        detected_data = DATA_QUEUE.loc[(detecting_range_steps[0]-DROP_DATA_LENGTH): (detecting_range_steps[1] - DROP_DATA_LENGTH)].reset_index(drop=True)
        anomaly_info = detect_step_time_anomalies(detected_data, args)

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
