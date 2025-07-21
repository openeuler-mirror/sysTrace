# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：slow_node_detection.py
Author: h00568282/huangbin
Create Date: 2025/06/05 11:23
Notes:

"""
import os
import pandas as pd
from failslow.dataloader import systrace_pb2
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)

class StepReader:
    def __init__(self):
        self.save_path = None
        self.former_first_event = None
        self.is_update = True
        self.debug = False

    def init_save_path(self, file_path):
        self.save_path = os.path.dirname(file_path)

    def get_step_data_from_timeline(self, probuf_file_path):
        logger.info(f"process file: {probuf_file_path}.")
        self.init_save_path(probuf_file_path)
        with open(probuf_file_path, "rb") as f:
            pytorch_data = systrace_pb2.Pytorch()
            pytorch_data.ParseFromString(f.read())
        
        before_start = None
        timestamps = []
        steps_time = []
        if self.debug:
            index = 1
        else:
            index = 0
            
        for stage in pytorch_data.pytorch_stages:
            if index == 0:
                if self.former_first_event:
                    # 表明torch数据未更新，则不用解析数据检测
                    if self.former_first_event.start_us == stage.start_us:
                        self.is_update = False
                        logger.info(f"data not update.")
                        break
                    else:
                        self.former_first_event = stage
                else:
                    self.former_first_event = stage
            
            index += 1
            if "dataloader" in stage.stage_type:
                start_ms = int(stage.start_us / 1000)
                end_ms = int(stage.end_us / 1000)
                dur = end_ms - start_ms
                if before_start is None:
                    before_start = start_ms
                else:
                    steps_time.append(start_ms - before_start)
                    timestamps.append(start_ms)
                    before_start = start_ms
        data = {
                'time': timestamps,
                'step_time': steps_time
            }
        df = pd.DataFrame(data)
        if self.is_update:
            logger.info(f"step time data: {steps_time}.")
            save_file_path = os.path.join(self.save_path, "step_time.csv")
            df.to_csv(save_file_path, index=False)
            logger.info(f"Save file in {save_file_path}")
        else:
            logger.info(f"data not update, not save.")
        
        return df

    def get_step_data_from_training_log(self, log_file_path: str) -> pd.DataFrame:
        self.init_save_path(log_file_path)

        df = None
        try:
            with open(log_file_path, 'r', encoding='utf-8') as file:
                log_lines = file.readlines()

            valid_lines = [line for line in log_lines if 'per_step_time:' in line]
            timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)'
            step_time_pattern = r'per_step_time: (\d+)ms'

            # 准备数据
            timestamps = []
            step_times = []

            for line in valid_lines:
                # 查找时间戳
                timestamp_match = re.search(timestamp_pattern, line)
                # 查找 per_step_time
                step_time_match = re.search(step_time_pattern, line)

                if timestamp_match and step_time_match:
                    timestamp_str = timestamp_match.group(1)
                    step_time = step_time_match.group(1)

                    # 处理日期时间格式，将逗号替换为小数点
                    timestamp_str = timestamp_str.replace(',', '.')
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                    timestamps.append(int(timestamp.timestamp() * 1000))
                    step_times.append(float(step_time))

            data = {
                'time': timestamps,
                'step_time': step_times
            }
            df = pd.DataFrame(data)

            save_file_path = os.path.join(self.save_path, "step_time.csv")
            df.to_csv(save_file_path, index=False)
            logger.info(f"Save file in {save_file_path}")

        except FileNotFoundError:
            logger.error(f"Not find file path: {log_file_path}")
        except Exception as e:
            logger.error(f"Process data fail: {e}")

        return df


if __name__ == "__main__":
    ''' tp4pp2: 仅有rank0 rank4采集到dataloader '''
    probuf_file_path = "/home/sysTrace_dataloader/timeline/localhost.localdomain--00000.timeline"
    step_reader = StepReader()
    step_reader.get_step_data_from_timeline(probuf_file_path)