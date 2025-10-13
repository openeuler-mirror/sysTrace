# coding=utf-8
import os
import pandas as pd
from typing import Dict
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


class HBM_Dataloader:
    def __init__(self, data_path = None):
        self.data_path = data_path
        # self.data_path = "/home/hbdir/npu_data_sampler/0_metrics/npu_device_ranks/2025-10-13-14-test.csv"
   
    def init_save_path(self, file_path):
        self.save_path = os.path.dirname(file_path)

    def get_latest_csv_file(self):
        csv_files = [f for f in os.listdir(self.data_path) if f.endswith('.csv')]
        latest_file = max(csv_files, key=lambda x: os.path.getmtime(os.path.join(self.data_path, x)))
        return os.path.join(self.data_path, latest_file)

    def get_hbm_data_from_csv(self) -> Dict[int, pd.DataFrame]:
        devices_hbm_data_dict = {}
        logger.info(f"process hbm data file: {self.data_path}.")
        if not os.path.exists(self.data_path):
            logger.error(f"file not exist: {self.data_path}")
            return devices_hbm_data_dict
        
        latest_csv_file = self.get_latest_csv_file()
        data_df = pd.read_csv(latest_csv_file)

        grouped = data_df.groupby('device')
        for device_id, group in grouped:
            new_df = group[['time', 'HBM_util']].copy()
            devices_hbm_data_dict[device_id] = new_df

        logger.info(f"get npu metrics data num: {len(devices_hbm_data_dict)}.")
        return devices_hbm_data_dict

if __name__ == "__main__":
    dataloader = HBM_Dataloader()
    dataloader.debug = False
    devices_hbm_data_dict = dataloader.get_hbm_data_from_csv()