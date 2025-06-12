# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：convert_json2_csv.py
Author: h00568282/huangbin 
Create Date: 2025/3/28 16:17
Notes:

"""
import os
import json
import pandas as pd
from util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


def convert_json2csv(json_path):
    csv_path = f"{json_path[:-5]}.csv"
    if os.path.exists(csv_path):
        return

    try:
        with open(json_path, 'r', encoding='utf-8') as file:
            content = file.read()
            content = content.replace(']\n[', ',').strip()
            json_data = json.loads(content)
    except:
        logger.error("json data read error")
        json_data = None

    if not json_data:
        return
    df = pd.json_normalize(json_data, sep='_')

    logger.info(f"save path: {csv_path}")
    df.to_csv(csv_path, index=False)


def convert_jsons2csv(root_path):
    json_files = [file for file in os.listdir(root_path) if file.endswith("json")]

    for json_file in json_files:
        logger.info(f"{json_file}")
        json_path = os.path.join(root_path, json_file)
        convert_json2csv(json_path)


if __name__ == "__main__":
    # json_path = "./data/json_data/hccl_activity.3.json"
    # convert_json2csv(json_path)

    root_path = "./data/json_tp4dp1"
    convert_jsons2csv(root_path)