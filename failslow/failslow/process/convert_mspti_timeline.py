# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：slow_node_detection.py
Author: h00568282/huangbin
Create Date: 2025/3/26 11:23
Notes:

"""
import os
import json
import pandas as pd
from failslow.process.convert_json2csv import convert_jsons2csv

__all__ = ['convert_mspti_timeline']

MODE = {
    0: "Host",
    1: "Device"
}
OP_COLORS = {
    'HcclAllreduce': "good",
    'HcclAllReduce': "good",
    'HcclAllGather': "bad",
    'HcclBroadcast': "yellow",
    'HcclReduceScatter': "olive",
    'HcclSend': "good",
    'HcclReceive': "good",
    'HcclBatchSendRecv': "thread_state_runnable"
}


def create_args(row):
    return {
        "id": row["Id"],
        "comm_group": row["comm_group"],
        "count": row["count"]
    }


def split_df(df):
    """
    根据 mode 列将 DataFrame 拆分为 host 和 device 两个 DataFrame
    """
    df_host = df[df['SourceKind'] == 0]
    df_device = df[df['SourceKind'] == 1]
    return df_host, df_device


def process_df(data_df, device_id, id2name_dict: dict):
    """
    对 DataFrame 进行处理，包括分组聚合、列拆分、添加新列等操作
    """

    data_df["Name"] = data_df['Id'].map(id2name_dict)
    df = data_df.groupby('Id').agg({
        'Timestamp': ['min', 'max'],
        'Kind': 'first',
        'SourceKind': 'first',
        'Name': 'first',
    }).reset_index()
    df.columns = ['Id', 'start', 'end', 'Kind', 'SourceKind', 'Name']
    df[['comm_op', 'comm_group', 'data_type', 'count']] = df['Name'].str.replace('comm:', '').str.split(',',
                                                                                                        expand=True)
    df = df.drop(columns=['Name'])
    df['cat'] = "hccl"
    df['name'] = df['comm_op']
    df['cname'] = df['comm_op'].map(OP_COLORS)
    df['end'] = df['end'] / 1000.
    df['start'] = df['start'] / 1000.
    df['dur'] = df['end'] - df['start']
    df['ph'] = "X"
    df['pid'] = f"rank_{device_id}"
    df['tid'] = df["SourceKind"].map(MODE)
    df['args'] = df.apply(create_args, axis=1)
    result = df[['cat', 'name', 'ph', 'pid', 'tid', 'start', 'dur', 'cname', 'args']].rename(
        columns={'start': 'ts'}).to_dict(orient='records')
    return result


def process_files(root_path, debug: bool = False):
    """
    处理指定路径下的所有 CSV 文件
    """
    csv_files = [file for file in os.listdir(root_path) if file.endswith("csv") and "device" not in file]
    all_ranks = []
    for csv_file in csv_files:
        if "op_launch" in csv_file:
            continue
        print(f"start file: {csv_file}")
        csv_file_path = os.path.join(root_path, csv_file)
        df = pd.read_csv(csv_file_path)
        if debug:
            df = df.head(12)

        id2name_dict = df[df['Name'].notna()].set_index('Id')['Name'].to_dict()
        # df['name'] = df.groupby('id')['name'].transform(lambda x: x.ffill().bfill())
        df_host, df_device = split_df(df)
        device_id = df_device['msptiObjectId_Ds_DeviceId'].unique()[0]
        host_result = process_df(df_host, device_id, id2name_dict)
        all_ranks.extend(host_result)
        device_result = process_df(df_device, device_id, id2name_dict)
        all_ranks.extend(device_result)
    return all_ranks


def save_to_json(all_ranks, files_path):
    """
    将处理结果保存为 JSON 文件
    """
    output = {
        "traceEvents": all_ranks,
        "stackFrames": {}
    }
    json_output = json.dumps(output, indent=4)
    with open(os.path.join(files_path, f'mspti_comm_ops_timeline.json'), 'w') as f:
        f.write(json_output)


def convert_mspti_timeline(data_path: str):
    '''
        @return:
        @params:
            data_path: mspti采集数据的路径
    '''
    convert_jsons2csv(data_path)
    all_ranks = process_files(data_path)
    save_to_json(all_ranks, data_path)


if __name__ == "__main__":
    files_path = "./data/cal_op_0506"
    convert_mspti_timeline(files_path)
