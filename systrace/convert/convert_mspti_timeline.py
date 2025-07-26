# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：slow_node_detection.py
Author: c00570162/congdechun
Create Date: 2025/3/26 11:23
Notes:
    0726：完善通信算子连线，1 flow s ts 要小于f ts

"""
import sys
import os
import json
import pandas as pd
from collections import defaultdict

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
        "count": row["count"],
        "comm_name": row["Name"]
    }

def split_df(df):
    """
    根据 mode 列将 DataFrame 拆分为 host 和 device 两个 DataFrame
    0为host 1为device
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
    if len(df):
        if "!" in df["Name"].iloc[0]:
            df[['comm_op', 'comm_group', 'data_type', 'count']] = df['Name'].str.replace('comm:', '').str.split('!',
                                                                                                        expand=True)
        else:
            df[['comm_op', 'comm_group', 'data_type', 'count']] = df['Name'].str.replace('comm:', '').str.split(',',
                                                                                                        expand=True)
    try:
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
    except:
        print(f"data is empty!")
        result = {}
    return result


def split_events(events: list):
    sorted_host_events = []
    sorted_device_events = []
    host2device_events = []
    for event in events:
        if event["tid"] == "Host":
            sorted_host_events.append(event)
        else:
            sorted_device_events.append(event)

    if sorted_host_events and sorted_device_events:
        if sorted_device_events[0]["ts"] > sorted_host_events[-1]["ts"]:
            host2device_events = [sorted_host_events[-1], sorted_device_events[0]]

    return sorted_host_events, sorted_device_events, host2device_events

def add_outrank_flow_events(all_events: list, flow_id: int):
    """
        对于同组的通信算子，添加flow in和flow out事件
    """
    # 按ID和commname分组并收集事件
    id_to_events = defaultdict(list)

    for event in all_events:
        if 'args' in event and 'id' in event['args']:
            event_id = event['args']['id']
            comm_name = event['args']['comm_name']
            id_to_events[f"{event_id}_{comm_name}"].append(event)

    # 为每个ID组创建flow事件
    flow_events = []
    for event_id, events in id_to_events.items():
        # 按时间戳排序
        sorted_events = sorted(events, key=lambda x: x['ts'])
        # 按照tid区分device和host
        sorted_host_events, sorted_device_events, host2device_events = split_events(sorted_events)
        # 创建flow事件链
        flow_id = creat_flow_events_in_list(flow_events, flow_id, sorted_host_events)
        flow_id = creat_flow_events_in_list(flow_events, flow_id, sorted_device_events)
        flow_id = creat_flow_events_in_list(flow_events, flow_id, host2device_events)
    return flow_events, flow_id


def creat_flow_events_in_list(flow_events, flow_id, sorted_events):
    for i in range(len(sorted_events) - 1):
        prev = sorted_events[i]
        next_ev = sorted_events[i + 1]

        # 创建flow out事件 (从当前事件指向下一个事件)
        flow_out = {
            'name': 'flow',
            'cat': 'flow',
            'ph': 's',
            'id': flow_id,
            'pid': prev['pid'],
            'tid': prev['tid'],
            # 'ts': prev['ts'] + prev['dur'],
            'ts': prev['ts'],
            'bp': 'e'
        }

        # 创建flow in事件 (下一个事件接收flow)
        flow_in = {
            'name': 'flow',
            'cat': 'flow',
            'ph': 'f',
            'id': flow_id,
            'pid': next_ev['pid'],
            'tid': next_ev['tid'],
            'ts': next_ev['ts'],
            'bp': 'e'
        }

        flow_events.extend([flow_out, flow_in])
        flow_id += 1
    return flow_id


def process_files(root_path, debug: bool = False):
    """
    处理指定路径下的所有 CSV 文件
    """
    csv_files = [file for file in os.listdir(root_path) if file.endswith("csv") and "device" not in file]
    all_ranks = []
    flow_ids = 1
    for csv_file in csv_files:
        if "op_launch" in csv_file:
            continue
        print(f"[INFO] Start file: {csv_file}")
        csv_file_path = os.path.join(root_path, csv_file)
        df = pd.read_csv(csv_file_path)
        if debug:
            df = df.head(12)

        id2name_dict = df[df['Name'].notna()].set_index('Id')['Name'].to_dict()
        df_host, df_device = split_df(df)
        device_id = int(csv_file.split(".")[-2])
        host_result = process_df(df_host, device_id, id2name_dict)
        device_result = process_df(df_device, device_id, id2name_dict)

        if host_result:
            all_ranks.extend(host_result)
        if device_result:
            all_ranks.extend(device_result)

    print(f"[INFO] Generate flow for comm op.")
    outrank_flow_events, flow_id = add_outrank_flow_events(all_ranks, flow_ids)
    all_ranks.extend(outrank_flow_events)
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
    all_ranks = process_files(data_path)
    save_to_json(all_ranks, data_path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_mspti_timeline.py input_file_path")
        sys.exit(1)
    convert_mspti_timeline(sys.argv[1])
