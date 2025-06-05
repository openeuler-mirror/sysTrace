# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：instant.py
Author: h00568282/huangbin 
Create Date: 2025/3/14 15:44
Notes:

"""

from typing import List, Dict

METRIC_CONFIG_PATH = "/etc/systrace/config/metric_config.json"
MODEL_CONFIG_PATH = "/etc/systrace/config/model_config.json"

TIMESTAMP_MS_NUM = 1000
HOUR_TO_SECONDS = 3600
MS_TO_NS = 1e6

class AnomalyType:
    fail_slow = "failSlow"
    hang = "hang"

class SlowType:
    slow_cal = 0
    slow_comm = 1


class TableItem:
    '''
        mspti sample comm op data
        Domain,Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjecId_Ds_DeviceId,msptiObjecId_Ds_StreamId,msptiObjecId_Pt_ProcessId,msptiObjecId_Pt_ThreadId
    '''
    domain = "Domain"
    flag = "Flag"
    id = "Id"
    kind = "Kind"
    source_kind = "SourceKind"
    name = "Name"
    timestamp = "Timestamp"
    device_id = "msptiObjectId_Ds_DeviceId"
    stream_id = "msptiObjectId_Ds_StreamId"
    process_id = "msptiObjectId_Pt_ProcessId"
    thread_id = "msptiObjectId_Pt_ThreadId"

    ex_start_ts = "Start"
    ex_end_ts = "End"
    ex_comm_op = "Comm_op"
    ex_comm_group = "Comm_group"
    ex_data_type = "Data_type"
    ex_count = "Count"

    op_execute = "Excute_time"
    op_launch = "Launch_time"

    aggregate_window_size = "aggregate_window_size"
    alg_timestamp = "timestamp"


class CommOpType:
    reduce_scatter = "HcclReduceScatter"
    all_reduce = "HcclAllreduce"
    all_gather = "HcclAllGather"
    send = "HcclSend"
    receive = "HcclReceive"
    batch_send_recv = "HcclBatchSendRecv"
    broadcast = "HcclBroadcast"


class CommGroup:
    def __init__(self, comm_name: str, slice_index: int, comm_op: str, ranks: List, count_ops: Dict) -> None:
        self._comm_name = comm_name
        self._comm_op = comm_op
        self._ranks = ranks if isinstance(ranks, List) else [ranks]
        self._slice_index = slice_index
        self._count_ops = count_ops

    @property
    def comm_name(self) -> str:
        return self._comm_name

    @property
    def slice_index(self) -> int:
        return self._slice_index

    @property
    def comm_op(self) -> str:
        return self._comm_op

    @property
    def group_ranks(self) -> List:
        return self._ranks

    def set_group_ranks(self, ranks: List):
        self._ranks = ranks

    @property
    def count_ops(self) -> Dict:
        return self._count_ops

    def extend_group_rank(self, ranks: List):
        self._ranks.extend(ranks)

    def __eq__(self, other) -> bool:
        if isinstance(other, CommGroup):
            return self._comm_name == other._comm_name

        return False

    def __repr__(self):
        return f"CommGroup(_comm_name='{self._comm_name}', comm_op={self._comm_op}, _ranks: {self._ranks}, slice_index: {self._slice_index}, count_ops: {self._count_ops})"
