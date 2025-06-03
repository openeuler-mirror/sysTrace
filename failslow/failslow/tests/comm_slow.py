# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：comm_slow.py
Author: h00568282/huangbin 
Create Date: 2025/3/8 15:44
Notes:

"""
from typing import  List

def detect_most_anomaly_node(self, data_loader, anomaly_devices, get_rank2group_map, comm_slow_results: List):
    choose_group_type = "PP"
    topo_data = data_loader.topo_data
    rank_id2groups = get_rank2group_map(topo_data)
    anomaly_groups = set(rank_id2groups[choose_group_type][item] for item in anomaly_devices)
    final_result = {"is_bounded_to_card": False, "bounded_results": {}}
    for anomaly_group in anomaly_groups:
        # [(0,1), (1,2), (3,4)]
        detect_res = [1 if rankid in anomaly_devices else 0 for rankid in anomaly_group]
        scores = [detect_res[i - 1 if i - 1 >= 0 else None:i + 1] for i in range(len(detect_res) - 1)]
        scores = [sum(score) / len(score) for score in scores]
        result = []
        for i in range(len(scores) - 1):
            if scores[i] == 0.5 and scores[i + 1] == 1:
                result.append(anomaly_group[i + 1])
            elif scores[i] == 1 and scores[i + 1] == 0.5:
                result.append(anomaly_group[i])
        if result:
            final_result["is_bounded_to_card"] = True
            final_result["bounded_results"].setdefault(choose_group_type + str(anomaly_group), result)
    return final_result
