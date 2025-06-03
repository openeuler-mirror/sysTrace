# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：post_process.py
Author: h00568282/huangbin 
Create Date: 2025/3/8 14:52
Notes:

"""
import traceback
import numpy as np
from datetime import datetime, timezone
from typing import Dict, Tuple, List
from collections import Counter

from failslow.response import AIJobDetectResult, NodeData, ResultCode
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


class PostProcess():
    def __init__(self, metric_args, model_args):
        self.metric_args = metric_args
        self.model_args = model_args
        self.max_num_normal_results = self.model_args.get("max_num_normal_results", 10)
        self.record_kpi_value = self.model_args.get("record_kpi", False)

    def gen_final_alarm(self, detect_results: List):
        response = AIJobDetectResult()
        response.timestamp = int(datetime.now(timezone.utc).astimezone().astimezone().timestamp())
        all_anomaly_nodes = []

        for index, result in enumerate(detect_results):
            try:
                aomaly_devices = result.get("anomaly_devices")
                all_anomaly_nodes.extend(aomaly_devices)
                self.group_detect_ret_agg(response, result)
            except Exception:
                logger.error(traceback.format_exc())
            logger.info("Group accomplishment: %s/%s", index + 1, len(detect_results))

        return response, all_anomaly_nodes
    def group_detect_ret_agg(self, response: AIJobDetectResult, detect_result: Dict):
        anomaly_device_labels = detect_result.get("anomaly_devices", [])
        if not anomaly_device_labels:
            return

        response.result_code = ResultCode.anomaly
        metric_name = detect_result["metric_name"]
        kpi_params = self.metric_args.get(metric_name, {})
        response(kpi_params.get('type', "compute"))

        keep_devices, omitted_devices = self._determine_keep_omitted_devices(detect_result, anomaly_device_labels,
                                                                             metric_name)
        for device_label in anomaly_device_labels:
            abnormal_node_data = self._process_abnormal_device(detect_result, device_label, keep_devices,
                                                               omitted_devices, metric_name)
            response.abnormal_detail.append(abnormal_node_data)

        self._add_normal_devices(response, detect_result, keep_devices, metric_name)

    def _determine_keep_omitted_devices(self, detect_result: Dict, anomaly_device_labels: List, metric_name: str) -> (
            List, List):
        keep_devices, omitted_devices = [], []
        for device_label in anomaly_device_labels:
            method_type = detect_result.get("detect_result_type", {}).get(device_label, {}).get(metric_name, "TIME")
            if method_type == "SPACE":
                normal_devices = sorted(set(detect_result["group_data"].keys()) - set(anomaly_device_labels))
                keep_devices = normal_devices[:self.max_num_normal_results]
                omitted_devices = normal_devices[self.max_num_normal_results:]
                break  # Assuming only one SPACE type is considered for simplicity.
        return keep_devices, omitted_devices

    def _process_abnormal_device(self, detect_result: Dict, device_label: str, keep_devices: List,
                                 omitted_devices: List, metric_name: str) -> NodeData:
        method_type = detect_result["detect_result_type"][device_label].get(metric_name, "TIME")
        time_stamp_data, values = detect_result["anomaly_locations"][device_label][metric_name]
        label_dict = dict(zip(time_stamp_data.tolist(), values.tolist()))
        abnormal_node_data = NodeData(metric_name, device_label, method_type, keep_devices, omitted_devices)

        if self.record_kpi_value:
            g_ts, g_value = detect_result["group_data"][device_label].values[:, 0], detect_result["group_data"][
                                                                                        device_label].values[:, 1]
            kpi_data = [{str(key): str(value), "abnormal": label_dict.get(key, 0)} for key, value in
                        sorted(zip(g_ts.tolist(), g_value.tolist()), key=lambda x: x[0])]
            abnormal_node_data.kpi_data = kpi_data

        return abnormal_node_data

    def _add_normal_devices(self, response: AIJobDetectResult, detect_result: Dict, keep_devices: List,
                            metric_name: str):
        if keep_devices:
            for device_label in keep_devices:
                normal_node_data = NodeData(metric_name, device_label, "SPACE")
                if self.record_kpi_value:
                    g_ts, g_value = detect_result["group_data"][device_label].values[:, 0], detect_result["group_data"][
                                                                                                device_label].values[:,
                                                                                            1]
                    kpi_data = [{str(key): str(value)} for key, value in zip(g_ts.tolist(), g_value.tolist())]
                    normal_node_data.kpi_data = kpi_data
                response.normal_detail.append(normal_node_data)

    def process_comm_slow_result(self, slow_results: list, slow_group: list, group_ranks: list) -> list:
        '''
            target: find most anomaly rank in pp group.
            step1: Count the number of occurrences of each abnormal node and calculate the score.
            step2: Traverse the ranks greater than or equal to 0.5.
            If the score of an adjacent node is also greater than or equal to 0.5, then this node is considered an abnormal node.
            step3:If the scores of adjacent nodes all meet the condition in step 2,
            it is necessary to check whether there are any issues with the TP or DP communication groups they belong to.
            If there are problems, locate the relevant nodes.
        '''
        anomaly_scores = self.calculate_anomaly_scores(slow_results, group_ranks)
        most_anomaly_ranks = self.find_most_anomaly_ranks(anomaly_scores, group_ranks, slow_group)
        detection_results = self.merge_slow_results(slow_results, most_anomaly_ranks)

        return [detection_results]

    def calculate_anomaly_scores(self, slow_results: list, group_ranks: list) -> dict:
        anomaly_ranks = [rank for slow_result in slow_results for rank in slow_result["anomaly_devices"]]
        anomaly_ranks_dict = Counter(anomaly_ranks)
        detected_times = len(slow_results)

        return {rank: anomaly_ranks_dict.get(rank, 0) / detected_times for rank in group_ranks}

    def find_most_anomaly_ranks(self, anomaly_scores: dict, group_ranks: list, slow_groups: list) -> list:
        most_anomaly_ranks = []
        for index, rank in enumerate(group_ranks):
            if anomaly_scores[rank] == 1.:
                if index > 0 and anomaly_scores[group_ranks[index - 1]] >= 0.5:
                    most_anomaly_ranks.append(rank)
                if index < len(group_ranks) - 1 and anomaly_scores[group_ranks[index + 1]] >= 0.5:
                    most_anomaly_ranks.append(rank)

        filter_anomaly_ranks = []
        slow_groups = ['[6,7]']
        for rank in most_anomaly_ranks:
            for slow_group in slow_groups:
                if rank in eval(slow_group):
                    filter_anomaly_ranks.append(rank)
                    break
        if filter_anomaly_ranks:
            most_anomaly_ranks = filter_anomaly_ranks

        if len(group_ranks) == 2 and len(most_anomaly_ranks) == 2:
            filter_anomaly_ranks = []
            for rank in most_anomaly_ranks:
                for slow_group in anomaly_scores:
                    if rank in eval(slow_group):
                        filter_anomaly_ranks.append(rank)
                        break
            if filter_anomaly_ranks:
                most_anomaly_ranks = filter_anomaly_ranks

        return most_anomaly_ranks

    def merge_slow_results(self, slow_results: list, most_anomaly_ranks: list) -> dict:
        if len(slow_results) <= 1:
            return {}

        metric_name = slow_results[0].get("metric_name", "no_metric").split("!")[0]
        merged_anomaly_locations, merged_anomaly_type = {}, {}

        for slow_result in slow_results:
            self._merge_anomaly_locations(merged_anomaly_locations, slow_result['anomaly_locations'])
            self._merge_anomaly_types(merged_anomaly_type, slow_result['detect_result_type'])

        return {
            "metric_name": metric_name,
            "anomaly_devices": most_anomaly_ranks,
            "group_data": slow_results[0]["group_data"],
            "anomaly_locations": merged_anomaly_locations,
            "detect_result_type": merged_anomaly_type
        }

    def _merge_anomaly_locations(self, merged_anomaly_locations: dict, anomaly_locations: dict):
        for rank, locations in anomaly_locations.items():
            for metric_name_with_aggre, timestamp_with_label in locations.items():
                raw_metric_name = metric_name_with_aggre.split("!")[0]
                if rank not in merged_anomaly_locations:
                    merged_anomaly_locations[rank] = {raw_metric_name: timestamp_with_label}
                else:
                    if raw_metric_name not in merged_anomaly_locations[rank]:
                        merged_anomaly_locations[rank][raw_metric_name] = timestamp_with_label
                    else:
                        tmp_value = merged_anomaly_locations[rank][raw_metric_name][1] + timestamp_with_label[1]
                        merged_anomaly_locations[rank][raw_metric_name] = (
                            merged_anomaly_locations[rank][raw_metric_name][0],
                            tmp_value.astype(np.bool).astype(np.float32)
                        )

    def _merge_anomaly_types(self, merged_anomaly_type: dict, group_result_type: dict):
        for rank, result_type in group_result_type.items():
            for metric_name_with_aggre, detect_type in result_type.items():
                raw_metric_name = metric_name_with_aggre.split("!")[0]
                if rank not in merged_anomaly_type:
                    merged_anomaly_type[rank] = {raw_metric_name: detect_type}
                elif raw_metric_name not in merged_anomaly_type[rank]:
                    merged_anomaly_type[rank][raw_metric_name] = detect_type


if __name__ == "__main__":
    pass
