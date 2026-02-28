# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：post_process.py
Author: 
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
    def __init__(self, metric_args, model_args, node_ip2ranks):
        self.metric_args = metric_args
        self.model_args = model_args
        self.max_num_normal_results = self.model_args.get("max_num_normal_results", 10)
        self.record_kpi_value = self.model_args.get("record_kpi", False)
        self.node_ip2ranks = node_ip2ranks

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

    def get_node_id_by_rank(self, rank):
        node_id = "localhost"
        for tmp_node_ip, ranks in self.node_ip2ranks.items():
            if rank in ranks:
                node_id = tmp_node_ip
                break

        return node_id

    def _process_abnormal_device(self, detect_result: Dict, device_label: str, keep_devices: List,
                                 omitted_devices: List, metric_name: str) -> NodeData:
        method_type = detect_result["detect_result_type"][device_label].get(metric_name, "TIME")
        
        # 获取异常位置数据， (timestamps, values, anomaly_time_ranges)
        anomaly_data = detect_result["anomaly_locations"][device_label][metric_name]
        
        time_stamp_data, values, anomaly_time_ranges = anomaly_data[0], anomaly_data[1], anomaly_data[2]

        label_dict = dict(zip(time_stamp_data.tolist(), values.tolist()))
        node_ip = self.get_node_id_by_rank(device_label)
        
        # 将异常时间范围信息传递给NodeData
        abnormal_node_data = NodeData(
            metric_name, 
            device_label, 
            method_type, 
            node_ip, 
            keep_devices, 
            omitted_devices, 
            anomaly_time_ranges
        )

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
                node_ip = self.get_node_id_by_rank(device_label)
                # 正常设备通常不会有异常时间范围，但我们仍需要保持一致性
                anomaly_data = detect_result["anomaly_locations"].get(device_label, {}).get(metric_name, (None, None, []))
                
                # 如果有异常时间范围信息，提取它
                if len(anomaly_data) >= 3:
                    anomaly_time_ranges = anomaly_data[2]
                else:
                    anomaly_time_ranges = []
                
                normal_node_data = NodeData(metric_name, device_label, "SPACE", node_ip, anomaly_time_ranges=anomaly_time_ranges)
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
                        # 处理异常时间范围的合并
                        old_timestamps, old_values = merged_anomaly_locations[rank][raw_metric_name][0], \
                                                     merged_anomaly_locations[rank][raw_metric_name][1]
                        
                        new_timestamps, new_values = timestamp_with_label[0], timestamp_with_label[1]
                        
                        # 合并时间戳和值
                        combined_timestamps = np.concatenate((old_timestamps, new_timestamps))
                        combined_values = np.concatenate((old_values, new_values)).astype(np.bool).astype(np.float32)
                        
                        # 如果存在异常时间范围，也需要合并
                        if len(timestamp_with_label) >= 3 and len(merged_anomaly_locations[rank][raw_metric_name]) >= 3:
                            old_ranges = merged_anomaly_locations[rank][raw_metric_name][2]
                            new_ranges = timestamp_with_label[2]
                            combined_ranges = old_ranges + new_ranges
                            merged_anomaly_locations[rank][raw_metric_name] = (
                                combined_timestamps,
                                combined_values,
                                combined_ranges
                            )
                        else:
                            merged_anomaly_locations[rank][raw_metric_name] = (
                                combined_timestamps,
                                combined_values
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
