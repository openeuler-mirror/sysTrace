# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：slow_node_detection.py
Author: 
Create Date: 2025/2/26 11:23
Notes:

"""
import os
import json

import pprint
from typing import List, Dict
import pandas as pd
import numpy as np

from failslow.response import AIJobDetectResult
from failslow.dataloader.marker_data_reader import MarkerDataloader, CommGroup
from failslow.alg import time_node_detectors, space_node_detectors
from failslow.util.logging_utils import get_default_logger
from failslow.util.utils import is_same_list, is_continuous
from failslow.process.post_process import PostProcess
from failslow.util.constant import CommOpType, TableItem
from failslow.dataloader.restore_comm import RestoreComm

Dataloader = MarkerDataloader
logger = get_default_logger(__name__)


class SlowNodeDetector:
    def __init__(self, metric_args: Dict, model_args: Dict, start_time=None, end_time=None):
        '''
        :param root_path:
        :param hccl_domains: {tp:8, dp:2, pp:1}
        '''
        root_path = model_args.get("root_path", None)
        logger.info(f"Input data: {root_path}.")
        self.metric_args = metric_args
        self.model_args = model_args

        self._root_path = root_path
        is_filter_data = model_args.get("filter_data_by_timestamp", False)
        self.dataloader = Dataloader(root_path, start_time, end_time, is_filter_data)
        self.comm_groups: List[CommGroup] = self.dataloader.extract_comm_domain()
        self.ranks: List = self.dataloader.ranks
        self.hccl_domains = self._init_hccl_domains()

        self.aggregate_method = {}
        node_ip2ranks = self.dataloader.node_id2ranks_dict
        self.post_process = PostProcess(metric_args, model_args, node_ip2ranks)
        self.group_anomaly_detector = GroupAnomalyDetector()
        self.enable_detect_type = self.model_args.get("enable_detect_type", {})
        self.fail_slow_ops = self.model_args.get("fail_slow_ops", {})

    def _init_hccl_domains(self):
        hccl_domain_config = self.model_args.get("hccl_domain", {})
        if hccl_domain_config:
            hccl_domains = hccl_domain_config
        else:
            restore_comm = RestoreComm(self.comm_groups, self.ranks)
            restore_comm()
            hccl_domains = restore_comm.comm_domain
        logger.info(f"hccl_domains: {hccl_domains}.")
        return hccl_domains

    def generate_aggregate_strategy(self, metric_name: str):
        def generate_agge_key(_func_method: str, _func_params: Dict):
            for key, value in _func_params.items():
                _func_method += f"_{key}-{value}"

            return _func_method

        aggregations = self.metric_args.get(metric_name, {}).get("aggregation", {})
        during_s = aggregations.get("during_s", 5)
        self.aggregate_method[metric_name] = {
            "during": during_s
        }
        aggerate_funcs = aggregations.get("funcs", [])
        for aggerate_params in aggerate_funcs:
            func_method = aggerate_params.get("func", "mean")
            func_method_func = getattr(np, func_method)
            func_params = aggerate_params.get("func_params", {})

            if len(aggerate_funcs) == 1:
                metric_name_key = metric_name
            else:
                key = generate_agge_key(func_method, func_params)
                metric_name_key = f"{metric_name}!{key}"

            self.aggregate_method[metric_name][metric_name_key] = [func_method_func, func_params]

    def aggregate_by_timestamp(self, df: pd.DataFrame, metric_name: str) -> Dict:
        ''' aggregate by start timestamp within during time.
            ex:
                dur_p90 = np.percentile(group['dur'], 90)
                dur_p95 = np.percentile(group['dur'], 95)
                dur_mean_value = group['dur'].mean()
        '''

        start_time = df[TableItem.ex_start_ts].min()

        aggregate_method_by_metric_name = self.aggregate_method.get(metric_name, {})
        during_s = aggregate_method_by_metric_name.get("during", 5)
        during_ms = during_s * 10 ** 3
        # fake interval
        df[TableItem.aggregate_window_size] = ((df[TableItem.ex_start_ts] - start_time) // during_ms) + 1
        grouped = df.groupby(TableItem.aggregate_window_size)

        result = []
        for interval, group in grouped:
            start_timestamp = group[TableItem.ex_start_ts].min()
            tmp_point_dict = {TableItem.alg_timestamp: start_timestamp}
            for metric_name_key, aggerate_funcs in aggregate_method_by_metric_name.items():
                if metric_name_key == "during":
                    continue
                func_method_func = aggerate_funcs[0]
                func_params = aggerate_funcs[1]
                value = func_method_func(group[TableItem.op_execute], **func_params)

                tmp_point_dict[metric_name_key] = value

            result.append(tmp_point_dict)

        result_df = pd.DataFrame(result)
        cols = result_df.columns

        result_dfs = {}
        for col in cols:
            if col == TableItem.alg_timestamp:
                continue
            result_dfs[col] = result_df[[TableItem.alg_timestamp, col]]

        return result_dfs

    def plot_step_time(self, data: pd.DataFrame, metric_name: str, rank: int, ext: str = "latency"):
        import matplotlib.pyplot as plt

        data = np.array(data)
        plt.figure(figsize=(10, 6))
        # 去掉前0.1的数据
        data_len = len(data)
        data = data[int(data_len * 0.1):]
        plt.plot(data, label='raw_latency', marker='o')
        plt.title(f'Rank: {rank}, comm op {metric_name} latency.')
        plt.xlabel('index')
        plt.ylabel('latency(ms)')
        plt.legend()
        plt.grid(True)
        save_image_path = os.path.join(self._root_path, self.model_args.get("save_image", "image"))
        os.makedirs(save_image_path, exist_ok=True)
        save_image = os.path.join(save_image_path, f"rank_{rank}-op_{metric_name}-{ext}.png")
        plt.savefig(save_image)

    @staticmethod
    def output_anomaly_devices(metric: str, anomaly_location: dict):
        anomaly_devices = []
        for device_info in anomaly_location.keys():
            # 异常点数大于0, 则认为该指标出现异常
            if np.sum(anomaly_location[device_info][metric][1]) > 0:
                anomaly_devices.append(device_info)

        return anomaly_devices

    def preprocess_group_data(self, group_ranks_list: List, comm_name: str, metric_name: str, is_op_launch: bool = False):
        '''
            @params:
                group_ranks_list: 处理通信组的卡号列表
                comm_name: str, 通信组名称
                metric_name: str, 通信算子名称，算子下发带'_launch'后缀，用于metric_config中查找算法配置
                is_op_launch: bool, 判断是算子下发，算子执行 
        '''
        # load
        if is_op_launch:
            group_data = self.dataloader.read_op_launch_df_by_ranks(group_ranks_list)
            mspti_metric_name = metric_name.split("_")[0]
        else:
            group_data = self.dataloader.read_device_df_by_ranks(group_ranks_list)
            mspti_metric_name = metric_name
        # preprocess
        # 1 filter by comm_name
        # 2 filter by comm_op
        # 3 calculate latency of comm_op
        # 4 按照开始时间戳5s内设置step组合
        # 5 裁剪掉最前面step的数据
        new_detect_group_data = []
        length = 0
        for rank_id, data_df in group_data.items():
            data_df = data_df[data_df[TableItem.ex_comm_group] == comm_name]
            # ns -> ms
            data_df = data_df[data_df[TableItem.ex_comm_op] == mspti_metric_name]
            data_df[TableItem.ex_end_ts] = data_df[TableItem.ex_end_ts] / (1e6 * 1.)
            data_df[TableItem.ex_start_ts] = data_df[TableItem.ex_start_ts] / (1e6 * 1.)

            data_df[TableItem.op_execute] = abs(data_df[TableItem.ex_end_ts] - data_df[TableItem.ex_start_ts])
            # plot data
            if self.model_args.get("use_plot", False):
                self.plot_step_time(data_df[TableItem.op_execute], metric_name, rank_id)

            # 250517: 裁剪训练初始step的数据
            data_df = data_df[int(len(data_df) * 0.2):]
            aggerated_data_dfs: Dict = self.aggregate_by_timestamp(data_df, metric_name)
            if aggerated_data_dfs:
                length = len(list(aggerated_data_dfs.values())[0])
            else:
                length = 0
            if not new_detect_group_data:
                new_detect_group_data = [{} for _ in range(len(aggerated_data_dfs))]

            for index, (agge_matric_name, agge_data_df) in enumerate(aggerated_data_dfs.items()):
                if "metric_name" not in new_detect_group_data[index].keys():
                    new_detect_group_data[index]["metric_name"] = agge_matric_name

                if "data" not in new_detect_group_data[index].keys():
                    new_detect_group_data[index]["data"] = {}
                new_detect_group_data[index]["data"][rank_id] = agge_data_df

        return new_detect_group_data, length

    def group_detect_single_kpi(self, metric_name: str, group_ranks_list: List, comm_name: str,
                                is_group: bool = False, is_op_launch: bool = False) -> List:
        detect_datas, data_len = self.preprocess_group_data(group_ranks_list, comm_name, metric_name, is_op_launch=is_op_launch)

        all_results = []
        for detect_data in detect_datas:
            detection_results = self.detect_single_aggerate_metric(data_len, detect_data["metric_name"],
                                                                   detect_data["data"])
            all_results.append(detection_results)

        return all_results

    def detect_single_aggerate_metric(self, min_data_len: int, metric_name: str, detect_data):
        anomaly_devices = []
        anomaly_locations = {}
        time_anomaly_locations = {}
        space_anomaly_locations = {}
        metric_name_key = metric_name.split("!")[0]

        detection_results = {
            "anomaly_devices": anomaly_devices,
            "anomaly_locations": anomaly_locations,
            "detect_result_type": "TIME",
            "metric_name": metric_name,
            "group_data": detect_data,
        }
        logger.info(f"length: {min_data_len} ***************")

        if min_data_len == 0:
            logger.warning("GROUP data contains EMPTY DATA. GROUP_DATA:%s", pprint.pformat(detect_data))
            return [detection_results]
        # 时间检测
        logger.info("work on %s, %s started.", metric_name, "time node compare")
        metric_arg = self.metric_args.get(metric_name_key)
        time_detector_arg = metric_arg.get("time_detector")
        if time_detector_arg is not None:
            time_anomaly_locations = self.group_anomaly_detector.time_node_compare(metric_name, time_detector_arg,
                                                                                   detect_data)
            logger.info(
                f"time node compare result: {self.output_anomaly_devices(metric_name, time_anomaly_locations)}.")
        logger.info("work on %s, %s finished.", metric_name, "time node compare")

        space_detector_arg = metric_arg.get("space_detector")
        if space_detector_arg is not None:
            # 四个以上的对象才进行均质化
            if len(detect_data) >= 4:
                # 空间维度对比，输出异常节点
                space_anomaly_locations = self.group_anomaly_detector.space_nodes_compare(metric_name,
                                                                                          space_detector_arg,
                                                                                          detect_data)
                logger.info(
                    f"space_nodes_compare finish, result: {self.output_anomaly_devices(metric_name, space_anomaly_locations)}.")
            else:
                logger.info(
                    f"Skip space nodes compare, due to nodes number {len(detect_data)} is smaller than 4.")
        else:
            logger.info(f"Skip space nodes compare.")

        # 时间空间结果融合
        # 未采集数据记录，提醒重新验证测试
        empty_ranks = self.dataloader.empty_data_ranks
        anomaly_locations, detect_result_type = self.group_anomaly_detector.time_space_agg(time_anomaly_locations,
                                                                                           space_anomaly_locations,
                                                                                           metric_name, empty_ranks)
        anomaly_devices = self.output_anomaly_devices(metric_name, anomaly_locations)
        detection_results["anomaly_devices"] = anomaly_devices
        detection_results["anomaly_locations"] = anomaly_locations
        detection_results["detect_result_type"] = detect_result_type

        logger.info(f'''Time and space aggregated result: {anomaly_devices}.''')
        logger.info("work on %s, %s end.", metric_name, "slow_node_detection")

        return detection_results

    def get_send_groups(self, metric_name: str) -> List[CommGroup]:
        '''
            获取流水线并行的待检测组
            规则：
            1 通信组需要包含流水线并行通信算子
            2 
        '''
        pp_groups = self.hccl_domains.get("pp", [])

        send_groups = []
        for pp_group in pp_groups:
            for comm_group in self.comm_groups:
                ops_list = list(comm_group.count_ops.keys())
                if metric_name in ops_list and is_same_list(comm_group.group_ranks, pp_group):
                    send_groups.append(comm_group)

        return send_groups

    def merge_group_data(self, all_group_df: Dict, metric_name: str, detect_datas: List, group_ranks_list: List):
        '''

        :param detect_datas: [{"metric_name":..., "data":...}, ...]
        :return:
        '''
        detect_data = detect_datas[0]["data"]
        group_key = f"{group_ranks_list}"

        df_list = list(detect_data.values())
        base_df = df_list[0]

        merged_df = pd.concat([df[metric_name] for df in df_list], axis=1)
        merged_df["merge_value"] = merged_df.mean(axis=1, skipna=True)
        result_df = pd.DataFrame({
            'timestamp': base_df['timestamp'],
            metric_name: merged_df['merge_value'].values
        })
        all_group_df[group_key] = result_df

    def detect_group_slow(self, metric_name):
        '''
            step1 selec large comm group from tp or dp, (eg: tp4, dp2, pp4 -> select tp4)
        :return:
        '''
        self.generate_aggregate_strategy(metric_name)
        tp_groups = self.hccl_domains.get("tp", [])
        dp_groups = self.hccl_domains.get("dp", [])
        dp_size_per_group = len(dp_groups[0])
        tp_size_per_group = len(tp_groups[0])
        if tp_size_per_group == 1:
            metric_name = CommOpType.all_reduce
            target_groups = dp_groups
        else:
            target_groups = tp_groups

        all_group_df = {}
        all_data_len = 0
        for target_group in target_groups:
            for comm_group in self.comm_groups:
                comm_name = comm_group.comm_name
                group_ranks_list = comm_group.group_ranks
                if (not is_same_list(group_ranks_list, target_group)) or (
                        not is_continuous(group_ranks_list)):
                    continue
                detect_datas, data_len = self.preprocess_group_data(group_ranks_list, comm_name, metric_name)
                all_data_len = data_len
                self.merge_group_data(all_group_df, metric_name, detect_datas, group_ranks_list)

        logger.info(f"Starting Comm Group Slow Detect.")
        detection_results = self.detect_single_aggerate_metric(all_data_len, metric_name, all_group_df)
        logger.info(f"Finishing Comm Group Slow Detect.\n")

        return detection_results

    def detect_cal_slow(self, metric_name: str = CommOpType.reduce_scatter):
        ''' comparing tp comm op to find slow card
        :param
        '''
        self.generate_aggregate_strategy(metric_name)
        dp_groups = self.hccl_domains.get("dp", [])
        tp_groups = self.hccl_domains.get("tp", [])
        if dp_groups:
            dp_size_per_group = len(dp_groups[0])
        else:
            dp_size_per_group = 0
        if tp_groups:
            tp_size_per_group = len(tp_groups[0])
        else:
            tp_size_per_group = 0

        if tp_size_per_group == 1:
            target_groups = dp_groups
        else:
            target_groups = tp_groups

        all_results = []
        for target_group in target_groups:
            for comm_group in self.comm_groups:
                comm_name = comm_group.comm_name
                group_ranks_list = comm_group.group_ranks
                if (not is_same_list(group_ranks_list, target_group)):
                    logger.info(f"jump detection. Please check group ranks: {group_ranks_list}")
                    continue

                logger.info(f"Start Calculating Slow Detect in Group {group_ranks_list}.")
                group_result = self.group_detect_single_kpi(metric_name, group_ranks_list, comm_name)
                logger.info(f"Finishing Calculating Slow Detect in Group {group_ranks_list}.\n")
                all_results.extend(group_result)

        return all_results

    def detect_comm_slow(self, metric_name: str = CommOpType.send) -> List[Dict]:
        ''' use send/recieve comm op to find slow pair. and then aggregate to most anomaly card
            src send, dst recieve
        '''
        self.generate_aggregate_strategy(metric_name)
        group_slow_results = self.detect_group_slow(CommOpType.all_gather)

        all_results = []
        send_groups = self.get_send_groups(metric_name)
        for comm_group in send_groups:
            comm_name = comm_group.comm_name
            group_ranks_list = comm_group.group_ranks
            logger.info(f"Start Comm Pair Slow Detect in Group {group_ranks_list}.")
            result = self.group_detect_single_kpi(metric_name, group_ranks_list, comm_name)
            logger.info(f"Finishing Comm Pair Slow Detect in Group {group_ranks_list}.\n")
            # here vote for most anomaly node
            merge_result = self.post_process.process_comm_slow_result(result, group_slow_results["anomaly_devices"],
                                                                      group_ranks_list)
            all_results.extend(merge_result)

        return all_results

    def detect_op_launch_slow(self, metric_name):
        self.generate_aggregate_strategy(metric_name)
        dp_groups = self.hccl_domains.get("dp", [])
        tp_groups = self.hccl_domains.get("tp", [])

        if dp_groups:
            dp_size_per_group = len(dp_groups[0])
        else:
            dp_size_per_group = 0
        if tp_groups:
            tp_size_per_group = len(tp_groups[0])
        else:
            tp_size_per_group = 0
        if tp_size_per_group == 1:
            target_groups = dp_groups
        else:
            target_groups = tp_groups

        all_results = []
        for target_group in target_groups:
            for comm_group in self.comm_groups:
                comm_name = comm_group.comm_name
                group_ranks_list = comm_group.group_ranks
                if (not is_same_list(group_ranks_list, target_group)) or (
                        not is_continuous(group_ranks_list)):
                    continue

                logger.info(f"Start Op Launching Slow Detect in Group {group_ranks_list}.")
                group_result = self.group_detect_single_kpi(metric_name, group_ranks_list, comm_name, is_op_launch=True)
                logger.info(f"Finishing Op Launching Slow Detect in Group {group_ranks_list}.\n")
                all_results.extend(group_result)

        return all_results

    def detect(self) -> AIJobDetectResult:
        '''
        detect fail slow type with comm ops:
            "cal_slow": "HcclAllGather",
            "op_launch_slow": "HcclAllGather_launch",
            "comm_slow": "HcclBatchSendRecv"
        '''
        all_results = []
        enable_cal = self.enable_detect_type.get("enable_cal", True)
        enable_op_launch = self.enable_detect_type.get("enable_op_launch", False)
        enable_comm = self.enable_detect_type.get("enable_comm", False)
        if enable_cal:
            cal_slow_op = self.fail_slow_ops.get("cal_slow", CommOpType.all_gather)
            cal_slow_results = self.detect_cal_slow(cal_slow_op)
            all_results.extend(cal_slow_results)
        if enable_op_launch:
            op_launch_slow_op = self.fail_slow_ops.get("op_launch_slow", f"{CommOpType.all_gather}_launch")
            op_launch_results = self.detect_op_launch_slow(op_launch_slow_op)
            all_results.extend(op_launch_results)
        if enable_comm:
            if len(self.ranks) >= 8:
                ''' default multi node training scene.'''
                comm_slow_op = self.fail_slow_ops.get("comm_slow", CommOpType.batch_send_recv)
                comm_slow_results = self.detect_comm_slow(comm_slow_op)
                all_results.extend(comm_slow_results)

        response, all_anomaly_nodes = self.post_process.gen_final_alarm(all_results)

        return response

    def rm_csv_files(self):
        if not os.path.exists(self._root_path):
            return 
        for filename in os.listdir(self._root_path):
            file_path = os.path.join(self._root_path, filename)
            if os.path.isfile(file_path) and (filename.endswith('op_launch.csv') or filename.endswith('device.csv')):
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.warning(f"file can not remove {file_path}: {e}")
    
    def run(self)  -> AIJobDetectResult:
        response = self.detect()
        if not self.model_args.get("debug_data", False):
            self.rm_csv_files()
        
        return response

class GroupAnomalyDetector:
    ''' space compare in group, and time compare in single ts '''

    def __init__(self):
        pass

    @staticmethod
    def time_space_agg(time_anomaly_locations, space_anomaly_locations, metric_name, empty_ranks):
        detect_result_type = {}
        for node_id in time_anomaly_locations.keys():
            time_ret = np.sum(time_anomaly_locations[node_id][metric_name][1])
            if space_anomaly_locations:
                space_ret = np.sum(space_anomaly_locations[node_id][metric_name][1])
                # 如果均质化没有报错则消除告警
                # 若空间检测和时间检测结果都为空，则返回正常值
                # 若时间维度和空间维度都出现异常，以空间维度为主返回结果
                if space_ret == 0 or (space_ret > 0 and time_ret >= 0):
                    time_anomaly_locations[node_id][metric_name] = space_anomaly_locations[node_id][metric_name]
                    detect_result_type.setdefault(node_id, {}).setdefault(metric_name, "SPACE")
                else:
                    detect_result_type.setdefault(node_id, {}).setdefault(metric_name, "TIME")
            else:
                detect_result_type.setdefault(node_id, {}).setdefault(metric_name, "TIME")

        for empty_rank in empty_ranks:
            detect_result_type.setdefault(empty_rank, {}).setdefault(metric_name, "LACK")
            timestamp = time_anomaly_locations[node_id][metric_name][0]
            time_anomaly_locations[empty_rank] = {metric_name: (timestamp, np.ones(len(timestamp)))}
            
        return time_anomaly_locations, detect_result_type

    def time_node_compare(self, metric_name: str, cfg: Dict, detect_data: Dict):
        detector_class = time_node_detectors.get(cfg.get("type"))
        time_node_detector = detector_class(metric_name=metric_name, cfg=cfg)
        time_node_detector.fit(detect_data)
        locations = time_node_detector.predict(detect_data)
        expert_alarm_window_size = cfg.get("alarm_filter_window_size")

        for device_info, anomaly_locations in locations.items():
            filter_labels = self.alarm_filter(anomaly_locations[metric_name][1], expert_alarm_window_size)
            locations[device_info][metric_name][1][:] = filter_labels

        return locations

    @staticmethod
    def alarm_filter(labels, alarm_filter_window_size):
        copy_labels = np.zeros(len(labels))
        start_index = alarm_filter_window_size
        alarm_points = set()
        for i in range(start_index, len(labels) + 1):
            is_sequential_alarm = (np.sum(labels[i - alarm_filter_window_size:i]) >= alarm_filter_window_size)
            if not is_sequential_alarm:
                if np.sum(labels[i - alarm_filter_window_size:i]) > 0:
                    alarm_points.add(i - alarm_filter_window_size)
            else:
                copy_labels[i - alarm_filter_window_size:i] = labels[i - alarm_filter_window_size:i]
        # if alarm_points:
        #     logger.info(f"Alert Remove from point loc", list(alarm_points))

        return copy_labels

    def space_nodes_compare(self, metric_name: str, cfg: Dict, detect_data: Dict):
        detector_class = space_node_detectors.get(cfg.get("type"))
        space_detector = detector_class(cfg)
        df = pd.DataFrame()
        column_list = []
        for device_label, infer_data in detect_data.items():
            df[device_label] = infer_data[metric_name]
            column_list.append(device_label)

        detect_node_data = df[column_list].values

        labels = space_detector.detect(detect_node_data)

        labels = np.swapaxes(labels, 0, 1)
        space_detect_locations = {}

        i = 0
        for device_label in column_list:
            space_detect_locations[device_label] = {}
            space_detect_locations[device_label][metric_name] = detect_data[device_label]["timestamp"], labels[i]
            i += 1
        return space_detect_locations


if __name__ == "__main__":
    '''
        感知触发，感知模块发现性能劣化，触发慢节点定界，能保证获取到的数据，前半部分异常，后半部分正常
        补充感知这块逻辑
        循环触发，每隔半小时触发一次，时序数据有三种状态，时间序列维度上，全部正常，部分正常-部分异常，全部异常，需增加空间对比
        
    '''
    with open("../config/metric_config.json", 'r', encoding='utf-8') as reader:
        metric_args = json.load(reader)
    with open("../config/model_config.json", 'r', encoding='utf-8') as reader:
        model_args = json.load(reader)

    start_time = 1743675836
    end_time = 1743691878
    start_time = None
    end_time = None
    detector = SlowNodeDetector(metric_args, model_args, start_time, end_time)
    response: AIJobDetectResult = detector.detect()

    logger.info(f"reponse: {response}")
