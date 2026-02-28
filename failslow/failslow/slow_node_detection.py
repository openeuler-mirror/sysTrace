# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：slow_node_detection.py
Author:
Create Date: 2025/2/26 11:23
Notes:

"""
import json
import os
import pprint
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.ndimage import gaussian_filter1d

from failslow.alg import space_node_detectors, time_node_detectors
from failslow.dataloader.marker_data_reader import CommGroup, MarkerDataloader
from failslow.dataloader.restore_comm import RestoreComm
from failslow.process.post_process import PostProcess
from failslow.response import AIJobDetectResult
from failslow.util.constant import CommOpType, NcclTableItem, TableItem
from failslow.util.data_interface.aggregator import agg_data_by_time, smooth
from failslow.util.logging_utils import get_default_logger
from failslow.util.utils import is_continuous, is_same_list

Dataloader = MarkerDataloader
logger = get_default_logger(__name__)


SMOOTH_WINDOW_SIZE = 10


class SlowNodeDetector:
    def __init__(
        self, metric_args: Dict, model_args: Dict, start_time=None, end_time=None
    ):
        """
        :param root_path:
        :param hccl_domains: {tp:8, dp:2, pp:1}
        """
        root_path = model_args.get("root_path", None)
        # FIXME: 临时相对路径问题
        current_file_dir = os.path.dirname(os.path.abspath(__file__)) + "/task/custom_v1/"
        if not os.path.isabs(root_path):
            root_path = os.path.join(current_file_dir, root_path)

        self.gpu_or_npu = model_args.get("gpu_or_npu", "gpu")
        logger.info(f"Input data: {root_path}.")
        self.metric_args = metric_args
        self.model_args = model_args

        self._root_path = root_path
        is_filter_data = model_args.get("filter_data_by_timestamp", False)
        self.dataloader = Dataloader(
            self._root_path, self.gpu_or_npu, start_time, end_time, is_filter_data
        )
        self.comm_groups: List[CommGroup] = self.dataloader.extract_comm_domain()
        self.ranks: List = self.dataloader.ranks
        self.hccl_domains = self._init_hccl_domains()

        self.aggregate_method = {}
        node_ip2ranks = self.dataloader.node_id2ranks_dict
        self.post_process = PostProcess(metric_args, model_args, node_ip2ranks)
        self.group_anomaly_detector = GroupAnomalyDetector(model_args)
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
        self.aggregate_method[metric_name] = {"during": during_s}
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

            self.aggregate_method[metric_name][metric_name_key] = [
                func_method_func,
                func_params,
            ]

    def aggregate_by_timestamp_refactor(
        self, df: pd.DataFrame, metric_name: str
    ) -> Dict[str, pd.DataFrame]:
        """
        聚合时间序列数据
        df: pd.DataFrame, 包含至少
            NcclTableItem.ex_start_ts (ms)
        metric_name: str, 指标名称
        """
        start_timestamp_ms: int = df[NcclTableItem.ex_start_ts].min()
        agg_method_by_metric_name = self.aggregate_method.get(metric_name, {})
        during_s = agg_method_by_metric_name.get("during", 5)
        SEC_TO_MS = 1e3

        # TODO: aggregate_window_size 是否要换掉？ 命名也有问题
        df[NcclTableItem.aggregate_window_size] = df[NcclTableItem.ex_start_ts].apply(
            lambda x: ((x - start_timestamp_ms) // (during_s * SEC_TO_MS)) * during_s
            + 1
        )
        # 忽略第一个点
        df = df[df[NcclTableItem.aggregate_window_size] > 0]
        # 忽略极大值 TODO
        df = df[
            df[NcclTableItem.op_execute] < df[NcclTableItem.op_execute].quantile(0.999)
        ]
        # 忽略极小值
        df = df[
            df[NcclTableItem.op_execute] > df[NcclTableItem.op_execute].quantile(0.001)
        ]

        grouped_df = df.groupby(NcclTableItem.aggregate_window_size).agg(
            **{
                NcclTableItem.alg_timestamp: (NcclTableItem.ex_start_ts, "min"),
                **{
                    metric: (
                        NcclTableItem.op_execute,
                        lambda x, fp=func_params: fp[0](x, **fp[1]),
                    )
                    for metric, func_params in agg_method_by_metric_name.items()
                    if metric != "during"
                },
            }
        )
        logger.info(
            f"Aggregated {len(df)} rows to {len(grouped_df)} rows by {during_s} seconds window for metric {metric_name}."
        )
        for col in grouped_df.columns:
            if col == NcclTableItem.alg_timestamp:
                continue
            grouped_df[col] = smooth(grouped_df[col], "gaussian", SMOOTH_WINDOW_SIZE)

        # 丢弃前面若干秒
        # TODO: 秒数设置为参数
        DROP_SECONDS = 10
        min_valid_time = start_timestamp_ms + DROP_SECONDS * SEC_TO_MS
        grouped_df = grouped_df[
            grouped_df[NcclTableItem.alg_timestamp] >= min_valid_time
        ]

        return {
            col: grouped_df[[NcclTableItem.alg_timestamp, col]].reset_index(drop=True)
            for col in grouped_df.columns
            if col != NcclTableItem.alg_timestamp
        }

    def aggregate_by_timestamp_gpu(self, df: pd.DataFrame, metric_name: str) -> Dict:
        """aggregate by start timestamp within during time.
        ex:
            dur_p90 = np.percentile(group['dur'], 90)
            dur_p95 = np.percentile(group['dur'], 95)
            dur_mean_value = group['dur'].mean()
        """

        start_time = df[NcclTableItem.ex_start_ts].min()

        aggregate_method_by_metric_name = self.aggregate_method.get(metric_name, {})
        # logger.info(f"metric_name: {metric_name}, aggregate_method_by_metric_name: {aggregate_method_by_metric_name}")
        during_s = aggregate_method_by_metric_name.get("during", 5)
        during_ms = during_s * 1e3
        # fake interval
        df[NcclTableItem.aggregate_window_size] = (
            (df[NcclTableItem.ex_start_ts] - start_time) // during_ms
        ) + 1
        grouped = df.groupby(NcclTableItem.aggregate_window_size)

        result = []
        for interval, group in grouped:
            start_timestamp = group[NcclTableItem.ex_start_ts].min()
            tmp_point_dict = {NcclTableItem.alg_timestamp: start_timestamp}
            for (
                metric_name_key,
                aggerate_funcs,
            ) in aggregate_method_by_metric_name.items():
                # logger.debug("aggregate %s by %s", metric_name_key, aggerate_funcs)
                if metric_name_key == "during":
                    continue
                func_method_func = aggerate_funcs[0]
                func_params = aggerate_funcs[1]
                value = func_method_func(group[NcclTableItem.op_execute], **func_params)

                tmp_point_dict[metric_name_key] = value

            result.append(tmp_point_dict)
        # logger.info("result_df: %s", result)

        result_df = pd.DataFrame(result)
        cols = result_df.columns

        result_dfs = {}
        for col in cols:
            if col == NcclTableItem.alg_timestamp:
                continue
            result_dfs[col] = result_df[[NcclTableItem.alg_timestamp, col]]
        # logger.info("result_dfs: %s", result_dfs)
        return result_dfs

    def aggregate_by_timestamp(self, df: pd.DataFrame, metric_name: str) -> Dict:
        """aggregate by start timestamp within during time.
        ex:
            dur_p90 = np.percentile(group['dur'], 90)
            dur_p95 = np.percentile(group['dur'], 95)
            dur_mean_value = group['dur'].mean()
        """

        start_time = df[TableItem.ex_start_ts].min()

        aggregate_method_by_metric_name = self.aggregate_method.get(metric_name, {})
        during_s = aggregate_method_by_metric_name.get("during", 5)
        during_ms = during_s * 10**3
        # fake interval
        df[TableItem.aggregate_window_size] = (
            (df[TableItem.ex_start_ts] - start_time) // during_ms
        ) + 1
        grouped = df.groupby(TableItem.aggregate_window_size)

        result = []
        for interval, group in grouped:
            start_timestamp = group[TableItem.ex_start_ts].min()
            tmp_point_dict = {TableItem.alg_timestamp: start_timestamp}
            for (
                metric_name_key,
                aggerate_funcs,
            ) in aggregate_method_by_metric_name.items():
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

    def plot_step_time(
        self, data: pd.DataFrame, metric_name: str, rank: int, ext: str = "latency"
    ):
        import matplotlib.pyplot as plt

        data = np.array(data)
        plt.figure(figsize=(10, 6))
        # 去掉前0.1的数据
        data_len = len(data)
        data = data[int(data_len * 0.1) :]
        plt.plot(data, label="raw_latency", marker="o")
        plt.title(f"Rank: {rank}, comm op {metric_name} latency.")
        plt.xlabel("index")
        plt.ylabel("latency(ms)")
        plt.legend()
        plt.grid(True)
        save_image_path = os.path.join(
            self._root_path, self.model_args.get("save_image", "image")
        )
        os.makedirs(save_image_path, exist_ok=True)
        save_image = os.path.join(
            save_image_path, f"rank_{rank}-op_{metric_name}-{ext}.png"
        )
        plt.savefig(save_image)
        plt.close()

    def plot_all_ranks_step_time(
        self,
        all_ranks_data: Dict[int, pd.Series],
        metric_name: str,
        ext: str = "latency",
    ):
        import matplotlib.pyplot as plt

        plt.figure(figsize=(12, 7))

        # 使用 colormap 以便在 Rank 较多时自动区分颜色
        cmap = plt.get_cmap("tab20")

        # 记录是否成功绘制了数据
        has_data = False

        for i, (rank, series) in enumerate(all_ranks_data.items()):
            data = np.array(series)
            if len(data) == 0:
                continue

            has_data = True

            data_len = len(data)
            data = data[int(data_len * 0.1) :]

            plt.plot(
                data, label=f"Rank {rank}", color=cmap(i % 20), alpha=0.8, linewidth=1.5
            )

        if not has_data:
            plt.close()
            return

        plt.title(f"All Ranks: comm op {metric_name} {ext} comparison")
        plt.xlabel("Step Index (after 10% warmup)")
        plt.ylabel("Latency (ms)")

        if len(all_ranks_data) > 10:
            plt.legend(
                bbox_to_anchor=(1.05, 1), loc="upper left", fontsize="small", ncol=2
            )
        else:
            plt.legend()

        plt.grid(True, linestyle="--", alpha=0.6)
        plt.tight_layout()

        save_image_path = os.path.join(
            self._root_path, self.model_args.get("save_image", "image")
        )
        os.makedirs(save_image_path, exist_ok=True)
        save_filename = os.path.join(
            save_image_path, f"all_ranks-op_{metric_name}-{ext}.png"
        )

        plt.savefig(save_filename, dpi=150)
        plt.close()

    @staticmethod
    def output_anomaly_devices(metric: str, anomaly_location: dict):
        anomaly_devices = []
        for device_info in anomaly_location.keys():
            # 异常点数大于0, 则认为该指标出现异常
            # anomaly_location[device_info][metric] 现在是一个元组 (timestamps, labels, anomaly_time_ranges)
            if len(anomaly_location[device_info][metric]) >= 2:
                # 检查标签数组中的异常点数量
                labels = anomaly_location[device_info][metric][1]
                if np.sum(labels) > 0:
                    anomaly_devices.append(device_info)
            else:
                # 如果没有足够的元素，使用原来的逻辑
                if np.sum(anomaly_location[device_info][metric][1]) > 0:
                    anomaly_devices.append(device_info)

        return anomaly_devices

    def preprocess_group_gpu_data(
        self, group_ranks_list: List, metric_name: str, is_op_launch: bool = False
    ):
        """
        预处理GPU通信组数据，根据算子下发或执行模式读取相应的数据并进行预处理

        Args:
            group_ranks_list (List): 处理通信组的卡号列表
            metric_name (str): 通信算子名称，算子下发带'_launch'后缀，用于metric_config中查找算法配置
            is_op_launch (bool, optional): 判断是算子下发还是算子执行，默认为False

        Returns:
            tuple: (new_detect_group_data, length) - 预处理后的检测组数据列表和数据长度
        """
        # 根据is_op_launch标志决定读取下发数据还是执行数据
        if is_op_launch:
            group_data = self.dataloader.read_op_launch_df_by_ranks(group_ranks_list)
            # 截断'_launch'后缀获取原始算子名称
            mspti_metric_name = metric_name.rsplit("_", 1)[0]
            logger.debug(
                f"读取下发group_data：mspti_metric_name is {mspti_metric_name}"
            )
        else:
            group_data = self.dataloader.read_device_df_by_ranks(group_ranks_list)
            mspti_metric_name = metric_name
        # 预处理数据：1.按通信算子过滤 2.计算通信算子延迟 3.按开始时间戳5秒内设置step组合 4.裁剪最前面step的数据
        new_detect_group_data = []
        length = 0
        all_rank_series = {}
        for rank_id, rdata_df in group_data.items():
            # us转换为ms
            data_df = rdata_df[
                rdata_df[NcclTableItem.ex_comm_op] == mspti_metric_name
            ].copy()
            filtered_count = len(data_df)
            logger.info(
                f"Rank {rank_id} filtered {filtered_count} rows for comm_op {mspti_metric_name} (from {len(rdata_df)})."
            )
            data_df[TableItem.ex_end_ts] = data_df[TableItem.ex_end_ts] / (1e3 * 1.0)
            data_df[TableItem.ex_start_ts] = data_df[TableItem.ex_start_ts] / (
                1e3 * 1.0
            )
            # data_df[TableItem.ex_end_ts] = data_df[TableItem.ex_end_ts]
            # data_df[TableItem.ex_start_ts] = data_df[TableItem.ex_start_ts]
            data_df.loc[:, NcclTableItem.op_execute] = abs(
                data_df[NcclTableItem.ex_end_ts] - data_df[NcclTableItem.ex_start_ts]
            )
            # 处理异常outlier

            # 忽略极大值
            # 忽略极小值
            ub = data_df[NcclTableItem.op_execute].dropna().quantile(0.995)
            lb = data_df[NcclTableItem.op_execute].dropna().quantile(0.005)
            data_df = data_df[(data_df[NcclTableItem.op_execute] < ub)]
            data_df = data_df[(data_df[NcclTableItem.op_execute] > lb)]

            all_rank_series[rank_id] = data_df[NcclTableItem.op_execute]

            # 绘制数据图表
            if self.model_args.get("use_plot", False):
                self.plot_step_time(
                    data_df[NcclTableItem.op_execute], metric_name, rank_id
                )

            # 裁剪训练初始step的数据
            # data_df = data_df[int(len(data_df) * 0.2) :]
            import datetime
            import time

            # ms to second
            start_sec = data_df[NcclTableItem.ex_start_ts].min() / 1e3
            end_sec = data_df[NcclTableItem.ex_end_ts].max() / 1e3
            logger.debug(
                "rank_id:%s %.2f second (start:%s end:%s)",
                rank_id,
                end_sec - start_sec,
                datetime.datetime.fromtimestamp(start_sec),
                datetime.datetime.fromtimestamp(end_sec),
            )

            # aggerated_data_dfs: Dict[str, pd.DataFrame] = self.aggregate_by_timestamp_gpu(
            #    data_df, metric_name
            # )
            aggerated_data_dfs: Dict[str, pd.DataFrame] = (
                self.aggregate_by_timestamp_refactor(data_df, metric_name)
            )

            if aggerated_data_dfs:
                length = len(list(aggerated_data_dfs.values())[0])
            else:
                length = 0
            if not new_detect_group_data:
                new_detect_group_data = [{} for _ in range(len(aggerated_data_dfs))]

            for index, (agge_matric_name, agge_data_df) in enumerate(
                aggerated_data_dfs.items()
            ):
                if "metric_name" not in new_detect_group_data[index].keys():
                    new_detect_group_data[index]["metric_name"] = agge_matric_name

                if "data" not in new_detect_group_data[index].keys():
                    new_detect_group_data[index]["data"] = {}
                new_detect_group_data[index]["data"][rank_id] = agge_data_df

        if self.model_args.get("use_plot", False) and all_rank_series:
            self.plot_all_ranks_step_time(all_rank_series, metric_name)
        """
        # 对 new_detect_group_data 各维度长度进行统一截断
        min_common_length = float('inf')
        
        # 1. 第一遍遍历：找到所有指标、所有 Rank 中的全局最小长度
        for group_item in new_detect_group_data:
            rank_data_dict = group_item.get("data", {})
            for rank_id, series in rank_data_dict.items():
                min_common_length = min(min_common_length, len(series))
        
        # 如果没有数据，重置为 0
        if min_common_length == float('inf'):
            min_common_length = 0
            
        # 2. 第二遍遍历：执行截断
        for group_item in new_detect_group_data:
            rank_data_dict = group_item.get("data", {})
            for rank_id in rank_data_dict.keys():
                # 统一截断到最小长度
                rank_data_dict[rank_id] = rank_data_dict[rank_id][:min_common_length]
        
        length = min_common_length
        logger.info(f"数据对齐完成，所有维度统一截断长度为: {length}")
        # """
        return new_detect_group_data, length

    def preprocess_group_data(
        self,
        group_ranks_list: List,
        comm_name: str,
        metric_name: str,
        is_op_launch: bool = False,
    ):
        """
        @params:
            group_ranks_list: 处理通信组的卡号列表
            comm_name: str, 通信组名称
            metric_name: str, 通信算子名称，算子下发带'_launch'后缀，用于metric_config中查找算法配置
            is_op_launch: bool, 判断是算子下发，算子执行
        """
        # load
        if is_op_launch:
            group_data = self.dataloader.read_op_launch_df_by_ranks(group_ranks_list)
            mspti_metric_name = metric_name.rsplit("_", 1)[0]
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
            data_df[TableItem.ex_end_ts] = data_df[TableItem.ex_end_ts] / (1e6 * 1.0)
            data_df[TableItem.ex_start_ts] = data_df[TableItem.ex_start_ts] / (
                1e6 * 1.0
            )

            data_df[TableItem.op_execute] = abs(
                data_df[TableItem.ex_end_ts] - data_df[TableItem.ex_start_ts]
            )
            # plot data
            if self.model_args.get("use_plot", False):
                self.plot_step_time(data_df[TableItem.op_execute], metric_name, rank_id)

            # 250517: 裁剪训练初始step的数据
            # data_df = data_df[int(len(data_df) * 0.2) :]

            aggerated_data_dfs: Dict = self.aggregate_by_timestamp(data_df, metric_name)
            if aggerated_data_dfs:
                length = len(list(aggerated_data_dfs.values())[0])
            else:
                length = 0
            if not new_detect_group_data:
                new_detect_group_data = [{} for _ in range(len(aggerated_data_dfs))]

            for index, (agge_matric_name, agge_data_df) in enumerate(
                aggerated_data_dfs.items()
            ):
                if "metric_name" not in new_detect_group_data[index].keys():
                    new_detect_group_data[index]["metric_name"] = agge_matric_name

                if "data" not in new_detect_group_data[index].keys():
                    new_detect_group_data[index]["data"] = {}
                new_detect_group_data[index]["data"][rank_id] = agge_data_df
        # 检查是否长度一致
        if new_detect_group_data:
            expected_length = None
            for item in new_detect_group_data:
                for rank_id, data in item["data"].items():
                    current_len = len(data)
                    if expected_length is None:
                        expected_length = current_len
                        logger.debug("期望数据长度设定为：%d", expected_length)
                    elif current_len != expected_length:
                        logger.debug(
                            f"数据长度不一致：rank {rank_id} 的长度为 {current_len}，"
                            f"期望长度为 {expected_length}"
                        )

        return new_detect_group_data, length

    def group_detect_single_kpi(
        self,
        metric_name: str,
        group_ranks_list: List,
        comm_name: str,
        is_group: bool = False,
        is_op_launch: bool = False,
    ) -> List:
        if self.gpu_or_npu == "npu":
            detect_datas, data_len = self.preprocess_group_data(
                group_ranks_list, comm_name, metric_name, is_op_launch=is_op_launch
            )
        else:
            detect_datas, data_len = self.preprocess_group_gpu_data(
                group_ranks_list, metric_name, is_op_launch=is_op_launch
            )
        all_results = []
        for detect_data in detect_datas:
            detection_results = self.detect_single_aggerate_metric(
                data_len, detect_data["metric_name"], detect_data["data"]
            )
            all_results.append(detection_results)

        return all_results

    def detect_single_aggerate_metric(
        self, min_data_len: int, metric_name: str, detect_data
    ):
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
        if min_data_len == 0:
            logger.warning(
                "GROUP data contains EMPTY DATA. GROUP_DATA:%s",
                pprint.pformat(detect_data),
            )
            return [detection_results]
        # 时间检测
        logger.info("work on %s, %s started.", metric_name, "time node compare")
        metric_arg = self.metric_args.get(metric_name_key)
        time_detector_arg = metric_arg.get("time_detector")
        if time_detector_arg is not None:
            time_anomaly_locations = self.group_anomaly_detector.time_node_compare(
                metric_name, time_detector_arg, detect_data
            )
            logger.info(
                f"time node compare result: {self.output_anomaly_devices(metric_name, time_anomaly_locations)}."
            )
        logger.info("work on %s, %s finished.", metric_name, "time node compare")
        logger.info("work on %s, %s started.", metric_name, "space node compare")
        space_detector_arg = metric_arg.get("space_detector")
        if space_detector_arg is not None:
            # 四个以上的对象才进行均质化
            if len(detect_data) >= 2:
                # 空间维度对比，输出异常节点
                space_anomaly_locations = (
                    self.group_anomaly_detector.space_nodes_compare(
                        metric_name, space_detector_arg, detect_data
                    )
                )
                logger.info(
                    f"space_nodes_compare finish, result: {self.output_anomaly_devices(metric_name, space_anomaly_locations)}."
                )
            else:
                logger.info(
                    f"Skip space nodes compare, due to nodes number {len(detect_data)} is smaller than 4."
                )
        else:
            logger.info(f"Skip space nodes compare.")

        # 时间空间结果融合
        # 未采集数据记录，提醒重新验证测试
        empty_ranks = self.dataloader.empty_data_ranks
        anomaly_locations, detect_result_type = (
            self.group_anomaly_detector.time_space_agg(
                time_anomaly_locations,
                space_anomaly_locations,
                metric_name,
                empty_ranks,
            )
        )
        anomaly_devices = self.output_anomaly_devices(metric_name, anomaly_locations)
        detection_results["anomaly_devices"] = anomaly_devices
        detection_results["anomaly_locations"] = anomaly_locations
        detection_results["detect_result_type"] = detect_result_type

        logger.info(f"""Time and space aggregated result: {anomaly_devices}.""")
        logger.info("work on %s, %s end.", metric_name, "slow_node_detection")

        return detection_results

    def get_send_groups(self, metric_name: str) -> List[CommGroup]:
        """
        获取流水线并行的待检测组
        规则：
        1 通信组需要包含流水线并行通信算子
        2
        """
        pp_groups = self.hccl_domains.get("pp", [])

        send_groups = []
        for pp_group in pp_groups:
            for comm_group in self.comm_groups:
                ops_list = list(comm_group.count_ops.keys())
                if metric_name in ops_list and is_same_list(
                    comm_group.group_ranks, pp_group
                ):
                    send_groups.append(comm_group)

        return send_groups

    def merge_group_data(
        self,
        all_group_df: Dict,
        metric_name: str,
        detect_datas: List,
        group_ranks_list: List,
    ):
        """

        :param detect_datas: [{"metric_name":..., "data":...}, ...]
        :return:
        """
        detect_data = detect_datas[0]["data"]
        group_key = f"{group_ranks_list}"

        df_list = list(detect_data.values())
        base_df = df_list[0]

        merged_df = pd.concat([df[metric_name] for df in df_list], axis=1)
        merged_df["merge_value"] = merged_df.mean(axis=1, skipna=True)
        result_df = pd.DataFrame(
            {
                "timestamp": base_df["timestamp"],
                metric_name: merged_df["merge_value"].values,
            }
        )
        all_group_df[group_key] = result_df

    def detect_group_slow(self, metric_name):
        """
            step1 selec large comm group from tp or dp, (eg: tp4, dp2, pp4 -> select tp4)
        :return:
        """
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
        logger.info(f"target_groups: {target_groups}")
        for target_group in target_groups:
            for comm_group in self.comm_groups:
                comm_name = comm_group.comm_name
                group_ranks_list = comm_group.group_ranks
                if (not is_same_list(group_ranks_list, target_group)) or (
                    not is_continuous(group_ranks_list)
                ):
                    continue
                detect_datas, data_len = self.preprocess_group_data(
                    group_ranks_list, comm_name, metric_name
                )
                all_data_len = data_len
                self.merge_group_data(
                    all_group_df, metric_name, detect_datas, group_ranks_list
                )

        logger.info(f"Starting Comm Group Slow Detect.")
        logger.debug(
            "数据长度列表：%s", [len(e[metric_name]) for e in all_group_df.values()]
        )

        detection_results = self.detect_single_aggerate_metric(
            all_data_len, metric_name, all_group_df
        )
        logger.info(f"Finishing Comm Group Slow Detect.\n")

        return detection_results

    def detect_cal_slow(self, metric_name: str = CommOpType.reduce_scatter):
        """comparing tp comm op to find slow card
        :param
        """
        logger.info(f"start detect_cal_slow, metric_name is {metric_name}.\n")
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
        logger.info(f"target_group is {target_groups}.\n")
        if self.gpu_or_npu == "npu":
            for target_group in target_groups:
                for comm_group in self.comm_groups:
                    comm_name = comm_group.comm_name
                    group_ranks_list = comm_group.group_ranks
                    if not is_same_list(group_ranks_list, target_group):
                        logger.info(
                            f"jump detection. Please check group ranks: {group_ranks_list}"
                        )
                        continue

                    logger.info(
                        f"Start Calculating Slow Detect in Group {group_ranks_list}."
                    )
                    group_result = self.group_detect_single_kpi(
                        metric_name, group_ranks_list, comm_name
                    )
                    logger.info(
                        f"Finishing Calculating Slow Detect in Group {group_ranks_list}.\n"
                    )
                    all_results.extend(group_result)
        else:
            for target_group in target_groups:
                group_ranks_list = target_group
                logger.info(
                    f"Start Calculating Slow Detect in Group {group_ranks_list}."
                )
                group_result = self.group_detect_single_kpi(
                    metric_name, group_ranks_list, None
                )
                logger.info(
                    f"Finishing Calculating Slow Detect in Group {group_ranks_list}.\n"
                )
                all_results.extend(group_result)

        return all_results

    def detect_comm_slow(self, metric_name: str = CommOpType.send) -> List[Dict]:
        """use send/recieve comm op to find slow pair. and then aggregate to most anomaly card
        src send, dst recieve
        """
        self.generate_aggregate_strategy(metric_name)
        if self.gpu_or_npu == "gpu":
            group_slow_results = self.detect_group_slow(CommOpType.nccl_all_reduce)
        else:
            group_slow_results = self.detect_group_slow(CommOpType.all_gather)

        all_results = []
        send_groups = self.get_send_groups(metric_name)
        for comm_group in send_groups:
            comm_name = comm_group.comm_name
            group_ranks_list = comm_group.group_ranks
            logger.info(f"Start Comm Pair Slow Detect in Group {group_ranks_list}.")
            result = self.group_detect_single_kpi(
                metric_name, group_ranks_list, comm_name
            )
            logger.info(
                f"Finishing Comm Pair Slow Detect in Group {group_ranks_list}.\n"
            )
            # here vote for most anomaly node
            merge_result = self.post_process.process_comm_slow_result(
                result, group_slow_results["anomaly_devices"], group_ranks_list
            )
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
        if self.gpu_or_npu == "npu":
            for target_group in target_groups:
                for comm_group in self.comm_groups:
                    comm_name = comm_group.comm_name
                    group_ranks_list = comm_group.group_ranks
                    if (not is_same_list(group_ranks_list, target_group)) or (
                        not is_continuous(group_ranks_list)
                    ):
                        continue

                    logger.info(
                        f"Start Op Launching Slow Detect in Group {group_ranks_list}."
                    )
                    group_result = self.group_detect_single_kpi(
                        metric_name, group_ranks_list, comm_name, is_op_launch=True
                    )
                    logger.info(
                        f"Finishing Op Launching Slow Detect in Group {group_ranks_list}.\n"
                    )
                    all_results.extend(group_result)
        else:
            for target_group in target_groups:
                group_ranks_list = target_group
                logger.info(
                    f"Start Op Launching Slow Detect in Group {group_ranks_list}."
                )
                group_result = self.group_detect_single_kpi(
                    metric_name, group_ranks_list, None, is_op_launch=True
                )
                logger.info(
                    f"Finishing Op Launching Slow Detect in Group {group_ranks_list}.\n"
                )
                all_results.extend(group_result)

        return all_results

    def detect(self) -> AIJobDetectResult:
        """
        detect fail slow type with comm ops:
            "cal_slow": "HcclAllGather",
            "op_launch_slow": "HcclAllGather_launch",
            "comm_slow": "HcclBatchSendRecv"
        """
        all_results = []
        enable_cal = self.enable_detect_type.get("enable_cal", True)
        enable_op_launch = self.enable_detect_type.get("enable_op_launch", False)
        enable_comm = self.enable_detect_type.get("enable_comm", False)
        logger.info(
            f"Detection Configuration: enable_cal={enable_cal}, enable_op_launch={enable_op_launch}, enable_comm={enable_comm}"
        )
        if enable_cal:
            cal_slow_op = self.fail_slow_ops.get("cal_slow", CommOpType.all_gather)
            cal_slow_results = self.detect_cal_slow(cal_slow_op)
            all_results.extend(cal_slow_results)
        if enable_op_launch:
            op_launch_slow_op = self.fail_slow_ops.get(
                "op_launch_slow", f"{CommOpType.all_gather}_launch"
            )
            op_launch_results = self.detect_op_launch_slow(op_launch_slow_op)
            all_results.extend(op_launch_results)
        if enable_comm:
            if len(self.ranks) >= 8:
                """default multi node training scene."""
                comm_slow_op = self.fail_slow_ops.get(
                    "comm_slow", CommOpType.batch_send_recv
                )
                comm_slow_results = self.detect_comm_slow(comm_slow_op)
                all_results.extend(comm_slow_results)

        response, all_anomaly_nodes = self.post_process.gen_final_alarm(all_results)
        logger.critical(f"Final anomaly nodes: {all_anomaly_nodes}")
        return response

    def rm_csv_files(self):
        if not os.path.exists(self._root_path):
            return
        for filename in os.listdir(self._root_path):
            file_path = os.path.join(self._root_path, filename)
            if os.path.isfile(file_path) and (
                filename.endswith("op_launch.csv") or filename.endswith("device.csv")
            ):
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.warning(f"file can not remove {file_path}: {e}")

    def run(self) -> AIJobDetectResult:
        response = self.detect()
        # if not self.model_args.get("debug_data", False):
        #    self.rm_csv_files()

        return response


class GroupAnomalyDetector:
    """space compare in group, and time compare in single ts"""

    def __init__(self, model_args: Dict):
        self.model_args = model_args
        pass

    @staticmethod
    def time_space_agg(
        time_anomaly_locations, space_anomaly_locations, metric_name, empty_ranks
    ):
        detect_result_type = {}
        for node_id in time_anomaly_locations.keys():
            # 处理时间异常结果
            time_ret = np.sum(time_anomaly_locations[node_id][metric_name][1])
            
            # 检查是否存在空间异常检测结果
            if space_anomaly_locations and node_id in space_anomaly_locations:
                # 提取空间异常结果
                space_result = space_anomaly_locations[node_id][metric_name]
                space_ret = np.sum(space_result[1])  # [1]是标签
                
                # 如果均质化没有报错则消除告警
                # 若空间检测和时间检测结果都为空，则返回正常值
                # 若时间维度和空间维度都出现异常，以空间维度为主返回结果
                if space_ret == 0 or (space_ret > 0 and time_ret >= 0):
                    # 将空间检测结果替换时间检测结果
                    time_anomaly_locations[node_id][metric_name] = space_result
                    detect_result_type.setdefault(node_id, {}).setdefault(
                        metric_name, "SPACE"
                    )
                else:
                    detect_result_type.setdefault(node_id, {}).setdefault(
                        metric_name, "TIME"
                    )
            else:
                detect_result_type.setdefault(node_id, {}).setdefault(
                    metric_name, "TIME"
                )

        for empty_rank in empty_ranks:
            detect_result_type.setdefault(empty_rank, {}).setdefault(
                metric_name, "LACK"
            )
            timestamp = time_anomaly_locations[node_id][metric_name][0]
            time_anomaly_locations[empty_rank] = {
                metric_name: (timestamp, np.ones(len(timestamp)))
            }

        return time_anomaly_locations, detect_result_type

    def time_node_compare(self, metric_name: str, cfg: Dict, detect_data: Dict):
        detector_class = time_node_detectors.get(cfg.get("type"))
        time_node_detector = detector_class(metric_name=metric_name, cfg=cfg)
        time_node_detector.fit(detect_data)
        locations = time_node_detector.predict(detect_data)
        expert_alarm_window_size = cfg.get("alarm_filter_window_size")

        for device_info, anomaly_locations in locations.items():
            anomaly_data = anomaly_locations[metric_name]
            # anomaly_data[0]是timestamps, anomaly_data[1]是labels
            # 如果已经有时间范围（来自空间检测），保留它们；否则计算新的时间范围
            if len(anomaly_data) >= 3:
                # 已经有时间范围，只需过滤标签
                labels = anomaly_data[1]
                filter_labels = self.alarm_filter(labels, expert_alarm_window_size)
                anomaly_locations[metric_name] = (
                    anomaly_data[0],  # timestamps
                    filter_labels,    # filtered labels
                    anomaly_data[2]   # anomaly_time_ranges
                )
            else:
                # 没有时间范围，计算并添加它们
                labels = anomaly_data[1]
                filter_labels = self.alarm_filter(labels, expert_alarm_window_size)
                
                # 提取异常时间范围
                timestamps = anomaly_data[0]
                anomaly_time_ranges = self.extract_anomaly_time_ranges(timestamps, filter_labels)
                
                anomaly_locations[metric_name] = (
                    timestamps,
                    filter_labels,
                    anomaly_time_ranges
                )

        return locations

    @staticmethod
    def alarm_filter(labels, alarm_filter_window_size):
        copy_labels = np.zeros(len(labels))
        start_index = alarm_filter_window_size
        alarm_points = set()
        for i in range(start_index, len(labels) + 1):
            is_sequential_alarm = (
                np.sum(labels[i - alarm_filter_window_size : i])
                >= alarm_filter_window_size
            )
            if not is_sequential_alarm:
                if np.sum(labels[i - alarm_filter_window_size : i]) > 0:
                    alarm_points.add(i - alarm_filter_window_size)
            else:
                copy_labels[i - alarm_filter_window_size : i] = labels[
                    i - alarm_filter_window_size : i
                ]
        # if alarm_points:
        #     logger.info(f"Alert Remove from point loc", list(alarm_points))

        return copy_labels

    @staticmethod
    def extract_anomaly_time_ranges(timestamps, labels):
        """
        从时间戳和标签中提取异常时间段
        :param timestamps: 时间戳序列
        :param labels: 异常标签序列（0表示正常，1表示异常）
        :return: 异常时间范围列表 [{'start': start_time, 'end': end_time}, ...]
        """
        # FIXME：这里强制对数据进行了对齐，但需确认是否正确，而且labels应该不需要再截断，它一定是更短的那个
        if len(timestamps) != len(labels):
            # 确定最小长度（通常 labels 是被 detect 裁剪短的那一个）
            min_len = min(len(timestamps), len(labels))
            
            # 从末尾删除（截断）多出的部分
            timestamps = timestamps[:min_len]
            labels = labels[:min_len]
            logger.warning(
                "Data was truncated during the detection process. Re-aligning timestamps to match the label length"
            )
        
        anomaly_time_ranges = []
        i = 0
        while i < len(labels):
            if labels[i] == 1:  # 发现异常点
                start_idx = i
                # 找到连续异常序列的结束位置
                while i < len(labels) and labels[i] == 1:
                    i += 1
                end_idx = i - 1
                
                # 获取对应的开始和结束时间戳
                start_time = timestamps[start_idx]
                end_time = timestamps[end_idx]
                
                anomaly_time_ranges.append({
                    'start': start_time,
                    'end': end_time
                })
            else:
                i += 1
        
        return anomaly_time_ranges

    def space_nodes_compare(self, metric_name: str, cfg: Dict, detect_data: Dict):
        detector_class = space_node_detectors.get(cfg.get("type"))
        space_detector = detector_class(cfg)
        df = pd.DataFrame()
        column_list = []
        lengths = []
        timestamps_list = []
        for device_label, infer_data in detect_data.items():
            data_series = infer_data[metric_name]
            lengths.append(len(data_series))
            df[device_label] = data_series
            column_list.append(device_label)
            # 保存时间戳序列
            timestamps_list.append(infer_data[NcclTableItem.alg_timestamp])

        # 检查所有序列长度是否一致
        if len(set(lengths)) > 1:
            logger.debug(
                f"data length inconsistent: "
                f"{dict(zip(detect_data.keys(), lengths))}"
            )

        detect_node_data = df[column_list].values
        logger.debug(
            "detect by space_node_detector: %s", space_detector.__class__.__name__
        )
        labels = space_detector.detect(detect_node_data)

        labels = np.swapaxes(labels, 0, 1)
        space_detect_locations = {}

        for i, device_label in enumerate(column_list):
            space_detect_locations[device_label] = {}
            # 获取对应设备的时间戳
            timestamps = timestamps_list[i]
            device_labels = labels[i]
            
            # 计算异常时间范围
            anomaly_time_ranges = self.extract_anomaly_time_ranges(timestamps, device_labels)
            # FIXME: 这里的timestamps应该就是detect_data[device_label]["timestamp"]，不需要额外再获取
            space_detect_locations[device_label][metric_name] = (
                timestamps,
                device_labels,
                anomaly_time_ranges  # 添加异常时间范围
            )

        return space_detect_locations


if __name__ == "__main__":
    """
    感知触发，感知模块发现性能劣化，触发慢节点定界，能保证获取到的数据，前半部分异常，后半部分正常
    补充感知这块逻辑
    循环触发，每隔半小时触发一次，时序数据有三种状态，时间序列维度上，全部正常，部分正常-部分异常，全部异常，需增加空间对比

    """
    with open("tests/local/run/metric_config.json", "r", encoding="utf-8") as reader:
        metric_args = json.load(reader)
    with open("tests/local/run/model_config.json", "r", encoding="utf-8") as reader:
        model_args = json.load(reader)
    # logger.info(f"metric_args: {json.dumps(metric_args, indent=4)}")
    logger.info(f"model_args: {json.dumps(model_args, indent=4)}")

    start_time = 1743675836
    end_time = 1743691878
    start_time = None
    end_time = None

    from failslow.task.custom_v1.slow_node_locator_detector import (
        get_slow_node_detection_time_range,
    )

    start_time, end_time = get_slow_node_detection_time_range(model_args)
    detector = SlowNodeDetector(metric_args, model_args, start_time, end_time)
    response: AIJobDetectResult = detector.detect()

    logger.info(f"reponse: {[response['abnormalDetail']]}")
    logger.info(f"reponse: {[response['abnormalDetail']]}")
