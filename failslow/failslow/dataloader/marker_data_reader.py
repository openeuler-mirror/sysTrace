import re
import os
import datetime
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from typing import List, Dict, Tuple

from failslow.util.logging_utils import get_default_logger
from failslow.util.constant import CommGroup, TableItem, MS_TO_NS
from failslow.process.convert_json2csv import convert_jsons2csv

logger = get_default_logger(__name__)


def extract_step_time_from_log(root_path):
    log_path = os.path.join(root_path, "train_llama3_8b_preload.log")
    with open(log_path, "r") as f:
        data = f.read()

    pattern = r'elapsed time per iteration \(ms\): (\d+\.\d+)'
    matches = re.findall(pattern, data)

    elapsed_times = [float(match) for match in matches]
    logger.info(f"gt length: {len(elapsed_times)}")
    logger.info(f"{elapsed_times}")

    return elapsed_times


class MarkerDataloader:
    def __init__(self, root_path, start_time=None, end_time=None, is_filter_data=False):
        self._root_path = root_path
        self.start_time = start_time
        self.end_time = end_time
        convert_jsons2csv(self._root_path)

        self.csv_files = self.get_csv_files()
        self.ranks = self.get_all_ranks()
        self.id2name_maps = dict()
        self.local_d_files = dict()
        self.local_op_launch_files = dict()
        self.is_filter_data = is_filter_data
        self.empty_data_ranks = []
        self.node_id2ranks_dict = {}

    @staticmethod
    def read_csv(file_path):
        if os.path.exists(file_path):
            data_df = pd.read_csv(file_path)
        else:
            data_df = None

        return data_df

    def get_node_ip_by_rank(self, rank):
        for node_ip, ranks in self.node_id2ranks_dict.items():
            if rank in ranks:
                return node_ip
        
        return None

    def read_local_device_df_by_rank(self, rank: int):
        node_ip = self.get_node_ip_by_rank(rank)
        file = f"hccl_activity-{node_ip}-.{rank}.csv"
        if file in self.csv_files:
            local_device_path = self.local_d_files.get(file, None)
            if local_device_path:
                return pd.read_csv(local_device_path)

        return None

    def read_device_df_by_ranks(self, ranks: List):
        comm_results: Dict = {}
        for rank in ranks:
            local_device_df = self.read_local_device_df_by_rank(rank)
            if local_device_df is not None:
                comm_results[rank] = local_device_df

        return comm_results
    
    def read_local_op_launch_df_by_rank(self, rank: int):
        node_ip = self.get_node_ip_by_rank(rank)
        file = f"hccl_activity-{node_ip}-.{rank}.csv"
        if file in self.csv_files:
            local_device_path = self.local_op_launch_files.get(file, None)
            if local_device_path:
                return pd.read_csv(local_device_path)

        return None

    def read_op_launch_df_by_ranks(self, ranks: List):
        comm_results: Dict = {}
        for rank in ranks:
            local_device_df = self.read_local_op_launch_df_by_rank(rank)
            if local_device_df is not None:
                comm_results[rank] = local_device_df

        return comm_results

    def _collect_all_csv_data(self) -> Dict:
        comm_results: Dict = {}
        for file in self.csv_files:
            rank = int(file.split('.')[-2])
            file_path = os.path.join(self._root_path, file)
            comm_results[rank] = pd.read_csv(file_path, delimiter=';')

        return comm_results

    def get_csv_files(self):
        if not os.path.exists(self._root_path):
            logger.warning(f"Data path: {self._root_path} not exist, please confirm input data.")
            return []
        return [file for file in os.listdir(self._root_path) if file.endswith("csv") and "device" not in file and "op_launch" not in file]

    def get_all_ranks(self) -> List:
        ranks = []
        for csv_file in self.csv_files:
            rank = int(csv_file.split('.')[-2])
            ranks.append(rank)
        logger.info(f"AI model all ranks: {ranks}")
        return ranks

    def create_comm_groups(self, comm_names: List[str], slice_indices: List[int], comm_ops: List[str], rank,
                           count_ops) -> List[CommGroup]:
        comm_groups = []
        for comm_name, slice_index, comm_op in zip(comm_names, slice_indices, comm_ops):
            ''' megatron slice index 0 for all ranks time sync'''
            if slice_index == 0:
                continue
            count_op = count_ops[comm_name]
            comm_groups.append(CommGroup(comm_name, slice_index, comm_op, rank, count_op))

        return comm_groups

    def extend_group_ranks(self, all_comm_groups: List[CommGroup], new_comm_groups: List[CommGroup]) -> None:
        if all_comm_groups:
            extra_comm_groups = []
            for new_comm_group in new_comm_groups:
                for comm_group in all_comm_groups:
                    if new_comm_group == comm_group:
                        comm_group.extend_group_rank(new_comm_group.group_ranks)
                        break
                else:
                    extra_comm_groups.append(new_comm_group)
            all_comm_groups.extend(extra_comm_groups)
        else:
            all_comm_groups.extend(new_comm_groups)

    def extract_device_df(self, input_df: pd.DataFrame) -> pd.DataFrame:
        ''' sourcekind 1表示 device, 0表示host '''
        df_device = input_df[input_df[TableItem.source_kind] == 1]

        return df_device

    def extract_op_launch_df(self, input_df: pd.DataFrame) -> pd.DataFrame:
        '''
            source_kind: 0 host, 1 device
            取: 0的max 1的min
        :param input_df:
        :return:
        '''
        mode_0_max_timestamp = input_df[input_df[TableItem.source_kind] == 0].groupby(TableItem.id)[
            TableItem.timestamp].idxmax()
        result_mode_0 = input_df.loc[mode_0_max_timestamp]

        mode_1_min_timestamp = input_df[input_df[TableItem.source_kind] == 1].groupby(TableItem.id)[
            TableItem.timestamp].idxmin()
        result_mode_1 = input_df.loc[mode_1_min_timestamp]

        final_result = pd.concat([result_mode_0, result_mode_1]).sort_values(by=TableItem.id)

        return final_result

    def extract_id2name_map(self, csv_file: str, input_df: pd.DataFrame) -> None:
        id2name_map = input_df[input_df[TableItem.name].notna()].set_index(TableItem.id)[TableItem.name].to_dict()
        self.id2name_maps[csv_file] = id2name_map

    def extract_comm_domain(self):
        all_comm_groups = []
        for csv_file in self.csv_files:
            csv_path = os.path.join(self._root_path, csv_file)
            data_df = self.read_csv(csv_path)
            self.extract_id2name_map(csv_file, data_df)

            device_df = self.extract_device_df(data_df)
            op_launch_df = self.extract_op_launch_df(data_df)

            device_ids = int(csv_file.split(".")[-2])
            self.get_node_ids_from_filepath(csv_file, device_ids)
            if not len(device_df):
                self.empty_data_ranks.append(device_ids)
            # 分列以及生成start,end timestamp
            device_df = self.process_df(device_df, csv_file)
            op_launch_df = self.process_df(op_launch_df, csv_file)
            self.save_device_df(device_df, csv_file)
            self.save_op_launch_df(op_launch_df, csv_file)
            if len(device_df):
                comm_groups_ids = device_df[TableItem.ex_comm_group].unique()   
            else:
                comm_groups_ids = []
            selected_indices, comm_ops = self.get_ops_by_comm_name(comm_groups_ids, device_df)
            count_ops = self.get_count_ops(comm_groups_ids, device_df)

            logger.info(f"src file:{csv_file}, selected comm op index: {selected_indices}, comm ops: {comm_ops}")
            comm_groups = self.create_comm_groups(comm_groups_ids, selected_indices, comm_ops, device_ids, count_ops)
            self.extend_group_ranks(all_comm_groups, comm_groups)

        logger.info(f"node id and ranks: {self.node_id2ranks_dict}")
        all_comm_groups = self.get_fp_comm_groups(all_comm_groups)
        return all_comm_groups

    def get_node_ids_from_filepath(self, csv_file: str, rank: int):
        ''' csv_file: hccl_activity-9.13.100.7-.0.csv '''
        node_id = csv_file.split("-")[1]
        if node_id not in self.node_id2ranks_dict.keys():
            self.node_id2ranks_dict[node_id] = [rank]
        else:
            self.node_id2ranks_dict[node_id].append(rank)

    def fix_node_ids2ranks(self):
        for rank_empty in self.empty_data_ranks:
            empty_ranks_interg = rank_empty // 8
            match_flag = False
            for node_id, ranks in self.node_id2ranks_dict.items():
                if ranks:
                    node_rank_interg = ranks[0] // 8
                    if node_rank_interg == empty_ranks_interg:
                        self.node_id2ranks_dict[node_id].append(rank_empty)
                        match_flag = True
                        break
                if match_flag:
                    break

    def process_df(self, data_df: pd.DataFrame, csv_file: str, op_ext=None) -> pd.DataFrame:
        """
        对 DataFrame 进行处理，包括分组聚合、列拆分、添加新列等操作
        """
        id2name_dict = self.id2name_maps[csv_file]
        data_df.loc[:, TableItem.name] = data_df[TableItem.id].map(id2name_dict)
        df = data_df.groupby(TableItem.id).agg({
            TableItem.timestamp: ['min', 'max'],
            TableItem.kind: 'first',
            TableItem.source_kind: 'first',
            TableItem.name: 'first',
        }).reset_index()
        df.columns = [TableItem.id, TableItem.ex_start_ts, TableItem.ex_end_ts, TableItem.kind, TableItem.source_kind,
                      TableItem.name]

        metric_name = TableItem.ex_comm_op
        if op_ext:
            metric_name = f"{metric_name}_launch"

        if len(df):
            if "!" in df["Name"].iloc[0]:
                df[[metric_name, TableItem.ex_comm_group, TableItem.ex_data_type, TableItem.ex_count]] = df[
                    TableItem.name].str.replace('comm:', '').str.split('!', expand=True)
            else:
                df[[metric_name, TableItem.ex_comm_group, TableItem.ex_data_type, TableItem.ex_count]] = df[
                    TableItem.name].str.replace('comm:', '').str.split(',', expand=True)

        return df

    def extract_data_by_time_range(self, data: pd.DataFrame) -> pd.DataFrame:
        if self.end_time is None and self.start_time is None:
            # no detection
            clip_data = data.iloc[0:0]
        else:
            if self.is_filter_data:
                start_time = self.start_time * MS_TO_NS
                end_time = self.end_time * MS_TO_NS
                clip_data = data[(data[TableItem.ex_end_ts] >= start_time) & (data[TableItem.ex_end_ts] <= end_time)]
            else:
                clip_data = data

        return clip_data

    def save_device_df(self, device_df: pd.DataFrame, csv_file: str) -> None:
        csv_path = os.path.join(self._root_path, csv_file)
        save_path = f"{csv_path[:-4]}_device.csv"
        self.local_d_files[csv_file] = save_path
        device_df = self.extract_data_by_time_range(device_df)
        device_df.to_csv(save_path, index=False)

    def save_op_launch_df(self, op_launch_df: pd.DataFrame, csv_file: str) -> None:
        csv_path = os.path.join(self._root_path, csv_file)
        save_path = f"{csv_path[:-4]}_op_launch.csv"
        self.local_op_launch_files[csv_file] = save_path

        op_launch_df = self.extract_data_by_time_range(op_launch_df)
        op_launch_df.to_csv(save_path, index=False)

    def get_fp_comm_groups(self, comm_groups: List[CommGroup]):
        # group_rank: comm_group
        # 相同rank的通信组仅保留一组作为前向
        fp_comm_groups = {}
        for comm_group in comm_groups:
            group_ranks = str(comm_group.group_ranks)
            if group_ranks not in fp_comm_groups:
                fp_comm_groups[group_ranks] = comm_group
            else:
                in_fp_comm_group = fp_comm_groups[group_ranks]
                in_count_ops = in_fp_comm_group.count_ops
                in_ops_list = list(in_count_ops.keys())

                count_ops = comm_group.count_ops
                ops_list = list(count_ops.keys())
                if len(ops_list) > len(in_ops_list):
                    fp_comm_groups[group_ranks] = comm_group
                elif len(ops_list) == len(in_ops_list):
                    # judge by count
                    in_num_per_ops = Counter(in_count_ops)
                    num_per_ops = Counter(count_ops)

                    in_large_num_per_count = list(in_num_per_ops.values())[0]
                    large_num_per_count = list(num_per_ops.values())[0]
                    if large_num_per_count > in_large_num_per_count:
                        fp_comm_groups[group_ranks] = comm_group

        logger.info(f"comm groups: {len(comm_groups)}, fp comm groups: {len(fp_comm_groups)}")
        return list(fp_comm_groups.values())

    def _simple_match_groups(self, all_comm_ids: Dict, all_devices_id: Dict):
        comm_groups = {}
        for csv_file, comm_ids in all_comm_ids.items():
            devices_id = all_devices_id[csv_file]
            for comm_id in comm_ids:
                if comm_id in comm_groups.keys():
                    comm_groups[comm_id].append(devices_id)
                else:
                    comm_groups[comm_id] = [devices_id]
        logger.info(f"comm groups: {comm_groups}")
        return comm_groups

    def get_count_ops(self, comm_group_ids: List, data_df: pd.DataFrame) -> Dict:
        count_ops = {}
        for comm_group_id in comm_group_ids:
            count_ops[comm_group_id] = {}
            group_data_df = data_df[data_df[TableItem.ex_comm_group] == comm_group_id]
            ops = group_data_df[TableItem.ex_comm_op].unique()
            for op in ops:
                count_ops[comm_group_id][op] = len(group_data_df[group_data_df[TableItem.ex_comm_op] == op])

        return count_ops

    def get_ops_by_comm_name(self, comm_group_ids: List, data_df: pd.DataFrame) -> Tuple[List, List]:
        '''表内所有的comm_groups找到第一个索引的索引号和算子'''
        selected_indices = []
        comm_ops = []
        for comm_id in comm_group_ids:
            mask = data_df[TableItem.ex_comm_group] == comm_id
            if sum(mask) == 0:
                continue
            index = int(data_df[mask].index[0])
            comm_ops.append(data_df.loc[index][TableItem.ex_comm_op])
            selected_indices.append(index)

        return selected_indices, comm_ops

    def get_broadcast_ops(self, broadcast_ops="HcclBroadcast"):
        ''' Use broadcast time estimate step time '''
        # for csv_file in self.csv_files:
        #     csv_path = os.path.join(self._root_path, csv_file)
        #     data_df = self.read_csv(csv_path)
        #     data_df['start_stamp'] = data_df['start'].apply(self.convert_timestamp2datetime)
        #     data_df['end_stamp'] = data_df['end'].apply(self.convert_timestamp2datetime)
        #     data_df.to_csv(f"new_{csv_file}", index=False)

        csv_path = os.path.join(self._root_path, self.csv_files[0])
        data_df = self.read_csv(csv_path)
        data_df['start_stamp'] = data_df[TableItem.ex_start_ts].apply(self.convert_timestamp2datetime)
        # data_df.to_csv("./broadcast_df.csv", index=False)
        # n = len(data_df)
        # quarter = n // 4
        # data_df = data_df[quarter:]
        mask = data_df[TableItem.name] == broadcast_ops
        broadcast_df = data_df[mask]
        logger.info(f"broadcast df length: {len(broadcast_df)}")
        broadcast_df['start_stamp'] = broadcast_df[TableItem.ex_start_ts].apply(self.convert_timestamp2datetime)
        # broadcast_df.to_csv("./broadcast_df.csv", index=False)
        broadcast_df = self._filter_conti_index(broadcast_df)
        step_time = np.array(broadcast_df[TableItem.ex_start_ts].diff() / 1e6)[2:]
        logger.info(f"estimate length: {len(broadcast_df)}")

        self.plot_step_time(step_time)

    def convert_timestamp2datetime(self, data):

        dt_object = datetime.datetime.fromtimestamp(data / (1e9 * 1.0))
        # 格式化日期为字符串
        date_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
        return date_time

    def plot_step_time(self, data):
        step_time = extract_step_time_from_log(self._root_path)
        mean_value = np.mean(data)
        plt.figure(figsize=(10, 6))
        plt.plot(step_time[10:110], label='GT', marker='^')
        plt.plot(data[10:110], label='extimate_time', marker='o')
        # 绘制均值线
        # plt.axhline(y=mean_value, color='r', linestyle='--', label='Mean')
        # 设置图表标题和坐标轴标签
        plt.title('Estimate step time by dataloader.')
        plt.xlabel('step index')
        plt.ylabel('latency(ms)')
        plt.legend()
        plt.grid(True)
        plt.show()

    @staticmethod
    def _filter_deviation_data(data):
        ''' filter data exceed or lower than 3 * means '''
        processed_data = []

        mean_value = np.mean(data)
        for value in data:
            if value > 3 * mean_value or value < 1 / 3 * mean_value:
                processed_data.append(mean_value)
            else:
                processed_data.append(value)

        return processed_data

    @staticmethod
    def _filter_conti_index(df):
        # 计算索引的差值
        diff = df.index.to_series().diff()
        # 标记连续索引组
        groups = (diff != 1).cumsum()
        # 每组仅保留第一行
        result = df.groupby(groups).first()

        return result


if __name__ == "__main__":
    # _root_path = "data/tp4dp1_1.5b"
    # _root_path = "data/tp2pp4"
    # _root_path = "data/json_tp4dp1"
    _root_path = "data/jdata/json_tp2dp2pp2"
    _root_path = "data/jdata/json_tp1dp2pp4"
    _root_path = "data/jdata/json_tp1dp4pp2"
    _root_path = "data/jdata/json_tp2dp2pp2"
    # _root_path = "data/jdata/json_tp2dp4pp1"  # wrong
    # _root_path = "data/jdata/json_tp4dp1pp2"
    # _root_path = "data/jdata/json_tp4dp2pp1"
    # _root_path = "data/jdata/json_tp8dp1pp1"

    convert_jsons2csv(_root_path)
    dataloader = MarkerDataloader(_root_path)
    # all_comm_groups = dataloader.get_broadcast_ops()
    logger.info(f"{dataloader.csv_files}")
    from restore_comm import RestoreComm

    comm_groups = dataloader.extract_comm_domain()
    ranks = dataloader.ranks
    restore_comm = RestoreComm(comm_groups, ranks)
    restore_comm()
    logger.info(f"{restore_comm.comm_domain}")
    # for comm_group in comm_groups:
    #     print(comm_group)
