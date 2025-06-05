# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：recovery_comm.py
Author: h00568282/huangbin 
Create Date: 2025/3/14 15:34
Notes:

"""
from typing import List
from failslow.util.constant import CommGroup, CommOpType
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)

class RestoreComm:
    def __init__(self, comm_groups: List[CommGroup], ranks: List):
        self.comm_domain = {"tp": [], "dp": [], "pp": [], "ep": []}
        self.comm_groups = comm_groups
        self.ranks = ranks
        self.default_comm_list = self.default_group()
    def default_group(self):
        return [[rank] for rank in self.ranks]

    def __call__(self, *args, **kwargs):
        for comm_group in self.comm_groups:
            count_ops = comm_group.count_ops
            group_ranks = comm_group.group_ranks
            ops_list = list(count_ops.keys())
            # first and last has broadcast
            if CommOpType.broadcast in ops_list:
                ops_list.remove(CommOpType.broadcast)
            logger.info(f"comm group has {group_ranks} with {ops_list}")

            if CommOpType.send in ops_list or CommOpType.receive in ops_list or CommOpType.batch_send_recv in ops_list:
                self.add_group_ranks("pp", group_ranks)
            elif CommOpType.reduce_scatter in ops_list and len(ops_list) > 1:
                self.add_group_ranks("tp", group_ranks)
            elif CommOpType.all_reduce in ops_list and len(ops_list) == 1:
                self.add_group_ranks("dp", group_ranks)

        for comm_domain, value in self.comm_domain.items():
            if not value:
                self.comm_domain[comm_domain] = self.default_comm_list

        self.fix_dp_comm_domain()

    def add_group_ranks(self, comm_group_type: str, group_rank: List):
        current_group_ranks = self.comm_domain[comm_group_type]
        if group_rank not in current_group_ranks:
            skip_flag = False
            insert_flag = False
            for index, current_group_rank in enumerate(current_group_ranks):
                if self.is_subset_using_set(current_group_rank, group_rank):
                    skip_flag = True
                    break

                if self.is_subset_using_set(group_rank, current_group_rank):
                    insert_flag = True
                    break
            if insert_flag:
                current_group_ranks[index] = group_rank
            elif not skip_flag:
                current_group_ranks.append(group_rank)

    def test_fix_dp_comm_domain(self):
        self.ranks = [i for i in range(32)]
        tp_size = 4
        pp_size = 2
        dp_size = 4
        tp_groups = len(self.ranks) // tp_size
        dp_groups = len(self.ranks) // dp_size
        pp_groups = len(self.ranks) // pp_size

        tp_groups = [[i + i_group * tp_size for i in range(tp_size)] for i_group in range(tp_groups)]
        dp_groups = [self.ranks]
        pp_groups = [[i_group + tp_size*dp_size * i for i in range(pp_size)] for i_group in range(pp_groups)]
        self.comm_domain["tp"] = tp_groups
        self.comm_domain["dp"] = dp_groups
        self.comm_domain["pp"] = pp_groups
        logger.info(f"before: {self}")

        self.fix_dp_comm_domain()

    def is_valid_dp_domain(self, dp_list: List) -> bool:
        if not dp_list:
            return False

        first_length = len(dp_list[0])
        for sub_lst in dp_list:
            if len(sub_lst) != first_length:
                return False

        return True

    def fix_dp_comm_domain(self):
        total_ranks = len(self.ranks)

        if not total_ranks:
            logger.warning(f"There has 0 ranks, please check input data.")
            return

        if self.comm_domain["pp"]:
            pp_size = len(self.comm_domain["pp"][0])
        else:
            logger.warning(f"There has pipeline paralel with size 0, which should be larger than 1.")
            return
        
        tp_dp_size = total_ranks / pp_size
        
        if self.comm_domain["tp"]:
            tp_size = len(self.comm_domain["tp"][0])
        else:
            logger.warning(f"There has tensor paralel with size 0, which should be larger than 1.")
            return 

        if self.comm_domain["dp"]:
            dp_size = len(self.comm_domain["dp"][0])
        else:
            logger.warning(f"There has data paralel with size 0, which should be larger than 1.")
            return 
        
        real_dp_size = int(tp_dp_size / tp_size)
        is_valid_dp_domain = self.is_valid_dp_domain(self.comm_domain["dp"])

        if is_valid_dp_domain and  (dp_size == real_dp_size):
            return
        # fix dp
        new_dp_groups = []
        num_dp_groups = int(total_ranks / real_dp_size)
        for i_group in range(num_dp_groups):
            new_dp_group = [i_group + tp_size * index for index in range(real_dp_size)]
            new_dp_groups.append(new_dp_group)

        self.comm_domain["dp"] = new_dp_groups


    @staticmethod
    def is_subset_using_set(A, B):
        return set(B).issubset(set(A))

    def __repr__(self):
        return f"comm domain: {self.comm_domain}"


if __name__ == "__main__":
    restore_comm = RestoreComm([], [])
    restore_comm.test_fix_dp_comm_domain()
    print(restore_comm)
