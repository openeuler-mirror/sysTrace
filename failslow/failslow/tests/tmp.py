# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：tmp.py
Author: h00568282/huangbin 
Create Date: 2025/3/7 17:03
Notes:

"""
from collections import Counter

def main():
    pass


if __name__ == "__main__":
    abc = '[6,7]'
    abc = eval(abc)
    print(abc, type(abc))
    aggerated_data_dfs  = [1,2,3]
    new_detect_group_data =  [{} for _ in range(len(aggerated_data_dfs))]
    new_detect_group_data[0]["abc"] = "abc"
    print(new_detect_group_data)
    group_ranks = [1,2,3,1]
    anomaly_scores = [0] * len(group_ranks)
    anomaly_scores[1] = 2
    print(anomaly_scores)
    g_ranks_dict = Counter(group_ranks)
    print(g_ranks_dict)