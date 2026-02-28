from typing import List
import pandas as pd
import os
import asyncio
import json

from failslow.task.custom_v1.custom_v1 import GPUFailSlowDetectionNaive
from failslow.task.custom_v1.interface import StepMetrics, KernelType
async def main():
    # 创建检测器
    gpuFailSlowDetector = GPUFailSlowDetectionNaive()
    
    # 从tp8读取数据，自己划分step
    base_path = "/home/sysTrace/data/csv/tp8"
    total_steps = 10
    total_ranks = 8

    rank_data_frames = {}
    for rank_id in range(total_ranks):
        file_path = os.path.join(base_path, f"hccl_activity-127.0.0.1-.{rank_id}.csv")
        rank_data_frames[rank_id] = pd.read_csv(file_path)

    for step in range(total_steps):  
        rank2dataList: List[StepMetrics] = []
        for rank_id in range(total_ranks):  
            # 从路径/home/sysTrace/data/csv/tp8中读取数据，rank0就从文件data/csv/tp8/hccl_activity-127.0.0.1-.0.csv读，t1_ns对应t1，t2_ns对应t2
            # 创建 KernelType 列表
            df = rank_data_frames[rank_id]
            rows_per_step = len(df) // total_steps
            start_idx = step * rows_per_step
            end_idx = (step + 1) * rows_per_step if step < total_steps - 1 else len(df)
            step_data = df.iloc[start_idx:end_idx]

            kernels = []
            # 将/home/sysTrace/data/csv/tp8中的数据划分20份，每份读取相应行数的数据
            for _, row in step_data.iterrows():
                kernel = KernelType(
                    name=row['kernel'],
                    t1_ns=int(row['t1']),
                    t2_ns=int(row['t2']),
                    t_delta_ns=50000.0,
                    t_exec_ns=25000.0,
                    t3_ns=int(row['t3']),
                    t4_ns=int(row['t4'])
                )
                kernels.append(kernel)
            
            step_metrics = StepMetrics(
                start_time_ns=step * 1000000,
                end_time_ns=step * 1000000 + 100000,
                step=step,
                rank_id=rank_id,
                local_rank_id=rank_id % 2,  # 模拟 local rank
                node_ip=f"192.168.1.1",
                node_port=8000 + rank_id,
                kernels=kernels
            )
            
            rank2dataList.append(step_metrics)
    
        gpuFailSlowDetector.on_recv_all_step(rank2dataList)

if __name__ == "__main__":
    asyncio.run(main())