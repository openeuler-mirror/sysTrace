import os
import threading
import pandas as pd
import time
import subprocess
import argparse
import json

from failslow.task.custom_v1.custom_v1 import GPUFailSlowDetectionNaive
from failslow.task.custom_v1.interface import StepMetrics, KernelType
from failslow.task.custom_v1.performance_degradation_perception import OnlinePerformanceDegradationDetectorCollections
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)

# TODO：远程文件传输就不要再启动线程执行了，直接作为一个同步操作，被MultiNodesSlowNodeDetector调用
class RemoteFileSync:
    """用于同步远程文件到本地的类"""
    
    def __init__(self, remote_hosts, remote_path, local_path, username="root", port=22):
        self.remote_hosts = remote_hosts  # 远程主机列表
        self.remote_path = remote_path    # 远程路径
        self.local_path = local_path      # 本地路径
        self.username = username          # SSH用户名
        self.port = port                  # SSH端口
        self.bak_remote_mspti_files()

    def sync_from_remote_mspti_files(self):
        """从远程同步文件到本地"""
        try:
            for host in self.remote_hosts:
                # 使用正则表达式匹配mspti-marker-{ip}-{rank}.csv格式的文件
                rsync_cmd = (
                    f"rsync -avz --partial --progress --include='mspti-marker-*-[0-9]*.csv' --exclude='*' -e 'ssh -p {self.port}' "
                    f"{self.username}@{host}:{self.remote_path}/ "
                    f"{self.local_path}/"
                )
                
                logger.info(f"Syncing from {host} using command: {rsync_cmd}")
                
                result = subprocess.run(
                    rsync_cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    logger.warning(f"Warning: Failed to sync from {host}: {result.stderr}")
                else:
                    logger.info(f"Successfully synced mspti files from {host}")
        except Exception as e:
            logger.error(f"Error syncing mspti files from remote: {e}")

    def sync_from_remote_training_logs(self):
        """从远程同步文件到本地"""
        try:
            for host in self.remote_hosts:
                # 使用正则表达式匹配training_step_time_{rank}.csv格式的文件
                rsync_cmd = (
                    f"rsync -avz --partial --progress --include='training_step_time_[0-9]*.csv' --exclude='*' -e 'ssh -p {self.port}' "
                    f"{self.username}@{host}:{self.remote_path}/ "
                    f"{self.local_path}/"
                )
                
                logger.info(f"Syncing from {host} using command: {rsync_cmd}")
                
                result = subprocess.run(
                    rsync_cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    logger.warning(f"Warning: Failed to sync from {host}: {result.stderr}")
                else:
                    logger.info(f"Successfully synced training logs from {host}")
        except Exception as e:
            logger.error(f"Error syncing training logs from remote: {e}")

    def bak_remote_mspti_files(self):
        """远程移动对应机器上的mspti文件到备份目录"""
        try:
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = f"{self.remote_path}_backup_{timestamp}"
            
            for host in self.remote_hosts:
                # 使用ssh连接到远程主机并移动文件到备份目录
                ssh_cmd = f"ssh -p {self.port} {self.username}@{host} 'mkdir -p {backup_dir} && mv \"{self.remote_path}\"/* {backup_dir}/ 2>/dev/null || echo \"No files to move\"'"
                
                logger.info(f"Moving files on {host} using command: {ssh_cmd}")
                
                result = subprocess.run(
                    ssh_cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0 and "No files to move" not in result.stdout:
                    logger.warning(f"Warning: Failed to move files on {host}: {result.stderr}")
                else:
                    logger.info(f"Successfully moved files on {host} to {backup_dir}")
        except Exception as e:
            logger.error(f"Error moving remote files: {e}")


class MultiNodesSlowNodeDetector:
    def __init__(self, mspti_files, detection_interval=10, remote_hosts=None, ssh_port=22, enable_detection=True, remote_sync = None):
        self.mspti_files = mspti_files
        self.model_config_path = self.__default_config_path()
        with open(self.model_config_path, 'r', encoding='utf-8') as reader:
            self.model_args = json.load(reader)
        self.detection_interval = detection_interval
        self.current_step = 0
        self.ssh_port = ssh_port
        self.gpu_fail_slow_detector = GPUFailSlowDetectionNaive()
        self.remote_hosts = remote_hosts or []  # 远程主机列表
        self.remote_sync = None  
        self.enable_detection = threading.Event()
        
        if enable_detection:
            self.enable_detection.set()  # 默认启用检测
        
        if self.remote_hosts:
            self.remote_sync = remote_sync
        
        # 初始化时清理csv文件
        self.bak_csv_files()
        self.bak_mspti_files()
        
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def __default_config_path(self) -> str:
        return "/etc/systrace/config/model_config.json"

    def trigger_npu_slow_node_detection(self, rank2data_list):
        """触发GPUFailSlowDetector的on_recv_all_step方法"""
        self.gpu_fail_slow_detector.on_recv_all_step(rank2data_list)

    def _worker(self):
        """后台工作线程，定时执行检测，在每次检测前同步远程数据"""
        while True:
            self.enable_detection.wait()
            time.sleep(self.detection_interval/2)
            
            # 如果有远程主机配置，则同步数据
            if self.remote_sync:
                logger.info("Starting remote data sync before Slow node detection...")
                self.remote_sync.sync_from_remote_mspti_files()
            
            rank2data_list = self.process_hccl_data()

            time.sleep(self.detection_interval/2)

            if rank2data_list:
                self.trigger_npu_slow_node_detection(rank2data_list)
            else:
                logger.info("No Mspti Marker Data Found.")

    def enable_slow_node_detection(self):
        """启用慢节点检测"""
        self.enable_detection.set()
        logger.info("Starting slow node detection...")

    def disable_slow_node_detection(self):
        """禁用慢节点检测"""
        self.enable_detection.clear()
        
    def process_hccl_data(self):
        """解析CSV数据为StepMetrics对象"""
        # 1. 获取待处理文件列表
        if os.path.isdir(self.mspti_files):
            csv_files = [f for f in os.listdir(self.mspti_files) if f.startswith("mspti-marker-") and f.endswith(".csv")]
        else:
            csv_files = [os.path.basename(self.mspti_files)] if self.mspti_files.endswith('.csv') else []
        rank2data_list = []
        for filename in csv_files:
            # 解析文件名中的 IP 和 Rank
            # 假设格式: mspti-marker-192.168.1.1-0.csv
            name_parts = filename.replace('.csv', '').split('-')
            if len(name_parts) < 4:
                continue
                
            try:
                ip_address = name_parts[2]
                rank_id = int(name_parts[3])
                filepath = os.path.join(self.mspti_files, filename)
                df = pd.read_csv(filepath)
                # df = self.safe_process_csv(filepath)

                kernels = []
                all_timestamps = []

                # 2. 按 Id 分组处理算子
                for obj_id, group in df.groupby('Id'):
                    valid_names = group[group['Name'].str.contains('comm:', na=False)]['Name']
                    if not valid_names.empty:
                        raw_full_name = str(valid_names.iloc[0])
                        op_name = raw_full_name.split('comm:')[1].split('!')[0]
                    else:
                        continue

                    timestamps = sorted(group['Timestamp'].dropna().unique().tolist())
                    
                    # 确保有 4 个时间戳点
                    if len(timestamps) == 4:
                        t1, t2, t3, t4 = timestamps
                        kernel = KernelType(
                            name=op_name,
                            t1_ns=t1,
                            t2_ns=t2,
                            t_delta_ns=t3 - t2,  # 调度延迟/等待时间
                            t_exec_ns=t4 - t3,    # 实际执行耗时
                            t3_ns=t3,
                            t4_ns=t4
                        )
                        kernels.append(kernel)
                        all_timestamps.extend(timestamps)

                # 4. 构建 StepMetrics
                if kernels:
                    step_metrics = StepMetrics(
                        start_time_ns=min(all_timestamps),
                        end_time_ns=max(all_timestamps),
                        step=self.current_step,
                        rank_id=rank_id,
                        local_rank_id=rank_id, # local_rank暂时设置为global_rank
                        node_ip=ip_address,
                        node_port=12355,
                        kernels=kernels
                    )
                    rank2data_list.append(step_metrics)
        
            except Exception as e:
                logger.error(f"Error: Fail to parse {filename}: {e}")
                continue

        self.current_step = getattr(self, 'current_step', 0) + 1
        return rank2data_list

    def bak_csv_files(self):
        csv_files = self.model_args.get("root_path")

        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isabs(csv_files):
            csv_files_path = os.path.join(current_file_dir, csv_files)
        else:
            csv_files_path = csv_files

        if not os.path.exists(csv_files_path):
            return
        
        import shutil
        import datetime
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = f"{csv_files_path}_backup_{timestamp}"
            
            if os.path.isdir(csv_files_path):
                # 移动整个目录
                shutil.move(csv_files_path, backup_dir)
                logger.info(f"Successfully moved directory {csv_files_path} to {backup_dir}")
            else:
                # 创建备份目录并移动单个文件
                os.makedirs(backup_dir, exist_ok=True)
                filename = os.path.basename(csv_files_path)
                backup_filepath = os.path.join(backup_dir, f"{filename}_{timestamp}")
                shutil.move(csv_files_path, backup_filepath)
                logger.info(f"Successfully moved file {csv_files_path} to {backup_filepath}")
        except OSError as e:
            logger.error(f"Error moving directory or file {csv_files_path}: {e}")

    def bak_mspti_files(self):
        if not os.path.exists(self.mspti_files):
            return
        
        import shutil
        import datetime
        
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = f"{self.mspti_files}_backup_{timestamp}"
            
            if os.path.isdir(self.mspti_files):
                # 移动整个目录
                shutil.move(self.mspti_files, backup_dir)
                logger.info(f"Successfully moved MSPTI directory {self.mspti_files} to {backup_dir}")
            else:
                # 创建备份目录并移动单个文件
                os.makedirs(backup_dir, exist_ok=True)
                filename = os.path.basename(self.mspti_files)
                backup_filepath = os.path.join(backup_dir, f"{filename}_{timestamp}")
                shutil.move(self.mspti_files, backup_filepath)
                logger.info(f"Successfully moved MSPTI file {self.mspti_files} to {backup_filepath}")
        except OSError as e:
            logger.error(f"Error moving MSPTI directory or file {self.mspti_files}: {e}")


class MultiNodesFailSlowDetector:
    def __init__(self, mspti_files, remote_hosts=None, ssh_port=22, enable_detection=True, remote_sync = None):
        self.mspti_files = mspti_files
        self.config_path = self.__default_config_path()
        with open(self.config_path, 'r', encoding='utf-8') as reader:
            self.config = json.load(reader)
        self.detection_interval = 10
        self.ssh_port = ssh_port
        self.online_performance_degradation_detector = OnlinePerformanceDegradationDetectorCollections(
            degradation_perception_default_config = self.config['degradation_perception'])
        self.remote_hosts = remote_hosts or []  # 远程主机列表
        self.remote_sync = None  
        # 新增：跟踪每个rank的最后处理step数
        self.last_processed_steps = {}  # {rank_id: last_step_number}

        self.enable_detection = threading.Event()
        if enable_detection:
            self.enable_detection.set()  # 默认启用检测
        
        if self.remote_hosts:
            self.remote_sync = remote_sync
        
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def __default_config_path(self) -> str:
        return "/etc/systrace/config/config.json"

    def trigger_npu_fail_slow_detection(self, step_metrics: StepMetrics):
        self.online_performance_degradation_detector.on_recv(step_metrics)

    def _worker(self):
        """后台工作线程，定时执行检测，在每次检测前同步远程数据"""
        while True:
            self.enable_detection.wait()
            time.sleep(self.detection_interval)
            
            # 如果有远程主机配置，则同步数据
            if self.remote_sync:
                logger.info("Starting remote data sync before Slow node identification...")
                self.remote_sync.sync_from_remote_training_logs()
            
            self.process_training_step_data()

    def enable_fail_slow_detection(self):
        """启用劣化感知"""
        self.enable_detection.set()
        logger.info("Starting degradation detection...")

    def disable_fail_slow_detection(self):
        """禁用劣化检测"""
        self.enable_detection.clear()
        
    def process_training_step_data(self):
        """解析CSV数据为StepMetrics对象，跳过已处理的step"""
        if os.path.isdir(self.mspti_files):
            csv_files = [f for f in os.listdir(self.mspti_files) if f.startswith("training_step_time_") and f.endswith(".csv")]
        else:
            csv_files = [os.path.basename(self.mspti_files)] if self.mspti_files.endswith('.csv') else []
        
        for filename in csv_files:
            # 解析文件名中的 Rank
            name_parts = filename.replace('.csv', '').split('_')
            if len(name_parts) < 4:
                continue
                
            try:
                rank_id = int(name_parts[3])
                filepath = os.path.join(self.mspti_files, filename)
                
                # 获取该rank的最后处理step
                last_processed_step = self.last_processed_steps.get(rank_id, -1)
                
                df = pd.read_csv(filepath)
                
                # 过滤掉已经处理过的step
                new_steps_df = df[df['step_id'] > last_processed_step]
                
                if new_steps_df.empty:
                    continue
                
                for row in new_steps_df.itertuples(index=False):     
                    # 为每一行数据创建kernels列表
                    kernels = []
                    # 构建 StepMetrics
                    step_metrics = StepMetrics(
                        start_time_ns = row.step_start_time,
                        end_time_ns = row.step_end_time,
                        step = row.step_id,
                        rank_id = rank_id,
                        local_rank_id = rank_id, # local_rank暂时设置为global_rank
                        node_ip = "127.0.0.1",
                        node_port = 12355,
                        kernels = kernels
                    )
                    self.trigger_npu_fail_slow_detection(step_metrics)
                    
                    # 更新该rank的最后处理step
                    self.last_processed_steps[rank_id] = row.step_id
        
            except Exception as e:
                logger.error(f"Error: Fail to parse {filename} : {e}")
                continue
        
        return

def main():
    parser = argparse.ArgumentParser(description="Multi-nodes slow node detection")
    parser.add_argument("--metric-path", type=str, help="Path to metric files", 
                       default = os.getenv("METRIC_PATH", "/home/sysTrace/mspti"))
    parser.add_argument("--detection-interval", type=int, help="Detection interval in seconds", 
                       default = 60)
    parser.add_argument("--remote-hosts", type=str, help="Comma-separated list of remote hosts", 
                       default = None)
    parser.add_argument("--ssh-port", type=int, help="SSH port for remote connections", 
                       default = 22)
    parser.add_argument("--enable-slow-node", action='store_true', help="Enable Slow Node Detection")
    parser.add_argument("--enable-fail-slow", action='store_true', help="Enable Fail Slow Detection")
    
    args = parser.parse_args()
    
    # 解析远程主机列表
    remote_hosts = args.remote_hosts.split(",") if args.remote_hosts else []
    
    remoteFileSync = RemoteFileSync(
        remote_hosts=remote_hosts,
        remote_path=args.metric_path,
        local_path=args.metric_path,
        port=args.ssh_port
    )

    # 创建检测器实例
    slowNodeDetector = MultiNodesSlowNodeDetector(
        args.metric_path, 
        args.detection_interval, 
        remote_hosts, 
        args.ssh_port,
        enable_detection=args.enable_slow_node,
        remote_sync = remoteFileSync
    )
    
    FailSlowDetector = MultiNodesFailSlowDetector(
        args.metric_path, 
        remote_hosts, 
        args.ssh_port,
        enable_detection=args.enable_fail_slow,
        remote_sync = remoteFileSync
    )
    
    if args.enable_slow_node:
        slowNodeDetector.enable_slow_node_detection()
    else:
        slowNodeDetector.disable_slow_node_detection()
        
    if args.enable_fail_slow:
        FailSlowDetector.enable_fail_slow_detection()
    else:
        FailSlowDetector.disable_fail_slow_detection()
    
    # 阻止主线程退出，保持后台线程运行
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Detection Stopped.")


if __name__ == "__main__":
    main()