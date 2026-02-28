"""
慢节点定位检测器
用于检测和定位训练中的慢节点
"""

import json
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import threading
from queue import Queue, Empty
from concurrent.futures import Future
import pandas as pd
from pydantic import BaseModel, Field
from failslow.response import AIJobDetectResult
from failslow.slow_node_detection import SlowNodeDetector
from failslow.task.alert_reporter import (
    AlertReporterBase,
    AlertReporterConfig,
    AlertReporterFactory,
)
from failslow.util.constant import HOUR_TO_SECONDS, TIMESTAMP_MS_NUM, AnomalyType
from failslow.util.demangle import demangle
from failslow.util.logging_utils import get_default_logger
from .interface import StepMetrics
import shutil
from collections import Counter

logger = get_default_logger(__name__)


class SlowNodeConfig(BaseModel):
    csv_path: str
    max_rows: int = 100000
    model_config_path: str
    metric_config_path: str

    alert_reporter_config: AlertReporterConfig = AlertReporterConfig()
    metric_white_list: List[str] = Field(default_factory=list)
    detection_minimum_interval_seconds: int = 10


def get_slow_node_detection_time_range(model_args):
    end_time = None
    start_time = None
    with_fail_slow = model_args.get("with_fail_slow", False)
    slow_node_detection_range_times = model_args.get(
        "slow_node_detection_range_times", []
    )
    # fail_slow_perception_result.json
    fail_slow_perception_path = model_args.get("fail_slow_perception_path", "/log")
    slow_node_detection_time_span_hours = model_args.get(
        "slow_node_detection_time_span_hours", 0.5
    )
    if slow_node_detection_range_times:
        start_time = slow_node_detection_range_times[0]
        end_time = slow_node_detection_range_times[1]
    else:
        if with_fail_slow:
            # fail slow status, no fail no detect
            if os.path.exists(fail_slow_perception_path):
                file_slow_result_files = [
                    file
                    for file in os.listdir(fail_slow_perception_path)
                    if AnomalyType.fail_slow in file
                ]
                if file_slow_result_files:
                    file_slow_result_files.sort(reverse=True)

                    latest_slow_result_file = file_slow_result_files[0]
                    latest_slow_result_path = os.path.join(
                        fail_slow_perception_path, latest_slow_result_file
                    )
                    with open(latest_slow_result_path, "r", encoding="utf-8") as reader:
                        fail_slow_result = json.load(reader)
                    start_time = fail_slow_result.get("start_time")
                    end_time = fail_slow_result.get("end_time")
        else:
            if end_time is None:
                # 若自动触发，当前时间往前推两个小时开始检测
                end_time = int(time.time() * TIMESTAMP_MS_NUM)
                time_span = int(
                    int(slow_node_detection_time_span_hours)
                    * HOUR_TO_SECONDS
                    * TIMESTAMP_MS_NUM
                )
                start_time = end_time - time_span

    logger.info(
        f"fail slow used:"
        + str(with_fail_slow)
        + ", Start time: "
        + str(start_time)
        + ", End timestamp: "
        + str(end_time)
    )
    return start_time, end_time


def demangle_name(rank2data: Dict[int, "StepMetrics"]) -> Dict[int, "StepMetrics"]:
    """
    解析字典中所有 Rank 的 StepMetrics 里的 C++ 算子修饰名。
    """
    # 使用字典作为缓存，跨 Rank 共享解析结果，大幅提升效率
    name_cache = {}

    # 1. 遍历字典的所有值 (StepMetrics)
    for step_metric in rank2data.values():
        if not hasattr(step_metric, "kernels") or not step_metric.kernels:
            continue

        # 2. 遍历每个 StepMetrics 中的 kernels 列表
        for kernel in step_metric.kernels:
            original_name = kernel.name

            # 检查缓存中是否已经解析过
            if original_name in name_cache:
                kernel.name = name_cache[original_name]
                continue

            # 只有以 _Z 开头的才是 C++ 修饰名，需要解析
            if original_name.startswith("_Z"):
                try:
                    # 调用 demangle 解析
                    demangled = demangle(original_name)
                    # 截取 '(' 之前的部分获取纯净函数名
                    pure_name = demangled.split("(")[0]
                    name_cache[original_name] = pure_name
                    kernel.name = pure_name
                except Exception:
                    # 如果解析失败（例如环境缺少 c++filt），保持原样
                    name_cache[original_name] = original_name
            else:
                # 非修饰名，直接记录缓存
                name_cache[original_name] = original_name

    return rank2data


class AlertReporter(ABC):
    @abstractmethod
    def report_alert(self, alert) -> None:
        """报告一个告警"""
        raise NotImplementedError

    @abstractmethod
    def get_all_alerts(self) -> List[Any]:
        """获取所有报告"""
        raise NotImplementedError


class CSVAsyncWriter:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """实现单例模式"""
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(CSVAsyncWriter, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.queue = Queue()
        self.kernel_name_selected = None
        # 每隔check_interval秒检查一次queue是否有数据，若没数据，则增加interval_increment，最大到max_check_interval
        self.check_interval = 0
        self.interval_increment = 0.1
        self.max_check_interval = 1
        # 添加一个事件用于通知数据写入完成
        self.write_complete_event = threading.Event()
        # 增加一个完成标志，用于等待数据写完
        self.worker_thread = threading.Thread(target=self._write_loop, daemon=True)
        self.worker_thread.start()
        self._initialized = True
       
    def _find_detect_kernel_name(
        self, rank2data: dict[int, StepMetrics]
    ) -> Optional[str]:
        all_names = []
        for step_metrics in rank2data.values():
            for kernel in step_metrics.kernels:
                all_names.append(kernel.name)

        if not all_names:
            logger.error("No kernel names found in the provided data.")
            raise ValueError("No kernel names found in the provided data.")

        name_counts = Counter(all_names)
        ops_counts = sorted(list(name_counts.items()), key=lambda x: x[1], reverse=True)

        if not self.config.metric_white_list:
            logger.info(
                "No metric white list provided, selecting most frequent kernel: "
                f"{ops_counts[0][0]} with count {ops_counts[0][1]}"
            )
            return ops_counts[0][0]
        for name, count in ops_counts:
            if name in self.config.metric_white_list:
                logger.info(
                    (
                        "Selected kernel name for slow node detection "
                        f"from white list: {name} with count {count}"
                    )
                )
                return name
        logger.error(
            (
                "No valid kernel name found in white list. "
                "Available kernel names and their counts: \n\t%s\n"
                "White list: %s"
            ),
            "\n".join([f"\t{name}: {count}" for name, count in ops_counts]),
            self.config.metric_white_list,
        )
        raise ValueError("No valid kernel name found in white list")

    def rank2data_to_csv(self, rank_id: int, data: Any, csv_path: str):
        """
        将数据保存到 CSV 文件

        Args:
            rank_id: 设备 ID
            data: 要保存的数据，可以是 StepMetrics 对象或 DataFrame
            csv_path: 可选的 CSV 文件路径，如果为 None 则使用默认路径
        """
        data_dict = data.__dict__
        current_step = data_dict["step"]
        node_ip = data_dict["node_ip"]

        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isabs(csv_path):
            csv_path = os.path.join(current_file_dir, csv_path)

        # 确保提供的路径存在
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        # 如果提供的路径是目录，则添加文件名
        # TODO: 防冲突
        if os.path.isdir(csv_path):
            csv_path = os.path.join(csv_path, f"hccl_activity-{node_ip}-.{rank_id}.csv")

        try:
            # 只提取kernels的数据
            if "kernels" in data_dict and isinstance(data_dict["kernels"], list):
                kernels_list = data_dict["kernels"]
                rows = []

                for kernel in kernels_list:
                    rows.append(
                        {
                            "kernel": kernel.name,
                            "t1": kernel.t1_ns // 1000,
                            "t2": kernel.t2_ns // 1000,
                            "t3": kernel.t3_ns // 1000,
                            "t4": kernel.t4_ns // 1000,
                            "step": current_step,
                        }
                    )
                new_df = pd.DataFrame(rows)

                file_exists = os.path.isfile(csv_path)

                # 确保父目录存在（线程安全）
                parent_dir = os.path.dirname(csv_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)

                new_df.to_csv(
                    csv_path, 
                    mode='a', 
                    index=False, 
                    header=not file_exists, 
                    encoding='utf-8'
                )

        except Exception as e:
            logger.error(f"fail: save data to CSV file: {e}")
            raise

    def _write_loop(self):
        while True:
            if not self.queue.empty():
                self.check_interval = 0
                item = None
                try:
                    try:
                        # 尝试获取最新数据
                        item = self.queue.get(timeout=1.0)
                    except Empty:
                        # 超时直接进入下一次循环，不调用 task_done
                        continue
                    # 检查结束信号
                    if item is None:
                        self.queue.task_done()
                        break

                    # 从队列中取出数据，开始落盘
                    rank2data, csv_path = item
                    rank2data = demangle_name(rank2data)

                    if not self.kernel_name_selected:
                        self.kernel_name_selected = self._find_detect_kernel_name(rank2data)
                        
                    # 执行写入逻辑
                    for rank_id, data in rank2data.items():
                        self.rank2data_to_csv(rank_id, data, csv_path)

                    # 设置写入完成事件，通知其他线程数据已写入完成
                    self.write_complete_event.set()
                    
                    self.queue.task_done()
                except Exception as e:
                    self.queue.task_done()
                    # 发生异常也要清除事件，确保下次能继续监听
                    self.write_complete_event.clear()
            else:
                self.check_interval += self.interval_increment
                self.check_interval = max(self.check_interval, self.max_check_interval)
                time.sleep(self.check_interval)

    def add_task(self, rank2data: dict[int, StepMetrics], csv_path: str):
        """推送任务"""
        self.queue.put((rank2data, csv_path))


class AsyncSlowNodeDetector:
    def __init__(self, config, metric_args, model_args):
        self.config = config
        self.metric_args = metric_args
        self.model_args = model_args
        self.kernel_name_selected = None
        # 用于控制检测启动间隔
        self._last_detection_timestamp = -1
        self.alert_reporter: AlertReporterBase = AlertReporterFactory.create_reporter(
            self.config.alert_reporter_config
        )
        self.event = threading.Event()
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def _worker(self):
        """后台工作线程，等待数据写入完成再执行检测"""
        while True:
            # 等待事件被设置
            self.event.wait()
            self.event.clear()
            
            # 等待数据写入完成
            writer = CSVAsyncWriter()
            writer.write_complete_event.wait()
            writer.write_complete_event.clear()
            
            # 执行检测任务
            self._run_task()

    def trigger_detection(self):
        """触发检测任务"""
        self.event.set()

    def on_alert(self, alert) -> None:
        """处理检测到的告警"""
        self.alert_reporter.report_alert(alert)

    def _run_task(self):
        try:
            writer = CSVAsyncWriter() 
            self.kernel_name_selected = writer.kernel_name_selected
            logger.info("SlowNode Detecting: CSVAsyncWriter Queue size: " + str(writer.queue.qsize()))
            if not self.kernel_name_selected:
                logger.warning("Kernel name not selected yet, skipping detection.")
                return
            
            # 更新模型参数中的慢节点检测算子
            self.model_args["fail_slow_ops"]["cal_slow"] = self.kernel_name_selected
            self.model_args["fail_slow_ops"]["op_launch_slow"] = (
                self.kernel_name_selected + "_launch"
            )
            logger.info(f"fail_slow_ops: {self.model_args['fail_slow_ops']}")

            # FIXME: 应该不需要了，检查是否满足最小检测间隔
            interval = time.time() - self._last_detection_timestamp
            if interval < self.config.detection_minimum_interval_seconds:
                logger.debug(
                    f"Skipping slow node detection. Last detection was {interval:.2f} seconds ago."
                )
                return
                
            self._last_detection_timestamp = time.time()
            start_time, end_time = get_slow_node_detection_time_range(self.model_args)

            detector = SlowNodeDetector(
                self.metric_args, self.model_args, start_time=start_time, end_time=end_time
            )
            response: AIJobDetectResult = detector.run()
            self.on_alert(response.get("abnormalDetail"))
        except Exception as e:
            logger.error(f"Error during async slow node detection: {e}", exc_info=True)


class SlowNodeLocatorDetector:
    """慢节点定位检测器"""

    def __init__(self, config: SlowNodeConfig):
        """
        初始化慢节点定位检测器
        """
        self.config = config
        # 将相对路径转换为绝对路径，基于当前文件所在目录
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isabs(config.model_config_path):
            model_config_path = os.path.join(current_file_dir, config.model_config_path)
        else:
            model_config_path = config.model_config_path
            
        if not os.path.isabs(config.metric_config_path):
            metric_config_path = os.path.join(current_file_dir, config.metric_config_path)
        else:
            metric_config_path = config.metric_config_path

        logger.debug(
            "loading slow node locator detector config from \n%s\n%s",
            model_config_path,
            metric_config_path,
        )
        with open(model_config_path, "r", encoding="utf-8") as reader:
            self.model_args = json.load(reader)
        with open(metric_config_path, "r", encoding="utf-8") as reader:
            self.metric_args = json.load(reader)

        # 初始化时清理csv文件
        self.rm_csv_files()

        # 初始化异步检测器
        self.async_detector = AsyncSlowNodeDetector(
            self.config,
            self.metric_args,
            self.model_args
        )

    def rm_csv_files(self):
        tmp_path = self.model_args.get("root_path")
        if not os.path.exists(tmp_path):
            return

        import shutil

        try:
            if os.path.isdir(tmp_path):
                shutil.rmtree(tmp_path)
            else:
                os.remove(tmp_path)
        except OSError as e:
            print(f"删除目录或文件 {tmp_path} 时发生错误: {e}")

    def on_recv(self, rank2data: dict[int, StepMetrics]):
        # 把StepMetrics中KernelType的name转换一下
        logger.info(
            "SlowNodeLocatorDetector received data for ranks: " + str(rank2data.keys())
        )

        # 推送至单例写入器
        writer = CSVAsyncWriter()
        writer.config = self.config  # 设置writer的config引用
        writer.add_task(rank2data, self.config.csv_path)
        logger.info("CSVAsyncWriter Queue size: " + str(writer.queue.qsize()))

        # 唤醒检测器执行检测
        self.async_detector.trigger_detection()