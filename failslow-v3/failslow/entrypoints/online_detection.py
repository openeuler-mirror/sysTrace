"""
在线检测测试入口程序

测试 failslow-v3 的在线检测能力：
1. 从本地 CSV 数据目录读取数据
2. 按 step 分组，每个 step 间隔一段时间
3. 将数据传入 Task.on_recv_all_step 接口

用法:
    python -m failslow.entrypoints.online_test --data-dir /path/to/data --interval 1.0
"""

import argparse
import csv
import logging
import os
import time
from pathlib import Path
from typing import Dict, List

from ..domain.models import KernelType, StepMetrics, TaskType
from ..task.task import Task


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
)


def load_nccl_data(data_dir: str) -> Dict[int, List[StepMetrics]]:
    """
    从 NCCL 数据目录加载数据，按 step 分组。
    """
    data_by_step: Dict[int, List[StepMetrics]] = {}

    csv_files = sorted(Path(data_dir).glob("*.csv"))
    if not csv_files:
        logging.warning("No CSV files found in %s", data_dir)
        return data_by_step

    logging.info("Found %d CSV files in %s", len(csv_files), data_dir)

    for csv_file in csv_files:
        if not _is_standard_nccl_filename(csv_file.name):
            logging.debug("Skipping non-standard file: %s", csv_file.name)
            continue

        rank_id = _extract_rank_from_filename(csv_file.name)
        logging.info("Processing file: %s (rank=%d)", csv_file.name, rank_id)

        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                step_id = int(row.get("step", row.get("Step", 0)))
                t1_us = int(row["t1"])
                t2_us = int(row["t2"])
                t3_us = int(row["t3"])
                t4_us = int(row["t4"])
                t1_ns = t1_us * 1000
                t2_ns = t2_us * 1000
                t3_ns = t3_us * 1000
                t4_ns = t4_us * 1000
                kernel = KernelType(
                    name=row["kernel"],
                    t1_ns=t1_ns,
                    t2_ns=t2_ns,
                    t_delta_ns=float(t3_us - t2_us) * 1000,
                    t_exec_ns=float(t4_us - t3_us) * 1000,
                    t3_ns=t3_ns,
                    t4_ns=t4_ns,
                )

                step = StepMetrics(
                    start_time_ns=t1_ns,
                    end_time_ns=t4_ns,
                    step=step_id,
                    rank_id=rank_id,
                    local_rank_id=rank_id,
                    node_ip="10.2.44.100",
                    node_port=8080,
                    kernels=[kernel],
                )

                if step_id not in data_by_step:
                    data_by_step[step_id] = []
                data_by_step[step_id].append(step)

    logging.info(
        "Loaded %d steps from %d ranks",
        len(data_by_step),
        len(set(s.rank_id for steps in data_by_step.values() for s in steps)),
    )
    return data_by_step


def _is_standard_nccl_filename(filename: str) -> bool:
    """检查文件名是否为标准 NCCL 格式，跳过 _with_delta/_device/_op_launch 等衍生文件"""
    import re

    basename = os.path.splitext(filename)[0]
    if not re.search(r"[.-]\d+$", basename):
        return False
    for suffix in ("_with_delta", "_device", "_op_launch"):
        if basename.endswith(suffix):
            return False
    return True


def _extract_rank_from_filename(filename: str) -> int:
    """从文件名提取 rank ID"""
    import re

    basename = os.path.splitext(filename)[0]

    match = re.search(r"-(\d+)$", basename)
    if match:
        return int(match.group(1))

    match = re.search(r"\.(\d+)$", basename)
    if match:
        return int(match.group(1))

    logging.warning("Could not extract rank from filename: %s", filename)
    return 0


def run_online_test(config_path: str, data_dir: str, interval: float, max_steps: int = None):
    """
    运行在线检测测试

    Args:
        config_path: 配置文件路径
        data_dir: 数据目录路径
        interval: 每个 step 之间的间隔时间（秒）
        max_steps: 最大测试步数，None 表示测试所有步
    """
    logging.info("=" * 60)
    logging.info("在线检测测试开始")
    logging.info("配置文件: %s", config_path)
    logging.info("数据目录: %s", data_dir)
    logging.info("Step 间隔: %.2f 秒", interval)
    logging.info("=" * 60)

    task = Task(config_path=config_path)
    logging.info("Task 创建成功: %s (type=%s)", task.name, task.task_type)

    if not data_dir:
        task_config = task._config.tasks[0]
        ds = task_config.data_source
        if ds is not None:
            if hasattr(ds, '_params') and hasattr(ds._params, 'directory_path'):
                data_dir = ds._params.directory_path
            elif hasattr(ds, 'params') and hasattr(ds.params, 'directory_path'):
                data_dir = ds.params.directory_path
        if data_dir:
            logging.info("使用配置文件中的 data_source.directory_path: %s", data_dir)
        else:
            logging.error("未指定数据目录，请使用 --data-dir 参数指定，或在配置文件中设置 data_source.params.directory_path")
            task.shutdown()
            return

    data_by_step = load_nccl_data(data_dir)
    if not data_by_step:
        logging.error("No data loaded, exiting")
        return

    sorted_steps = sorted(data_by_step.keys())
    if max_steps:
        sorted_steps = sorted_steps[:max_steps]

    logging.info("将发送 %d 个 steps", len(sorted_steps))
    logging.info("开始发送数据...")

    for i, step_id in enumerate(sorted_steps):
        steps = data_by_step[step_id]
        ranks = [s.rank_id for s in steps]
        # logging.info(
        #     "[Step %d/%d] 发送 step_id=%d, ranks=%s (%d ranks)",
        #     i + 1,
        #     len(sorted_steps),
        #     step_id,
        #     ranks,
        #     len(steps),
        # )

        task.on_recv_all_step(steps)

        if i < len(sorted_steps) - 1:
            time.sleep(interval)

    time.sleep(50)
    logging.info("=" * 60)
    logging.info("在线检测测试完成")
    logging.info("=" * 60)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="在线检测测试入口",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --data-dir /path/to/data --interval 1.0

  指定配置文件和最大步数:
  %(prog)s --config /etc/systrace/config/config.slow_calc.json \\
           --data-dir /path/to/data --max-steps 100
        """
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="配置文件路径（默认使用 config/config.v3.json）",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="数据目录路径",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="每个 step 之间的间隔时间（秒）",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="最大测试步数",
    )
    args = parser.parse_args()

    config_path = args.config
    if not config_path:
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "..",
            "config",
            "config.v3.json",
        )

    run_online_test(
        config_path=config_path,
        data_dir=args.data_dir,
        interval=args.interval,
        max_steps=args.max_steps,
    )


if __name__ == "__main__":
    main()
