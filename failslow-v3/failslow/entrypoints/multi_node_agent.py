"""
多节点慢节点检测 - 节点采集代理入口

从本地 CSV 文件读取采集数据，推送到中心检测服务器。

NPU 场景：各节点运行此代理，读取本地落盘的 CSV 文件并推送
GPU 场景：外部分布式逻辑直接调用服务器 API，无需此代理

用法:
    python -m failslow.entrypoints.multi_node_agent \
        --server-url http://10.2.44.100:8765 \
        --data-dir /path/to/local/csv \
        --node-ip 10.2.44.104
"""

import argparse
import logging
import os
import signal
import sys

from failslow.infrastructure.services.node_agent import NodeAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="多节点慢节点检测 - 节点采集代理",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --server-url http://10.2.44.100:8765 --data-dir /var/log/systrace/csv

        """
    )
    parser.add_argument(
        "--server-url",
        type=str,
        help="中心检测服务器 URL，例如: http://10.2.44.100:8765",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        help="本地 CSV 数据目录路径",
    )
    parser.add_argument(
        "--node-ip",
        type=str,
        default=None,
        help="本节点 IP 地址（默认: 自动检测）",
    )
    parser.add_argument(
        "--data-format",
        type=str,
        default="auto",
        choices=["auto", "nccl", "hccl"],
        help="数据格式（auto/nccl/hccl，默认: auto 自动检测）",
    )
    parser.add_argument(
        "--data-source",
        type=str,
        default="auto",
        choices=["auto", "degradation", "local_csv"],
        help="数据源类型（auto/degradation/local_csv，默认: auto 自动检测）",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="数据推送间隔（秒，默认: 1.0）",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="推送失败最大重试次数（默认: 3）",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=5.0,
        help="重试间隔（秒，默认: 5.0）",
    )
    args = parser.parse_args()

    server_url = args.server_url
    data_dir = args.data_dir

    if not server_url:
        parser.error("--server-url is required")
    if not data_dir:
        parser.error("--data-dir is required")

    node_ip = args.node_ip
    if not node_ip:
        import socket

        try:
            node_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            node_ip = "127.0.0.1"
        logger.info("Auto-detected node IP: %s", node_ip)

    if not os.path.isdir(data_dir):
        logger.warning("Data directory does not yet exist: %s, will wait for it", data_dir)

    logger.info("=" * 60)
    logger.info("多节点慢节点检测 - 节点采集代理")
    logger.info("服务器: %s", server_url)
    logger.info("数据目录: %s", data_dir)
    logger.info("节点 IP: %s", node_ip)
    logger.info("推送间隔: %.1f 秒", args.interval)
    logger.info("数据格式: %s", args.data_format)
    logger.info("=" * 60)

    agent = NodeAgent(
        server_url=server_url,
        node_ip=node_ip,
        data_dir=data_dir,
        data_format=args.data_format,
        data_source=args.data_source,
        interval=args.interval,
        max_retries=args.max_retries,
        retry_delay=args.retry_delay,
    )

    def signal_handler(sig, frame):
        logger.info("Received signal %s, stopping agent...", sig)
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
