"""
多节点慢节点检测 - 中心服务器入口

启动 HTTP 服务器接收各节点推送的数据，并转发给 Task 按配置周期检测。

GPU 场景：外部分布式逻辑将其他节点数据收集后推送到此服务器
NPU 场景：各节点 Agent 读取本地 CSV 文件并推送到此服务器

用法:
    python -m failslow.entrypoints.multi_node_server --config config/config.json --port 8765
"""

import argparse
import json
import logging
import sys

from failslow.infrastructure.services.detection_server import DetectionServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="多节点慢节点检测 - 中心服务器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --config /etc/systrace/config/config.multi_node_slow_calc.json --port 8765

  指定预期节点:
  %(prog)s --config /etc/systrace/config/config.multi_node_slow_calc.json \\
           --expected-nodes '{"10.0.0.1": 8, "10.0.0.2": 8}'

        """
    )
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="配置文件路径",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="服务器监听地址 (默认: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="服务器监听端口 (默认: 8765)",
    )
    parser.add_argument(
        "--expected-nodes",
        type=str,
        default=None,
        help='预期节点配置 JSON，例如: \'{"10.2.44.100": 8, "10.2.44.104": 8}\'',
    )
    args = parser.parse_args()

    host = args.host or "0.0.0.0"
    port = args.port or 8765

    expected_nodes = {}
    if args.expected_nodes:
        try:
            expected_nodes = json.loads(args.expected_nodes)
        except json.JSONDecodeError as e:
            logger.error("Invalid expected-nodes JSON: %s", e)
            sys.exit(1)

    logger.info("=" * 60)
    logger.info("多节点慢节点检测 - 中心服务器")
    logger.info("配置文件: %s", args.config)
    logger.info("监听地址: %s:%d", host, port)
    logger.info("预期节点: %s", expected_nodes)
    logger.info("检测间隔: 使用配置文件中的 detect_interval_seconds")
    logger.info("=" * 60)

    server = DetectionServer(
        config_path=args.config,
        host=host,
        port=port,
        expected_nodes=expected_nodes,
    )

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
