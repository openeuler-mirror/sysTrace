from typing import Union

import json

from mcp.server import FastMCP

from failslow.response.response import AIJobDetectResult
from failslow.util.logging_utils import get_default_logger
from failslow.util.constant import MODEL_CONFIG_PATH
from failslow.main import main as slow_node_detection_api

from systrace_mcp.report_api import generate_normal_report, generate_degraded_report, generate_default_report
from systrace_mcp.mcp_data import PerceptionResult
from systrace_mcp.fail_slow_detection_api import run_slow_node_perception
from systrace_mcp.remote_file_fetcher import sync_server_by_ip_and_type

logger = get_default_logger(__name__)
# 仅在 Linux 环境下强制使用 spawn 方式
import multiprocessing
import os
if os.name == "posix":  # posix 表示 Linux/macOS
    multiprocessing.set_start_method("spawn", force=True)
# 创建MCP Server
mcp = FastMCP("SysTrace MCP Server", host="0.0.0.0", port=12145)


@mcp.prompt(description="工具定位")
def self_introduction() -> str:
    return "面向运维、开发人员，支持自然语言对接，实现启发式调优，实现3个工具接口，分别为性能劣化感知工具，慢卡定界工具，报告输出工具。"


@mcp.prompt(description="调用逻辑:1. 当用户询问特定任务ID的机器性能是否劣化时调用。2. 检测结果将决定后续流程走向。\
            3. 调用完成后如果出现劣化现象，则把当前工具得到的结果作为入参，调用slow_node_detection_tool方法 ，如果没有出现劣化现象，则调用报告工具返回报告给用户。\
            4. 本方法得到的结果必须再调用generate_report 生成报告给到用户"
            )
@mcp.tool(
    name="slow_node_perception_tool"
)
def slow_node_perception_tool(task_id: str) -> PerceptionResult:
    """
    这是检测指定task_id的机器性能是否发生劣化的工具;
    入参 task_id ，如 192.168.2.122;
    返回 PerceptionResult 如果is_anomaly=false，该结果需要调用generate_report_tool再返回给用户;如果is_anomaly=True,该结果必须调用slow_node_detection_tool得到报告
    """
    print("性能劣化感知工具 开启")
    print("task_id = " + task_id)

    with open(MODEL_CONFIG_PATH, 'r', encoding='utf-8') as reader:
        model_args = json.load(reader)
    sync_server_by_ip_and_type(task_id, "perception")
    res = run_slow_node_perception(model_args,task_id)
    return res


@mcp.prompt(description="调用逻辑:1. 仅在感知工具返回is_anomaly=True时调用。2. 接收感知工具的全量性能数据作为输入。 3. 本方法得到的结果必须再调用generate_report 生成报告给到用户")
@mcp.tool(name="slow_node_detection_tool")
def slow_node_detection_tool(performance_data: PerceptionResult) -> AIJobDetectResult:
    """
    这是针对slow_node_perception_tool工具返回is_anomaly=True时调用的慢卡定界工具
    输入:
    performance_data: 感知工具返回的完整性能数据PerceptionResult；
    输出：AIJobDetectResult，该结果必须要调用generate_report_tool得到报告再返回给用户
    """
    print("慢卡定界工具")
    print("performance_data = " + str(performance_data))
    sync_server_by_ip_and_type(performance_data["task_id"], "detection")
    _res = slow_node_detection_api()
    print(json.dumps(_res))
    return _res


@mcp.prompt(description="调用slow_node_perception_tool 或 slow_node_detection_tool 后把结果传入generate_report ")
@mcp.tool()
def generate_report_tool(source_data: Union[dict, str], report_type: str) -> dict:
    """
    使用 报告工具：生成最终Markdown格式报告
    输入:
    source_data 感知或定界的结果
    report_type 是否劣化 normal anomaly
    您是一个专业的性能劣化分析人员，擅长分析服务器运行健康状态，生成报告，报告标题“AI训练任务性能诊断报告”。一下内容如实回答，不要发散。注意训练任务使用的是NPU卡，不是GPU，不要带有GPU相关字眼。未劣化时，直接给结论，不要发散，没有cpu、磁盘等指标之类的字眼。
    当前时间：{{ time }}，可以作为时间参照。
    先判断是否性能劣化，{report_type}为normal 未劣化，anomaly 劣化；
    未劣化分析步骤如下：
    1、总览：根据<context>里的{start_time}{end_time}得到开始和结束时间，结论是当前AI训练任务运行正常，将持续监测。
    劣化分析步骤如下：
    1、总览：根据<context>里的{time}得到检测时间，{abnormalNodeCount}异常节点数量，{compute}{network}{storage}异常类型true为异常，false正常；
    2、细节：每条节点的具体卡号{objectId}、异常指标{kpiId}（其中：HcclAllGather表示集合通信库的AllGather时序序列指标；HcclReduceScatter表示集合通信库的ReduceScatter时序序列指标；HcclAllReduce表示集合通信库的AllReduce时序序列指标；），检测方法{methodType}（SPACE 多节点空间对比检测器，TIME 单节点时间检测器），以表格形式呈现；
    3、针对这个节点给出检测建议，如果是计算类型，建议检测卡的状态，算子下发以及算子执行的代码，对慢节点进行隔离；如果是网络问题，建议检测组网的状态，使用压测节点之间的连通状态；如果是存储问题，建议检测存储的磁盘以及用户脚本中的dataloader和保存模型代码。
    """
    print("调用了报告工具，report_type = " + report_type)
    # 根据报告类型调用对应的生成方法
    if report_type == "normal":
        return json.dumps(generate_normal_report(source_data))
    elif report_type == "anomaly":
        return json.dumps(generate_degraded_report(source_data))
    else:
        # 默认报告类型
        return generate_default_report(source_data)

def main():
    # 初始化并启动服务
    mcp.run(transport='sse')
if __name__ == "__main__":
    main()
