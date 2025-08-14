import json
from datetime import datetime

from systrace_mcp.mcp_data import PerceptionResult, AIJobDetectResult


def generate_normal_report(data: PerceptionResult) -> dict:
    """生成无劣化的正常报告"""
    data = data.model_dump()
    timestamp = data.get("start_time")
    start_time = datetime.fromtimestamp(timestamp // 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"
    timestamp = data.get("end_time")
    end_time = datetime.fromtimestamp(timestamp // 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"
    data["start_time"] = start_time
    data["end_time"] = end_time

    return data


def generate_degraded_report(data: AIJobDetectResult) -> dict:
    """
        生成设备异常状态的JSON报告

        参数:
            data: 包含设备状态信息的字典

        返回:
            格式化的JSON报告字典
        """
    # 解析时间戳为可读格式
    data = data.model_dump()
    timestamp = data.get("timestamp")
    detect_time = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"
    # 提取异常信息
    abnormalDetail = data.get("abnormal_detail", [])
    abnormal_count = len(abnormalDetail)

    # 整理异常节点详情
    abnormal_nodes = []
    for abnormal in abnormalDetail:
        abnormal_nodes.append({
            "objectId": abnormal.get("objectId"),
            "serverIp": abnormal.get("serverIp"),
            "deviceInfo": abnormal.get("deviceInfo"),
            "methodType": abnormal.get("methodType"),
            "kpiId": abnormal.get("kpiId"),
            "relaIds": abnormal.get("relaIds", [])
        })

    # 整理正常节点信息
    normal_nodes = [item["deviceInfo"] for item in data.get("normal_detail", [])]

    # 构建JSON报告
    report = {
        "reportName": "AI训练任务性能诊断报告",
        "overview": {
            "detectTime": detect_time,
            "abnormalNodeCount": abnormal_count,
            "compute": data.get("compute"),
            "network": data.get("network"),
            "storage": data.get("storage"),
        },
        "abnormalNodes": abnormal_nodes,
        "normalNodes": {
            "count": len(normal_nodes),
            "devices": normal_nodes
        },
        "errorMessage": data.get("errorMsg", "")
    }

    return report

