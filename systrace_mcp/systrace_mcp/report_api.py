import json
from datetime import datetime


def generate_normal_report(data: dict) -> dict:
    """生成无劣化的正常报告"""
    # 解析时间戳为可读格式
    timestamp = data.get("start_time")
    start_time = datetime.fromtimestamp(timestamp // 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"
    timestamp = data.get("end_time")
    end_time = datetime.fromtimestamp(timestamp // 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"
    data["start_time"] = start_time
    data["end_time"] = end_time

    return data


def generate_degraded_report(data: dict) -> dict:
    """
        生成设备异常状态的JSON报告

        参数:
            data: 包含设备状态信息的字典

        返回:
            格式化的JSON报告字典
        """
    # 解析时间戳为可读格式
    timestamp = data.get("timestamp")
    detect_time = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"
    # 提取异常信息
    abnormalDetail = data.get("abnormalDetail", [])
    abnormal_count = len(abnormalDetail)


    # 整理异常节点详情
    abnormal_nodes = []
    for abnormal in abnormalDetail:
        abnormal_nodes.append({
            "objectId": abnormal.get("objectId"),
            "serverIp": abnormal.get("serverIp"),
            "deviceInfo": abnormal.get("deviceInfo"),
            "methodType": abnormal.get("methodType"),
            "kpiId":abnormal.get("kpiId"),
            "relaIds": abnormal.get("relaIds", [])
        })

    # 整理正常节点信息
    normal_nodes = [item["deviceInfo"] for item in data.get("normalDetail", [])]

    # 构建JSON报告
    report = {
        "reportName": "AI训练任务性能诊断报告",
        "overview": {
            "detectTime": detect_time,
            "abnormalNodeCount": abnormal_count,
            "compute": data.get("compute") ,
            "network": data.get("network") ,
            "storage": data.get("storage") ,
        },
        "abnormalNodes": abnormal_nodes,
        "normalNodes": {
            "count": len(normal_nodes),
            "devices": normal_nodes
        },
        "errorMessage": data.get("errorMsg", "")
    }

    return report


def generate_default_report(data: dict) -> dict:
    """生成默认报告（当类型不匹配时），返回JSON格式字典"""
    return {
        "report_title": "机器性能分析报告",
        "warning": "报告类型未识别，以下是原始数据摘要",
        "raw_data": data,
        "report_type": "default"
    }

