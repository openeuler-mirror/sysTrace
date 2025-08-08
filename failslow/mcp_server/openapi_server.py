import json
import os
from time import sleep
from typing import Union, Dict, Any, Optional
from pydantic import BaseModel
import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from failslow.response.response import AIJobDetectResult
from failslow.main import main as slow_node_detection_api
from failslow.util.logging_utils import get_default_logger
from failslow.util.constant import MODEL_CONFIG_PATH
from mcp_server.mcp_data import PerceptionResult
from mcp_server.fail_slow_detection_api import run_slow_node_perception
from mcp_server.remote_file_fetcher import sync_server_by_ip_and_type
from mcp_server.report_api import generate_normal_report, generate_degraded_report, generate_default_report
# 仅在 Linux 环境下强制使用 spawn 方式
import multiprocessing

if os.name == "posix":  # posix 表示 Linux/macOS
    multiprocessing.set_start_method("spawn", force=True)
# 初始化日志
logger = get_default_logger(__name__)

# 创建FastAPI应用
app = FastAPI(title="systrace运维接口", version="1.0.0")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 数据模型定义
class ApiResponse(BaseModel):
    """通用API响应模型"""
    data: Optional[Any] = None
    code: int = 200
    message: str = "success"


# 工具实现
def slow_node_perception_tool(task_id: str) -> PerceptionResult:
    """检测指定task_id的机器性能是否发生劣化的工具"""
    logger.info(f"性能劣化感知工具开启，task_id = {task_id}")

    try:
        with open(MODEL_CONFIG_PATH, 'r', encoding='utf-8') as reader:
            model_args = json.load(reader)
    except Exception as e:
        logger.error(f"加载模型配置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"加载模型配置失败: {str(e)}")

    try:
        sync_server_by_ip_and_type(task_id, "perception")
        res = run_slow_node_perception(model_args,task_id)
        res["task_id"] = task_id
        logger.info(f"性能感知结果: {str(res)}")
        return res
    except Exception as e:
        logger.error(f"性能劣化感知工具出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"性能劣化感知工具出错: {str(e)}")


def slow_node_detection_tool(performance_data: PerceptionResult) -> AIJobDetectResult:
    """针对性能劣化进行具体问题点诊断的工具"""
    logger.info(f"慢卡定界工具开启，performance_data = {str(performance_data)}")

    try:
        sync_server_by_ip_and_type(performance_data["task_id"], "detection")
        _res = slow_node_detection_api(performance_data)
        logger.info(f"慢卡定界结果: {json.dumps(_res)}")
        return _res
    except Exception as e:
        logger.error(f"慢卡定界工具出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"慢卡定界工具出错: {str(e)}")


def generate_report_tool(source_data: Union[dict, str], report_type: str) -> Union[str, Dict[str, Any]]:
    """生成最终报告的工具"""
    logger.info(f"调用报告工具，report_type = {report_type}")

    try:
        if report_type == "normal":
            report_content = generate_normal_report(source_data)
        elif report_type == "anomaly":
            report_content = generate_degraded_report(source_data)
        else:
            report_content = generate_default_report(source_data)

        return report_content
    except Exception as e:
        logger.error(f"报告生成工具出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"报告生成工具出错: {str(e)}")


@app.get("/slow-node/systrace", response_model=ApiResponse)
async def slow_node_perception(ip: str = Query("127.0.0.1", description="节点IP地址")):
    """
    systrace运维接口
    """
    result = slow_node_perception_tool(ip)
    # 判断是否劣化
    report_type = "anomaly" if result.get("is_anomaly", True) else "normal"
    if True is result["is_anomaly"]:
        result = slow_node_detection_tool(result)
    # 3. 自动调用报告生成
    report_content = generate_report_tool(result, report_type)

    # 4. 返回结果（包含感知结果和报告）
    return ApiResponse(data={
        "report": report_content,
        "report_type": report_type
    })


def main():
    """启动服务"""
    logger.info("启动性能调优数据采集接口服务...")
    uvicorn.run(app, host="0.0.0.0", port=12146)


if __name__ == "__main__":
    main()
