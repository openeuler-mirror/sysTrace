"""
Serialization utilities for StepMetrics and KernelType.

Converts between domain dataclass objects and JSON-compatible dicts
for HTTP transmission between nodes.
"""

import logging
from typing import Dict, List

from failslow.domain.models import KernelType, StepMetrics

logger = logging.getLogger(__name__)


def kernel_to_dict(kernel: KernelType) -> Dict:
    return {
        "name": kernel.name,
        "t1_ns": kernel.t1_ns,
        "t2_ns": kernel.t2_ns,
        "t_delta_ns": kernel.t_delta_ns,
        "t_exec_ns": kernel.t_exec_ns,
        "t3_ns": kernel.t3_ns,
        "t4_ns": kernel.t4_ns,
    }


def kernel_from_dict(data: Dict) -> KernelType:
    return KernelType(
        name=data["name"],
        t1_ns=data["t1_ns"],
        t2_ns=data["t2_ns"],
        t_delta_ns=data["t_delta_ns"],
        t_exec_ns=data["t_exec_ns"],
        t3_ns=data["t3_ns"],
        t4_ns=data["t4_ns"],
    )


def step_metrics_to_dict(sm: StepMetrics) -> Dict:
    return {
        "start_time_ns": sm.start_time_ns,
        "end_time_ns": sm.end_time_ns,
        "step": sm.step,
        "rank_id": sm.rank_id,
        "local_rank_id": sm.local_rank_id,
        "node_ip": sm.node_ip,
        "node_port": sm.node_port,
        "kernels": [kernel_to_dict(k) for k in sm.kernels],
    }


def step_metrics_from_dict(data: Dict) -> StepMetrics:
    return StepMetrics(
        start_time_ns=data["start_time_ns"],
        end_time_ns=data["end_time_ns"],
        step=data["step"],
        rank_id=data["rank_id"],
        local_rank_id=data["local_rank_id"],
        node_ip=data["node_ip"],
        node_port=data["node_port"],
        kernels=[kernel_from_dict(k) for k in data["kernels"]],
    )


def serialize_step_metrics_list(step_metrics_list: List[StepMetrics]) -> Dict:
    node_ip = step_metrics_list[0].node_ip if step_metrics_list else ""
    return {
        "node_ip": node_ip,
        "step_metrics_list": [step_metrics_to_dict(sm) for sm in step_metrics_list],
    }


def deserialize_step_metrics_payload(payload: Dict) -> tuple:
    node_ip = payload.get("node_ip", "")
    step_metrics_list = [
        step_metrics_from_dict(d) for d in payload.get("step_metrics_list", [])
    ]
    return node_ip, step_metrics_list
