"""
Implementation of a data sink that writes StepMetrics to local CSV files.

Output format is compatible with LocalCsvDataSource, so persisted data
can be re-loaded for offline detection.

Supported formats:
- "nccl": hccl_activity-{ip}-.{rank}.csv (columns: kernel,t1,t2,t3,t4,step)
- "hccl": mspti-marker-{ip}-{rank}.csv (columns: Flag,Id,Kind,Name,SourceKind,Timestamp,...)
"""
import copy
import logging
import os
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set

from failslow.domain.models import StepMetrics
from failslow.infrastructure.framework.registration import DataSinkRegistry

from .schema import LocalCsvDataSinkParams

logger = logging.getLogger(__name__)

_HCCL_HEADER = "Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjectId_Ds_DeviceId,msptiObjectId_Ds_StreamId,msptiObjectId_Pt_ProcessId,msptiObjectId_Pt_ThreadId"

_NCCL_HEADER = "kernel,t1,t2,t3,t4,step"


class LocalCsvDataSink(DataSinkRegistry):
    """
    Data sink that writes StepMetrics to local CSV files.

    Supports two output formats:
    - "nccl": hccl_activity-{node_ip}-.{rank_id}.csv (time unit: us)
    - "hccl": mspti-marker-{node_ip}-{rank_id}.csv (time unit: ns)
    """

    COMPONENT_NAME = "local_csv"

    def __init__(self, params: LocalCsvDataSinkParams = None, **kwargs):
        if params is not None:
            self._params = params
        else:
            self._params = LocalCsvDataSinkParams(**kwargs)

        self._output_directory = self._params.output_directory
        self._format = self._params.format.lower()
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._lock = threading.Lock()
        self._pending_futures = []
        self._closed = False
        self._created_files: Set[str] = set()
        self._file_lock = threading.Lock()
        self._next_id: Dict[int, int] = {}

        self._ensure_output_dir()

        logger.info(
            "LocalCsvDataSink initialized: output_directory=%s, format=%s",
            self._output_directory,
            self._format,
        )

    def _ensure_output_dir(self) -> None:
        os.makedirs(self._output_directory, exist_ok=True)

    def write(self, step_metrics_list: List[StepMetrics]) -> None:
        if self._closed:
            logger.warning("DataSink is closed, skipping write")
            return

        if not step_metrics_list:
            return

        data_copy = copy.deepcopy(step_metrics_list)
        future = self._executor.submit(self._do_write, data_copy)
        with self._lock:
            self._pending_futures.append(future)

    def _do_write(self, step_metrics_list: List[StepMetrics]) -> None:
        rank_data: Dict[int, List[StepMetrics]] = defaultdict(list)
        for sm in step_metrics_list:
            rank_data[sm.rank_id].append(sm)

        for rank_id, metrics_list in rank_data.items():
            self._write_rank_file(rank_id, metrics_list)

    def _write_rank_file(self, rank_id: int, metrics_list: List[StepMetrics]) -> None:
        if self._format == "hccl":
            self._write_rank_file_hccl(rank_id, metrics_list)
        else:
            self._write_rank_file_nccl(rank_id, metrics_list)

    def _write_rank_file_nccl(self, rank_id: int, metrics_list: List[StepMetrics]) -> None:
        representative = metrics_list[0]
        node_ip = representative.node_ip

        filename = f"hccl_activity-{node_ip}-.{rank_id}.csv"
        filepath = os.path.join(self._output_directory, filename)

        rows = []
        for sm in metrics_list:
            for kernel in sm.kernels:
                t1_us = kernel.t1_ns // 1000
                t2_us = kernel.t2_ns // 1000
                t3_us = kernel.t3_ns // 1000
                t4_us = kernel.t4_ns // 1000
                rows.append(f"{kernel.name},{t1_us},{t2_us},{t3_us},{t4_us},{sm.step}")

        try:
            with self._file_lock:
                write_header = filepath not in self._created_files
                if write_header:
                    self._created_files.add(filepath)
                with open(filepath, "a") as f:
                    if write_header:
                        f.write(_NCCL_HEADER + "\n")
                    f.write("\n".join(rows) + "\n")
        except OSError as e:
            logger.error("Failed to write data to %s: %s", filepath, e)

    def _write_rank_file_hccl(self, rank_id: int, metrics_list: List[StepMetrics]) -> None:
        representative = metrics_list[0]
        node_ip = representative.node_ip

        filename = f"mspti-marker-{node_ip}-{rank_id}.csv"
        filepath = os.path.join(self._output_directory, filename)

        with self._file_lock:
            global_id = self._next_id.get(rank_id, 0)

        rows = []
        for sm in metrics_list:
            for kernel in sm.kernels:
                op_name = self._format_hccl_op_name(kernel.name, node_ip, sm)
                kid = global_id
                global_id += 1

                rows.append(f"16,{kid},1,{op_name},0,{kernel.t1_ns},0,0,0,0")
                rows.append(f"16,{kid},1,,1,{kernel.t3_ns},0,0,0,0")
                rows.append(f"32,{kid},1,,1,{kernel.t4_ns},0,0,0,0")
                if kernel.t2_ns > 0:
                    rows.append(f"32,{kid},1,,0,{kernel.t2_ns},0,0,0,0")

        try:
            with self._file_lock:
                self._next_id[rank_id] = global_id
                write_header = filepath not in self._created_files
                if write_header:
                    self._created_files.add(filepath)
                with open(filepath, "a") as f:
                    if write_header:
                        f.write(_HCCL_HEADER + "\n")
                    f.write("\n".join(rows) + "\n")
        except OSError as e:
            logger.error("Failed to write data to %s: %s", filepath, e)

    @staticmethod
    def _format_hccl_op_name(kernel_name: str, node_ip: str, sm: StepMetrics) -> str:
        """Format kernel name into HCCL Name field.

        Preserves the original kernel name so that _HCCLDataParser._extract_op_name
        can restore it exactly when reading back.

        Example: ncclDevKernel_AllReduce_Sum_f32_RING_LL -> comm:ncclDevKernel_AllReduce_Sum_f32_RING_LL!10.2.44.100!0!0
        """
        return f"comm:{kernel_name}!{node_ip}!0!0"

    def flush(self) -> None:
        with self._lock:
            futures = list(self._pending_futures)
            self._pending_futures.clear()

        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.error("Error flushing data sink: %s", e)

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self.flush()
        self._executor.shutdown(wait=True)
        logger.info("LocalCsvDataSink closed: output_directory=%s", self._output_directory)
