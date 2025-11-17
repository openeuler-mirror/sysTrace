from prometheus_client import generate_latest, registry, write_to_textfile
from typing import List, Any
import uuid as uid
import os
from queue import Queue
from threading import Thread, Event
import time
import logging
import weakref
from failslow.dataloader.hbm_sample.metrics.prom import (
    TimestampedGauge
)
from failslow.dataloader.hbm_sample.metrics._csv import (
    write_to_csv
)
from failslow.dataloader.hbm_sample.const  import (
    STEP_HEADERS, COMM_HEADERS,
    ELASTICML_JOB_ID, ELASTICML_METRICSDIR_KEY,
    ENABLE_CSV_METRICS_KEY, ENABLE_PROM_METRICS_KEY,
    DEFAULT_METRICS_DIR_VAL
)
import subprocess
STEPTIME = "e2e_step_time"
COMMTIME = "comm_time"
FWSTEPTIME = "fw_step_time"
BWSTEPTIME = "bw_step_time"

logger = logging.getLogger(__file__)

__all__ = ["metrics_registry"]

GLOBAL_METRICS_REGISTRY = None

def metrics_registry() -> 'WorkerMetricsRegistry':
    global GLOBAL_METRICS_REGISTRY
    if GLOBAL_METRICS_REGISTRY is None:
        GLOBAL_METRICS_REGISTRY = WorkerMetricsRegistry()
    return GLOBAL_METRICS_REGISTRY


class WorkerMetricsRegistry:
    """
        NOTE: TBC
    
        Export Metrics in text file format as this fits the CBG usecase
        where prometheus are not hosted on the same machine, but the metrics can be written
        to a shared file system.
    """
    def __init__(self):
        self._uuid = os.environ.get(ELASTICML_JOB_ID, str(uid.uuid4()))
        # get host name via hostname command
        try:
            # Using subprocess with a context manager
            with subprocess.Popen(["hostname"], stdout=subprocess.PIPE, text=True) as process:
                output = process.stdout.read().strip()
            self._host = output
        except Exception as e:
            logger.error(f"Cannot obtain hostname via hostname cmd, trying to obtain the hostname via XDL_IP envvar.")
            self._host = os.environ.get("XDL_IP", "localhost")
        
        self._ns = "elastic_ml"
        self._metrics_directory = os.environ.get(ELASTICML_METRICSDIR_KEY, DEFAULT_METRICS_DIR_VAL)
        self._metrics_directory = os.path.join(self._metrics_directory, self._uuid)
        if not os.path.exists(self._metrics_directory):
            os.makedirs(self._metrics_directory, exist_ok=True, mode=0o777)
        self._rank = int(os.environ.get("RANK", "0"))
        self._csv_dir_base = f"{self._rank}_metrics"
        self._csv_dir = {
            STEPTIME: os.path.join(self._metrics_directory, f"{self._csv_dir_base}_step"),
            COMMTIME: os.path.join(self._metrics_directory, f"{self._csv_dir_base}_comm"),
        }
        
        self._enable_prom_dump = int(os.environ.get(ENABLE_PROM_METRICS_KEY, "0"))
        self._enable_csv_dump = int(os.environ.get(ENABLE_CSV_METRICS_KEY, "1"))
        
        if self._enable_prom_dump:
            self._registry = registry.CollectorRegistry()
            self._prom_file_name = f"{self._rank}_metrics.prom"
            self._prom_file_path = os.path.join(self._metrics_directory, self._prom_file_name)
        
            self._prom_metrics = {
                # TODO: Perhaps it is better to use a counter
                # so we can treat these times like http_request_times[5m] for visual clues
                STEPTIME: TimestampedGauge(STEPTIME, "Time taken for a single e2e step",
                                labelnames=["uuid", "global_rank", 
                                            "host", "custom_tag"],
                                registry=self._registry, namespace=self._ns),
                COMMTIME: TimestampedGauge(COMMTIME, "Time taken for communication",
                                labelnames=["uuid", "op", "host", "global_rank",
                                            "src_rank", "dst_rank",
                                            "input_dtype", "input_shape",
                                            "output_dtype", "output_shape", "custom_tag"],
                                registry=self._registry, namespace=self._ns),
                FWSTEPTIME: TimestampedGauge(FWSTEPTIME, "Time taken for forward step",
                                labelnames=["uuid", "global_rank", "host", "custom_tag"],
                                registry=self._registry, namespace=self._ns),
                BWSTEPTIME: TimestampedGauge(BWSTEPTIME, "Time taken for backward step",
                                labelnames=["uuid", "global_rank", "host", "custom_tag"],
                                registry=self._registry, namespace=self._ns)
            }
            
        self._csv_records = {
            STEPTIME: Queue(),
            COMMTIME: Queue(),
        }
        
        self._flush_thread_started = False
        self._finished = Event()
        self.flust_to_file()
        
    def flust_to_file(self):
        if self._flush_thread_started:
            return
        logger.info("Started Flush thread.")
        # weakref to avoid holding itself.
        wf = weakref.ref(self)
        self._flush_timer = Thread(target=self.periodic_flush_file, args=(5, wf), 
                                   name="background_metrics_thread", daemon=True)
        self._flush_timer.start()
        self._flush_thread_started = True
        
        time.sleep(2)
        if not self._flush_timer.is_alive():
            raise RuntimeError("Flush thread did not start.")
        
    def write_e2e_step(self, time_in_ms: float, rank: int, num_step: float, 
                       start_time: float, custom_tag: str = None):
        if self._enable_prom_dump:
            self._prom_metrics[STEPTIME].labels(uuid=self._uuid, 
                                    host=self._host,
                                    global_rank=rank, 
                                    custom_tag=custom_tag).set(time_in_ms, start_time)
        if self._enable_csv_dump:
            self._csv_records[STEPTIME].put_nowait(
                (time_in_ms, self._host, rank, custom_tag,
                 start_time, num_step, False, False, True)
            )
        
    
    def write_fw_step(self, time_in_ms: float, rank: int, num_step: float, 
                      start_time: float, custom_tag: str = None):
        if self._enable_prom_dump:
            self._prom_metrics[FWSTEPTIME].labels(uuid=self._uuid, 
                                        host=self._host,
                                        global_rank=rank, 
                                        custom_tag=custom_tag).set(time_in_ms, start_time)
        if self._enable_csv_dump:
            self._csv_records[STEPTIME].put_nowait(
                (time_in_ms, self._host, rank, custom_tag, 
                 start_time, num_step, True, False, False)
            )
    
    
    def write_bw_step(self, time_in_ms: float, rank: int, num_step: float, 
                      start_time: float, custom_tag: str = None):
        if self._enable_prom_dump:
            self._prom_metrics[BWSTEPTIME].labels(uuid=self._uuid, 
                                        host=self._host,
                                        global_rank=rank, 
                                        custom_tag=custom_tag).set(time_in_ms, start_time)

        if self._enable_csv_dump:
            self._csv_records[STEPTIME].put_nowait(
                (time_in_ms, self._host, rank, custom_tag, 
                 start_time, num_step, False, True, False)
            )
    
    def write_comm(self, time_in_ms: float, global_rank: int, src_rank: int, dst_rank: int,
                   op: str, input_dtype: List[Any], input_shape: List[Any],
                   output_dtype: List[Any], output_shape: List[Any], 
                   host_start_time: float, 
                   task_start_time: float = None,
                   custom_tag: str = None, 
                   async_op: bool = False):
        if self._enable_prom_dump:
            self._prom_metrics[COMMTIME].labels(op=op, 
                                                global_rank=global_rank,
                                                src_rank=src_rank, 
                                                dst_rank=dst_rank,
                                                input_dtype=str(input_dtype), 
                                                input_shape=str(input_shape),
                                                output_dtype=str(output_dtype), 
                                                output_shape=str(output_shape),
                                                host=self._host,
                                                uuid=self._uuid,
                                                custom_tag=custom_tag).set(time_in_ms, host_start_time)
        if self._enable_csv_dump:
            self._csv_records[COMMTIME].put_nowait(
                (time_in_ms, self._host, global_rank, src_rank, dst_rank,
                 op, input_dtype, input_shape,
                 output_dtype, output_shape, host_start_time, task_start_time,
                 custom_tag, async_op))
    
    def latest(self) -> bytes:
        return generate_latest(self._registry)
    
    def dump_file(self):
        if self._enable_prom_dump:
            write_to_textfile(self._prom_file_path, self._registry)
        if self._enable_csv_dump:
            copied_steps = []
            copied_comms = []
            step_time_size = self._csv_records[STEPTIME].qsize()
            while step_time_size > 0:
                copied_steps.append(self._csv_records[STEPTIME].get_nowait())
                step_time_size -= 1
            
            comm_time_size = self._csv_records[COMMTIME].qsize()
            while comm_time_size > 0:
                copied_comms.append(self._csv_records[COMMTIME].get_nowait())
                comm_time_size -= 1
                    
            write_to_csv(self._csv_dir[COMMTIME], 
                         copied_comms,
                         COMM_HEADERS)
                
            write_to_csv(self._csv_dir[STEPTIME], 
                        copied_steps,
                        STEP_HEADERS)
        
    def periodic_flush_file(self, interval: int, wf: weakref.ref):
        """User should make sure this is wrapper around a background thread."""
        while True:
            o_self = wf()
            if o_self is None:
                break
            logger.debug("Waking up to dump metrics")
            o_self.dump_file()
            time.sleep(interval)
        logger.info("Finish periodic flush.")
        
    def stop_flush_thread(self):
        logger.info("Stopping flush thread...")
        if self._flush_timer.is_alive():
            self._finished.set()
    
    def __del__(self):
        self.dump_file()
        
if __name__ == "__main__":
    import time
    host_name = "localhost"
    metrics_dir = "/tmp/trainingjob_metrics"
    mr = WorkerMetricsRegistry(host_name, metrics_dir)
    for s in range(1000000):
        start_time = time.time()
        mr.write_e2e_step(0.1, 0, s, start_time)
        mr.write_comm(0.1, 0, 0, 1, "allreduce", [1, 2, 3], [4, 5, 6], [1, 2, 3], [4, 5, 6], start_time)
        time.sleep(1)
        print("dump")
        mr.dump_file()
        
