"""Some of the functions are adopted from asys ascend-system-advisor"""

from datetime import datetime, timezone
import ctypes
from queue import Queue
import logging
from enum import Enum
import time, os
from typing import List, Dict, Union, Tuple
from failslow.dataloader.hbm_sample.metrics._csv import write_to_csv
from failslow.dataloader.hbm_sample.metrics_registry import metrics_registry
from functools import lru_cache
from threading import Lock
import copy

from failslow.util.logging_utils import get_default_logger
logger = get_default_logger(__name__)

DCMILIB = "libdcmi.so"


DSMI_ERROR_CORE = {
    1: "the device does not exist.",
    2: "invalid device ID.",
    3: "invalid value",
    4: "invalid handle",
    6: "out of memory",
    7: "inner err",
    8: "para error",
    10: "repeated init",
    11: "not exist",
    13: "device busy",
    14: "device nor resources",
    16: "wait timeout",
    17: "iocrl failed",
    27: "send mesg failed",
    37: "over limit",
    38: "file ops",
    46: "oper not permitted",
    51: "try again",
    58: "memory opt fai",
    86: "partitio not right",
    87: "resource occupied",
    89: "resume",
    91: "bist hw err",
    92: "bist sw err",
    93: "dup config",
    94: "power of fail",
    -8255: "not supported",
    65534: "not support"
}

class NPUFreqType(Enum):
    CONTROL_CPU = 2
    HBM = 6
    AI_CORE_CURRENT = 7
    AI_CORE_RATED = 9

NPU_FREQUENCY_TYPE = [
    NPUFreqType.CONTROL_CPU,
    NPUFreqType.HBM,
    NPUFreqType.AI_CORE_CURRENT,
    NPUFreqType.AI_CORE_RATED
]

"""
struct dcmi_network_pkt_stats_info {

unsigned long long mac_tx_mac_pause_num;

MAC发送的pause帧总报文数

unsigned long long mac_rx_mac_pause_num;

MAC接收的pause帧总报文数

unsigned long long mac_tx_pfc_pkt_num;

MAC发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri0_pkt_num;

MAC 0号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri1_pkt_num;

MAC 1号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri2_pkt_num;

MAC 2号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri3_pkt_num;

MAC 3号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri4_pkt_num;

MAC 4号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri5_pkt_num;

MAC 5号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri6_pkt_num;

MAC 6号调度队列发送的PFC帧总报文数

unsigned long long mac_tx_pfc_pri7_pkt_num;

MAC 7号调度队列发送的PFC帧总报文数

unsigned long long mac_rx_pfc_pkt_num;

MAC接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri0_pkt_num;

MAC 0号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri1_pkt_num;

MAC 1号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri2_pkt_num;

MAC 2号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri3_pkt_num;

MAC 3号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri4_pkt_num;

MAC 4号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri5_pkt_num;

MAC 5号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri6_pkt_num;

MAC 6号调度队列接收的PFC帧总报文数

unsigned long long mac_rx_pfc_pri7_pkt_num;

MAC 7号调度队列接收的PFC帧总报文数

unsigned long long mac_tx_total_pkt_num;

MAC发送的总报文数

unsigned long long mac_tx_total_oct_num;

MAC发送的总报文字节数

unsigned long long mac_tx_bad_pkt_num;

MAC发送的坏包总报文数

unsigned long long mac_tx_bad_oct_num;

MAC发送的坏包总报文字节数

unsigned long long mac_rx_total_pkt_num;

MAC接收的总报文数

unsigned long long mac_rx_total_oct_num;

MAC接收的总报文字节数

unsigned long long mac_rx_bad_pkt_num;

MAC接收的坏包总报文数

unsigned long long mac_rx_bad_oct_num;

MAC接收的坏包总报文字节数

unsigned long long mac_rx_fcs_err_pkt_num;

MAC接收的存在FCS错误的报文数

unsigned long long roce_rx_rc_pkt_num;

RoCEE接收的RC类型报文数

unsigned long long roce_rx_all_pkt_num;

RoCEE接收的总报文数

unsigned long long roce_rx_err_pkt_num;

RoCEE接收的坏包总报文数

unsigned long long roce_tx_rc_pkt_num;

RoCEE发送的RC类型报文数

unsigned long long roce_tx_all_pkt_num;

RoCEE发送的总报文数

unsigned long long roce_tx_err_pkt_num;

RoCEE发送的坏包总报文数

unsigned long long roce_cqe_num;

RoCEE任务完成的总元素个数

unsigned long long roce_rx_cnp_pkt_num;

RoCEE接收的CNP类型报文数

unsigned long long roce_tx_cnp_pkt_num;

RoCEE发送的CNP类型报文数

unsigned long long roce_err_ack_num;

RoCEE接收的非预期ACK报文数，NPU做丢弃处理，不影响业务

unsigned long long roce_err_psn_num;

RoCEE接收的PSN>预期PSN的报文，或重复PSN报文数。乱序或丢包，会触发重传

unsigned long long roce_verification_err_num;

RoCEE接收的域段校验错误的报文数，如：icrc、报文长度、目的端口号等校验失败

unsigned long long roce_err_qp_status_num;

RoCEE接收的QP连接状态异常产生的报文数

unsigned long long roce_new_pkt_rty_num;

RoCEE发送的超次重传的数量统计

unsigned long long roce_ecn_db_num;

RoCEE接收的存在ECN标记位的报文数

unsigned long long nic_tx_all_pkg_num;

NIC发送的总报文数

unsigned long long nic_tx_all_oct_num;

NIC发送的总报文字节数

unsigned long long nic_rx_all_pkg_num;

NIC接收的总报文数

unsigned long long nic_rx_all_oct_num;

NIC接收的总报文字节数

long tv_sec;

查询发生时的当前系统时间（单位s）

long tv_usec;

查询发生时的当前系统时间（单位us）

unsigned char reserved[64];

};

"""
# Mimic the c struct above
class NetworkPacketStatInfo(ctypes.Structure):
    _fields_ = [
        ("mac_tx_mac_pause_num", ctypes.c_ulonglong),
        ("mac_rx_mac_pause_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri0_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri1_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri2_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri3_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri4_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri5_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri6_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_pfc_pri7_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri0_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri1_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri2_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri3_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri4_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri5_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri6_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_pfc_pri7_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_total_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_total_oct_num", ctypes.c_ulonglong),
        ("mac_tx_bad_pkt_num", ctypes.c_ulonglong),
        ("mac_tx_bad_oct_num", ctypes.c_ulonglong),
        ("mac_rx_total_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_total_oct_num", ctypes.c_ulonglong),
        ("mac_rx_bad_pkt_num", ctypes.c_ulonglong),
        ("mac_rx_bad_oct_num", ctypes.c_ulonglong),
        ("mac_rx_fcs_err_pkt_num", ctypes.c_ulonglong),
        ("roce_rx_rc_pkt_num", ctypes.c_ulonglong),
        ("roce_rx_all_pkt_num", ctypes.c_ulonglong),
        ("roce_rx_err_pkt_num", ctypes.c_ulonglong),
        ("roce_tx_rc_pkt_num", ctypes.c_ulonglong),
        ("roce_tx_all_pkt_num", ctypes.c_ulonglong),
        ("roce_tx_err_pkt_num", ctypes.c_ulonglong),
        ("roce_cqe_num", ctypes.c_ulonglong),
        ("roce_rx_cnp_pkt_num", ctypes.c_ulonglong),
        ("roce_tx_cnp_pkt_num", ctypes.c_ulonglong),
        ("roce_err_ack_num", ctypes.c_ulonglong),
        ("roce_err_psn_num", ctypes.c_ulonglong),
        ("roce_verification_err_num", ctypes.c_ulonglong),
        ("roce_err_qp_status_num", ctypes.c_ulonglong),
        ("roce_new_pkt_rty_num", ctypes.c_ulonglong),
        ("roce_ecn_db_num", ctypes.c_ulonglong),
        ("nic_tx_all_pkg_num", ctypes.c_ulonglong),
        ("nic_tx_all_oct_num", ctypes.c_ulonglong),
        ("nic_rx_all_pkg_num", ctypes.c_ulonglong),
        ("nic_rx_all_oct_num", ctypes.c_ulonglong),
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_long),
        ("reserved", ctypes.c_ubyte * 64)
    ]

MAX_CHIP_NAME = 32
class NPUChipInfo(ctypes.Structure):
    _fields_ = [
        ("chip_type", ctypes.c_char * MAX_CHIP_NAME),
        ("chip_name", ctypes.c_char * MAX_CHIP_NAME),
        ("chip_ver", ctypes.c_char * MAX_CHIP_NAME),
    ]

class NPUUtilizationType(Enum):
    Memory = 1
    AICore = 2
    AICPU = 3
    CtrlCPU = 4
    MemoryBW = 5
    HBM = 6
    HBMBW = 10

NPU_UTIL_TYPE = [
    # NPUUtilizationType.Memory, Not Supported
    NPUUtilizationType.AICore,
    NPUUtilizationType.AICPU,
    NPUUtilizationType.CtrlCPU,
    # NPUUtilizationType.MemoryBW, Not supported
    NPUUtilizationType.HBM,
    NPUUtilizationType.HBMBW
]

"""
#define AGENTDRV_PROF_DATA_NUM 3   /* pcie bandwidth MIN/MAX/AVG */
struct dcmi_pcie_link_bandwidth_info {
    int profiling_time;
    unsigned int tx_p_bw[AGENTDRV_PROF_DATA_NUM];
    unsigned int tx_np_bw[AGENTDRV_PROF_DATA_NUM];
    unsigned int tx_cpl_bw[AGENTDRV_PROF_DATA_NUM];
    unsigned int tx_np_lantency[AGENTDRV_PROF_DATA_NUM];

    unsigned int rx_p_bw[AGENTDRV_PROF_DATA_NUM];
    unsigned int rx_np_bw[AGENTDRV_PROF_DATA_NUM];
    unsigned int rx_cpl_bw[AGENTDRV_PROF_DATA_NUM];
};"""

class NPUPCIeLinkBWInfo(ctypes.Structure):
    _fields_ = [
        ("profiling_time", ctypes.c_int),
        ("tx_p_bw", ctypes.c_uint * 3),
        ("tx_np_bw", ctypes.c_uint * 3),
        ("tx_cpl_bw", ctypes.c_uint * 3),
        ("tx_np_lantency", ctypes.c_uint * 3),
        ("rx_p_bw", ctypes.c_uint * 3),
        ("rx_np_bw", ctypes.c_uint * 3),
        ("rx_cpl_bw", ctypes.c_uint * 3)
    ]

from dataclasses import dataclass

@dataclass
class NPUPCIeLinkBWDCMI:
    profiling_time: int
    tx_p_bw: list
    tx_np_bw: list
    tx_cpl_bw: list
    tx_np_lantency: list
    rx_p_bw: list
    rx_np_bw: list
    rx_cpl_bw: list

@dataclass
class NPUFreqDCMI:
    component: str
    freq: int

@dataclass
class NPUUtilDCMI:
    component: str
    util: int

class NPUCollector:
    def __init__(self, collect_interval_sec: int = 1):
        try:
            self._dcmi_handle = ctypes.cdll.LoadLibrary(DCMILIB)
            logger.info("Loaded dcmi library")
        except OSError as oe:
            logger.error(f"Failed to load {DCMILIB}: {oe}")
            self._dcmi_handle = None

        self._headers = None

        self._metric_dir = None
        self._initialized = False
        
        self._initialized = self._init_dcmi()
        if not self._initialized:
            logger.error("Failed to initialize dcmi")
        else:
            logger.info("Initialized dcmi")
            
        self._last_collect_time = None
        self.collect_interval_sec = collect_interval_sec
        self.cards_num = self.get_cards_num()
    
    def _init_dcmi(self):
        if self._initialized:
            return True
        
        if self._dcmi_handle is None:
            return False
        
        try:
            ret = self._dcmi_handle.dcmi_init()
        except AttributeError as e:
            logger.error(f"Failed to get dcmi_init: {e}")
            return False
        if not self.check_status(ret, "Failed to get dcmi_init"):
            return False

        return True
    
    def cleanup(self):
        if self._dcmi_handle is not None:
            # 假设你有一个反初始化函数叫 dcmi_deinit()
            if hasattr(self._dcmi_handle, 'dcmi_deinit'):
                self._dcmi_handle.dcmi_deinit()
            self._dcmi_handle = None

    def get_cards_num(self):
        """Get the number of cards in the system."""
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
            
        if self._dcmi_handle is None:
            return None
        card_num = ctypes.pointer(ctypes.c_int())
        card_list = (ctypes.c_int * 16)()
        list_len = 16
        try:
            ret = self._dcmi_handle.dcmi_get_card_list(card_num, card_list, list_len)
        except AttributeError as e:
            logger.error(f"Failed to get dcmi_get_device_temperature: {e}")
            return 0
        if not self.check_status(ret, "Failed to get dcmi_get_card_list"):
            return 0
        
        return card_num.contents.value

    def check_status(self, ret, msg="Failed to query data"):
        if ret == 0:
            return True
        logger.error(f"Status Checked - {msg}: {DSMI_ERROR_CORE.get(ret)}")
        return False
    
    def get_npu_temperature(self, device: int):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
            
        if self._dcmi_handle is None:
            return None
        p_temperature = ctypes.pointer(ctypes.c_int())
        try:
            ret = self._dcmi_handle.dcmi_get_device_temperature(device, 0, p_temperature)
        except AttributeError as e:
            logger.error(f"Failed to get dcmi_get_device_temperature: {e}")
            return 0
        if not self.check_status(ret, "Failed to get dcmi_get_device_temperature"):
            return 0
        return p_temperature.contents.value
    
    def get_npu_frequency(self, device: int):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        if self._dcmi_handle is None:
            logger.warning("Failed to load dcmi library")
            return None
        results = []
        for freq_type in NPU_FREQUENCY_TYPE:
            p_freq = ctypes.pointer(ctypes.c_int())
            try:
                ret = self._dcmi_handle.dcmi_get_device_frequency(device, 0, 
                                                                  int(freq_type.value), p_freq)
            except AttributeError as e:
                logger.error(f"Attribute - Failed to get dcmi_get_device_frequency: {e}")
                return 0
            if not self.check_status(ret, "Failed to get dcmi_get_device_frequency"):
                continue
            else:
                results.append(NPUFreqDCMI(freq_type.name, p_freq.contents.value))
                
        return results
    
    def get_npu_power(self, device: int):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        if self._dcmi_handle is None:
            return None
        p_power = ctypes.pointer(ctypes.c_int())
        try:
            ret = self._dcmi_handle.dcmi_get_device_power_info(device, 0, p_power)
        except AttributeError as e:
            logger.error(f"Failed to get dcmi_get_device_power_info: {e}")
            return 0
        if not self.check_status(ret, "Failed to get dcmi_get_device_power_info"):
            return 0
        return p_power.contents.value
    
    def _convert_pkt_status_to_dict(self, pkt_stats: NetworkPacketStatInfo):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        pkt_stats_dict = {}
        for field, _ in pkt_stats._fields_:
            if "reserved" in field:
                continue
            pkt_stats_dict[field] = getattr(pkt_stats, field)
        return pkt_stats_dict
    
    def _convert_pcie_struct_to_dataclass(self, pcie_struct: NPUPCIeLinkBWInfo):
        return NPUPCIeLinkBWDCMI(
            profiling_time=pcie_struct.profiling_time,
            tx_p_bw=list(pcie_struct.tx_p_bw),
            tx_np_bw=list(pcie_struct.tx_np_bw),
            tx_cpl_bw=list(pcie_struct.tx_cpl_bw),
            tx_np_lantency=list(pcie_struct.tx_np_lantency),
            rx_p_bw=list(pcie_struct.rx_p_bw),
            rx_np_bw=list(pcie_struct.rx_np_bw),
            rx_cpl_bw=list(pcie_struct.rx_cpl_bw)
        )
    
    def get_npu_netdev_pkt_stats_info(self, device: int):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        if self._dcmi_handle is None:
            return None
        p_pkt_stats = ctypes.pointer(NetworkPacketStatInfo())
        try:
            ret = self._dcmi_handle.dcmi_get_netdev_pkt_stats_info(device, 0, 0, p_pkt_stats)
        except AttributeError as e:
            logger.error(f"Failed to get dcmi_get_netdev_pkt_stats_info: {e}")
            return None
        if not self.check_status(ret, "Failed to get dcmi_get_netdev_pkt_stats_info"):
            return None
        
        return self._convert_pkt_status_to_dict(p_pkt_stats.contents)
    
    def get_npu_utilization_rate(self, device: int):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        # dcmi_get_device_utilization_rate
        if self._dcmi_handle is None:
            return None
        
        results = []
        for util_type in NPU_UTIL_TYPE:
            p_util = ctypes.pointer(ctypes.c_int())
            try:
                ret = self._dcmi_handle.dcmi_get_device_utilization_rate(device, 0, 
                                                                  int(util_type.value), p_util)
            except AttributeError as e:
                logger.error(f"Attribute - Failed to get dcmi_get_device_utilization_rate: {e}")
                return results
            if not self.check_status(ret, f"Failed to get dcmi_get_device_utilization_rate - {util_type.name}"):
                continue
            else:
                results.append(NPUUtilDCMI(util_type.name, p_util.contents.value))
        
        return results
    
    @lru_cache(maxsize=1)
    def get_npu_chip_info(self, device: int):
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        """int dcmi_get_device_chip_info(int card_id, int device_id, struct dcmi_chip_info *chip_info)"""
        p_chip_info = ctypes.pointer(NPUChipInfo())
        try:
            ret = self._dcmi_handle.dcmi_get_device_chip_info(device, 0, p_chip_info)
        except AttributeError as e:
            logger.error(f"Attribute - Failed to get dcmi_get_device_chip_info: {e}")
            return 0
        if not self.check_status(ret, "Failed to get dcmi_get_device_chip_info"):
            return None
        
        chip_type = p_chip_info.contents.chip_type.decode()
        chip_name = p_chip_info.contents.chip_name.decode()
        chip_ver = p_chip_info.contents.chip_ver.decode()
        return " ".join([chip_type, chip_name, chip_ver])
    
    def get_npu_pcie_bw_link(self, device: int, interval_ms: int = 1000):
        """
        NOTE: This function blocks the host, use with caution.
        
        int dcmi_get_pcie_link_bandwidth_info (int card_id, int device_id, struct dcmi_pcie_link_bandwidth_info *pcie_link_bandwidth_info)
        """
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return None
        
        p_pcie_bw_info = ctypes.pointer(NPUPCIeLinkBWInfo(profiling_time=interval_ms))
        try:
            ret = self._dcmi_handle.dcmi_get_pcie_link_bandwidth_info(device, 0, p_pcie_bw_info)
        except AttributeError as e:
            logger.error(f"Attribute - Failed to get dcmi_get_pcie_link_bandwidth_info: {e}")
            return None
        if not self.check_status(ret, "Failed to get dcmi_get_pcie_link_bandwidth_info"):
            return None

        return self._convert_pcie_struct_to_dataclass(p_pcie_bw_info.contents)
    

    def collect_once(self, device: int):
        """Collect NPU HW Data."""
        
        # return immediately, if the last collect time is less than 1 second
        if self._last_collect_time is not None and time.time() - self._last_collect_time < self.collect_interval_sec:
            return {}
        
        result = {}
        if not self._initialized:
            logger.error("Initialize dcmi first, see _init_dcmi.")
            return result
        logger.info(f"Sampling {device} NPU HW Data...")

        # result["name"] = self.get_npu_chip_info(device)
        # logger.info(f"Sampled {device} NPU chip info...")
        result["temp"] = self.get_npu_temperature(device)
        logger.info(f"Sampled {device} NPU temperature info...")
        device_freq = self.get_npu_frequency(device)
        for freq in device_freq:
            result.update(self.transform_freq_to_dict(freq))
        logger.info(f"Sampled {device} NPU Freq info...")
        result["power"] = self.get_npu_power(device)
        logger.info(f"Sampled {device} NPU power info...")
        result["device"] = device
        
        # device_netdev_pkt_status = self.get_npu_netdev_pkt_stats_info(device)
        # logger.info(f"Sampled {device} NPU netdev info...")
        # result.update(device_netdev_pkt_status)
        device_utils = self.get_npu_utilization_rate(device)
        for dutil in device_utils:
            result.update({
                f"{dutil.component}_util": dutil.util
            })
        logger.info(f"Sampled {device} NPU utilization info...")
        if self._headers is None:
            self._headers = list(result.keys())
        
        self._last_collect_time = time.time()
        now_time = datetime.now(timezone.utc).astimezone()
        now_time_stamp = now_time.timestamp()
        result["time"] = int(now_time_stamp)
        return result
    
    
    def transform_freq_to_dict(self, freq_dcmi: NPUFreqDCMI):
        return {
            f"{freq_dcmi.component}_freq": freq_dcmi.freq
        }
    
            
class NPUHWCache:
    def __init__(self, collect_interval_sec: int = 1):
        self._device = 0   # test for rank 0 sample
        self._collector = None
        self._collector = NPUCollector(collect_interval_sec=collect_interval_sec)
        self._cards_num = self._collector.cards_num
        self._collect_interval_sec = collect_interval_sec
        self._metric_dir = None
        self._last_data = None
        self._lock = Lock()
    
    def sample_once_for_all_ranks_in_node(self) -> List[Dict]:
        result = []
        for i in range(self._cards_num):
            with self._lock:
                data = self._collector.collect_once(i)
                result.append(data)
                logger.info(f"Sampled {i} NPU HW Data: {data}...")
            time.sleep(1)
        return result
    
    def dump_node_npu_data(self, result: list):
        """Dump all ranks sample data to csv. 
           The location is determined by the metrics registry.
        """
        if self._metric_dir is None:
            self._metric_dir = metrics_registry()._csv_dir_base
            self._metric_dir = os.path.join(self._metric_dir, f"npu_device_ranks")
        
        with self._lock:
            if len(result) == 0:
                # logger.warning("No NPUHW data to dump")
                return
            # copied = copy.deepcopy(self._last_data)
            # self._last_data = None
        if result:
            headers = list(result[0].keys())
        else:
            headers = []
        
        write_to_csv(self._metric_dir, 
                     result, 
                     headers)

    def clean_up(self):
        self._collector.cleanup()
        
    def sample_once(self):
        """
        Sample data once and store it in the cache。
        Up to the user to decide how to collect this data."""
        with self._lock:
            self._last_data = self._collector.collect_once(self._device)
        return self._last_data

    def dump_last(self):
        """Dump the last sample to csv. 
           The location is determined by the metrics registry.
        """
        if self._metric_dir is None:
            self._metric_dir = metrics_registry()._csv_dir_base
            self._metric_dir = os.path.join(self._metric_dir, f"npu_device_{self._device}")
        
        
        with self._lock:
            if self._last_data is None or len(self._last_data) == 0:
                # logger.warning("No NPUHW data to dump")
                return
            copied = copy.deepcopy(self._last_data)
            self._last_data = None
        k = list(copied.keys())
        
        write_to_csv(self._metric_dir, 
                     [copied], 
                     k)
        

GLOBAL_NPU_HW_CACHE = None
MAX_LEN = 1
def get_npu_hw_cache(collect_interval_sec: int = 1):
    global GLOBAL_NPU_HW_CACHE
    if GLOBAL_NPU_HW_CACHE is None:
        GLOBAL_NPU_HW_CACHE = NPUHWCache(collect_interval_sec=collect_interval_sec)
    return GLOBAL_NPU_HW_CACHE

def npu_sampler():
    all_result = []
    collect_interval_sec = 1
    nm = get_npu_hw_cache(collect_interval_sec)

    try:
        while True: 
            result = nm.sample_once_for_all_ranks_in_node()
            all_result.extend(result)
            if len(all_result) > MAX_LEN:
                nm.dump_node_npu_data(all_result)
                all_result = []
            time.sleep(5) 

        nm.clean_up()
        
    except:
        logger.info(f"Exit program.")

if __name__ == "__main__":
    npu_sampler()


