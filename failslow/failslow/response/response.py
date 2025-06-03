# coding=utf-8
"""
Copyright (c) Huawei Technologies Co., Ltd. 2020-2028. All rights reserved.
Description:
FileName：response.py
Author: h00568282/huangbin
Create Date: 2024/02/28 14:30
Notes:

"""

import time
from typing import List, Dict
from failslow.util.logging_utils import get_default_logger

logger = get_default_logger(__name__)


def typed_property(name, expected_type, strict_type_check=True):
    """create property for class and check types."""
    storage_name = '_' + name

    @property
    def prop(self):
        result = getattr(self, storage_name, None)
        msg = "property '{}' of instance '{}' hasn't been set. And returning None.".format(name, type(self))
        if result is None:
            logger.warning(msg)
        return result

    @prop.setter
    def prop(self, value):
        msg = "property '{}' of instance '{}' must be a {}, but got %s with type {}"
        msg = msg.format(name, type(self), expected_type, value, type(value))
        if hasattr(self, "__hijack_type_check__") and self.__hijack_type_check__:
            setattr(self, storage_name, value)
        elif strict_type_check:
            if isinstance(value, expected_type):
                setattr(self, storage_name, value)
            else:
                raise ValueError(msg)
        else:
            if not isinstance(value, expected_type):
                logger.warning(msg)
            setattr(self, storage_name, value)

    return prop


class ResultCode:
    anomaly = 201
    normal = 200


class AIJobDetectResult(dict):
    timestamp = typed_property("timestamp", int, True)
    result_code = typed_property("resultCode", int, True)
    compute = typed_property("compute", bool, False)
    network = typed_property("network", bool, False)
    storage = typed_property("storage", bool, False)
    abnormal_detail = typed_property("abnormalDetail", list, False)
    normal_detail = typed_property("normalDetail", list, False)
    error_msg = typed_property("errorMsg", str, False)

    def __init__(self):
        super().__init__()
        self.result_code = ResultCode.normal
        self.compute = False
        self.network = False
        self.storage = False
        self.abnormal_detail = []
        self.normal_detail = []
        self.error_msg = ""
        self.timestamp = 0

    def __setattr__(self, key, value):
        if key.startswith("_"):
            super().__setitem__(key.lstrip("_"), value)
        super().__setattr__(key, value)

    def __call__(self, abnormal_type):
        if abnormal_type in ["compute", "network", "storage"]:
            setattr(self, abnormal_type, True)
        else:
            raise ValueError("Invalid abnormal type")

    __setitem__ = None


class NodeData(dict):
    object_id = typed_property("objectId", str, False)
    server_ip = typed_property("serverIp", str, False)
    device_info = typed_property("deviceInfo", str, False)
    kpi_id = typed_property("kpiId", str, False)
    method_type = typed_property("methodType", str, False)
    kpi_data = typed_property('kpiData', list, False)
    rela_ids = typed_property("relaIds", list, False)
    omitted_devices = typed_property("omittedDevices", list, False)

    def __init__(self, metric_name, device_label, method_type, relate_device_labels=None, omitted_devices=None):
        super().__init__()
        # device_label: 1
        sys_id = device_label
        server_ip = "localhost"
        self.object_id = str(sys_id)
        self.server_ip = server_ip
        self.device_info = f"rank_{device_label}"
        self.kpi_id = metric_name
        self.method_type = method_type
        self.kpi_data = []
        # rela_ids = [item[-1] for item in relate_device_labels] if relate_device_labels else []
        self.rela_ids = [int(item) for item in relate_device_labels] if relate_device_labels else []
        # self.omitted_devices = [item[-1] for item in omitted_devices] if omitted_devices else []
        self.omitted_devices = [int(item) for item in omitted_devices] if omitted_devices else []

    def __setattr__(self, key, value):
        if key.startswith("_"):
            super().__setitem__(key.lstrip("_"), value)
        super().__setattr__(key, value)

    __setitem__ = None



