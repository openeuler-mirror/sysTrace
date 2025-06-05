# coding=utf-8
import json
import logging
import threading
import time
from functools import wraps

import numpy as np

from failslow.util.logging_utils import get_default_logger

LOGGER = get_default_logger(__name__)


def typed_property(name, expected_type, strict_type_check=True):
    """create property for class and check types."""
    storage_name = '_' + name

    @property
    def prop(self):
        result = getattr(self, storage_name, None)
        msg = "property '{}' of instance '{}' hasn't been set. And returning None.".format(name, type(self))
        if result is None:
            logging.warning(msg)
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
                LOGGER.warning(msg)
            setattr(self, storage_name, value)

    return prop


class Thread(threading.Thread):
    """
    Rewrite the thread in the official hreading so that the return value
    of the function can be obtained.
    """
    _results = None

    def run(self):
        """Method representing the thread's activity."""
        try:
            if self._target:
                self._results = self._target(*self._args, **self._kwargs)
        finally:
            # Avoid a refcycle if the thread is running a function with
            # an argument that has a member that points to the thread.
            del self._target, self._args, self._kwargs

    def get_results(self, timeout=None):
        self.join(timeout=timeout)
        return self._results


def cal_time(log_obj: logging.Logger, logger_level="info"):
    def _cal_time(func):
        @wraps(func)
        def _wrap(*args, **kwargs):
            t0 = time.time()
            res = func(*args, **kwargs)
            t1 = time.time()
            msg = f"function named '{func.__name__} cost {t1 - t0:}s"
            getattr(log_obj, logger_level)(msg)
            return res

        return _wrap

    return _cal_time


class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return super(NpEncoder, self).default(obj)

def is_same_list(list1, list2):
    return sorted(list1) == sorted(list2)


def is_continuous(rank_list):
    if not rank_list:
        return True

    sorted_list = sorted(rank_list)
    for i in range(len(sorted_list) - 1):
        # 检查每一对相邻元素之间的差是否为1
        if sorted_list[i + 1] - sorted_list[i] != 1:
            return False
    return True
