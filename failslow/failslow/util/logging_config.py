# coding=utf-8
import logging
import os

LOGGER_LEVEL_ENV = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR
}

LOG_FILE_ROOT = os.path.join(os.getenv('_APP_LOG_DIR', ""), os.getenv('POD_NAME', ""), 'log')

LOG_LEVEL = "INFO"
# 压缩文件数量
MAX_BACKUP_COUNT = 5
# 单位是兆
FILE_SIZE = 200

PRINT_LOG_TO_CONSOLE = True
MAX_SIZE = FILE_SIZE * 1024 * 1024
ROTATE_MAX_SIZE = 1 * MAX_SIZE

LOGGER_CONTENT_FORMAT = "%(asctime)s.%(msecs)03d(%(process)d|%(thread)d)\
[%(levelname)s][%(module)s:%(lineno)d]%(message)s"

LOGGER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
