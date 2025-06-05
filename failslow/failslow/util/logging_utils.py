# coding=utf-8

import logging
import logging.handlers
import os
import re
import secrets
import time
import traceback
from datetime import datetime
from zipfile import ZIP_DEFLATED, ZipFile

from failslow.util import logging_config
from failslow.util.logging_config import MAX_SIZE, MAX_BACKUP_COUNT, LOG_LEVEL, LOG_FILE_ROOT, PRINT_LOG_TO_CONSOLE

__DEFAULT_LOGGERS = dict()

root_path = os.path.dirname(os.path.dirname(__file__))

formatter = logging.Formatter(
    logging_config.LOGGER_CONTENT_FORMAT,
    logging_config.LOGGER_TIME_FORMAT)


def get_default_logger(module="default", log_path=None) -> logging.Logger:
    global __DEFAULT_LOGGERS
    if not __DEFAULT_LOGGERS.get(module):
        __DEFAULT_LOGGERS[module] = get_logger(module=module,
                                               log_path=log_path or os.path.join(LOG_FILE_ROOT,
                                                                                 "failslow_localization.log"),
                                               max_file_size=MAX_SIZE,
                                               max_backup_count=MAX_BACKUP_COUNT)

    return __DEFAULT_LOGGERS.get(module)


def get_logger(module, log_path, max_file_size, max_backup_count):
    logger = logging.getLogger(module)
    if len(logger.handlers) == 0:
        logger.propagate = 0
        logger.setLevel(LOG_LEVEL)
        if PRINT_LOG_TO_CONSOLE:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
        else:
            handler = get_log_handler(log_path, max_file_size, max_backup_count)
        logger.addHandler(handler)
    return logger


def get_dummy_logger():
    logger = logging.getLogger()
    if len(logger.handlers) == 0:
        logger.propagate = 0
        logger.setLevel(LOG_LEVEL)
        """
        When the permission of the log directory is 000, 
        to avoid the execution of the command line,
        the log is printed to the console.
        """
        logger.addHandler(logging.NullHandler())
    return logger


def uniep_log_namer(name):
    return name + ".zip"


def uniep_log_rotator(source, dest):
    """
    Dump function, the main logic is as follows:
    1. First compress the file
    2. According to the dump file, get the final file content,
    and write to the source file to prevent the loss of file content.
    """
    try:
        with ZipFile(dest, "w", ZIP_DEFLATED) as archived_file:
            archived_file.write(source, os.path.basename(source))
        if os.path.getsize(source) > 2 * logging_config.ROTATE_MAX_SIZE:
            # Abnormal scenes directly clear the file. Avoid unlimited log growth.
            os.remove(source)
    except Exception:
        # Abnormal scenes directly clear the file. Avoid unlimited log growth.
        os.remove(source)


class LockFile:
    def __init__(self, roll_tag_file_path):
        self._roll_tag_file_path = roll_tag_file_path

    def __enter__(self):
        with os.fdopen(os.open(self._roll_tag_file_path, os.O_WRONLY | os.O_CREAT, 0o640), "w"):
            pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if os.path.exists(self._roll_tag_file_path):
            os.remove(self._roll_tag_file_path)


def get_log_handler(log_path, max_file_size, max_backup_count):
    sop_log_handler = None
    try:
        log_dir = os.path.dirname(log_path)
        os.makedirs(log_dir, 0o750, exist_ok=True)
        sop_log_handler = ConcurrentRotatingFileHandler(log_path,
                                                        max_bytes=max_file_size,
                                                        backup_count=max_backup_count)
        sop_log_handler.rotator = uniep_log_rotator
        sop_log_handler.namer = uniep_log_namer
        sop_log_handler.setFormatter(formatter)
    except BaseException:
        get_dummy_logger().exception('Get LOGGER filed, used stdout instead')
    return sop_log_handler


class ConcurrentRotatingFileHandler(logging.handlers.RotatingFileHandler,
                                    logging.handlers.WatchedFileHandler):
    def __init__(self, log_path, max_bytes=20, backup_count=5):
        logging.handlers.RotatingFileHandler.__init__(self, log_path,
                                                      maxBytes=max_bytes,
                                                      backupCount=backup_count)
        logging.handlers.WatchedFileHandler.__init__(self, log_path)

        self._sop_file_size = max_bytes
        self.dev, self.ino = -1, -1
        log_dir, log_full_name = os.path.split(log_path)

        self.log_dir = log_dir
        self.log_full_name = log_full_name
        self._roll_tag_file_path = os.path.join(log_dir, "ROLLING_TAG")
        self._statstream()

    @staticmethod
    def get_zip_log_files(log_dir, log_full_name):
        log_name = log_full_name.rstrip(".log")
        watched_backup_file = []
        create_time_dict = {}
        for file_name in os.listdir(log_dir):
            if re.match(log_name + r"_\d+\.zip", file_name):
                path = os.path.join(log_dir, file_name)
                watched_backup_file.append(path)
                search_result = re.search(r"(\d+)", file_name)
                create_time_dict[path] = search_result.group()

        watched_backup_file = sorted(watched_backup_file, key=lambda x: create_time_dict[x])
        return watched_backup_file

    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        max_try = 0
        if self.backupCount > 0:
            while max_try < 10:
                if os.path.exists(self.baseFilename):
                    _rotator_file_size = os.path.getsize(self.baseFilename)
                else:
                    with os.fdopen(os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT, 0o640), "w"):
                        pass
                    _rotator_file_size = 0
                if _rotator_file_size < logging_config.ROTATE_MAX_SIZE:
                    return
                else:
                    # 避免多个进程同时创建了lock_file
                    for i in range(10):
                        time.sleep(secrets.randbelow(100) / 1000)  # 生成0到0.099之间的随机浮点数
                    while os.path.exists(self._roll_tag_file_path):
                        time.sleep(max(0.5, secrets.randbelow(1000) / 1000))  # 生成0到0.999之间的随机浮点数，至少为0.5
                        max_try += 1
                    else:
                        try:
                            self.rotate_backup_dfn()
                        except Exception:
                            if not os.path.exists(self.baseFilename):
                                with os.fdopen(os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT, 0o640), "w"):
                                    pass
                            with os.fdopen(os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT, 0o640), "r+") as f:
                                f.write(traceback.print_exc())

        if not self.delay:
            self.stream = self._open()

    def rotate_backup_dfn(self):
        with LockFile(self._roll_tag_file_path):
            now = datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]
            current_zip_files = self.get_zip_log_files(self.log_dir, self.log_full_name)
            while len(current_zip_files) >= self.backupCount:
                oldest_backup = current_zip_files[0]
                if os.path.exists(oldest_backup):
                    os.remove(oldest_backup)
                current_zip_files = self.get_zip_log_files(self.log_dir, self.log_full_name)
            # 多进程下
            name, suffix = os.path.splitext(self.baseFilename)
            os.rename(self.baseFilename, name + "_" + now + suffix)
            if not os.path.exists(self.baseFilename):
                with os.fdopen(os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT, 0o640), "w"):
                    pass
        backup_dfn = self.rotation_filename(name + "_" + now)
        self.rotate(name + "_" + now + suffix, backup_dfn)
        if os.path.exists(name + "_" + now + suffix):
            os.remove(name + "_" + now + suffix)

    def emit(self, record):
        self.reopenIfNeeded()
        super().emit(record)
