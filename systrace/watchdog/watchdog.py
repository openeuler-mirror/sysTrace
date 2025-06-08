#!/usr/bin/env python3
"""
系统监控脚本 v1.0
功能：双配置文件监控、环境变量更新、进程逃生管理
"""
import os
import json
import time
import signal
import logging
import argparse
import subprocess
import threading
from schedule import every, run_pending
from datetime import datetime

# 配置全局参数
DEFAULT_TRACE_FILE = "trace.json"
DEFAULT_LOOP_TIME = 3
DEFAULT_LOG_FILE = "log.json"
ENV_MAPPING = {
    "sysTraceD_L0": "sysTraceD_L0",
    "sysTraceD_L1": "sysTraceD_L1",
    "sysTraceD_L2": "sysTraceD_L2",
    "sysTraceD_L3": "sysTraceD_L3",
    "escape_switch": "sysTrace_Escape"
}

class SystemMonitor:
    def __init__(self, trace_file):
        self.trace_file = trace_file
        self.sysTrace_pid = None
        self._setup_logging()
        self._parse_args()
        self.start_sysTrace()

    def _setup_logging(self):
        """配置日志记录"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[logging.FileHandler('monitor.log'), logging.StreamHandler()]
        )

    def _parse_args(self):
        """解析命令行参数"""
        parser = argparse.ArgumentParser(description='System Monitor Daemon')
        parser.add_argument('--trace', type=str, default=DEFAULT_TRACE_FILE, 
                          help='Path to trace config (default: trace.json)')
        parser.add_argument('--tracelog', type=str, default=DEFAULT_LOG_FILE,
                          help='Path to trace config (default: log.json)')
        self.args = parser.parse_args()

    def start_sysTrace(self):
        """启动监控进程"""
        try:
            proc = subprocess.Popen(["sysTrace"], stdout=subprocess.PIPE)
            self.sysTrace_pid = proc.pid
            logging.info(f"Started sysTrace (PID: {self.sysTrace_pid})")
        except FileNotFoundError:
            logging.error("sysTrace executable not found in PATH")

    def kill_sysTrace(self):
        """终止监控进程"""
        if self.sysTrace_pid and os.path.exists(f"/proc/{self.sysTrace_pid}"):
            os.kill(self.sysTrace_pid, signal.SIGTERM)
            logging.info(f"Killed sysTrace (PID: {self.sysTrace_pid})")
            self.sysTrace_pid = None

    @staticmethod
    def validate_json(file_path):
        """验证JSON文件格式"""
        try:
            with open(file_path) as f:
                json.load(f)
                return True
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logging.error(f"Invalid JSON {file_path}: {str(e)}")
            return False

    def check_systrace_stream(self, file_path, buffer_size=4096):
        """内存优化的流式检查"""
        target = "i am sysTrace"
        window = ""
    
        try:
            with open(file_path, 'r') as f:
                while (chunk := f.read(buffer_size)) :
                    window += chunk
                    if target in window:
                        logging.info(f"find str")
                        return True
                    # 保留可能跨分块的尾部字符
                    window = window[-len(target):] if len(window) > len(target) else window
            return False
        except FileNotFoundError:
            print(f"文件 {file_path} 不存在")
            return False

    def update_env_vars(self):
        """更新环境变量"""
        if not self.validate_json(self.args.trace):
            return
        try:
            with open(self.args.trace, 'r') as f:
                data = json.load(f)
                for key, env_var in ENV_MAPPING.items():
                    value = str(data.get(key, "false")).lower()
                    os.environ[env_var] = value
                    logging.info(f"Set {env_var}={value}")
        except Exception as e:
            logging.error(f"Env update failed: {str(e)}")

    def check_escape_trigger(self):
        """检查逃生开关"""
        if not self.validate_json(self.args.trace):
            return
        try:
            with open(self.args.trace, 'r') as f:
                data = json.load(f)
                if data.get("escape_switch", False) is True:
                    self.kill_sysTrace()
        except Exception as e:
            logging.error(f"Escape check failed: {str(e)}")

    def scheduler_task(self):
        """定时任务调度"""
        every(DEFAULT_LOOP_TIME).seconds.do(self.update_env_vars)
        every(DEFAULT_LOOP_TIME).seconds.do(self.check_escape_trigger)
        every(DEFAULT_LOOP_TIME).seconds.do(self.check_systrace_stream, self.args.tracelog)
        while True:
            run_pending()
            time.sleep(1)

    def run(self):
        """主运行循环"""
        threading.Thread(target=self.scheduler_task, daemon=True).start()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            self.kill_sysTrace()
            logging.info("Service stopped")

if __name__ == "__main__":
    monitor = SystemMonitor(DEFAULT_TRACE_FILE)
    monitor.run()