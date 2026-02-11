import json
import re
import argparse
import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Dict, List, Any, Deque
from tqdm import tqdm
import psutil

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s]:%(message)s')

CPU_SCHED_PID = "CPU Scheduling"
PROCESS_SCHED_PID = 'Process Scheduling'
KERNEL_PROCESS_KEYWORDS = ['migration', 'swapper', 'kworker']


class TraceEvent(ABC):
    """所有 Trace 事件的基类"""

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]: pass


class SchedSliceEvent(TraceEvent):

    def __init__(self, comm, pid, ts, cpu, prio):
        self.comm = comm
        self.pid = pid
        self.ts = ts
        self.cpu = f"CPU {cpu}"
        self.prio = prio
        self.dur = 0
        self.end_state = "Unknown"

    def finish(self, end_ts, end_state, prio):
        self.dur = end_ts - self.ts
        self.end_state = end_state
        self.prio = prio

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": f"{self.comm}:{self.pid}",
            "ph": "X",
            "pid": CPU_SCHED_PID,
            "tid": self.cpu,
            "ts": self.ts,
            "dur": self.dur,
            "args": {"end_state": self.end_state, "prio": self.prio}
        }


class IrqEvent(TraceEvent):

    def __init__(self, name, ts, cpu, tid_name, args=None, ph="X"):
        self.name = name
        self.ts = ts
        self.cpu = f"CPU {cpu}"
        self.tid_name = tid_name
        self.args = args or {}
        self.dur = 0
        self.ph = ph

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ph": self.ph,
            "pid": CPU_SCHED_PID,
            "tid": self.tid_name,
            "ts": self.ts,
            "dur": self.dur,
            "args": self.args
        }


class ProcessStateManager:
    """管理进程在 'Process Scheduling' 视图下的状态机 (Runnable/Running/Sleep)"""

    def __init__(self):
        self.processes = {}  # key: comm:pid -> dict

    def _get_p(self, comm, pid, ts):
        key = f"{comm}:{pid}"
        if key not in self.processes:
            self.processes[key] = {
                "comm": comm, "pid": pid, "ts": ts,
                "state": 'W', "events": [],
                "meta_added": False
            }
        return self.processes[key]

    def _add_event(self, p, end_ts):
        name = "Running" if p['state'] == 'R' else "Runnable"
        if end_ts > p['ts']:
            p['events'].append({
                "name": name, "ph": "X", "pid": PROCESS_SCHED_PID,
                "tid": f"{p['comm']}:{p['pid']}", "ts": p['ts'], "dur": end_ts - p['ts']
            })

    def wakeup(self, comm, pid, ts):
        p = self._get_p(comm, pid, ts)
        p['state'] = 'W'
        p['ts'] = ts

    def run(self, comm, pid, ts):
        p = self._get_p(comm, pid, ts)
        if p['state'] == 'W':
            self._add_event(p, ts)
        p['ts'] = ts
        p['state'] = 'R'

    def sleep(self, comm, pid, ts):
        p = self._get_p(comm, pid, ts)
        if p['state'] == 'R':
            self._add_event(p, ts)
        p['ts'] = ts
        p['state'] = 'S'

    def exit(self, comm, pid, ts):
        p = self._get_p(comm, pid, ts)
        self._add_event(p, ts)
        p['state'] = 'X'

    def get_all_events(self, last_ts):
        results = []
        for key, p in self.processes.items():
            if any(k in p['comm'] for k in KERNEL_PROCESS_KEYWORDS): continue

            results.append({"name": "process_name", "ph": "M", "pid": PROCESS_SCHED_PID, "tid": key})

            if p['state'] in ['R', 'W']:
                self._add_event(p, last_ts)
            results.extend(p['events'])
        return results


class TraceParsingStrategy(ABC):
    @abstractmethod
    def parse_line(self, line: str): pass

    @abstractmethod
    def get_result(self): pass


class SchedLatencyStrategy(TraceParsingStrategy):
    def __init__(self):
        self.re_trace = re.compile(
            r'\s*(?P<task>.+?)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<flags>.{4,5})\s+(?P<ts>\s*[\d.]+):\s+(?P<action>\w+):\s+(?P<args>.*)'
        )
        self.parse_softirq_pattern = re.compile(r'vec=(?P<vec>\d+)\s+\[action=(?P<action>.+)\]')
        self.boot_us = int(psutil.boot_time() * 1000000)
        self.known_cpus = set()
        self.cpu_active_slices: Dict[str, Dict[str, SchedSliceEvent]] = {}  # cpu -> {comm:pid -> SchedSliceEvent}
        self.irq_stacks: Dict[str, Deque[IrqEvent]] = {}
        self.proc_mgr = ProcessStateManager()
        self.last_time = 0

    def _to_us(self, ts_str):
        return self.boot_us + int(float(ts_str) * 1000000)

    def parse_softirq_param(self, string: str):
        match = self.parse_softirq_pattern.search(string.strip())
        if match is None:
            logging.debug("Not match regex:{}", string)
            return
        vec = match.group('vec')
        action = match.group('action')
        result = {"vec": vec, "action": action}
        return result

    def _parse_args(self, args_str):
        kv = args_str.split(' ')
        result = [kv[0]]
        for i in range(1, len(kv)):
            if '=' in kv[i]:
                result.append(kv[i])
            else:
                result[-1] += " " + kv[i]
        kv_dic = {}
        for item in result:
            if item == '==>':
                continue
            k, v = item.split("=")
            kv_dic[k] = v

        return kv_dic

    def parse_line(self, line: str) -> List[Dict]:
        match = self.re_trace.search(line)
        if not match: return []

        ctx = match.groupdict()
        ts = self._to_us(ctx['ts'])
        self.last_time = ts
        cpu = ctx['cpu']
        action = ctx['action']

        events_to_write = []
        if cpu not in self.known_cpus:
            events_to_write.append({"name": f"CPU {cpu}", "ph": "M", "pid": CPU_SCHED_PID, "tid": f"CPU {cpu}"})
            self.known_cpus.add(cpu)

        handler = getattr(self, f"_handle_{action}", None)
        if handler:
            res = handler(cpu, ts, ctx)
            if res: events_to_write.extend(res)

        return events_to_write

    def _handle_sched_switch(self, cpu, ts, ctx):
        kv = self._parse_args(ctx['args'])
        prev_name = f"{kv['prev_comm']}:{kv['prev_pid']}"
        next_name = f"{kv['next_comm']}:{kv['next_pid']}"

        results = []
        cpu_slices = self.cpu_active_slices.setdefault(cpu, {})
        if prev_name in cpu_slices:
            ev = cpu_slices.pop(prev_name)
            ev.finish(ts, kv['prev_state'], kv['prev_prio'])
            results.append(ev.to_dict())

        cpu_slices[next_name] = SchedSliceEvent(kv['next_comm'], kv['next_pid'], ts, cpu, kv['next_prio'])

        self.proc_mgr.sleep(kv['prev_comm'], kv['prev_pid'], ts)
        self.proc_mgr.run(kv['next_comm'], kv['next_pid'], ts)
        return results

    def _handle_sched_wakeup(self, cpu, ts, ctx):
        kv = self._parse_args(ctx['args'])
        self.proc_mgr.wakeup(kv['comm'], kv['pid'], ts)
        return []

    def _handle_sched_wakeup_new(self, cpu, ts, ctx):
        return self._handle_sched_wakeup(cpu, ts, ctx)

    def _handle_sched_process_exec(self, cpu, ts, ctx):
        kv = self._parse_args(ctx['args'])
        filename = kv['filename'].split('/')[-1]
        self.proc_mgr.run(filename, kv['pid'], ts)
        self.cpu_active_slices.setdefault(cpu, {})[f"{filename}:{kv['pid']}"] = \
            SchedSliceEvent(filename, kv['pid'], ts, cpu, "unknown")
        return []

    def _handle_sched_process_free(self, cpu, ts, ctx):
        kv = self._parse_args(ctx['args'])
        self.proc_mgr.exit(kv['comm'], kv['pid'], ts)
        return []

    def _handle_irq_handler_entry(self, cpu, ts, ctx):
        kv = self._parse_args(ctx['args'])
        args = {"name": kv.get("name"), "task": f"{ctx['task']}:{ctx['pid']}", "irq": kv.get("irq")}
        ev = IrqEvent("irq", ts, cpu, f"CPU {cpu}", args)
        self.irq_stacks.setdefault(cpu, deque()).append(ev)
        return []

    def _handle_irq_handler_exit(self, cpu, ts, ctx):
        stack = self.irq_stacks.get(cpu)
        if stack:
            ev = stack.pop()
            ev.dur = ts - ev.ts
            return [ev.to_dict()]
        return []

    def _handle_softirq_entry(self, cpu, ts, ctx):
        kv = self.parse_softirq_param(ctx['args'])
        args = {"vec": kv.get("vec"), "action": kv.get("action"), "task": f"{ctx['task']}:{ctx['pid']}"}
        ev = IrqEvent("softirq", ts, cpu, f"CPU {cpu}", args)
        self.irq_stacks.setdefault(cpu, deque()).append(ev)
        return []

    def _handle_softirq_exit(self, cpu, ts, ctx):
        return self._handle_irq_handler_exit(cpu, ts, ctx)

    def _handle_softirq_raise(self, cpu, ts, ctx):
        kv = self.parse_softirq_param(ctx['args'])
        args = {"vec": kv.get("vec"), "action": kv.get("action"), "task": f"{ctx['task']}:{ctx['pid']}"}
        ev = IrqEvent("softirq_raise", ts, cpu, f"CPU {cpu}", args, ph="i")
        ev.dur = 0
        return [ev.to_dict()]

    def get_result(self):
        return self.proc_mgr.get_all_events(self.last_time)


class MmapLockStrategy(TraceParsingStrategy):
    def __init__(self):
        self.re_trace = re.compile(
            r'\s*(?P<task>.+?)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+.*?\s+(?P<ts>[\d.]+):\s+(?P<action>mmap_lock_\w+):\s+(?P<args>.*)'
        )
        self.boot_us = int(psutil.boot_time() * 1000000)
        self.pending_locks = {}  # key: pid, 记录正在申请锁的信息
        self.active_locks = {}  # key: pid, 记录已经持有锁的信息
        self.last_time = 0

    def _to_us(self, ts_str):
        return self.boot_us + int(float(ts_str) * 1000000)

    def _parse_args(self, args_str):
        items = args_str.split()
        return {item.split('=')[0]: item.split('=')[1] for item in items if '=' in item}

    def parse_line(self, line: str) -> List[Dict]:
        match = self.re_trace.search(line)
        if not match: return []

        ctx = match.groupdict()
        ts = self._to_us(ctx['ts'])
        self.last_time = ts
        pid = ctx['pid']
        comm = ctx['task']
        action = ctx['action']
        args = self._parse_args(ctx['args'])
        args['cpu'] = ctx['cpu']
        key = f"{ctx['cpu']}:{ctx['pid']}"
        events = []

        if action == "mmap_lock_start_locking":
            self.pending_locks[key] = {"ts": ts, "comm": comm, "write": args.get("write")}

        elif action == "mmap_lock_acquire_returned":
            if (args.get("success") == 'true'):
                self.active_locks[key] = {"ts": ts, "comm": comm, "write": args.get("write")}
            if key in self.pending_locks:
                start_info = self.pending_locks.pop(key)
                events.append({
                    "name": f"mmap_lock_wait({'Write' if start_info['write'] == 'true' else 'Read'})",
                    "ph": "X",
                    "pid": f"MmapLock",
                    "tid": f"{comm}:{pid}",
                    "ts": start_info['ts'],
                    "dur": ts - start_info['ts'],
                    "args": args
                })
            else:
                events.append({
                    "name": f"mmap_lock_wait({'Write' if args.get('write') == 'true' else 'Read'})",
                    "ph": "i",
                    "pid": f"MmapLock",
                    "tid": f"{comm}:{pid}",
                    "ts": ts,
                    "args": args
                })

        elif action == "mmap_lock_released":
            if key in self.active_locks:
                lock_info = self.active_locks.pop(key)
                events.append({
                    "name": f"mmap_lock_hold({'Write' if lock_info['write'] == 'true' else 'Read'})",
                    "ph": "X",
                    "pid": f"MmapLock",
                    "tid": f"{comm}:{pid}",
                    "ts": lock_info['ts'],
                    "dur": ts - lock_info['ts'],
                    "args": args
                })
            else:
                events.append({
                    "name": f"mmap_lock_hold({'Write' if args.get('write') == 'true' else 'Read'})",
                    "ph": "i",
                    "pid": f"MmapLock",
                    "tid": f"{comm}:{pid}",
                    "ts": ts,
                    "args": args
                })

        return events

    def get_result(self):
        return []

class BigDataTraceConverter:
    def __init__(self, strategy: TraceParsingStrategy):
        self.strategy = strategy

    def convert(self, input_path: str, output_path: str):
        logging.info(f"Converting {input_path} -> {output_path}")

        with open(input_path, 'r', encoding='utf-8') as fin, \
                open(output_path, 'w', encoding='utf-8') as fout:

            fout.write('{"traceEvents": [\n')

            first = True
            for line in tqdm(fin, desc="Lines"):
                if line.startswith('#') or not line.strip(): continue

                events = self.strategy.parse_line(line)
                for ev in events:
                    if not first: fout.write(",\n")
                    fout.write(json.dumps(ev))
                    first = False

            final_events = self.strategy.get_result()
            for ev in final_events:
                fout.write(",\n" + json.dumps(ev))

            fout.write('\n],\n"displayTimeUnit": "ns"}\n')


class StrategyFactory:
    _strategies = {"sched": SchedLatencyStrategy, "mmaplock": MmapLockStrategy}

    @classmethod
    def get_strategy(cls, name: str) -> TraceParsingStrategy:
        if name not in cls._strategies: raise ValueError(f"Unknown type: {name}")
        return cls._strategies[name]()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Linux Kernel Trace Converter - A tool to transform ftrace logs into Chrome/Perfetto JSON format.")

    parser.add_argument(
        "--input",
        default="trace.log",
        help="Path to the raw ftrace log file (default: trace.log)"
    )
    parser.add_argument(
        "--output",
        default="view.json",
        help="Path for the output JSON file (default: view.json)"
    )
    parser.add_argument(
        "--type",
        choices=["sched", "mmaplock"],
        default="sched",
        help="Parsing strategy to use: 'sched' for task scheduling, 'mmaplock' for memory lock analysis."
    )
    args = parser.parse_args()

    start_time = time.perf_counter()
    strategy = StrategyFactory.get_strategy(args.type)
    BigDataTraceConverter(strategy).convert(args.input, args.output)
    logging.info(f"Done in {time.perf_counter() - start_time:.2f}s")
