#!/usr/bin/env python3
import sys
import json
import os
import subprocess
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from systrace_pb2 import ProcMem, StageType

class FixedFlameGraphConverter:
    def __init__(self):
        self.stage_names = {
            StageType.STAGE_UNKNOWN: "UNKNOWN",
            StageType.STAGE_DATALOADER: "DATALOADER",
            StageType.STAGE_FORWARD: "FORWARD",
            StageType.STAGE_BACKWARD: "BACKWARD",
            StageType.STAGE_SYNCHRONIZATION: "SYNCHRONIZATION",
            getattr(StageType, "STAGE_GC", 5): "GC"
        }
        self.symbol_cache = {}
        self.so_path_cache = {}
        self.executor = ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

    def convert(self, input_pb, output_json):
        proc_mem = self._load_proc_mem(input_pb)
        alloc_groups = self._analyze_allocations(proc_mem)
        self._precache_symbols(alloc_groups)
        
        trace_events = []
        global_timestamp = 0
        
        # 按stage_name分组处理
        stage_data = defaultdict(list)
        for (stage_type, stage_id), allocs in alloc_groups.items():
            stage_name = f"{stage_id}_{self.stage_names.get(stage_type, 'UNKNOWN')}"
            stage_data[stage_name].extend(allocs)
        
        for stage_name, allocs in stage_data.items():
            # if any(s in stage_name for s in ["0_", "1_", "2_"]):
            #     continue
                
            # 生成该stage的所有事件
            stage_events = []
            min_ts = global_timestamp
            max_ts = global_timestamp + sum(a.mem_size for a in allocs)
            
            # 先添加容器事件（强制置顶）
            container_event = {
                "name": stage_name,
                "ph": "X",
                "ts": min_ts,
                "dur": max_ts - min_ts,
                "pid": proc_mem.pid,
                "tid": proc_mem.pid,
                "args": {
                    "stage_type": self.stage_names.get(next(iter(alloc_groups.keys()))[0], "UNKNOWN"),
                    "stage_id": next(iter(alloc_groups.keys()))[1],
                    "is_container": True
                }
            }
            stage_events.append(container_event)
            
            # 处理每个分配
            current_ts = global_timestamp
            for alloc in allocs:
                alloc_events, _ = self._process_allocation(alloc, proc_mem.pid, current_ts)
                stage_events.extend(alloc_events)
                current_ts += alloc.mem_size
            
            # 合并同名调用
            merged_events = self._merge_calls(stage_events, stage_name)
            trace_events.extend(merged_events)
            global_timestamp = max_ts
        
        self._save_json(output_json, trace_events)
        self.executor.shutdown()

    def _merge_calls(self, events, stage_name):
        """合并相同stage下的同名调用"""
        # 分离容器事件和调用事件
        container = [e for e in events if e.get("args", {}).get("is_container")][0]
        calls = [e for e in events if not e.get("args", {}).get("is_container")]
        
        # 按深度和名称分组
        call_groups = defaultdict(list)
        for e in calls:
            key = (e["args"]["depth"], e["name"])
            call_groups[key].append(e)
        
        # 合并每组调用
        merged_calls = []
        for (depth, name), group in call_groups.items():
            if len(group) == 1:
                merged_calls.extend(group)
                continue
                
            group.sort(key=lambda x: x["ts"])
            current = dict(group[0])
            
            for e in group[1:]:
                if e["ts"] == current["ts"] + current["dur"]:
                    current["dur"] += e["dur"]
                    current["args"]["bytes"] += e["args"]["bytes"]
                    if "merged_ptrs" not in current["args"]:
                        current["args"]["merged_ptrs"] = [current["args"]["alloc_ptr"]]
                    current["args"]["merged_ptrs"].append(e["args"]["alloc_ptr"])
                else:
                    if "merged_ptrs" in current["args"]:
                        current["args"]["alloc_ptr"] = ",".join(current["args"]["merged_ptrs"])
                        del current["args"]["merged_ptrs"]
                    merged_calls.append(current)
                    current = dict(e)
            
            if "merged_ptrs" in current["args"]:
                current["args"]["alloc_ptr"] = ",".join(current["args"]["merged_ptrs"])
                del current["args"]["merged_ptrs"]
            merged_calls.append(current)
        
        # 确保容器事件在最前
        return [container] + sorted(merged_calls, key=lambda x: x["ts"])

    def _process_allocation(self, alloc, pid, base_ts):
        """处理单个分配事件"""
        events = []
        alloc_duration = alloc.mem_size
        
        # 构建调用栈树
        call_tree = {
            "name": "[root]",
            "duration": alloc_duration,
            "children": []
        }
        current_parent = call_tree
        
        for frame in alloc.stack_frames:
            so_name = os.path.basename(frame.so_name)
            symbol = self._resolve_symbol(so_name, frame.address)
            node = {
                "name": symbol,
                "duration": alloc_duration,
                "children": []
            }
            current_parent["children"].append(node)
            current_parent = node
        
        # 调整duration
        def adjust_durations(node):
            if node["children"]:
                node["duration"] = sum(adjust_durations(child) for child in node["children"])
            return node["duration"]
        adjust_durations(call_tree)
        
        # 生成事件（BFS遍历）
        stack = deque([(call_tree, base_ts, 0)])
        call_events = []
        while stack:
            node, ts, depth = stack.popleft()
            call_events.append({
                "name": node["name"],
                "ph": "X",
                "ts": ts,
                "dur": node["duration"],
                "pid": pid,
                "tid": pid,
                "args": {
                    "depth": depth,
                    "bytes": alloc.mem_size,
                    "alloc_ptr": f"0x{alloc.alloc_ptr:x}"
                }
            })
            for child in reversed(node["children"]):
                stack.appendleft((child, ts, depth + 1))
        
        return call_events, alloc_duration

    # 保留其他基础方法
    def _load_proc_mem(self, path):
        with open(path, "rb") as f:
            proc_mem = ProcMem()
            proc_mem.ParseFromString(f.read())
            return proc_mem

    def _analyze_allocations(self, proc_mem):
        freed_ptrs = {free.alloc_ptr for free in proc_mem.mem_free_stacks}
        active_allocs = defaultdict(list)
        for alloc in proc_mem.mem_alloc_stacks:
            #if alloc.alloc_ptr not in freed_ptrs:
            active_allocs[(alloc.stage_type, alloc.stage_id)].append(alloc)
        return active_allocs

    def _precache_symbols(self, alloc_groups):
        unique_frames = set()
        for allocs in alloc_groups.values():
            for alloc in allocs:
                for frame in alloc.stack_frames:
                    so_name = os.path.basename(frame.so_name)
                    unique_frames.add((so_name, frame.address))
        list(self.executor.map(lambda args: self._resolve_symbol(*args), unique_frames))

    def _resolve_symbol(self, so_name, address):
        cache_key = f"{so_name}:{address:x}"
        if cache_key in self.symbol_cache:
            return self.symbol_cache[cache_key]
        
        so_path = self._find_so_path(so_name)
        if not so_path:
            symbol = f"{so_name}@0x{address:x}"
            self.symbol_cache[cache_key] = symbol
            return symbol
        
        try:
            result = subprocess.run(
                ["addr2line", "-e", so_path, "-f", "-C", "-p", f"0x{address:x}"],
                capture_output=True, text=True, timeout=0.05
            )
            func_name = result.stdout.split(" at ")[0].split("(")[0].strip() if result.returncode == 0 else ""
            symbol = f"{so_name}@{func_name}" if func_name else f"{so_name}@0x{address:x}"
        except:
            symbol = f"{so_name}@0x{address:x}"
        
        self.symbol_cache[cache_key] = symbol
        return symbol

    def _find_so_path(self, so_name):
        if so_name in self.so_path_cache:
            return self.so_path_cache[so_name]
        
        if os.path.isabs(so_name) and os.path.exists(so_name):
            self.so_path_cache[so_name] = so_name
            return so_name
        
        base_name = os.path.basename(so_name)
        search_paths = [
            "/usr/lib", "/usr/local/lib", "/lib",
            *os.getenv("LD_LIBRARY_PATH", "").split(":"),
            *os.getenv("PATH", "").split(":")
        ]
        
        for path in filter(os.path.isdir, search_paths):
            test_path = os.path.join(path, base_name)
            if os.path.exists(test_path):
                self.so_path_cache[so_name] = test_path
                return test_path
            
            if base_name.startswith("lib") and ".so" in base_name:
                lib_prefix = base_name.split(".so")[0]
                for ext in ["", ".1", ".2", ".3", ".4", ".5"]:
                    test_path = os.path.join(path, f"{lib_prefix}.so{ext}")
                    if os.path.exists(test_path):
                        self.so_path_cache[so_name] = test_path
                        return test_path
        
        self.so_path_cache[so_name] = None
        return None

    def _save_json(self, path, trace_events):
        if os.path.isdir(path):
            input_name = os.path.splitext(os.path.basename(sys.argv[1]))[0]
            path = os.path.join(path, f"{input_name}_fixed_flamegraph.json")
        
        with open(path, "w") as f:
            json.dump({
                "traceEvents": sorted(trace_events, key=lambda x: x["ts"]),
                "displayTimeUnit": "ns",
                "metadata": {
                    "format": "FixedFlameGraph",
                    "stage_order": list(self.stage_names.values())
                }
            }, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python proc_mem_converter.py input.pb output.json")
        sys.exit(1)
    FixedFlameGraphConverter().convert(sys.argv[1], sys.argv[2])