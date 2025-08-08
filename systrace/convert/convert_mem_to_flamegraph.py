#!/usr/bin/env python3
import sys
import json
import os
import subprocess
import glob
import argparse
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from systrace_pb2 import ProcMem, StageType

processed_files = defaultdict(bool)

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
        current_ts = 0
        alloc_records = {alloc.alloc_ptr: alloc for alloc in proc_mem.mem_alloc_stacks}
        stage_stats = defaultdict(lambda: {'allocated': 0, 'freed': 0})

        for alloc in proc_mem.mem_alloc_stacks:
            stage_key = (alloc.stage_type, alloc.stage_id)
            stage_stats[stage_key]['allocated'] += alloc.mem_size
        for free in proc_mem.mem_free_stacks:
            if free.alloc_ptr in alloc_records:
                alloc = alloc_records[free.alloc_ptr]
                stage_key = (free.stage_type, free.stage_id)
                stage_stats[stage_key]['freed'] += alloc.mem_size

        stage_data = defaultdict(list)
        for (stage_type, stage_id), allocs in alloc_groups.items():
            stage_name = f"{stage_id}_{self.stage_names.get(stage_type, 'UNKNOWN')}"
            stage_data[stage_name].extend(allocs)

        cumulative_alloc = 0
        stage_alloc_info = {}
        for stage_name, allocs in stage_data.items():
            stage_key = next(k for k in alloc_groups.keys()
                            if f"{k[1]}_{self.stage_names.get(k[0], 'UNKNOWN')}" == stage_name)
            current_alloc = sum(a.mem_size for a in allocs)
            current_free = stage_stats[stage_key]['freed']
            cumulative_alloc += (current_alloc - current_free)
            held_memory = max(cumulative_alloc, 0)
            stage_alloc_info[stage_name] = {
                'allocated': current_alloc,
                'freed': current_free,
                'held': held_memory
            }
            cumulative_alloc += current_alloc

        for stage_name, allocs in stage_data.items():
            if stage_name.startswith(("0_", "1_", "2_")):
                continue

            stage_events = []
            min_ts = current_ts
            allocated_size = sum(a.mem_size for a in allocs)
            max_ts = min_ts + allocated_size

            container_event = {
                "name": stage_name,
                "ph": "X",
                "ts": min_ts,
                "dur": stage_alloc_info[stage_name]['held'] / 10000000,
                "pid": proc_mem.pid,
                "tid": "stage",
                "args": {
                    "stage_type": self.stage_names.get(next(iter(alloc_groups.keys()))[0], "UNKNOWN"),
                    "stage_id": next(iter(alloc_groups.keys()))[1],
                    "is_container": True,
                    "allocated": stage_alloc_info[stage_name]['allocated'],
                    "freed": stage_alloc_info[stage_name]['freed'],
                    "held": stage_alloc_info[stage_name]['held']
                }
            }
            stage_events.append(container_event)

            alloc_start_ts = min_ts
            for alloc in allocs:
                alloc_events, _ = self._process_allocation(alloc, proc_mem.pid, alloc_start_ts)
                stage_events.extend(alloc_events)
                alloc_start_ts += alloc.mem_size
                processed_files[proc_mem.pid] = True

            trace_events.extend(self._merge_calls(stage_events, stage_name))


            current_ts = max_ts
        if not processed_files[proc_mem.pid]:
            empty_container = {
                "name": f"Empty_PID_{proc_mem.pid}",
                "ph": "X",
                "ts": current_ts,
                "dur": 0.1,  # 很小的持续时间
                "pid": proc_mem.pid,
                "tid": "NODATA",
                "args": {
                    "stage_type": "EMPTY",
                    "stage_id": -1,
                    "is_container": True,
                    "allocated": 0,
                    "freed": 0,
                    "held": 0
                }
            }
            trace_events.append(empty_container)
        self._save_json(output_json, trace_events)
        self.executor.shutdown()

    def _merge_calls(self, events, stage_name):
        container = [e for e in events if e.get("args", {}).get("is_container")][0]
        calls = [e for e in events if not e.get("args", {}).get("is_container")]
        call_groups = defaultdict(list)
        for e in calls:
            key = (e["args"]["depth"], e["name"])
            call_groups[key].append(e)

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
        return [container] + sorted(merged_calls, key=lambda x: x["ts"])

    def _process_allocation(self, alloc, pid, base_ts):
        events = []
        alloc_duration = alloc.mem_size
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

        def adjust_durations(node):
            if node["children"]:
                node["duration"] = sum(adjust_durations(child) for child in node["children"])
            return node["duration"]
        adjust_durations(call_tree)

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
                "tid": "Call Trace",
                "args": {
                    "depth": depth,
                    "bytes": alloc.mem_size,
                    "alloc_ptr": f"0x{alloc.alloc_ptr:x}"
                }
            })
            for child in reversed(node["children"]):
                stack.appendleft((child, ts, depth + 1))

        return call_events, alloc_duration

    def _load_proc_mem(self, path):
        with open(path, "rb") as f:
            proc_mem = ProcMem()
            proc_mem.ParseFromString(f.read())
            return proc_mem

    def _analyze_allocations(self, proc_mem):
        freed_ptrs = {free.alloc_ptr for free in proc_mem.mem_free_stacks}
        active_allocs = defaultdict(list)
        for alloc in proc_mem.mem_alloc_stacks:
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
    parser = argparse.ArgumentParser(description='Aggregate all *.pb files into a single JSON')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()
    output_path = args.output
    all_events = []

    pb_files = glob.glob("*.pb")
    for i, _ in enumerate(pb_files):
        processed_files[i] = False

    for pb_file in glob.glob("*.pb"):
        print(f"Processing {pb_file}")
        converter = FixedFlameGraphConverter()
        tmp_output = f"{os.path.splitext(pb_file)[0]}_tmp.json"
        converter.convert(pb_file, tmp_output)

        with open(tmp_output) as f:
            data = json.load(f)
            all_events.extend(data.get("traceEvents", []))
        os.remove(tmp_output)

    with open(output_path, "w") as f:
        json.dump({
            "traceEvents": sorted(all_events, key=lambda x: x["ts"]),
            "displayTimeUnit": "ns",
            "metadata": {
                "format": "FixedFlameGraph (Aggregated)",
                "source_files": glob.glob("*.pb")
            }
        }, f, indent=2)

    print(f"\n Aggregated {len(all_events)} events to {output_path}")