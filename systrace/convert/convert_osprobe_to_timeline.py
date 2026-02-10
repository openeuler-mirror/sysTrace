from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import glob
import json
import argparse
import os
from collections import defaultdict

try:
    import systrace_pb2
    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False

event_type_dic = {
    0: "mm_fault",
    1: "swap_page",
    2: "compaction",
    3: "vmscan",
    4: "offcpu",
    5: "unknown"
}

def process_json_file(input_path):
    trace_events = []
    cpu_trace_events = []
    last_delay = {}
    rank_acl = defaultdict(list)
    rank_acl_count = defaultdict(int)
    delay = 0

    try:
        with open(input_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    os_entries = data.get("os_entries", [])
                    
                    for entry_data in os_entries:
                        key = entry_data.get("key", 0)
                        start_us = entry_data.get("start", 0)
                        dur = entry_data.get("dur", 0)
                        rundelay = entry_data.get("delay", 0)
                        os_event_type = entry_data.get("type", 5)
                        rank = entry_data.get("rank", 0)
                        comm = entry_data.get("comm", "")
                        nxt_comm = entry_data.get("ncomm", "")
                        nxt_pid = entry_data.get("npid", 0)
                        
                        if os_event_type in [1, 2, 3]:
                            cpu_trace_events.append({
                                "name": event_type_dic.get(os_event_type, "unknown"),
                                "cat": "osprobe",
                                "ph": "X",
                                "pid": rank if os_event_type in [0, 4] else f"Rank: {rank} CPU: {key}",
                                "tid": f"{comm}: {key}" if os_event_type in [0, 4] else key,
                                "ts": start_us,
                                "dur": dur,
                                "args": {
                                    "cpu_rundelay": delay,
                                    "next_comm": nxt_comm,
                                    "next_pid": nxt_pid
                                } if os_event_type == 4 else {}
                            })
                        else:
                            if os_event_type == 4:
                                key_str = f"{comm}: {key}"
                                if key_str in last_delay:
                                    delay = rundelay - last_delay[key_str]
                                last_delay[key_str] = rundelay

                            event = {
                                "name": event_type_dic.get(os_event_type, "unknown"),
                                "cat": "osprobe",
                                "ph": "X",
                                "pid": rank if os_event_type != 1 else f"Rank: {rank} CPU: {key}",
                                "tid": f"{comm}: {key}" if os_event_type != 1 else key,
                                "ts": start_us,
                                "dur": dur,
                                "args": {
                                    "cpu_rundelay": delay,
                                    "sus_comm": nxt_comm,
                                    "sus_pid": nxt_pid
                                } if os_event_type == 4 else {}
                            }

                            if comm.lower() == "acl_thread":
                                rank_acl_count[key] += 1
                                rank_acl[key].append(event)
                            else:
                                trace_events.append(event)
                except json.JSONDecodeError as e:
                    print(f"[WARN] Skip invalid line in {input_path}: {e}")
                except Exception as e:
                    print(f"[WARN] Error processing line in {input_path}: {e}")
    except Exception as e:
        print(f"[ERROR] Failed to process file '{input_path}': {e}")
        return [], []

    if rank_acl_count:
        acl_thread = max(rank_acl_count, key=lambda k: rank_acl_count[k])
        trace_events.extend(rank_acl[acl_thread])

    return trace_events, cpu_trace_events

def process_protobuf_file(input_path):
    if not HAS_PROTOBUF:
        print(f"[ERROR] Cannot process {input_path}: systrace_pb2 not found.")
        return [], []
    
    trace_events = []
    cpu_trace_events = []
    last_delay = {}
    rank_acl = defaultdict(list)
    rank_acl_count = defaultdict(int)
    delay = 0

    try:
        with open(input_path, "rb") as f:
            osprobe_data = systrace_pb2.OSprobe()
            osprobe_data.ParseFromString(f.read())
    except Exception as e:
        print(f"[ERROR] Failed to process file '{input_path}': {e}")
        return [], []

    for entry in osprobe_data.OSprobe_entries:
        if entry.OS_event_type in [1, 2, 3]:
            cpu_trace_events.append({
                "name": event_type_dic[entry.OS_event_type],
                "cat": "osprobe",
                "ph": "X",
                "pid": entry.rank if entry.OS_event_type in [0, 4] else f"Rank: {entry.rank} CPU: {entry.key}",
                "tid": f"{entry.comm}: {entry.key}" if entry.OS_event_type in [0, 4] else entry.key,
                "ts": entry.start_us,
                "dur": entry.dur,
                "args": {
                    "cpu_rundelay": delay,
                    "next_comm": entry.nxt_comm,
                    "next_pid": entry.nxt_pid
                } if entry.OS_event_type == 4 else {}
            })
        else:
            if entry.OS_event_type == 4:
                key_str = f"{entry.comm}: {entry.key}"
                if key_str in last_delay:
                    delay = entry.rundelay - last_delay[key_str]
                last_delay[key_str] = entry.rundelay

            event = {
                "name": event_type_dic.get(entry.OS_event_type, "unknown"),
                "cat": "osprobe",
                "ph": "X",
                "pid": entry.rank if entry.OS_event_type != 1 else f"Rank: {entry.rank} CPU: {entry.key}",
                "tid": f"{entry.comm}: {entry.key}" if entry.OS_event_type != 1 else entry.key,
                "ts": entry.start_us,
                "dur": entry.dur,
                "args": {
                    "cpu_rundelay": delay,
                    "sus_comm": entry.nxt_comm,
                    "sus_pid": entry.nxt_pid
                } if entry.OS_event_type == 4 else {}
            }

            if entry.comm.lower() == "acl_thread":
                rank_acl_count[entry.key] += 1
                rank_acl[entry.key].append(event)
            else:
                trace_events.append(event)

    if rank_acl_count:
        acl_thread = max(rank_acl_count, key=lambda k: rank_acl_count[k])
        trace_events.extend(rank_acl[acl_thread])

    return trace_events, cpu_trace_events


def process_single_file(input_path):
    if input_path.endswith('.json'):
        return process_json_file(input_path)
    elif input_path.endswith('.pb'):
        return process_protobuf_file(input_path)
    else:
        print(f"[WARN] Unknown file type: {input_path}")
        return [], []

def aggregate_timeline_files(input_dir, output_path):
    trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "ns",
        "metadata": {"format": "eBPF OSProbe"}
    }

    cpu_trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "ns",
        "metadata": {"format": "eBPF OSProbe"}
    }
    
    json_files = glob.glob(os.path.join(input_dir, "*.json"))
    timeline_files = glob.glob(os.path.join(input_dir, "*.pb"))
    
    all_files = json_files + timeline_files
    print(f"Found {len(json_files)} JSON files and {len(timeline_files)} Protobuf files in {input_dir}")

    with Pool(processes=cpu_count()) as pool:
        for result, cpu_result in tqdm(pool.imap_unordered(process_single_file, all_files), 
                                     total=len(all_files), 
                                     desc="Processing files"):
            trace_data["traceEvents"].extend(result)
            cpu_trace_data["traceEvents"].extend(cpu_result)

    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(',', ':'))
    
    with open(f"{output_path}_cpu", "w") as f:
        json.dump(cpu_trace_data, f, indent=None, separators=(',', ':'))
        
    print(f"\nSuccessfully aggregated {len(trace_data['traceEvents'])} events to {output_path}")

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Aggregate JSON and Protobuf OSprobe traces into Chrome Trace Format')
    parser.add_argument('--input', default='.', help='Input directory containing trace files (default: current directory)')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()
    aggregate_timeline_files(args.input, args.output)