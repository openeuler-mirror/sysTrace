from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import glob
import json
import argparse
import systrace_pb2
from collections import defaultdict

event_type_dic = {
    0: "mm_fault",
    1: "swap_page",
    2: "compaction",
    3: "vmscan",
    4: "offcpu",
    5: "unknown"
}

def process_single_file(input_path):
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
        return []

    for entry in osprobe_data.OSprobe_entries:
        if entry.OS_event_type  in [1, 2, 3]:
            cpu_trace_events.append({
                "name": event_type_dic[entry.OS_event_type],
                "cat": "osprobe",
                "ph": "X",
                "pid": entry.rank if entry.OS_event_type in [0, 4] else f"Rank: {entry.rank} CPU: {entry.key}",
                "tid":  f"{entry.comm}: {entry.key}" if entry.OS_event_type in [0, 4] else entry.key ,
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


def aggregate_timeline_files(output_path):
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
    timeline_files = glob.glob("*.pb")
    print(f"Found {len(timeline_files)} timeline files.")

    with Pool(processes=cpu_count()) as pool:
        # tqdm 结合 imap_unordered 实现进度显示
        for result, cpu_result in tqdm(pool.imap_unordered(process_single_file, timeline_files), total=len(timeline_files), desc="Processing .pb files"):
            trace_data["traceEvents"].extend(result)
            cpu_trace_data["traceEvents"].extend(cpu_result)

    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(',', ':'))
    
    with open(f"cpu_{output_path}", "w") as f:
        json.dump(cpu_trace_data, f, indent=None, separators=(',', ':'))
        
    print(f"Aggregated {len(trace_data['traceEvents'])} events to {output_path}")
