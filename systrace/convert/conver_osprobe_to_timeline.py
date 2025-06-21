import json
import systrace_pb2
import argparse
import glob
from collections import defaultdict

event_type_dic = {
    0: "mm_fault",
    1: "swap_page",
    2: "compaction",
    3: "vmscan",
    4: "offcpu",
    5: "unknown"
    }

def process_timeline_file(input_path, trace_data):
    last_delay = {}
    rank_acl = defaultdict(list)
    rank_acl_count = defaultdict(int)
    min_acl_thread = float('inf')
    delay = 0
    with open(input_path, "rb") as f:
        osprobe_data = systrace_pb2.OSprobe()
        osprobe_data.ParseFromString(f.read())
    
    for entry in osprobe_data.OSprobe_entries:
        if entry.OS_event_type == 4:
            if f"{entry.comm}: {entry.key}" in last_delay:
                delay = entry.rundelay - last_delay[f"{entry.comm}: {entry.key}"]
            last_delay[f"{entry.comm}: {entry.key}"] = entry.rundelay
        if entry.comm == "ACL_thread":
            rank_acl_count[entry.key] += 1
            rank_acl[entry.key].append({
                "name": event_type_dic[entry.OS_event_type],
                "cat": "osprobe",
                "ph": "X",
                "pid": entry.rank if entry.OS_event_type in [0, 4] else f"CPU: {entry.key}",
                "tid":  f"{entry.comm}: {entry.key}" if entry.OS_event_type in [0, 4] else entry.key ,
                "ts": entry.start_us,
                "dur": entry.dur,
                "args": {
                    "cpu_rundelay": delay,
                    "sus_comm": entry.nxt_comm,
                    "sus_pid": entry.nxt_pid
                } if entry.OS_event_type == 4 else {}
            })
            continue

        trace_data["traceEvents"].append({
            "name": event_type_dic[entry.OS_event_type],
            "cat": "osprobe",
            "ph": "X",
            "pid": entry.rank if entry.OS_event_type in [0, 4] else f"CPU: {entry.key}",
            "tid":  f"{entry.comm}: {entry.key}" if entry.OS_event_type in [0, 4] else entry.key ,
            "ts": entry.start_us,
            "dur": entry.dur,
            "args": {
                "cpu_rundelay": delay,
                "next_comm": entry.nxt_comm,
                "next_pid": entry.nxt_pid
            } if entry.OS_event_type == 4 else {}
        })
    acl_thread = max(rank_acl_count, key=lambda k: rank_acl_count[k])
    trace_data["traceEvents"].extend(rank_acl[acl_thread])

def aggregate_timeline_files(output_path):
    trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "ns",
        "metadata": {"format": "eBPF OSProbe"}
    }

    for timeline_file in glob.glob("*.pb"):
        print(f"Processing {timeline_file}")
        process_timeline_file(timeline_file, trace_data)
    
    # trace_data["traceEvents"].sort(key=lambda x: x["args"]["stage_id"])
    
    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(',', ':'))
    print(f"Aggregated {len(trace_data['traceEvents'])} events to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Aggregate all *.timeline files into a single JSON')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()
    aggregate_timeline_files(args.output)