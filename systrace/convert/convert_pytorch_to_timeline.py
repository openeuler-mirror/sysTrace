#!/usr/bin/env python3
import json
import argparse
import glob
import os
import re

try:
    import systrace_pb2
    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False

def extract_rank_from_filename(filename: str) -> int:
    """
    从 JSON 文件名里提取 rank: 'localhost--00005--3918572.json' -> 5
    """
    base = os.path.basename(filename)
    m = re.search(r"--(\d+)--\d+\.json$", base)
    if m:
        return int(m.group(1))
    return 0

def process_json_file(input_path, trace_data):
    rank = extract_rank_from_filename(input_path)
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                stage = json.loads(line)
                file_rank = stage.get("rank", rank)
                
                name = stage.get("stage_type", "unknown")
                start_us = stage.get("start_us", 0)
                end_us = stage.get("end_us", 0)

                event = {
                    "name": name,
                    "cat": "pytorch",
                    "ph": "X",
                    "pid": file_rank,
                    "tid": f"{file_rank}:gc" if "GC" in name else file_rank,
                    "ts": start_us,
                    "dur": max(0, end_us - start_us),
                    "args": {
                        "stage_id": stage.get("stage_id", 0),
                        "comm": stage.get("comm", ""),
                        "stack_frames": stage.get("stack_frames", []),
                        "gc_collected": stage.get("gc_debug", {}).get("collected", 0),
                        "gc_uncollectable": stage.get("gc_debug", {}).get("uncollectable", 0),
                    },
                }
                trace_data["traceEvents"].append(event)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skip invalid line in {input_path}: {e}")

def process_timeline_file(input_path, trace_data):
    if not HAS_PROTOBUF:
        print(f"[ERROR] Cannot process {input_path}: systrace_pb2 not found.")
        return

    with open(input_path, "rb") as f:
        pytorch_data = systrace_pb2.Pytorch()
        try:
            pytorch_data.ParseFromString(f.read())
        except Exception as e:
            print(f"[ERROR] Failed to parse protobuf {input_path}: {e}")
            return
    
    rank = pytorch_data.rank
    for stage in pytorch_data.pytorch_stages:
        name = stage.stage_type
        trace_data["traceEvents"].append({
            "name": name,
            "cat": "pytorch",
            "ph": "X",
            "pid": rank,
            "tid": rank if "GC" not in name else f"{rank}:gc",
            "ts": stage.start_us,
            "dur": max(0, stage.end_us - stage.start_us),
            "args": {
                "stage_id": stage.stage_id,
                "comm": pytorch_data.comm,
                "stack_frames": list(stage.stack_frames),
                "gc_collected": stage.gc_debug.collected if stage.HasField("gc_debug") else 0,
                "gc_uncollectable": stage.gc_debug.uncollectable if stage.HasField("gc_debug") else 0
            }
        })

def aggregate_files(input_dir, output_path):
    trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "ns",
        "metadata": {"format": "Pytorch Profiler Aggregate"},
    }

    json_files = glob.glob(os.path.join(input_dir, "*.json"))
    timeline_files = glob.glob(os.path.join(input_dir, "*.timeline"))

    print(f"Found {len(json_files)} JSON files and {len(timeline_files)} Protobuf files.")

    for f in json_files:
        print(f"Processing JSON: {f}")
        process_json_file(f, trace_data)

    for f in timeline_files:
        print(f"Processing Protobuf: {f}")
        process_timeline_file(f, trace_data)

    trace_data["traceEvents"].sort(key=lambda x: x["ts"])

    with open(output_path, "w") as f:
        json.dump(trace_data, f, separators=(",", ":"))
    
    print(f"\nSuccessfully aggregated {len(trace_data['traceEvents'])} events.")
    print(f"Output: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aggregate JSON and Protobuf traces into Chrome Trace Format")
    parser.add_argument("--input", default=".", help="Directory containing trace files")
    parser.add_argument("--output", default="combined_trace.json", help="Output combined JSON file")
    args = parser.parse_args()

    aggregate_files(args.input, args.output)