#!/usr/bin/env python3
import json
import argparse
import glob
import os
import re

def extract_rank_from_filename(filename: str) -> int:
    """
    从文件名里提取 rank, 例如:
    'localhost--00005--3918572.json' -> 5
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
            if not line:
                continue
            try:
                stage = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skip invalid line in {input_path}: {e}")
                continue

            start_us = stage.get("start_us", 0)
            end_us = stage.get("end_us", 0)

            event = {
                "name": stage.get("stage_type", "unknown"),
                "cat": "pytorch",
                "ph": "X",
                "pid": rank,
                "tid": f"{rank}:gc" if "GC" in stage.get("stage_type", "") else rank,
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

def aggregate_json_files(input_dir, output_path):
    trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "ns",
        "metadata": {"format": "Pytorch Profiler"},
    }

    json_files = glob.glob(os.path.join(input_dir, "*.json"))
    print(f"Found {len(json_files)} json files to process")

    for json_file in json_files:
        print(f"Processing {json_file}")
        process_json_file(json_file, trace_data)

    trace_data["traceEvents"].sort(key=lambda x: x["args"]["stage_id"])

    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(",", ":"))
    print(f"Aggregated {len(trace_data['traceEvents'])} events to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aggregate all *.json files into a single traceEvents JSON")
    parser.add_argument("--input", default=".", help="Input directory containing json trace files (default: current directory)")
    parser.add_argument("--output", required=True, help="Output JSON file path")
    args = parser.parse_args()
    aggregate_json_files(args.input, args.output)
