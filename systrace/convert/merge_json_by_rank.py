import json
import argparse
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import threading

"""
Usage:
python merge_json_by_rank.py file1.json file2.json [...] --output merged.json
"""

def load_json_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def merge_events_by_pid(files):
    pid_map = defaultdict(list)
    lock = threading.Lock()

    def process_file(file_path):
        nonlocal pid_map
        data = load_json_file(file_path)
        with lock:
            for event in data['traceEvents']:
                pid_map[event['pid']].append(event)

    with ThreadPoolExecutor() as executor:
        executor.map(process_file, files)

    return pid_map

def save_merged_data(pid_map, output_file):
    merged_events = []
    for pid in sorted(pid_map.keys()):
        pid_events = sorted(pid_map[pid], key=lambda x: x['ts'])
        merged_events.extend(pid_events)

    merged_data = {
        "traceEvents": merged_events,
        "displayTimeUnit": "ns",
        "metadata": {
            "format": "Merged Trace Data",
            "merged_pids": len(pid_map),
            "total_events": len(merged_events)
        }
    }

    with open(output_file, 'w') as f:
        json.dump(merged_data, f, indent=None, separators=(',', ':'))

    print(f"Merged {len(pid_map)} PIDs with total {len(merged_events)} events to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Merge JSON trace files by PID with multithreading')
    parser.add_argument('input_files', nargs='+', help='Input JSON files to merge')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    pid_map = merge_events_by_pid(args.input_files)
    save_merged_data(pid_map, args.output)