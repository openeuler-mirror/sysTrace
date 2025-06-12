import json
import systrace_pb2
import argparse
import glob

def process_timeline_file(input_path, trace_data):
    with open(input_path, "rb") as f:
        pytorch_data = systrace_pb2.Pytorch()
        pytorch_data.ParseFromString(f.read())
    
    for stage in pytorch_data.pytorch_stages:
        trace_data["traceEvents"].append({
            "name": stage.stage_type,
            "cat": "pytorch",
            "ph": "X",
            "pid": pytorch_data.rank,
            "tid": pytorch_data.rank if "GC" not in stage.stage_type else f"{pytorch_data.rank}:gc",
            "ts": stage.start_us,
            "dur": stage.end_us - stage.start_us,
            "args": {
                "stage_id": stage.stage_id,
                "comm": pytorch_data.comm,
                "stack_frames": list(stage.stack_frames),
                "gc_collected": stage.gc_debug.collected if stage.HasField("gc_debug") else 0,
                "gc_uncollectable": stage.gc_debug.uncollectable if stage.HasField("gc_debug") else 0
            }
        })

def aggregate_timeline_files(output_path):
    trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "ns",
        "metadata": {"format": "Pytorch Profiler"}
    }

    for timeline_file in glob.glob("*timeline"):
        print(f"Processing {timeline_file}")
        process_timeline_file(timeline_file, trace_data)
    
    trace_data["traceEvents"].sort(key=lambda x: x["args"]["stage_id"])
    
    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(',', ':'))
    print(f"Aggregated {len(trace_data['traceEvents'])} events to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Aggregate all *.timeline files into a single JSON')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()
    aggregate_timeline_files(args.output)