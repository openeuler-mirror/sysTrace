import json
import systrace_pb2
import argparse
import glob
import os


def decode_filename(filename_bytes):
    try:
        return filename_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return filename_bytes.decode('utf-8', errors='backslashreplace')


def process_io_file(input_path, trace_data):
    with open(input_path, "rb") as f:
        io_data = systrace_pb2.IO()
        io_data.ParseFromString(f.read())

    for entry in io_data.IO_entries:
        filename = decode_filename(entry.file_name)
        if 'socket' in filename.lower():
            continue

        io_type_str = systrace_pb2.IOType.Name(entry.io_type)
        stage_type_str = systrace_pb2.StageType.Name(entry.stage_type)

        name = f"{stage_type_str}::{io_type_str}"
        tid = f"{entry.rank}:{filename}"

        trace_data["traceEvents"].append({
            "name": name,
            "cat": "io",
            "ph": "X",  # Complete event
            "pid": entry.rank,
            "tid": io_type_str,
            "ts": entry.start_us,
            "dur": entry.dur,
            "args": {
                "stage_id": entry.stage_id,
                "file_name": filename,
                "stage_type": stage_type_str,
                "io_type": io_type_str
            }
        })


def aggregate_io_files(input_dir, output_path):
    trace_data = {
        "traceEvents": [],
        "displayTimeUnit": "us",
        "metadata": {"format": "IO Profiler"}
    }

    pb_files = glob.glob(os.path.join(input_dir, "*.pb"))
    print(f"Found {len(pb_files)} .pb files to process")

    for pb_file in pb_files:
        print(f"Processing {pb_file}")
        process_io_file(pb_file, trace_data)

    trace_data["traceEvents"].sort(key=lambda x: x["ts"])

    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(',', ':'))

    print(f"Wrote {len(trace_data['traceEvents'])} events to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Aggregate all *.pb files into a Chrome Trace JSON')
    parser.add_argument('--input', default='.', help='Input directory containing .pb files (default: current directory)')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    aggregate_io_files(args.input, args.output)