import json
import argparse
import glob
import os

try:
    import systrace_pb2
    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False

IO_TYPE_MAP = {
    0: "IO_UNKNOWN",
    1: "IO_READ",
    2: "IO_WRITE",
    3: "IO_FREAD",
    4: "IO_FWRITE",
    5: "IO_FOPEN",
    6: "IO_FCLOSE",
    7: "IO_FFLUSH",
    8: "IO_REMOVE",
    9: "IO_RENAME",
    10: "IO_OPEN",
    11: "IO_CLOSE",
    12: "IO_FSYNC",
    13: "IO_MKDIR",
    14: "IO_RMDIR",
    15: "IO_UNLINK",
    16: "IO_OPENDIR",
    17: "IO_CLOSEDIR",
}

STAGE_TYPE_MAP = {
    0: "STAGE_UNKNOWN",
    1: "STAGE_DATALOADER",
    2: "STAGE_FORWARD",
    3: "STAGE_BACKWARD",
    4: "STAGE_SYNCHRONIZATION",
    5: "STAGE_GC",
}


def decode_filename(filename_bytes):
    try:
        return filename_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return filename_bytes.decode('utf-8', errors='backslashreplace')


def get_io_type_str(io_type_value):
    if HAS_PROTOBUF:
        try:
            return systrace_pb2.IOType.Name(io_type_value)
        except:
            pass
    return IO_TYPE_MAP.get(io_type_value, f"IO_UNKNOWN_{io_type_value}")


def get_stage_type_str(stage_type_value):
    if HAS_PROTOBUF:
        try:
            return systrace_pb2.StageType.Name(stage_type_value)
        except:
            pass
    return STAGE_TYPE_MAP.get(stage_type_value, f"STAGE_UNKNOWN_{stage_type_value}")


def process_json_file(input_path, trace_data):
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                io_entries = data.get("io_entries", [])
                
                for entry in io_entries:
                    filename = entry.get("file", "")
                    if 'socket' in filename.lower():
                        continue
                    
                    start_us = entry.get("start", 0)
                    dur = entry.get("dur", 0)
                    stage_id = entry.get("sid", 0)
                    stage_type_value = entry.get("st", 0)
                    io_type_value = entry.get("type", 0)
                    rank = entry.get("rank", 0)
                    
                    io_type_str = get_io_type_str(io_type_value)
                    stage_type_str = get_stage_type_str(stage_type_value)
                    
                    name = f"{stage_type_str}::{io_type_str}"
                    
                    trace_data["traceEvents"].append({
                        "name": name,
                        "cat": "io",
                        "ph": "X",
                        "pid": rank,
                        "tid": io_type_str,
                        "ts": start_us,
                        "dur": dur,
                        "args": {
                            "stage_id": stage_id,
                            "file_name": filename,
                            "stage_type": stage_type_str,
                            "io_type": io_type_str
                        }
                    })
            except json.JSONDecodeError as e:
                print(f"[WARN] Skip invalid line in {input_path}: {e}")
            except Exception as e:
                print(f"[WARN] Error processing line in {input_path}: {e}")


def process_protobuf_file(input_path, trace_data):
    if not HAS_PROTOBUF:
        print(f"[ERROR] Cannot process {input_path}: systrace_pb2 not found.")
        return
    
    with open(input_path, "rb") as f:
        io_data = systrace_pb2.IO()
        try:
            io_data.ParseFromString(f.read())
        except Exception as e:
            print(f"[ERROR] Failed to parse protobuf {input_path}: {e}")
            return

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

    json_files = glob.glob(os.path.join(input_dir, "*.json"))
    pb_files = glob.glob(os.path.join(input_dir, "*.pb"))

    print(f"Found {len(json_files)} JSON files and {len(pb_files)} Protobuf files.")

    for json_file in json_files:
        print(f"Processing JSON: {json_file}")
        process_json_file(json_file, trace_data)

    for pb_file in pb_files:
        print(f"Processing Protobuf: {pb_file}")
        process_protobuf_file(pb_file, trace_data)

    trace_data["traceEvents"].sort(key=lambda x: x["ts"])

    with open(output_path, "w") as f:
        json.dump(trace_data, f, indent=None, separators=(',', ':'))

    print(f"\nSuccessfully aggregated {len(trace_data['traceEvents'])} events.")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Aggregate JSON and Protobuf IO traces into Chrome Trace Format')
    parser.add_argument('--input', default='.', help='Input directory containing trace files (default: current directory)')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    aggregate_io_files(args.input, args.output)