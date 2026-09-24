import json
import logging
import time
import argparse
from tqdm import tqdm
from typing import Optional, Tuple

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s]:%(message)s')

ACQUIRE_NAME = "require_gil"
RELEASE_NAME = "release_gil"
HOLD_NAME = "hold_gil"

OFFSET = 0.5

def get_safe_event_value(event: dict, key: str, default: any = None) -> any:
    value = event.get(key, default)
    if key in ["ts", "dur"]:
        try:
            return float(value) if value is not None else 0.0
        except (ValueError, TypeError):
            return 0.0
    elif key in ["pid", "tid"]:
        return str(value) if value is not None else "unknown"
    return value

def calculate_hold_gil(
        take_ts: float, take_dur: float, drop_ts: float
) -> Optional[Tuple[float, float]]:
    hold_start = take_ts + take_dur + OFFSET
    hold_end = drop_ts - OFFSET
    hold_dur = hold_end - hold_start

    if hold_dur > 0 and hold_start < hold_end:
        return (hold_start, hold_dur)
    return None

def convert_gil_trace(input_path: str, output_path: str):
    logging.info(f"Start conversion: {input_path} → {output_path}")

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_path}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON format in input file: {e}")
        raise

    if isinstance(raw_data, dict) and "traceEvents" in raw_data:
        events = raw_data["traceEvents"]
    elif isinstance(raw_data, list):
        events = raw_data
    else:
        logging.error("Input data must be a list or a dict with 'traceEvents' key")
        raise ValueError("Invalid input data format")

    logging.info(f"Loaded {len(events)} raw events")
    if not events:
        logging.warning("No events found in input file")

    for i, ev in enumerate(events):
        ev['_idx'] = i
    events.sort(key=lambda x: (get_safe_event_value(x, "ts"), x.get("_idx", 0)))

    output_events = []
    last_takes = {}

    for event in tqdm(events, desc="Processing events"):
        ev_copy = event.copy()
        ev_copy.pop('_idx', None)

        name = get_safe_event_value(ev_copy, "name")
        ts = get_safe_event_value(ev_copy, "ts")
        dur = get_safe_event_value(ev_copy, "dur")
        pid = get_safe_event_value(ev_copy, "pid")
        tid = get_safe_event_value(ev_copy, "tid")
        ph = get_safe_event_value(ev_copy, "ph")

        if ph != "X":
            output_events.append(ev_copy)
            continue

        if name == "take_gil":
            ev_copy["name"] = ACQUIRE_NAME
            output_events.append(ev_copy)
            last_takes[(pid, tid)] = (ts, dur)

        elif name == "drop_gil":
            ev_copy["name"] = RELEASE_NAME
            output_events.append(ev_copy)

            take_info = last_takes.pop((pid, tid), None)
            if take_info is not None:
                take_ts, take_dur = take_info
                hold_result = calculate_hold_gil(take_ts, take_dur, ts)
                if hold_result is not None:
                    hold_start, hold_dur = hold_result
                    hold_event = {
                        "name": HOLD_NAME,
                        "ph": "X",
                        "ts": round(hold_start, 3),
                        "dur": round(hold_dur, 3),
                        "pid": pid,
                        "tid": tid
                    }
                    output_events.append(hold_event)
        else:
            output_events.append(ev_copy)

    for i, ev in enumerate(output_events):
        ev['_idx2'] = i
    output_events.sort(key=lambda x: (get_safe_event_value(x, "ts"), x.get("_idx2", 0)))
    for ev in output_events:
        ev.pop('_idx2', None)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('{\n"traceEvents": [\n')
            total = len(output_events)
            for i, ev in enumerate(output_events):
                line = json.dumps(ev, separators=(',', ':'))
                f.write(f"  {line}{',' if i < total - 1 else ''}\n")
            f.write('],\n"displayTimeUnit": "ns"\n}')
    except Exception as e:
        logging.error(f"Failed to write output file: {e}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert GIL trace events")
    parser.add_argument("--input", default="gil.json", help="Input GIL trace file path")
    parser.add_argument("--output", default="output.json", help="Output CTF trace file path")
    args = parser.parse_args()

    start = time.perf_counter()
    try:
        convert_gil_trace(args.input, args.output)
        logging.info(f"Conversion completed in {time.perf_counter() - start:.2f}s")
    except Exception as e:
        logging.error(f"Conversion failed: {str(e)}", exc_info=True)