import json
import logging
import time
import argparse
from abc import ABC, abstractmethod
from typing import Dict, List, Any
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s]:%(message)s')

ACQUIRE_NAME = "require_gil"
RELEASE_NAME = "release_gil"
HOLD_NAME = "hold_gil"


class GilTracker:
    def __init__(self):
        self.events = []
        self.pending_acquire: Dict[str, tuple] = {}
        self.pending_release: Dict[str, tuple] = {}
        self.last_hold_start: Dict[str, tuple] = {}

    def process_event(self, raw_event: Dict[str, Any]):
        try:
            name = raw_event["name"]
            ph = raw_event["ph"]
            ts = raw_event["ts"]
            pid = raw_event["pid"]
            tid = raw_event["tid"]

            if name == "take_gil":
                if ph == "B":
                    self.pending_acquire[tid] = (ts, pid)
                elif ph == "E":
                    start_ts, start_pid = self.pending_acquire.pop(tid, (0, 0))
                    if start_ts > 0:
                        self.events.append({
                            "name": ACQUIRE_NAME, "ph": "X", "ts": start_ts,
                            "dur": ts - start_ts, "pid": start_pid, "tid": tid
                        })
                        self.last_hold_start[tid] = (ts, start_pid)

            elif name == "drop_gil":
                if ph == "B":
                    self.pending_release[tid] = (ts, pid)
                    hold_ts, hold_pid = self.last_hold_start.pop(tid, (0, 0))
                    if hold_ts > 0:
                        self.events.append({
                            "name": HOLD_NAME, "ph": "X", "ts": hold_ts,
                            "dur": ts - hold_ts, "pid": hold_pid, "tid": tid
                        })
                elif ph == "E":
                    start_ts, start_pid = self.pending_release.pop(tid, (0, 0))
                    if start_ts > 0:
                        self.events.append({
                            "name": RELEASE_NAME, "ph": "X", "ts": start_ts,
                            "dur": ts - start_ts, "pid": start_pid, "tid": tid
                        })

        except KeyError as e:
            logging.warning(f"Missing field {e} in event: {raw_event}")

    def get_sorted_events(self) -> List[Dict[str, Any]]:
        return sorted(self.events, key=lambda x: x["ts"])


class ParsingStrategy(ABC):
    @abstractmethod
    def parse(self, input_path: str) -> List[Dict[str, Any]]:
        pass


class FullCycleStrategy(ParsingStrategy):
    def parse(self, input_path: str) -> List[Dict[str, Any]]:
        tracker = GilTracker()
        with open(input_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
            if isinstance(raw_data, list):
                for event in tqdm(raw_data, desc="Parsing events"):
                    tracker.process_event(event)
            else:
                tracker.process_event(raw_data)
        return tracker.get_sorted_events()


class TraceConverter:
    def __init__(self, strategy: ParsingStrategy):
        self.strategy = strategy

    def convert(self, input_path: str, output_path: str):
        logging.info(f"Start conversion: {input_path} → {output_path}")
        events = self.strategy.parse(input_path)
        output_data = {
            "traceEvents": events,
            "displayTimeUnit": "ns"
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GIL Trace Converter")
    parser.add_argument("--input", default="gil.json", help="Input file path")
    parser.add_argument("--output", default="output.json", help="Output file path")
    args = parser.parse_args()

    start = time.perf_counter()
    try:
        strategy = FullCycleStrategy()
        converter = TraceConverter(strategy)
        converter.convert(args.input, args.output)
        logging.info(f"Total time elapsed: {time.perf_counter() - start:.2f} seconds")
    except Exception as e:
        logging.error(f"Conversion failed: {e}")
        raise