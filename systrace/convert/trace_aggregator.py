import json
import os
import argparse
from pathlib import Path

def aggregate_traces(input_dir, output_file):
    input_path = Path(input_dir)
    if not input_path.is_dir():
        print(f"Error: {input_dir} is not a directory.")
        return

    json_files = list(input_path.glob("*.json"))
    if not json_files:
        print(f"No json files found in {input_dir}")
        return

    print(f"Found {len(json_files)} files. Aggregating...")

    with open(output_file, 'w', encoding='utf-8') as out_f:
        out_f.write('{"traceEvents": [')
        
        first_event = True
        for file_path in json_files:
            print(f"  Reading: {file_path.name}")
            try:
                with open(file_path, 'r', encoding='utf-8') as in_f:
                    data = json.load(in_f)

                    events = data.get("traceEvents", []) if isinstance(data, dict) else data
                    
                    if not events:
                        continue
                        
                    for event in events:
                        if not first_event:
                            out_f.write(',')
                        json.dump(event, out_f)
                        first_event = False
            except Exception as e:
                print(f"  Error processing {file_path.name}: {e}")

        out_f.write('], "displayTimeUnit": "ns"}')

    print(f"\nSuccess! Combined trace saved to: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Trace Aggregator")
    parser.add_argument("--input", type=str, required=True, help="Path to the directory containing json files")
    parser.add_argument("--output", type=str, required=True, help="Output combined json file path")
    
    args = parser.parse_args()
    aggregate_traces(args.input, args.output)