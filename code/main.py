"""Main CLI entrypoint for Ghost Data Still Exists deletion audit agent.

Processes deletion_requests.csv and outputs output.csv.
"""

import argparse
import csv
import json
import os
import sys
from typing import List, Dict

# Ensure code directory and repo root are in path
current_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.abspath(os.path.join(current_dir, ".."))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from auditor import Auditor
from config import CSV_HEADER, STATUS_COMPLETE, STATUS_INCOMPLETE, STATUS_NOT_APPLICABLE


def parse_args():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Pipeline")
    parser.add_argument(
        "--dataset",
        type=str,
        default="dataset",
        help="Path to dataset directory containing identities, activities, rules, evidence, etc.",
    )
    parser.add_argument(
        "--input",
        type=str,
        default="dataset/deletion_requests.csv",
        help="Path to input deletion requests CSV",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output.csv",
        help="Path to output CSV destination",
    )
    return parser.parse_args()


def run_pipeline(dataset_dir: str, input_csv: str, output_csv: str):
    print(f"Initializing Auditor with dataset: {dataset_dir}...")
    auditor = Auditor(dataset_dir)

    print(f"Reading deletion requests from: {input_csv}...")
    with open(input_csv, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        requests = list(reader)

    # Sort requests by numeric case_id where possible or string
    def sort_key(row):
        cid = row.get("case_id", "")
        num_part = "".join(filter(str.isdigit, cid))
        return (int(num_part) if num_part else 0, cid)

    requests.sort(key=sort_key)
    print(f"Processing {len(requests)} deletion requests...")

    output_rows = []
    status_counts = {
        STATUS_COMPLETE: 0,
        STATUS_INCOMPLETE: 0,
        STATUS_NOT_APPLICABLE: 0,
    }

    for idx, req in enumerate(requests, 1):
        case_id = req["case_id"]
        status, steps = auditor.audit_case(req)

        status_counts[status] = status_counts.get(status, 0) + 1
        steps_json = json.dumps(steps, separators=(",", ":"))

        output_rows.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": steps_json,
        })

        if idx % 50 == 0 or idx == len(requests):
            print(f"Processed {idx}/{len(requests)} requests...")

    print(f"Writing outputs to: {output_csv}...")
    with open(output_csv, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Completed! Summary:")
    print(f"  Total Cases: {len(output_rows)}")
    for s, c in status_counts.items():
        print(f"  {s}: {c} ({c / len(output_rows):.1%})")


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(args.dataset, args.input, args.output)
