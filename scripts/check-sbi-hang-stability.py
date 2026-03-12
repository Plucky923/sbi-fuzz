#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path

from sbi_results import replay_result_entry, resolve_helper_cmd


def summarize_case(entry: dict, attempts: int, target: Path, injector: Path, helper_cmd, timeout_secs: int, smp: int, log_root: Path | None):
    case_log_dir = None
    if log_root is not None:
        case_log_dir = log_root / entry.get("hash", "unknown")

    results = [
        replay_result_entry(
            entry,
            target,
            injector,
            helper_cmd,
            timeout_secs,
            smp,
            case_log_dir,
        )
        for _ in range(attempts)
    ]
    by_actual = Counter(item.get("actual", "Unknown") for item in results)
    by_classification = Counter(
        item.get("classification", "unknown") for item in results
    )
    hang_count = sum(1 for item in results if item.get("classification") == "hang")
    stable_ratio = (hang_count / attempts) if attempts else 0.0
    if hang_count == attempts:
        label = "stable_hang"
    elif hang_count == 0:
        label = "non_hang"
    else:
        label = "flaky_hang"

    return {
        "hash": entry.get("hash"),
        "input": entry.get("input"),
        "extension": entry.get("extension"),
        "eid": entry.get("eid"),
        "fid": entry.get("fid"),
        "attempts": attempts,
        "hang_count": hang_count,
        "stable_ratio": stable_ratio,
        "label": label,
        "by_actual": dict(by_actual),
        "by_classification": dict(by_classification),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay hang candidates multiple times and summarize stability")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("replay_json", type=Path)
    parser.add_argument("--helper-bin")
    parser.add_argument("--timeout-secs", type=int, default=12)
    parser.add_argument("--smp", type=int, default=1)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--label", default="SBI")
    args = parser.parse_args()

    replay_data = json.loads(args.replay_json.read_text())
    hang_entries = [
        item
        for item in replay_data.get("results", [])
        if item.get("classification") == "hang"
    ]
    helper_cmd = resolve_helper_cmd(args.helper_bin)
    cases = [
        summarize_case(
            entry,
            args.attempts,
            args.target,
            args.injector,
            helper_cmd,
            args.timeout_secs,
            args.smp,
            args.log_dir,
        )
        for entry in hang_entries
    ]

    summary = {
        "label": args.label,
        "total_cases": len(cases),
        "attempts_per_case": args.attempts,
        "stable_hang_cases": sum(1 for item in cases if item["label"] == "stable_hang"),
        "flaky_hang_cases": sum(1 for item in cases if item["label"] == "flaky_hang"),
        "non_hang_cases": sum(1 for item in cases if item["label"] == "non_hang"),
        "cases": cases,
        "cases_by_hash": {item["hash"]: item for item in cases if item.get("hash")},
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
