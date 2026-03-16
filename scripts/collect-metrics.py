#!/usr/bin/env python3
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

LINE_RE = re.compile(
    r"#(\d+)\s+(INITED|NEW|REDUCE|RELOAD|DONE)\s+cov:\s+(\d+)\s+ft:\s+(\d+)\s+corp:\s+(\d+)/([^\s]+).*?exec/s:\s+(\d+).*?rss:\s+(\d+)Mb"
)
DONE_RE = re.compile(r"Done\s+(\d+)\s+runs\s+in\s+(\d+)\s+second\(s\)")
CRASH_RE = re.compile(r"Test unit written to ")


def parse_log(path: Path) -> dict:
    last = None
    peak_exec = 0
    total_runs = None
    duration_secs = None
    crash_artifacts = 0
    progress_seq = 0
    first_crash_seq = None
    first_new_seq = None
    new_events = 0
    reduce_events = 0
    with path.open() as handle:
        for line in handle:
            match = LINE_RE.search(line)
            if match:
                seq, event, cov, ft, corp_count, corp_size, execs, rss = match.groups()
                progress_seq = int(seq)
                last = {
                    "coverage": int(cov),
                    "features": int(ft),
                    "corpus_count": int(corp_count),
                    "corpus_size": corp_size,
                    "exec_per_sec": int(execs),
                    "rss_mb": int(rss),
                }
                peak_exec = max(peak_exec, int(execs))
                if event == "NEW":
                    new_events += 1
                    if first_new_seq is None:
                        first_new_seq = progress_seq
                elif event == "REDUCE":
                    reduce_events += 1
                continue

            done = DONE_RE.search(line)
            if done:
                total_runs, duration_secs = (int(value) for value in done.groups())
                continue

            if CRASH_RE.search(line):
                crash_artifacts += 1
                if first_crash_seq is None:
                    first_crash_seq = progress_seq

    def estimate_time(first_seq: int | None) -> float | None:
        if first_seq is None or total_runs in (None, 0) or duration_secs is None:
            return None
        return round((first_seq / total_runs) * duration_secs, 3)

    return {
        "log": str(path),
        "last": last,
        "peak_exec_per_sec": peak_exec,
        "total_runs": total_runs,
        "duration_secs": duration_secs,
        "crash_artifacts": crash_artifacts,
        "new_events": new_events,
        "reduce_events": reduce_events,
        "estimated_time_to_first_new_secs": estimate_time(first_new_seq),
        "estimated_time_to_first_crash_secs": estimate_time(first_crash_seq),
    }


def summarize_triage(paths: list[Path]) -> dict | None:
    if not paths:
        return None
    total_buckets = 0
    total_results = 0
    violation_counts = defaultdict(int)
    for path in paths:
        data = json.loads(path.read_text())
        total_buckets += len(data.get("buckets", {}))
        total_results += len(data.get("results", []))
        for key, value in data.get("by_violation_type", {}).items():
            violation_counts[key] += value
    return {
        "inputs": [str(path) for path in paths],
        "total_buckets": total_buckets,
        "total_results": total_results,
        "by_violation_type": dict(sorted(violation_counts.items())),
    }


def summarize_cross_layer(paths: list[Path]) -> dict | None:
    if not paths:
        return None
    total_unique = 0
    total_bugs = 0
    for path in paths:
        data = json.loads(path.read_text())
        total_unique += int(data.get("total_unique", 0))
        total_bugs += len(data.get("bugs", {}))
    return {
        "inputs": [str(path) for path in paths],
        "total_unique": total_unique,
        "total_bugs": total_bugs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect fuzz campaign metrics from libFuzzer logs")
    parser.add_argument("log_paths", nargs="*", type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--triage-json", nargs="*", type=Path, default=[])
    parser.add_argument("--cross-layer-json", nargs="*", type=Path, default=[])
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    logs = list(args.log_paths)
    if args.log_dir:
        logs.extend(sorted(args.log_dir.glob("*.log")))
    logs = [path for path in logs if path.exists()]

    entries = [parse_log(path) for path in logs]
    by_target = defaultdict(list)
    for entry in entries:
        target = Path(entry["log"]).stem
        by_target[target].append(entry)

    summary = {
        "targets": {
            target: {
                "worker_logs": len(items),
                "peak_exec_per_sec": max(item["peak_exec_per_sec"] for item in items),
                "last": next((item["last"] for item in reversed(items) if item["last"]), None),
                "total_runs": sum(item["total_runs"] or 0 for item in items),
                "duration_secs": sum(item["duration_secs"] or 0 for item in items),
                "crash_artifacts": sum(item["crash_artifacts"] for item in items),
                "new_events": sum(item["new_events"] for item in items),
                "reduce_events": sum(item["reduce_events"] for item in items),
                "estimated_time_to_first_new_secs": next(
                    (
                        item["estimated_time_to_first_new_secs"]
                        for item in items
                        if item["estimated_time_to_first_new_secs"] is not None
                    ),
                    None,
                ),
                "estimated_time_to_first_crash_secs": next(
                    (
                        item["estimated_time_to_first_crash_secs"]
                        for item in items
                        if item["estimated_time_to_first_crash_secs"] is not None
                    ),
                    None,
                ),
            }
            for target, items in sorted(by_target.items())
        },
        "triage": summarize_triage([path for path in args.triage_json if path.exists()]),
        "cross_layer": summarize_cross_layer(
            [path for path in args.cross_layer_json if path.exists()]
        ),
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
