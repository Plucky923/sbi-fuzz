#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def summarize_metrics(data: dict) -> dict:
    targets = data.get("targets", {})
    return {
        "target_count": len(targets),
        "total_runs": sum(int(target.get("total_runs") or 0) for target in targets.values()),
        "total_new_events": sum(int(target.get("new_events") or 0) for target in targets.values()),
        "total_crash_artifacts": sum(
            int(target.get("crash_artifacts") or 0) for target in targets.values()
        ),
        "peak_exec_per_sec": max(
            (int(target.get("peak_exec_per_sec") or 0) for target in targets.values()),
            default=0,
        ),
        "max_last_coverage": max(
            (
                int((target.get("last") or {}).get("coverage") or 0)
                for target in targets.values()
            ),
            default=0,
        ),
    }


def summarize_triage(data: dict) -> dict:
    results = data.get("results", [])
    confirmed = sum(1 for entry in results if entry.get("confirmed"))
    total = len(results)
    return {
        "total_cases": int(data.get("total_cases") or total),
        "total_buckets": len(data.get("buckets", {})),
        "confirmed_cases": confirmed,
        "confirmed_ratio": 1.0 if total == 0 else confirmed / total,
        "by_violation_type": data.get("by_violation_type", {}),
    }


def make_check(actual, threshold, op: str) -> dict:
    if op == ">=":
        passed = actual >= threshold
    elif op == "<=":
        passed = actual <= threshold
    else:
        raise ValueError(f"unsupported operator: {op}")
    return {
        "actual": actual,
        "threshold": threshold,
        "operator": op,
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate host-side campaign quality")
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--triage", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--min-total-runs", type=int, default=1000)
    parser.add_argument("--min-new-events", type=int, default=1)
    parser.add_argument("--min-buckets", type=int, default=1)
    parser.add_argument("--min-confirmed-ratio", type=float, default=0.5)
    parser.add_argument("--min-peak-exec-per-sec", type=int, default=1)
    args = parser.parse_args()

    metrics = summarize_metrics(load_json(args.metrics))
    triage = summarize_triage(load_json(args.triage))
    checks = {
        "total_runs": make_check(metrics["total_runs"], args.min_total_runs, ">="),
        "new_events": make_check(metrics["total_new_events"], args.min_new_events, ">="),
        "buckets": make_check(triage["total_buckets"], args.min_buckets, ">="),
        "confirmed_ratio": make_check(
            round(triage["confirmed_ratio"], 4), args.min_confirmed_ratio, ">="
        ),
        "peak_exec_per_sec": make_check(
            metrics["peak_exec_per_sec"], args.min_peak_exec_per_sec, ">="
        ),
    }
    status = "pass" if all(check["passed"] for check in checks.values()) else "fail"
    report = {
        "status": status,
        "metrics_path": str(args.metrics),
        "triage_path": str(args.triage),
        "summary": {
            "metrics": metrics,
            "triage": triage,
        },
        "checks": checks,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
