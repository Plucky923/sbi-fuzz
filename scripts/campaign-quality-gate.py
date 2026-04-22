#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from campaign_utils import bug_id_from_bucket as shared_bug_id_from_bucket


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def current_bug_id_from_bucket(summary: dict, key: str, bucket: dict) -> str:
    return shared_bug_id_from_bucket(summary, key, bucket)


def bucket_impact(bucket: dict) -> str:
    if bucket.get("impact"):
        return str(bucket["impact"])
    classification = bucket.get("classification") or bucket.get("violation_type")
    if classification in {"sanitizer", "crash"}:
        return "crash"
    if classification == "hang":
        return "hang"
    if classification in {"spec_violation", "memory_violation", "mismatch", "capability_mismatch"}:
        return "spec_violation"
    return str(classification or "unknown")


def summarize_triage(data: dict) -> dict:
    results = data.get("results", [])
    buckets = data.get("buckets", {})
    bucket_items = list(buckets.items()) if isinstance(buckets, dict) else []
    bug_index = {
        current_bug_id_from_bucket(data, key, bucket): bucket
        for key, bucket in bucket_items
    }
    hang_bug_ids = sorted(
        bug_id
        for bug_id, bucket in bug_index.items()
        if bucket_impact(bucket) == "hang" or bucket.get("classification") == "hang"
    )
    high_severity_bug_ids = sorted(
        bug_id
        for bug_id, bucket in bug_index.items()
        if bucket_impact(bucket) == "crash"
    )
    confirmed = sum(1 for entry in results if entry.get("confirmed"))
    total = len(results)
    return {
        "total_cases": int(data.get("total_cases") or total),
        "total_buckets": len(bucket_items),
        "confirmed_cases": confirmed,
        "confirmed_ratio": 1.0 if total == 0 else confirmed / total,
        "by_violation_type": data.get("by_violation_type", {}),
        "bug_ids": sorted(bug_index),
        "high_severity_bug_ids": high_severity_bug_ids,
        "hang_bug_ids": hang_bug_ids,
    }


def load_closed_bug_ids(path: Path | None) -> set[str]:
    if not path:
        return set()
    data = load_json(path)
    if isinstance(data, list):
        return {str(item) for item in data}
    if isinstance(data, dict):
        if isinstance(data.get("closed_bug_ids"), list):
            return {str(item) for item in data["closed_bug_ids"]}
        if isinstance(data.get("buckets"), dict):
            return {
                shared_bug_id_from_bucket(data, key, item)
                for key, item in data["buckets"].items()
            }
        if isinstance(data.get("bugs"), dict):
            return {str(item.get("bug_id")) for item in data["bugs"].values() if item.get("bug_id")}
    return set()


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate host-side campaign quality")
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--triage", type=Path, required=True)
    parser.add_argument("--previous-triage", type=Path)
    parser.add_argument("--closed-bugs", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--min-total-runs", type=int, default=1000)
    parser.add_argument("--min-new-events", type=int, default=1)
    parser.add_argument("--min-buckets", type=int, default=1)
    parser.add_argument("--min-confirmed-ratio", type=float, default=0.5)
    parser.add_argument("--min-peak-exec-per-sec", type=int, default=1)
    parser.add_argument("--max-hang-bucket-ratio", type=float, default=0.5)
    args = parser.parse_args()

    metrics = summarize_metrics(load_json(args.metrics))
    triage = summarize_triage(load_json(args.triage))
    previous_triage = summarize_triage(load_json(args.previous_triage)) if args.previous_triage else None
    closed_bug_ids = load_closed_bug_ids(args.closed_bugs)

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

    blockers = []
    for name, check in checks.items():
        if not check["passed"]:
            blockers.append(
                {
                    "code": f"threshold_{name}",
                    "message": f"{name} failed its threshold check",
                    "details": check,
                }
            )

    previous_bug_ids = set(previous_triage["bug_ids"]) if previous_triage else set()
    current_bug_ids = set(triage["bug_ids"])
    new_bug_ids = sorted(current_bug_ids - previous_bug_ids) if previous_triage else []
    new_high_severity_bug_ids = sorted(
        bug_id for bug_id in triage["high_severity_bug_ids"] if bug_id not in previous_bug_ids
    ) if previous_triage else []
    reopened_bug_ids = sorted(current_bug_ids & closed_bug_ids)

    if new_high_severity_bug_ids:
        blockers.append(
            {
                "code": "new_high_severity_bugs",
                "message": "new crash-like bug IDs were detected",
                "bug_ids": new_high_severity_bug_ids,
            }
        )

    if reopened_bug_ids:
        blockers.append(
            {
                "code": "reopened_bugs",
                "message": "previously closed bug IDs reappeared",
                "bug_ids": reopened_bug_ids,
            }
        )

    warnings = []
    hang_bucket_ratio = (
        0.0 if triage["total_buckets"] == 0 else len(triage["hang_bug_ids"]) / triage["total_buckets"]
    )
    if hang_bucket_ratio > args.max_hang_bucket_ratio:
        warnings.append(
            {
                "code": "high_hang_bucket_ratio",
                "message": "hang-like buckets exceed the configured warning threshold",
                "actual": round(hang_bucket_ratio, 4),
                "threshold": args.max_hang_bucket_ratio,
            }
        )

    status = "pass" if not blockers else "fail"
    report = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "status": status,
        "metrics_path": str(args.metrics),
        "triage_path": str(args.triage),
        "previous_triage_path": str(args.previous_triage) if args.previous_triage else None,
        "summary": {
            "metrics": metrics,
            "triage": triage,
            "previous_triage": previous_triage,
        },
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "history": {
            "new_bug_ids": new_bug_ids,
            "new_high_severity_bug_ids": new_high_severity_bug_ids,
            "reopened_bug_ids": reopened_bug_ids,
            "persisting_bug_ids": sorted(current_bug_ids & previous_bug_ids) if previous_triage else [],
        },
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
