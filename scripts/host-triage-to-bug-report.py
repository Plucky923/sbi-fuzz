#!/usr/bin/env python3
import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_markdown(summary: dict, output: Path, label: str) -> None:
    lines = [
        f"# {label} Bug Report",
        "",
        f"- Total replayed cases: {summary['total_results']}",
        f"- Bug candidates: {summary['candidate_count']}",
        "",
        "## By Classification",
        "",
    ]
    for key, value in sorted(summary["by_classification"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Representative Buckets", ""]
    for key, bucket in summary["buckets"].items():
        lines.append(
            f"- `{bucket['bug_id']}` x{bucket['count']} -> `{bucket['input']}` | target={bucket['affected_target']} impact={bucket['impact']} class={bucket['classification']}"
        )
    output.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert host triage output into bug-report schema")
    parser.add_argument("input", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--label", default="OpenSBI Host")
    args = parser.parse_args()

    triage = json.loads(args.input.read_text())
    buckets = triage.get("buckets", {})
    bug_buckets = {}
    by_classification = Counter()
    generated_at = utc_now()
    candidate_count = 0

    for key, bucket in buckets.items():
        classification = bucket.get("classification", "unknown")
        bucket_count = int(bucket.get("count", 1) or 1)
        by_classification[classification] += bucket_count
        candidate_count += bucket_count
        dedup_key = bucket.get("dedup_key", key)
        bug_id = bucket.get("bug_id") or f"bug-{hashlib.sha256(str(dedup_key).encode()).hexdigest()[:12]}"
        bug_buckets[key] = {
            "count": bucket_count,
            "bug_id": bug_id,
            "classification": classification,
            "impact": bucket.get("impact", classification),
            "affected_target": bucket.get("affected_target") or bucket.get("target_kind"),
            "dedup_key": dedup_key,
            "signature": dedup_key,
            "raw_signature": bucket.get("violation_detail", key),
            "instruction_signature": bucket.get("violation_detail", key),
            "impl_kind": bucket.get("target_kind"),
            "input_kind": "host_smoke",
            "supported_by_target": True,
            "signals": [],
            "actual": classification,
            "expected": "n/a",
            "hash": (bucket.get("hashes") or [""])[0],
            "input": bucket.get("reproducer"),
            "extension": bucket.get("violation_type"),
            "eid": bucket.get("eid"),
            "fid": bucket.get("fid"),
            "notes": [],
            "log_path": None,
            "state_signature": None,
            "memory_signature": None,
            "semantic_signature": bucket.get("violation_detail"),
            "temporal_signature": None,
            "stability_label": bucket.get("repro_stability", {}).get("label", "single_replay"),
            "stability_score": bucket.get("repro_stability", {}).get("stable_ratio", 1.0),
            "repro_stability": bucket.get(
                "repro_stability",
                {"attempts": 1, "label": "single_replay", "stable_ratio": 1.0},
            ),
            "first_seen": bucket.get("first_seen", generated_at),
            "last_seen": bucket.get("last_seen", generated_at),
            "output_excerpt": "",
        }

    summary = {
        "schema_version": 1,
        "generated_at_utc": generated_at,
        "report_type": "bug_report",
        "total_results": triage.get("total_cases", len(bug_buckets)),
        "candidate_count": candidate_count,
        "by_classification": dict(by_classification),
        "by_signal": {},
        "by_signature": {bucket["dedup_key"]: bucket["count"] for bucket in bug_buckets.values()},
        "buckets": bug_buckets,
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    args.json_out.write_text(encoded)
    if args.md_out:
        write_markdown(summary, args.md_out, args.label)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
