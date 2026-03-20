#!/usr/bin/env python3
import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def merge_buckets(entries: list[dict]) -> dict:
    def impact_for_entry(entry: dict) -> str:
        classification = entry.get("classification")
        violation_type = entry.get("violation_type")
        if classification in {"sanitizer", "crash"}:
            return "crash"
        if classification == "hang":
            return "hang"
        if violation_type in {"spec_violation", "memory_violation"} or entry.get("confirmed"):
            return "spec_violation"
        return entry.get("impact") or classification or "unknown"

    def entry_dedup_key(entry: dict) -> str:
        if entry.get("dedup_key"):
            return entry["dedup_key"]
        return "|".join(
            [
                str(entry.get("affected_target") or entry.get("target_kind") or "unknown"),
                str(entry.get("eid", 0)),
                str(entry.get("fid", 0)),
                str(entry.get("violation_type") or entry.get("classification") or "unknown"),
                str(entry.get("violation_detail") or entry.get("signature") or "none"),
            ]
        )

    grouped: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        grouped[entry_dedup_key(entry)].append(entry)

    buckets = {}
    for key, items in sorted(grouped.items()):
        rep = items[0]
        hashes = []
        for item in items:
            hashes.extend(item.get("hashes", []))
            if item.get("hash"):
                hashes.append(item["hash"])
        buckets[key] = {
            "count": len(items),
            "target_kind": rep.get("target_kind"),
            "eid": rep.get("eid"),
            "fid": rep.get("fid"),
            "violation_type": rep.get("violation_type"),
            "violation_detail": rep.get("violation_detail"),
            "classification": rep.get("classification"),
            "reproducer": rep.get("path") or rep.get("reproducer"),
            "hashes": sorted(set(hashes)),
            "affected_target": rep.get("affected_target"),
            "impact": impact_for_entry(rep),
            "dedup_key": rep.get("dedup_key", key),
            "bug_id": rep.get("bug_id") or f"bug-{hashlib.sha256(key.encode()).hexdigest()[:12]}",
            "repro_stability": rep.get(
                "repro_stability",
                {"attempts": 1, "label": "single_replay", "stable_ratio": 1.0},
            ),
            "first_seen": min(item.get("first_seen", utc_now()) for item in items),
            "last_seen": max(item.get("last_seen", utc_now()) for item in items),
        }
    return buckets


def write_markdown(summary: dict, output: Path) -> None:
    def as_int(value) -> int:
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        return int(str(value), 0)

    lines = [
        "# Host Fuzz Triage",
        "",
        f"- Total cases: {summary['total_cases']}",
        "",
        "## By Target",
        "",
    ]
    for key, value in sorted(summary["by_target"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## By Violation", ""]
    for key, value in sorted(summary["by_violation_type"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Buckets", ""]
    for key, bucket in summary["buckets"].items():
        lines.append(
            f"- `{bucket['bug_id']}` x{bucket['count']} -> `{bucket['reproducer']}` | eid=0x{as_int(bucket['eid']):x} fid=0x{as_int(bucket['fid']):x} | type={bucket['violation_type']} | class={bucket['classification']}"
        )
    output.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge multiple host triage summaries into one report")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path)
    args = parser.parse_args()

    entries = []
    for path in args.inputs:
        data = json.loads(path.read_text())
        current_entries = data.get("results", [])
        has_complete_results = bool(current_entries) and all(
            (
                entry.get("dedup_key")
                or entry.get("violation_type")
                or entry.get("violation_detail")
                or entry.get("signature")
            )
            for entry in current_entries
        )
        if has_complete_results:
            entries.extend(current_entries)
            continue
        for bucket in data.get("buckets", {}).values():
            entries.append(
                {
                    "affected_target": bucket.get("affected_target"),
                    "target_kind": bucket.get("target_kind"),
                    "eid": bucket.get("eid"),
                    "fid": bucket.get("fid"),
                    "classification": bucket.get("classification"),
                    "violation_type": bucket.get("violation_type"),
                    "violation_detail": bucket.get("violation_detail"),
                    "dedup_key": bucket.get("dedup_key"),
                    "bug_id": bucket.get("bug_id"),
                    "hashes": bucket.get("hashes", []),
                    "first_seen": bucket.get("first_seen"),
                    "last_seen": bucket.get("last_seen"),
                    "repro_stability": bucket.get("repro_stability"),
                    "path": bucket.get("reproducer"),
                    "reproducer": bucket.get("reproducer"),
                    "impact": bucket.get("impact"),
                }
            )

    summary = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "report_type": "host_triage",
        "total_cases": len(entries),
        "by_target": dict(
            Counter(
                entry.get("target_kind")
                or entry.get("affected_target")
                or "unknown"
                for entry in entries
            )
        ),
        "by_violation_type": dict(
            Counter(entry.get("violation_type", "unknown") for entry in entries)
        ),
        "results": entries,
        "buckets": merge_buckets(entries),
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    args.json_out.write_text(encoded)
    if args.md_out:
        write_markdown(summary, args.md_out)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
