#!/usr/bin/env python3
import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_target(value: str | None) -> str:
    normalized = (value or "unknown").strip().lower()
    if normalized in {"open_sbi", "opensbi", "open-sbi"}:
        return "opensbi"
    if normalized in {"rust_sbi", "rustsbi", "rust-sbi"}:
        return "rustsbi"
    if normalized in {"both", "diff"}:
        return "both"
    return normalized or "unknown"


def impact_for_item(item: dict) -> str:
    if item.get("impact"):
        return item["impact"]
    classification = item.get("classification") or item.get("violation_type") or item.get("violation")
    if classification in {"sanitizer", "crash"}:
        return "crash"
    if classification == "hang":
        return "hang"
    if classification in {"mismatch", "capability_mismatch", "spec_violation", "memory_violation"}:
        return "spec_violation"
    return classification or "unknown"


def dedup_key_for_item(source: str, item: dict) -> str:
    if item.get("dedup_key"):
        return item["dedup_key"]
    target = normalize_target(item.get("affected_target") or item.get("target_kind") or item.get("impl_kind") or source)
    eid = item.get("eid", 0)
    fid = item.get("fid", 0)
    classification = item.get("classification") or item.get("violation_type") or item.get("violation") or "unknown"
    detail = item.get("violation_detail") or item.get("signature") or item.get("raw_signature") or "none"
    return f"{target}|{eid}|{fid}|{classification}|{detail}"


def bug_id_for_key(dedup_key: str) -> str:
    return f"bug-{hashlib.sha256(dedup_key.encode()).hexdigest()[:12]}"


def extract_source_items(source: str, data: dict) -> list[dict]:
    if isinstance(data.get("buckets"), dict):
        items = list(data["buckets"].values())
    elif isinstance(data.get("bugs"), dict):
        items = list(data["bugs"].values())
    elif isinstance(data.get("results"), list):
        items = list(data["results"])
    else:
        items = []

    normalized_items = []
    for item in items:
        dedup_key = dedup_key_for_item(source, item)
        reproducer = item.get("reproducer") or item.get("input")
        reproducer_list = item.get("reproducers") or ([reproducer] if reproducer else [])
        affected_target = normalize_target(
            item.get("affected_target") or item.get("target_kind") or item.get("impl_kind") or source
        )
        normalized_items.append(
            {
                "source": source,
                "bug_id": item.get("bug_id") or bug_id_for_key(dedup_key),
                "dedup_key": dedup_key,
                "affected_target": affected_target,
                "classification": item.get("classification") or item.get("violation_type") or item.get("violation"),
                "impact": impact_for_item(item),
                "eid": item.get("eid", 0),
                "fid": item.get("fid", 0),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "reproducers": reproducer_list,
            }
        )
    return normalized_items


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-layer deduplicate host/sequence/QEMU reports")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    grouped: dict[str, list[dict]] = defaultdict(list)
    for path in args.inputs:
        data = json.loads(path.read_text())
        for item in extract_source_items(path.stem, data):
            grouped[item["dedup_key"]].append(item)

    summary = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "report_type": "cross_layer_dedup",
        "total_unique": len(grouped),
        "bugs": {
            dedup_key: {
                "bug_id": items[0]["bug_id"],
                "dedup_key": dedup_key,
                "count": len(items),
                "sources": sorted({item["source"] for item in items}),
                "affected_target": items[0]["affected_target"],
                "eid": items[0]["eid"],
                "fid": items[0]["fid"],
                "classification": items[0]["classification"],
                "impact": items[0]["impact"],
                "first_seen": min(
                    (item["first_seen"] for item in items if item.get("first_seen")),
                    default=None,
                ),
                "last_seen": max(
                    (item["last_seen"] for item in items if item.get("last_seen")),
                    default=None,
                ),
                "reproducers": sorted(
                    {
                        reproducer
                        for item in items
                        for reproducer in item.get("reproducers", [])
                        if reproducer
                    }
                ),
            }
            for dedup_key, items in sorted(grouped.items())
        },
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
