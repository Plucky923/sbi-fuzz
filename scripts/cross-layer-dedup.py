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


def normalize_numeric(value) -> str:
    if value is None:
        return "0"
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    try:
        return str(int(text, 0))
    except ValueError:
        return text or "0"


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


def dedup_key_for_item(source: str, item: dict, report_type: str | None = None) -> str:
    if item.get("dedup_key"):
        dedup_key = str(item["dedup_key"])
        if report_type == "host_triage" and dedup_key.count("|") >= 4:
            target, eid, fid, classification, detail = dedup_key.split("|", 4)
            return "|".join(
                [
                    target,
                    normalize_numeric(eid),
                    normalize_numeric(fid),
                    classification,
                    detail,
                ]
            )
        if report_type == "bug_report":
            if dedup_key.count("|") >= 4:
                target, eid, fid, classification, detail = dedup_key.split("|", 4)
                return "|".join(
                    [
                        normalize_target(target),
                        normalize_numeric(eid),
                        normalize_numeric(fid),
                        classification,
                        detail,
                    ]
                )
            target = normalize_target(
                item.get("affected_target") or item.get("target_kind") or item.get("impl_kind") or source
            )
            classification = item.get("classification") or item.get("violation_type") or item.get("violation") or "unknown"
            detail = item.get("signature") or item.get("raw_signature") or item.get("violation_detail") or "none"
            return "|".join(
                [
                    target,
                    normalize_numeric(item.get("eid", 0)),
                    normalize_numeric(item.get("fid", 0)),
                    classification,
                    detail,
                ]
            )
        return dedup_key
    target = normalize_target(item.get("affected_target") or item.get("target_kind") or item.get("impl_kind") or source)
    eid = normalize_numeric(item.get("eid", 0))
    fid = normalize_numeric(item.get("fid", 0))
    classification = item.get("classification") or item.get("violation_type") or item.get("violation") or "unknown"
    detail = item.get("violation_detail") or item.get("raw_signature") or item.get("signature") or "none"
    return f"{target}|{eid}|{fid}|{classification}|{detail}"


def bug_id_for_key(dedup_key: str) -> str:
    return f"bug-{hashlib.sha256(dedup_key.encode()).hexdigest()[:12]}"


def choose_best_reproducer(paths: list[str]) -> str | None:
    candidates = [path for path in paths if path]
    if not candidates:
        return None
    return min(candidates, key=lambda path: (len(path), path))


def summarize_source_reproducers(items: list[dict]) -> dict[str, str]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for item in items:
        for reproducer in item.get("reproducers", []):
            if reproducer:
                grouped[item["source"]].append(reproducer)
    return {
        source: best
        for source, best in (
            (source, choose_best_reproducer(paths))
            for source, paths in sorted(grouped.items())
        )
        if best
    }


def extract_source_items(source: str, data: dict) -> list[dict]:
    report_type = data.get("report_type")
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
        dedup_key = dedup_key_for_item(source, item, report_type)
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
                "eid": normalize_numeric(item.get("eid", 0)),
                "fid": normalize_numeric(item.get("fid", 0)),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "reproducers": reproducer_list,
            }
        )
    return normalized_items


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-layer deduplicate host/sequence/QEMU reports")
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Explicit source label and path in the form label=path",
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    grouped: dict[str, list[dict]] = defaultdict(list)
    explicit_sources: list[tuple[str, Path]] = []
    for item in args.source:
        if "=" not in item:
            raise SystemExit(f"invalid --source value {item!r}; expected label=path")
        label, raw_path = item.split("=", 1)
        explicit_sources.append((label, Path(raw_path)))

    inputs = explicit_sources or [(path.stem, path) for path in args.inputs]
    if not inputs:
        raise SystemExit("no input reports provided")

    for source, path in inputs:
        data = json.loads(path.read_text())
        for item in extract_source_items(source, data):
            grouped[item["dedup_key"]].append(item)

    summary = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "report_type": "cross_layer_dedup",
        "total_unique": len(grouped),
        "bugs": {
            dedup_key: {
                "bug_id": bug_id_for_key(dedup_key),
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
                "source_reproducers": summarize_source_reproducers(items),
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
