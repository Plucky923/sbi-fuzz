#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict
from pathlib import Path


def normalize_bucket(source: str, item: dict) -> tuple[str, dict]:
    target = item.get("target_kind") or item.get("impl_kind") or source
    eid = item.get("eid", 0)
    fid = item.get("fid", 0)
    violation = item.get("violation_type") or item.get("classification") or "unknown"
    detail = item.get("violation_detail") or item.get("signature") or item.get("raw_signature") or "none"
    signature = f"{target}|{eid}|{fid}|{violation}|{detail}"
    return signature, {
        "source": source,
        "target": target,
        "eid": eid,
        "fid": fid,
        "violation": violation,
        "detail": detail,
        "reproducer": item.get("reproducer") or item.get("input"),
    }


def choose_best_reproducer(paths: list[str]) -> str | None:
    candidates = [path for path in paths if path]
    if not candidates:
        return None
    return min(candidates, key=lambda path: (len(path), path))


def summarize_source_reproducers(items: list[dict]) -> dict[str, str]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for item in items:
        if item.get("reproducer"):
            grouped[item["source"]].append(item["reproducer"])
    return {
        source: best
        for source, best in (
            (source, choose_best_reproducer(paths))
            for source, paths in sorted(grouped.items())
        )
        if best
    }


def extract_items(source: str, data: dict) -> list[dict]:
    if isinstance(data.get("buckets"), dict):
        return [normalize_bucket(source, bucket)[1] | {"signature": normalize_bucket(source, bucket)[0]} for bucket in data["buckets"].values()]
    if isinstance(data.get("results"), list):
        return [normalize_bucket(source, item)[1] | {"signature": normalize_bucket(source, item)[0]} for item in data["results"]]
    return []


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
        for item in extract_items(source, data):
            grouped[item["signature"]].append(item)

    summary = {
        "total_unique": len(grouped),
        "bugs": {
            signature: {
                "count": len(items),
                "sources": sorted({item["source"] for item in items}),
                "targets": sorted({str(item["target"]) for item in items}),
                "eid": items[0]["eid"],
                "fid": items[0]["fid"],
                "violation": items[0]["violation"],
                "detail": items[0]["detail"],
                "reproducers": sorted({item["reproducer"] for item in items if item.get("reproducer")}),
                "source_reproducers": summarize_source_reproducers(items),
            }
            for signature, items in sorted(grouped.items())
        },
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
