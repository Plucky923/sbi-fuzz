#!/usr/bin/env python3
"""Archive host fuzz findings by classification into a structured corpus.

Usage:
    archive-host-fuzz-findings.py <triage.json> --output-dir <corpus_dir>

Reads a host fuzz triage JSON and copies artifacts into per-classification
subdirectories:
    corpus_dir/
        spec_violation/
        memory_violation/
        impl_diff/
        unclassified/

Each artifact is stored with a deterministic filename derived from its bug_id.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path


def archive_findings(triage_path: Path, output_dir: Path) -> dict[str, int]:
    with open(triage_path, "r") as f:
        triage = json.load(f)

    output_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {
        "spec_violation": 0,
        "memory_violation": 0,
        "impl_diff": 0,
        "unclassified": 0,
    }

    buckets = triage.get("buckets", {})
    for bucket in buckets.values():
        classification = bucket.get("classification", "")
        bug_id = bucket.get("bug_id", "")
        source = bucket.get("source", "")

        if classification in ("spec_violation", "memory_violation"):
            dest_dir = output_dir / classification
        elif classification in ("impl_diff", "divergence", "capability_mismatch"):
            dest_dir = output_dir / "impl_diff"
        else:
            dest_dir = output_dir / "unclassified"

        dest_dir.mkdir(parents=True, exist_ok=True)

        if not source or not Path(source).exists():
            continue

        # Use bug_id hash for deterministic filename
        name = f"{hashlib.sha256(bug_id.encode()).hexdigest()[:16]}.host"
        dest = dest_dir / name
        shutil.copy2(source, dest)
        counts[dest_dir.name] += 1

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Archive host fuzz findings")
    parser.add_argument("triage", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    counts = archive_findings(args.triage, args.output_dir)
    print(f"Archived: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
