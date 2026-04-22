#!/usr/bin/env python3
"""Batch-convert archived host fuzz findings into system fuzzer seeds.

Usage:
    reback-host-corpus.py <corpus_dir> --output-dir <seed_dir>

Processes .host artifacts in corpus_dir and converts them to .exec/.seq seeds
using helper subcommands. Skips inputs that cannot be lowered to firmware.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def find_helper_bin() -> str | None:
    candidates = [
        "./target/release/helper",
        "./target/debug/helper",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def convert_host_to_exec(helper: str, host_path: Path, exec_path: Path) -> bool:
    try:
        subprocess.run(
            [helper, "convert-host-crash-to-exec", str(host_path), str(exec_path)],
            capture_output=True,
            check=True,
        )
        return exec_path.exists()
    except subprocess.CalledProcessError:
        return False


def convert_exec_to_seq(helper: str, exec_path: Path, seq_path: Path) -> bool:
    try:
        subprocess.run(
            [helper, "import-exec-as-sequence", str(exec_path), str(seq_path)],
            capture_output=True,
            check=True,
        )
        return seq_path.exists()
    except subprocess.CalledProcessError:
        return False


def reback_corpus(corpus_dir: Path, seed_dir: Path, helper: str | None) -> dict[str, int]:
    if helper is None:
        helper = find_helper_bin()
    if helper is None:
        print("ERROR: helper binary not found. Build with: cargo build -p helper --features qemu", file=sys.stderr)
        sys.exit(1)

    seed_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {"exec": 0, "seq": 0, "skipped": 0}

    for host_file in corpus_dir.rglob("*.host"):
        base = host_file.stem
        exec_path = seed_dir / f"{base}.exec"
        seq_path = seed_dir / f"{base}.seq"

        if not convert_host_to_exec(helper, host_file, exec_path):
            counts["skipped"] += 1
            continue

        counts["exec"] += 1

        # Also produce .seq variant for sequence-level fuzzing
        if convert_exec_to_seq(helper, exec_path, seq_path):
            counts["seq"] += 1

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Reback host corpus to system seeds")
    parser.add_argument("corpus_dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--helper", type=str, default=None)
    args = parser.parse_args()

    counts = reback_corpus(args.corpus_dir, args.output_dir, args.helper)
    print(f"Rebacked: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
