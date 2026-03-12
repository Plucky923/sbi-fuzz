#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path


def run_once(helper_bin: str, target: Path, injector: Path, input_path: Path, symbolize_limit: int, timeout_ms: int | None):
    cmd = [
        helper_bin,
        "collect-coverage",
        str(target),
        str(injector),
        str(input_path),
        "--symbolize-limit",
        str(symbolize_limit),
    ]
    if timeout_ms:
        cmd += ["--timeout-ms", str(timeout_ms)]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Repeat helper collect-coverage and summarize stability")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("input", type=Path)
    parser.add_argument("--helper-bin", default="target/debug/helper")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--symbolize-limit", type=int, default=0)
    parser.add_argument("--timeout-ms", type=int)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    reports = [
        run_once(
            args.helper_bin,
            args.target,
            args.injector,
            args.input,
            args.symbolize_limit,
            args.timeout_ms,
        )
        for _ in range(args.runs)
    ]
    pc_sets = [set(report.get("coverage", {}).get("pcs", [])) for report in reports]
    nonempty_sets = [pc_set for pc_set in pc_sets if pc_set]
    if nonempty_sets:
        stable = set.intersection(*nonempty_sets)
        union = set.union(*nonempty_sets)
    else:
        stable = set()
        union = set()

    summary = {
        "target": str(args.target),
        "injector": str(args.injector),
        "input": str(args.input),
        "runs": args.runs,
        "exit_kinds": [report["exit_kind"] for report in reports],
        "fallback_runs": sum(1 for report in reports if report.get("fallback_to_qemu_edges")),
        "unique_counts": [len(report.get("coverage", {}).get("pcs", [])) for report in reports],
        "stable_pc_count": len(stable),
        "union_pc_count": len(union),
        "stable_ratio": (len(stable) / len(union)) if union else 0.0,
        "reports": reports,
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
