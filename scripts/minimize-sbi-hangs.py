#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path

from sbi_results import resolve_helper_cmd


def minimize_case(case: dict, args, helper_cmd):
    hash_value = case.get("hash") or Path(case["input"]).stem
    output_exec = args.output_dir / f"{hash_value}.min.exec"
    report_json = args.output_dir / f"{hash_value}.min.json"
    cmd = helper_cmd + [
        "minimize-hang",
        str(args.target),
        str(args.injector),
        str(case["input"]),
        str(output_exec),
        "--smp",
        str(args.smp),
        "--timeout-ms",
        str(args.timeout_ms),
        "--attempts",
        str(args.attempts),
        "--json-out",
        str(report_json),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "hash": hash_value,
            "input": case.get("input"),
            "status": "failed",
            "error": (proc.stderr or proc.stdout).strip(),
            "output": str(output_exec),
            "report_path": str(report_json),
        }

    report = json.loads(report_json.read_text())
    report["hash"] = hash_value
    report["report_path"] = str(report_json)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimize stable SBI hang cases into shorter .exec reproducers")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("hang_stability_json", type=Path)
    parser.add_argument("--helper-bin")
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--smp", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--label", default="SBI")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    helper_cmd = resolve_helper_cmd(args.helper_bin)
    data = json.loads(args.hang_stability_json.read_text())
    stable_cases = [
        item for item in data.get("cases", []) if item.get("label") == "stable_hang"
    ]
    cases = [minimize_case(case, args, helper_cmd) for case in stable_cases]

    summary = {
        "label": args.label,
        "total_cases": len(stable_cases),
        "successful_cases": sum(1 for item in cases if item.get("status") != "failed"),
        "failed_cases": sum(1 for item in cases if item.get("status") == "failed"),
        "minimized_cases": sum(1 for item in cases if item.get("status") == "minimized"),
        "unique_semantic_signatures": len(
            {
                item.get("semantic_signature")
                for item in cases
                if item.get("semantic_signature")
            }
        ),
        "reduced_cases": sum(
            1
            for item in cases
            if item.get("status") in {"minimized", "kept"}
            and item.get("minimized_instruction_count", 0)
            < item.get("original_instruction_count", 0)
        ),
        "cases": cases,
        "cases_by_hash": {item["hash"]: item for item in cases if item.get("hash")},
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
