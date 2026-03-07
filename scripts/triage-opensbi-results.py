#!/usr/bin/env python3
import argparse
import json
import re
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

ADDRESS_KINDS = {"address", "address_low", "address_high", "hart_mask_address"}
STATUS_RE = re.compile(r"fuzz-([0-9a-f]+)-([A-Za-z]+)$")


def load_case(path: Path):
    data = tomllib.loads(path.read_text())
    metadata = data.get("metadata", {})
    args = data.get("args", {})
    schema = metadata.get("schema", {})
    source = metadata.get("source", "")
    match = STATUS_RE.search(source)
    hash_value = match.group(1) if match else path.stem.split("-")[-1]
    status = match.group(2) if match else "Unknown"

    arg_values = [args.get(f"arg{i}", 0) for i in range(6)]
    schema_values = [schema.get(f"arg{i}", "value") for i in range(6)]
    address_slots = [i for i, kind in enumerate(schema_values) if kind in ADDRESS_KINDS]
    nonzero_slots = [i for i, value in enumerate(arg_values) if value != 0]

    flags = []
    if all(value == 0 for value in arg_values):
        flags.append("all_zero_args")
    if any(value == 0xFFFFFFFFFFFFFFFF for value in arg_values):
        flags.append("u64_max_arg")
    if address_slots and any(arg_values[i] == 0 for i in address_slots):
        flags.append("zero_address_arg")
    if any(value & 0x7 for value in arg_values if value != 0):
        flags.append("unaligned_value")
    if args.get("eid", 0) not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x54494D45, 0x735049, 0x52464E43, 0x48534D, 0x53525354, 0x504D55, 0x4442434E, 0x53555350, 0x43505043, 0x535345, 0x46574654, 0x44425452, 0x4D505859):
        flags.append("unknown_eid")

    raw_exec = path.parent / ".raw" / f"{hash_value}.exec"
    return {
        "path": str(path),
        "hash": hash_value,
        "status": status,
        "extension": metadata.get("extension_name", "unknown"),
        "source": source,
        "eid": args.get("eid", 0),
        "fid": args.get("fid", 0),
        "args": arg_values,
        "schema": schema_values,
        "address_slots": address_slots,
        "nonzero_slots": nonzero_slots,
        "flags": flags,
        "raw_exec_exists": raw_exec.exists(),
    }


def summarize(cases):
    by_status = Counter(case["status"] for case in cases)
    by_extension = Counter(case["extension"] for case in cases)
    by_bucket = Counter(f"{case['extension']}:{case['fid']:x}:{case['status']}" for case in cases)
    flag_counts = Counter(flag for case in cases for flag in case["flags"])

    representatives = {}
    for case in cases:
        bucket = f"{case['extension']}:{case['fid']:x}:{case['status']}"
        representatives.setdefault(bucket, case)

    return {
        "total_cases": len(cases),
        "by_status": dict(by_status),
        "by_extension": dict(by_extension),
        "by_bucket": dict(by_bucket),
        "flag_counts": dict(flag_counts),
        "representatives": {
            bucket: {
                "path": rep["path"],
                "eid": f"0x{rep['eid']:X}",
                "fid": f"0x{rep['fid']:X}",
                "flags": rep["flags"],
                "raw_exec_exists": rep["raw_exec_exists"],
            }
            for bucket, rep in sorted(representatives.items())
        },
    }


def write_markdown(summary, output: Path):
    lines = [
        "# OpenSBI Triage Summary",
        "",
        f"- Total cases: {summary['total_cases']}",
        "",
        "## By Status",
        "",
    ]
    for key, value in sorted(summary["by_status"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## By Extension", ""]
    for key, value in sorted(summary["by_extension"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Flags", ""]
    for key, value in sorted(summary["flag_counts"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Representative Buckets", ""]
    for bucket, rep in summary["representatives"].items():
        lines.append(
            f"- `{bucket}` -> `{rep['path']}` | eid={rep['eid']} fid={rep['fid']} | flags={','.join(rep['flags']) or 'none'} | raw_exec={rep['raw_exec_exists']}"
        )
    output.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Triage OpenSBI sbifuzz result directories")
    parser.add_argument("result_dir", type=Path, help="Result directory containing *.toml and .raw/")
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary path")
    parser.add_argument("--md-out", type=Path, help="Optional Markdown summary path")
    args = parser.parse_args()

    cases = [load_case(path) for path in sorted(args.result_dir.glob("*.toml"))]
    if not cases:
        raise SystemExit(f"no TOML cases found in {args.result_dir}")

    summary = summarize(cases)
    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if args.md_out:
        write_markdown(summary, args.md_out)

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
