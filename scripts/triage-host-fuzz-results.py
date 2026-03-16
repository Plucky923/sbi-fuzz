#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


def resolve_helper(helper_bin: str | None) -> list[str]:
    if helper_bin:
        return [helper_bin]
    return ["cargo", "run", "-q", "-p", "helper", "--"]


def replay_case(helper_cmd: list[str], path: Path) -> dict:
    proc = subprocess.run(
        helper_cmd + ["run-host-harness", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"run-host-harness failed for {path}: {proc.stderr or proc.stdout}")
    return json.loads(proc.stdout)


def violation_signature(result: dict) -> tuple[str, str]:
    if result.get("spec_violations"):
        violation = result["spec_violations"][0]
        if isinstance(violation, dict):
            name = next(iter(violation))
            detail = json.dumps(violation[name], sort_keys=True)
            return name, detail
        return "spec_violation", json.dumps(violation, sort_keys=True)
    if result.get("memory_violations"):
        violation = result["memory_violations"][0]
        if isinstance(violation, dict):
            name = next(iter(violation))
            detail = json.dumps(violation[name], sort_keys=True)
            return name, detail
        return "memory_violation", json.dumps(violation, sort_keys=True)
    report = result.get("report", {})
    return report.get("classification", "ok"), report.get("signature", "none")


def build_entry(path: Path, result: dict) -> dict:
    input_data = result["input"]
    report = result["report"]
    eid = report.get("extid", 0)
    fid = report.get("fid", 0)
    violation_type, violation_detail = violation_signature(result)
    confirmed = bool(result.get("spec_violations") or result.get("memory_violations"))
    return {
        "path": str(path),
        "hash": hashlib.sha256(path.read_bytes()).hexdigest()[:12],
        "target_kind": report.get("target_kind"),
        "mode": report.get("mode"),
        "eid": eid,
        "fid": fid,
        "label": input_data.get("label"),
        "classification": report.get("classification"),
        "signature": report.get("signature"),
        "spec_violations": result.get("spec_violations", []),
        "memory_violations": result.get("memory_violations", []),
        "confirmed": confirmed,
        "violation_type": violation_type,
        "violation_detail": violation_detail,
    }


def summarize(entries: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        key = "|".join(
            [
                str(entry.get("target_kind")),
                hex(entry.get("eid", 0)),
                hex(entry.get("fid", 0)),
                entry.get("violation_type", "none"),
                entry.get("violation_detail", ""),
            ]
        )
        grouped[key].append(entry)

    buckets = {}
    for key, items in sorted(grouped.items()):
        rep = items[0]
        buckets[key] = {
            "count": len(items),
            "target_kind": rep.get("target_kind"),
            "eid": rep.get("eid"),
            "fid": rep.get("fid"),
            "violation_type": rep.get("violation_type"),
            "violation_detail": rep.get("violation_detail"),
            "classification": rep.get("classification"),
            "reproducer": rep.get("path"),
            "hashes": [item["hash"] for item in items],
        }

    return {
        "total_cases": len(entries),
        "by_target": dict(Counter(entry["target_kind"] for entry in entries)),
        "by_violation_type": dict(Counter(entry["violation_type"] for entry in entries)),
        "results": entries,
        "buckets": buckets,
    }


def write_markdown(summary: dict, path: Path) -> None:
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
            f"- `{key}` x{bucket['count']} -> `{bucket['reproducer']}` | eid=0x{bucket['eid']:x} fid=0x{bucket['fid']:x} | type={bucket['violation_type']} | class={bucket['classification']}"
        )
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Triage host_harness fuzz artifacts")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--helper-bin")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--all", action="store_true", help="Include non-violating artifacts")
    args = parser.parse_args()

    helper_cmd = resolve_helper(args.helper_bin)
    entries = []
    for path in sorted(args.artifact_dir.iterdir()):
        if not path.is_file():
            continue
        entry = build_entry(path, replay_case(helper_cmd, path))
        if args.all or entry["confirmed"]:
            entries.append(entry)

    summary = summarize(entries)
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    if args.md_out:
        write_markdown(summary, args.md_out)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
