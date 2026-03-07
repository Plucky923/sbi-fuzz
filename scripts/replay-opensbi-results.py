#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

STATUS_RE = re.compile(r"Run finish\. Exit kind: (\w+)")
SOURCE_RE = re.compile(r"fuzz-([0-9a-f]+)-(\w+)$")


def load_case(path: Path):
    data = tomllib.loads(path.read_text())
    metadata = data.get("metadata", {})
    args = data.get("args", {})
    source = metadata.get("source", "")
    match = SOURCE_RE.search(source)
    hash_value = match.group(1) if match else path.stem.split("-")[-1]
    expected = match.group(2) if match else "Unknown"
    raw_exec = path.parent / ".raw" / f"{hash_value}.exec"
    return {
        "toml": path,
        "raw_exec": raw_exec if raw_exec.exists() else None,
        "expected": expected,
        "hash": hash_value,
        "extension": metadata.get("extension_name", "unknown"),
        "eid": args.get("eid", 0),
        "fid": args.get("fid", 0),
    }


def resolve_helper_cmd(explicit: str | None):
    if explicit:
        return [explicit]
    built = Path("target/release/helper")
    if built.exists():
        return [str(built)]
    return ["cargo", "run", "-q", "-p", "helper", "--"]


def replay(case, target: Path, injector: Path, use_raw: bool, helper_cmd, timeout_secs: int):
    input_path = case["raw_exec"] if use_raw and case["raw_exec"] is not None else case["toml"]
    env = os.environ.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")
    cmd = helper_cmd + [
        "run",
        str(target), str(injector), str(input_path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout_secs)
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = stdout + stderr
        return {
            "input": str(input_path),
            "used_raw_exec": bool(use_raw and case["raw_exec"] is not None),
            "expected": case["expected"],
            "actual": "TimeoutExpired",
            "match": False,
            "returncode": None,
            "hash": case["hash"],
            "extension": case["extension"],
            "eid": f"0x{case['eid']:X}",
            "fid": f"0x{case['fid']:X}",
            "timed_out": True,
            "output_excerpt": output[-4000:],
        }
    output = proc.stdout + proc.stderr
    timed_out = False
    output = proc.stdout + proc.stderr
    match = STATUS_RE.search(output)
    actual = match.group(1) if match else "Unknown"
    return {
        "input": str(input_path),
        "used_raw_exec": bool(use_raw and case["raw_exec"] is not None),
        "expected": case["expected"],
        "actual": actual,
        "match": actual == case["expected"],
        "returncode": proc.returncode,
        "hash": case["hash"],
        "extension": case["extension"],
        "eid": f"0x{case['eid']:X}",
        "fid": f"0x{case['fid']:X}",
        "timed_out": timed_out,
        "output_excerpt": output[-4000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay OpenSBI result directories using helper run")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--prefer-raw-exec", action="store_true")
    parser.add_argument("--helper-bin", help="Path to a prebuilt helper binary")
    parser.add_argument("--timeout-secs", type=int, default=20)
    args = parser.parse_args()

    cases = [load_case(path) for path in sorted(args.result_dir.glob("*.toml"))[: args.limit]]
    if not cases:
        raise SystemExit(f"no TOML cases found in {args.result_dir}")

    helper_cmd = resolve_helper_cmd(args.helper_bin)
    results = [replay(case, args.target, args.injector, args.prefer_raw_exec, helper_cmd, args.timeout_secs) for case in cases]
    summary = {
        "result_dir": str(args.result_dir),
        "total": len(results),
        "matching": sum(1 for item in results if item["match"]),
        "results": results,
    }
    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
