#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

EXIT_RE = re.compile(r"Run finish\. Exit kind: (\w+)")
PATTERNS = {
    "kasan": re.compile(r"KASAN|heap-buffer-overflow|slab-out-of-bounds", re.I),
    "ubsan": re.compile(r"UBSAN|integer overflow|signed integer overflow", re.I),
}


def classify(output: str):
    kinds = [name for name, pattern in PATTERNS.items() if pattern.search(output)]
    match = EXIT_RE.search(output)
    return {
        "exit_kind": match.group(1) if match else "Unknown",
        "signals": kinds,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run fixed OpenSBI sanitizer-demo inputs and classify output")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("inputs", nargs='+', type=Path)
    parser.add_argument("--helper-bin", default="target/release/helper")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--timeout-secs", type=int, default=15)
    args = parser.parse_args()

    env = os.environ.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")

    results = []
    for input_path in args.inputs:
        cmd = [args.helper_bin, "run", str(args.target), str(args.injector), str(input_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=args.timeout_secs)
            output = proc.stdout + proc.stderr
            timed_out = False
            returncode = proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            output = stdout + stderr
            timed_out = True
            returncode = None
        cls = classify(output)
        results.append({
            "input": str(input_path),
            "returncode": returncode,
            "exit_kind": cls["exit_kind"] if not timed_out else "TimeoutExpired",
            "signals": cls["signals"],
            "timed_out": timed_out,
            "output_excerpt": output[-4000:],
        })

    summary = {
        "total": len(results),
        "results": results,
    }
    if args.json_out:
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
