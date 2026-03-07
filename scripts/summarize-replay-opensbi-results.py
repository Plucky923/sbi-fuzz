#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize replay-opensbi-results JSON output")
    parser.add_argument("input", type=Path)
    parser.add_argument("--md-out", type=Path)
    args = parser.parse_args()

    data = json.loads(args.input.read_text())
    results = data.get("results", [])
    by_expected = Counter(item.get("expected", "Unknown") for item in results)
    by_actual = Counter(item.get("actual", "Unknown") for item in results)
    exact_matches = sum(1 for item in results if item.get("match"))
    timed_out = sum(1 for item in results if item.get("timed_out"))

    summary = {
        "total": len(results),
        "matching": exact_matches,
        "timed_out": timed_out,
        "by_expected": dict(by_expected),
        "by_actual": dict(by_actual),
    }

    if args.md_out:
        lines = [
            "# OpenSBI Replay Summary",
            "",
            f"- Total cases: {summary['total']}",
            f"- Exact matches: {summary['matching']}",
            f"- Timed out replays: {summary['timed_out']}",
            "",
            "## Expected",
            "",
        ]
        for key, value in sorted(by_expected.items()):
            lines.append(f"- `{key}`: {value}")
        lines += ["", "## Actual", ""]
        for key, value in sorted(by_actual.items()):
            lines.append(f"- `{key}`: {value}")
        args.md_out.write_text("\n".join(lines) + "\n")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
