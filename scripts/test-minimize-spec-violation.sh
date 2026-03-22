#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

input_json="$out_dir/input.json"
output_json="$out_dir/output.json"
report_json="$out_dir/report.json"

cat >"$input_json" <<'JSON'
{
  "metadata": {
    "name": "minimize-ipi-invalid-hart-mask",
    "source": "test",
    "note": ""
  },
  "env": {
    "smp": 4,
    "impl_hint": "open_sbi",
    "platform": "host-test"
  },
  "memory": [],
  "steps": [
    {
      "kind": "busy_wait",
      "iterations": 8
    },
    {
      "kind": "call",
      "label": "ipi-invalid-mask",
      "eid": 7557193,
      "fid": 0,
      "args": [
        { "kind": "const", "value": 16 },
        { "kind": "const", "value": 60 },
        { "kind": "const", "value": 0 },
        { "kind": "const", "value": 0 },
        { "kind": "const", "value": 0 },
        { "kind": "const", "value": 0 }
      ]
    }
  ]
}
JSON

cargo run -q -p helper -- minimize-spec-violation \
  "$input_json" \
  --target-kind opensbi \
  "$output_json" \
  --json-out "$report_json" >/dev/null

python3 - "$output_json" "$report_json" <<'PY'
import json
import sys

program = json.load(open(sys.argv[1], "r", encoding="utf-8"))
report = json.load(open(sys.argv[2], "r", encoding="utf-8"))

assert len(program["steps"]) == 1, program
assert program["steps"][0]["kind"] == "call", program
assert report["original_steps"] == 2, report
assert report["minimized_steps"] == 1, report
assert report["violation"]["kind"] == "spec", report
PY

echo "minimize spec violation test passed"
