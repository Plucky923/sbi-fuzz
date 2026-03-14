#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

input_json="$out_dir/replay.json"
cat > "$input_json" <<'JSON'
{
  "results": [
    {
      "actual": "Crash",
      "classification": "crash",
      "expected": "Timeout",
      "extension": "base",
      "fid": "0x0",
      "hash": "aaaa1111",
      "input": "case-a.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "panic",
      "eid": "0x10",
      "signals": ["panic"],
      "signature": "signals:panic",
      "instruction_signature": "signals:panic",
      "semantic_signature": "call:0x10:0x0:schema=vvvvvv:nz=100000:addr=------",
      "temporal_signature": "single:0x10:0x0",
      "trap": null
    },
    {
      "actual": "Crash",
      "classification": "crash",
      "expected": "Timeout",
      "extension": "base",
      "fid": "0x0",
      "hash": "bbbb2222",
      "input": "case-b.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "panic",
      "eid": "0x10",
      "signals": ["panic"],
      "signature": "signals:panic",
      "instruction_signature": "signals:panic",
      "semantic_signature": "call:0x10:0x0:schema=vvvvvv:nz=010000:addr=------",
      "temporal_signature": "single:0x10:0x0",
      "trap": null
    }
  ]
}
JSON

json_out="$out_dir/bugs.json"
python3 "$repo_root/scripts/report-sbi-bugs.py" "$input_json" --json-out "$json_out" > "$out_dir/stdout.json"

python3 - "$json_out" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
buckets = data["buckets"]
assert len(buckets) == 2, buckets
for bucket in buckets.values():
    assert bucket["instruction_signature"] == "signals:panic", bucket
    assert bucket["signature"].startswith("signals:panic|semantic:"), bucket
PY

echo "layered signature bucket test passed"
