#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

replay_json="$out_dir/replay.json"
cat > "$replay_json" <<'JSON'
{
  "results": [
    {
      "actual": "Timeout",
      "classification": "hang",
      "expected": "Timeout",
      "extension": "base",
      "fid": "0x1",
      "hash": "aaaa1111",
      "input": "case-a.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "Run finish. Exit kind: Timeout",
      "eid": "0x10",
      "signals": [],
      "signature": "exit:Timeout",
      "trap": null
    },
    {
      "actual": "Timeout",
      "classification": "hang",
      "expected": "Timeout",
      "extension": "base",
      "fid": "0x2",
      "hash": "bbbb2222",
      "input": "case-b.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "Run finish. Exit kind: Timeout",
      "eid": "0x10",
      "signals": [],
      "signature": "exit:Timeout",
      "trap": null
    }
  ]
}
JSON

hang_stability_json="$out_dir/hang-stability.json"
cat > "$hang_stability_json" <<'JSON'
{
  "cases_by_hash": {
    "aaaa1111": {
      "attempts": 3,
      "hang_count": 3,
      "label": "stable_hang",
      "stable_ratio": 1.0
    },
    "bbbb2222": {
      "attempts": 3,
      "hang_count": 3,
      "label": "stable_hang",
      "stable_ratio": 1.0
    }
  },
  "flaky_hang_cases": 0,
  "non_hang_cases": 0,
  "stable_hang_cases": 2,
  "total_cases": 2
}
JSON

hang_minimize_json="$out_dir/hang-minimize.json"
cat > "$hang_minimize_json" <<'JSON'
{
  "cases": [
    {
      "hash": "aaaa1111",
      "input": "case-a.exec",
      "minimized_instruction_count": 2,
      "original_instruction_count": 7,
      "output": "case-a.min.exec",
      "semantic_signature": "hart1:raw->base_get_impl_id",
      "status": "minimized"
    },
    {
      "hash": "bbbb2222",
      "input": "case-b.exec",
      "minimized_instruction_count": 2,
      "original_instruction_count": 8,
      "output": "case-b.min.exec",
      "semantic_signature": "hart2:raw->base_get_impl_version",
      "status": "minimized"
    }
  ],
  "cases_by_hash": {
    "aaaa1111": {
      "hash": "aaaa1111",
      "input": "case-a.exec",
      "minimized_instruction_count": 2,
      "original_instruction_count": 7,
      "output": "case-a.min.exec",
      "semantic_signature": "hart1:raw->base_get_impl_id",
      "status": "minimized"
    },
    "bbbb2222": {
      "hash": "bbbb2222",
      "input": "case-b.exec",
      "minimized_instruction_count": 2,
      "original_instruction_count": 8,
      "output": "case-b.min.exec",
      "semantic_signature": "hart2:raw->base_get_impl_version",
      "status": "minimized"
    }
  },
  "failed_cases": 0,
  "minimized_cases": 2,
  "reduced_cases": 2,
  "successful_cases": 2,
  "total_cases": 2,
  "unique_semantic_signatures": 2
}
JSON

json_out="$out_dir/bugs.json"
md_out="$out_dir/bugs.md"
python3 "$repo_root/scripts/report-sbi-bugs.py" \
  "$replay_json" \
  --hang-stability "$hang_stability_json" \
  --hang-minimize "$hang_minimize_json" \
  --json-out "$json_out" \
  --md-out "$md_out" > "$out_dir/stdout.json"

python3 - "$json_out" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
buckets = data["buckets"]
assert len(buckets) == 2, buckets
keys = sorted(buckets)
assert keys[0] != keys[1], keys
for key, bucket in buckets.items():
    assert bucket["count"] == 1, bucket
    assert bucket["signature"].startswith("exit:Timeout|semantic:"), bucket
    assert bucket["raw_signature"] == "exit:Timeout", bucket
PY

rg -n 'semantic=hart1:raw->base_get_impl_id' "$md_out" >/dev/null
rg -n 'semantic=hart2:raw->base_get_impl_version' "$md_out" >/dev/null

echo "sbi hang semantic bucket test passed"
