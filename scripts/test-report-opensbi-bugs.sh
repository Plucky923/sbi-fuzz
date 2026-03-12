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
      "classification": "sanitizer",
      "expected": "Timeout",
      "extension": "pmu",
      "fid": "0x2",
      "hash": "aaaa1111",
      "input": "case-a.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "KASAN: heap-buffer-overflow",
      "eid": "0x504D55",
      "signals": ["kasan"],
      "signature": "signals:kasan",
      "trap": null
    },
    {
      "actual": "Crash",
      "classification": "sanitizer",
      "expected": "Timeout",
      "extension": "pmu",
      "fid": "0x2",
      "hash": "bbbb2222",
      "input": "case-b.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "KASAN: heap-buffer-overflow",
      "eid": "0x504D55",
      "signals": ["kasan"],
      "signature": "signals:kasan",
      "trap": null
    },
    {
      "actual": "Timeout",
      "classification": "hang",
      "expected": "Timeout",
      "extension": "console",
      "fid": "0x0",
      "hash": "cccc3333",
      "input": "case-c.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "Run finish. Exit kind: Timeout",
      "eid": "0x4442434E",
      "signals": [],
      "signature": "exit:Timeout",
      "trap": null
    },
    {
      "actual": "Ok",
      "classification": "ok",
      "expected": "Ok",
      "extension": "base",
      "fid": "0x0",
      "hash": "dddd4444",
      "input": "case-d.exec",
      "interesting": false,
      "notes": [],
      "output_excerpt": "Run finish. Exit kind: Ok",
      "eid": "0x10",
      "signals": [],
      "signature": "exit:Ok",
      "trap": null
    }
  ]
}
JSON

json_out="$out_dir/bugs.json"
md_out="$out_dir/bugs.md"
hang_stability_json="$out_dir/hang-stability.json"
hang_minimize_json="$out_dir/hang-minimize.json"
cat > "$hang_stability_json" <<'JSON'
{
  "attempts_per_case": 3,
  "cases_by_hash": {
    "cccc3333": {
      "attempts": 3,
      "hang_count": 3,
      "label": "stable_hang",
      "stable_ratio": 1.0
    }
  },
  "flaky_hang_cases": 0,
  "non_hang_cases": 0,
  "stable_hang_cases": 1,
  "total_cases": 1
}
JSON
cat > "$hang_minimize_json" <<'JSON'
{
  "cases": [
    {
      "hash": "cccc3333",
      "input": "case-c.exec",
      "minimized_instruction_count": 2,
      "minimized_call_count": 1,
      "original_instruction_count": 5,
      "original_call_count": 3,
      "output": "case-c.min.exec",
      "semantic_signature": "hart1:raw->base_get_impl_id",
      "status": "minimized"
    }
  ],
  "cases_by_hash": {
    "cccc3333": {
      "hash": "cccc3333",
      "input": "case-c.exec",
      "minimized_instruction_count": 2,
      "minimized_call_count": 1,
      "original_instruction_count": 5,
      "original_call_count": 3,
      "output": "case-c.min.exec",
      "semantic_signature": "hart1:raw->base_get_impl_id",
      "status": "minimized"
    }
  },
  "failed_cases": 0,
  "minimized_cases": 1,
  "reduced_cases": 1,
  "successful_cases": 1,
  "unique_semantic_signatures": 1,
  "total_cases": 1
}
JSON
python3 "$repo_root/scripts/report-opensbi-bugs.py" "$input_json" --hang-stability "$hang_stability_json" --hang-minimize "$hang_minimize_json" --json-out "$json_out" --md-out "$md_out" > "$out_dir/stdout.json"

rg -n '"candidate_count": 3' "$json_out" >/dev/null
rg -n '"sanitizer": 2' "$json_out" >/dev/null
rg -n '"hang": 1' "$json_out" >/dev/null
rg -n '"stable_hang_cases": 1' "$json_out" >/dev/null
rg -n '"label": "stable_hang"' "$json_out" >/dev/null
rg -n '"minimized_cases": 1' "$json_out" >/dev/null
rg -n '"unique_semantic_signatures": 1' "$json_out" >/dev/null
rg -n '"status": "minimized"' "$json_out" >/dev/null
rg -n 'signals:kasan' "$json_out" >/dev/null
rg -n 'stability=stable_hang 3/3' "$md_out" >/dev/null
rg -n 'semantic=hart1:raw->base_get_impl_id' "$md_out" >/dev/null
rg -n 'minimized=mini' "$md_out" >/dev/null
rg -n 'OpenSBI Bug Report' "$md_out" >/dev/null

echo "opensbi bug report test passed"
