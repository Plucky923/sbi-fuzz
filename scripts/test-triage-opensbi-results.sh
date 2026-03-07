#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

json_out="$out_dir/triage.json"
md_out="$out_dir/triage.md"
python3 "$repo_root/scripts/triage-opensbi-results.py" \
  "$repo_root/playground/opensbi-fuzz/output/result-smoke" \
  --json-out "$json_out" \
  --md-out "$md_out" > "$out_dir/stdout.json"

rg -n '"total_cases": 4' "$json_out" >/dev/null
rg -n '"Timeout": 4' "$json_out" >/dev/null
rg -n 'console' "$json_out" >/dev/null
rg -n 'Representative Buckets' "$md_out" >/dev/null
rg -n 'raw_exec=True|raw_exec=true' "$md_out" >/dev/null

echo "opensbi triage test passed"
