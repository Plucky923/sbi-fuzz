#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

json_out="$out_dir/sequence-bugs.json"
md_out="$out_dir/sequence-bugs.md"

python3 "$repo_root/scripts/report-sequence-bugs.py" \
  "$repo_root/tests/fixtures/workflow/sequence-replay.json" \
  --json-out "$json_out" \
  --md-out "$md_out" > "$out_dir/stdout.json"

python3 "$repo_root/scripts/validate-report-artifacts.py" "$json_out" --kind bug-report >/dev/null

rg -n '"schema_version": 1' "$json_out" >/dev/null
rg -n '"report_type": "bug_report"' "$json_out" >/dev/null
rg -n '"affected_target": "both"' "$json_out" >/dev/null
rg -n '"bug_id": "bug-' "$json_out" >/dev/null
rg -n 'SBI Sequence Bug Report' "$md_out" >/dev/null

echo "sequence bug report test passed"
