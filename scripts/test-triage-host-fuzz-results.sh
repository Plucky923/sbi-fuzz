#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

artifact_dir="$out_dir/artifacts"
json_out="$out_dir/triage.json"
md_out="$out_dir/triage.md"

mkdir -p "$artifact_dir"
cp "$repo_root/tests/regression/host/ipi_invalid_hart_mask.json" "$artifact_dir/case-a.json"
cp "$repo_root/tests/regression/host/ipi_invalid_hart_mask.json" "$artifact_dir/case-b.json"

python3 "$repo_root/scripts/triage-host-fuzz-results.py" \
  "$artifact_dir" \
  --json-out "$json_out" \
  --md-out "$md_out" >/dev/null

python3 - "$json_out" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["total_cases"] == 2, data
assert data["by_target"] == {"open_sbi": 2}, data
assert data["by_violation_type"] == {"HartMaskInvalidNotRejected": 2}, data
assert len(data["buckets"]) == 1, data
bucket = next(iter(data["buckets"].values()))
assert bucket["count"] == 2, bucket
assert bucket["violation_type"] == "HartMaskInvalidNotRejected", bucket
PY

rg -n 'HartMaskInvalidNotRejected' "$md_out" >/dev/null

echo "triage host fuzz results test passed"
