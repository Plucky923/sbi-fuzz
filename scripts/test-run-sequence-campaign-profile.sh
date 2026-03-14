#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp_dir=$(mktemp -d /tmp/sbifuzz-sequence-campaign-profile-XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

sequence_dir="$tmp_dir/sequences"
summary_json="$tmp_dir/summary.json"
mkdir -p "$sequence_dir"

python3 "$repo_root/scripts/run-sequence-campaign.py" \
  smoke-sequence \
  opensbi \
  "$sequence_dir" \
  --profile host-sequence \
  --helper-bin /bin/true \
  --json-out "$summary_json"

rg -n '"profile_name": "host-sequence"' "$summary_json" >/dev/null
rg -n '"timeout_secs": 20' "$summary_json" >/dev/null
rg -n '"run_manifest":' "$summary_json" >/dev/null

manifest_path=$(find "$sequence_dir/campaigns" -name run-manifest.json | head -n 1)
test -n "$manifest_path"
rg -n '"profile_name": "host-sequence"' "$manifest_path" >/dev/null
rg -n '"timeout_secs": 20' "$manifest_path" >/dev/null

echo "sequence campaign profile test passed"
