#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp_dir=$(mktemp -d /tmp/sbifuzz-sequence-replay-XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

cargo run -q -p helper -- generate-sequence-seeds --target-kind both "$tmp_dir"

replay_json="$tmp_dir/replay-opensbi.json"
python3 "$repo_root/scripts/replay-sequence-results.py" \
  opensbi \
  "$tmp_dir" \
  --limit 2 \
  --json-out "$replay_json"

rg -n '"input_kind": "sequence"' "$replay_json" >/dev/null
rg -n '"impl_kind": "open_sbi"' "$replay_json" >/dev/null
rg -n '"state_signature":' "$replay_json" >/dev/null
rg -n '"memory_signature":' "$replay_json" >/dev/null

campaign_json="$tmp_dir/campaign.json"
python3 "$repo_root/scripts/run-sequence-campaign.py" \
  opensbi-sequence \
  opensbi \
  "$tmp_dir" \
  --replay-limit 2 \
  --json-out "$campaign_json"

rg -n '"candidate_count":' "$campaign_json" >/dev/null
rg -n '"replayed_sequences":' "$campaign_json" >/dev/null

echo "sequence replay test passed"
