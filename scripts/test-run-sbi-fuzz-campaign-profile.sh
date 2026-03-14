#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp_dir=$(mktemp -d /tmp/sbifuzz-campaign-profile-XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

target_bin="$tmp_dir/target.bin"
injector_elf="$tmp_dir/injector.elf"
seed_dir="$tmp_dir/seeds"
result_dir="$tmp_dir/results"
summary_json="$tmp_dir/summary.json"

mkdir -p "$seed_dir" "$result_dir"
: > "$target_bin"
: > "$injector_elf"

python3 "$repo_root/scripts/run-sbi-fuzz-campaign.py" \
  smoke-profile \
  "$target_bin" \
  "$injector_elf" \
  "$seed_dir" \
  "$result_dir" \
  --profile single-hart-fast \
  --fuzzer-bin /bin/true \
  --helper-bin /bin/true \
  --json-out "$summary_json"

rg -n '"profile_name": "single-hart-fast"' "$summary_json" >/dev/null
rg -n '"timeout_ms": 100' "$summary_json" >/dev/null
rg -n '"run_manifest":' "$summary_json" >/dev/null

manifest_path=$(find "$result_dir/campaigns" -name run-manifest.json | head -n 1)
test -n "$manifest_path"
rg -n '"profile_name": "single-hart-fast"' "$manifest_path" >/dev/null
rg -n '"timeout_ms": 100' "$manifest_path" >/dev/null
rg -n '"skip_halt": true' "$manifest_path" >/dev/null

echo "firmware campaign profile test passed"
