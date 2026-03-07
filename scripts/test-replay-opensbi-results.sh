#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_json="$(mktemp)"
trap 'rm -f "$out_json"' EXIT

python3 "$repo_root/scripts/replay-opensbi-results.py" \
  "$repo_root/playground/opensbi-fuzz/output/opensbi/build/platform/generic/firmware/fw_dynamic.bin" \
  "$repo_root/injector/build/injector.elf" \
  "$repo_root/playground/opensbi-fuzz/output/result-smoke" \
  --limit 1 \
  --prefer-raw-exec \
  --helper-bin "$repo_root/target/release/helper" \
  --timeout-secs 15 \
  --json-out "$out_json" > /tmp/replay-opensbi.stdout.json

rg -n '"total": 1' "$out_json" >/dev/null
rg -n '"actual":' "$out_json" >/dev/null

echo "opensbi replay test passed"
