#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

helper_bin="$repo_root/target/debug/helper"
target_bin="$repo_root/playground/opensbi-fuzz/output/opensbi/build/platform/generic/firmware/fw_dynamic.bin"
injector_elf="$repo_root/injector/build/injector.elf"
input_toml="$repo_root/playground/opensbi-fuzz/output/seed/ext-base-get_impl_version.toml"
raw_out="$out_dir/cover.raw"
json_out="$out_dir/cover.json"
stability_out="$out_dir/stability.json"

if [ ! -f "$target_bin" ]; then
  echo "missing OpenSBI firmware at $target_bin; build playground/opensbi-fuzz first" >&2
  exit 1
fi

cargo build -p helper >/dev/null
make -C "$repo_root/injector" compile >/dev/null
python3 "$repo_root/scripts/check-opensbi-coverage.py" \
  "$target_bin" "$injector_elf" "$input_toml" \
  --helper-bin "$helper_bin" \
  --runs 3 \
  --json-out "$stability_out" >/tmp/opensbi-coverage-stability.stdout.json

"$helper_bin" collect-coverage \
  "$target_bin" "$injector_elf" "$input_toml" \
  --raw-out "$raw_out" \
  --json-out "$json_out" \
  --symbolize-limit 4 >/tmp/opensbi-collect-coverage.stdout.json

[ -s "$raw_out" ]
rg -n '"exit_kind": "Ok"' "$json_out" >/dev/null
rg -n '"raw_count":' "$json_out" >/dev/null
rg -n '"stable_ratio":' "$stability_out" >/dev/null
rg -n '"runs": 3' "$stability_out" >/dev/null

echo "opensbi coverage test passed"
