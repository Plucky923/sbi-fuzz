#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
target_bin="$repo_root/playground/rustsbi-fuzz/output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper-dynamic.bin"
injector_elf="$repo_root/injector/build/injector.elf"
seed_dir="$repo_root/playground/rustsbi-fuzz/output/seed-complex"
helper_bin="$repo_root/target/release/helper"
out_root="$(mktemp -d)"
trap 'rm -rf "$out_root"' EXIT

if [ ! -f "$target_bin" ]; then
  echo "missing RustSBI target at $target_bin; run 'make -C playground/rustsbi-fuzz prepare' first" >&2
  exit 1
fi

if [ ! -d "$seed_dir" ]; then
  echo "missing RustSBI complex seeds at $seed_dir; run 'make -C playground/rustsbi-fuzz complex-seeds' first" >&2
  exit 1
fi

if [ ! -f "$injector_elf" ]; then
  echo "missing injector at $injector_elf; run 'make -C injector compile' first" >&2
  exit 1
fi

cargo build -p helper --release >/dev/null

summary_json="$out_root/campaign-summary.json"
python3 "$repo_root/scripts/run-sbi-fuzz-campaign.py" \
  rustsbi-prototyper-complex-smoke \
  "$target_bin" \
  "$injector_elf" \
  "$seed_dir" \
  "$out_root/result" \
  --duration-secs 15 \
  --timeout-ms 100 \
  --smp 4 \
  --broker-port 19123 \
  --cores 1 \
  --replay-max-buckets 8 \
  --replay-timeout-secs 2 \
  --hang-stability-attempts 2 \
  --helper-bin "$helper_bin" \
  --json-out "$summary_json" > "$out_root/stdout.json"

python3 - "$summary_json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["after"]["corpus"] > 0, data
assert data["snapshot_errors"] == 0, data
assert data["runstate_warnings"] == 0, data
assert data["after"]["toml"] >= 0, data
PY

echo "rustsbi fuzz campaign smoke passed"
