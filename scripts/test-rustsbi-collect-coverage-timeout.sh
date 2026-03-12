#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
helper_bin="$repo_root/target/debug/helper"
target_bin="$repo_root/playground/rustsbi-fuzz/output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper.bin"
injector_elf="$repo_root/injector/build/injector.elf"
input_exec="$repo_root/playground/rustsbi-fuzz/output/seed-complex/base-identity-cross-hart.exec"
out_json="$(mktemp)"
trap 'rm -f "$out_json"' EXIT

if [ ! -f "$target_bin" ]; then
  echo "missing RustSBI target at $target_bin; run 'make -C playground/rustsbi-fuzz prepare' first" >&2
  exit 1
fi

if [ ! -f "$input_exec" ]; then
  echo "missing RustSBI oracle seed at $input_exec; run 'make -C playground/rustsbi-fuzz complex-seeds' first" >&2
  exit 1
fi

cargo build -p helper >/dev/null
make -C "$repo_root/injector" compile >/dev/null

"$helper_bin" collect-coverage \
  "$target_bin" \
  "$injector_elf" \
  "$input_exec" \
  --smp 4 \
  --timeout-ms 1000 \
  --json-out "$out_json" > /tmp/rustsbi-collect-coverage-timeout.stdout.json

rg -n '"exit_kind": "Timeout"' "$out_json" >/dev/null
rg -n '"coverage": null' "$out_json" >/dev/null

echo "rustsbi collect-coverage timeout test passed"
