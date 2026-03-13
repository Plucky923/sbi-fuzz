#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
helper_bin="$repo_root/target/debug/helper"
target_bin="$repo_root/playground/rustsbi-fuzz/output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper-dynamic.bin"
wrong_target_bin="/home/plucky/rustsbi/target/riscv64gc-unknown-none-elf/release/rustsbi-prototyper.bin"
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

# Wrong RustSBI artifact must be rejected before replay starts.
if "$helper_bin" run \
  "$wrong_target_bin" \
  "$injector_elf" \
  "$input_exec" \
  --smp 4 \
  --timeout-ms 1000 > "$out_json" 2>&1; then
  echo "expected contract mismatch for non-dynamic RustSBI target" >&2
  exit 1
fi

rg -n 'Target artifact contract mismatch:' "$out_json" >/dev/null

"$helper_bin" run \
  "$target_bin" \
  "$injector_elf" \
  "$input_exec" \
  --smp 4 \
  --timeout-ms 1000 > "$out_json" 2>&1

rg -n 'Redirecting hart 0 to 0x00000080600000' "$out_json" >/dev/null
rg -n 'Run finish\. Exit kind: Ok' "$out_json" >/dev/null

echo "rustsbi helper contract smoke passed"
