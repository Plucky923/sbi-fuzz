#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

helper_bin="$repo_root/target/debug/helper"
target_bin="$repo_root/playground/rustsbi-fuzz/output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper-dynamic.bin"
injector_elf="$repo_root/injector/build/injector.elf"
seed_exec="$repo_root/playground/rustsbi-fuzz/output/seed-complex/hsm-start-status-chain.exec"
case_hash="deadbeef"
json_out="$out_dir/replay.json"
log_dir="$out_dir/logs"

if [ ! -f "$target_bin" ]; then
  echo "missing RustSBI target at $target_bin; run 'make -C playground/rustsbi-fuzz prepare' first" >&2
  exit 1
fi

if [ ! -f "$seed_exec" ]; then
  echo "missing RustSBI complex seed at $seed_exec; run 'make -C playground/rustsbi-fuzz complex-seeds' first" >&2
  exit 1
fi

cargo build -p helper >/dev/null
make -C "$repo_root/injector" compile >/dev/null

mkdir -p "$out_dir/.raw" "$log_dir"
cp "$seed_exec" "$out_dir/.raw/$case_hash.exec"
cat > "$out_dir/hsm-0-$case_hash.toml" <<'EOF'
[metadata]
extension_name = "hsm"
source = "fuzz-deadbeef-Timeout"

[args]
eid = 0x48534D
fid = 0x0
arg0 = 0x1
arg1 = 0x80200000
arg2 = 0x0
arg3 = 0x0
arg4 = 0x0
arg5 = 0x0
EOF

python3 "$repo_root/scripts/replay-sbi-results.py" \
  "$target_bin" \
  "$injector_elf" \
  "$out_dir" \
  --all \
  --prefer-raw-exec \
  --helper-bin "$helper_bin" \
  --timeout-secs 15 \
  --smp 4 \
  --log-dir "$log_dir" \
  --json-out "$json_out" > "$out_dir/stdout.json"

rg -n '"total": 1' "$json_out" >/dev/null
rg -n '"used_raw_exec": true' "$json_out" >/dev/null
rg -n '"actual":' "$json_out" >/dev/null
rg -n '"log_path":' "$json_out" >/dev/null

echo "rustsbi replay test passed"
