#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
helper_bin="$repo_root/target/debug/helper"
target_bin="$repo_root/playground/rustsbi-fuzz/output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper-dynamic.bin"
injector_elf="$repo_root/injector/build/injector.elf"
input_exec="$repo_root/playground/rustsbi-fuzz/output/seed-complex/base-identity-cross-hart.exec"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

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

stability_json="$out_dir/hang-stability.json"
cat > "$stability_json" <<EOF
{
  "cases": [
    {
      "attempts": 2,
      "hang_count": 0,
      "hash": "hang1111",
      "input": "$input_exec",
      "label": "non_hang",
      "stable_ratio": 0.0
    }
  ],
  "cases_by_hash": {
    "hang1111": {
      "attempts": 2,
      "hang_count": 0,
      "hash": "hang1111",
      "input": "$input_exec",
      "label": "non_hang",
      "stable_ratio": 0.0
    }
  },
  "stable_hang_cases": 0,
  "total_cases": 1
}
EOF

summary_json="$out_dir/minimize.json"
python3 "$repo_root/scripts/minimize-sbi-hangs.py" \
  "$target_bin" \
  "$injector_elf" \
  "$stability_json" \
  --helper-bin "$helper_bin" \
  --timeout-ms 1000 \
  --smp 4 \
  --attempts 2 \
  --output-dir "$out_dir/minimized" \
  --json-out "$summary_json" > "$out_dir/stdout.json"

rg -n '"total_cases": 0' "$summary_json" >/dev/null
rg -n '"successful_cases": 0' "$summary_json" >/dev/null

echo "rustsbi hang minimization gating test passed"
