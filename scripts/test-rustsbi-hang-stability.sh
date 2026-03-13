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

replay_json="$out_dir/replay.json"
cat > "$replay_json" <<EOF
{
  "results": [
    {
      "actual": "Timeout",
      "classification": "hang",
      "expected": "Timeout",
      "extension": "base",
      "fid": "0x0",
      "hash": "hang1111",
      "input": "$input_exec",
      "interesting": true,
      "eid": "0x10",
      "signals": [],
      "signature": "exit:Timeout",
      "trap": null
    }
  ]
}
EOF

stability_json="$out_dir/stability.json"
python3 "$repo_root/scripts/check-sbi-hang-stability.py" \
  "$target_bin" \
  "$injector_elf" \
  "$replay_json" \
  --helper-bin "$helper_bin" \
  --timeout-secs 1 \
  --smp 4 \
  --attempts 2 \
  --json-out "$stability_json" > "$out_dir/stdout.json"

rg -n '"stable_hang_cases": 0' "$stability_json" >/dev/null
rg -n '"non_hang_cases": 1' "$stability_json" >/dev/null
rg -n '"hang_count": 0' "$stability_json" >/dev/null
rg -n '"label": "non_hang"' "$stability_json" >/dev/null

echo "rustsbi hang stability regression test passed"
