#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

python3 "$repo_root/scripts/import-linux-sbi-corpus.py" \
  "$repo_root/tests/fixtures/linux-corpus/sample_sbi_calls.c" \
  "$out_dir"

count="$(find "$out_dir" -name '*.toml' | wc -l | tr -d ' ')"
if [ "$count" != "3" ]; then
  echo "expected 3 generated seeds, got $count" >&2
  exit 1
fi

rg -n "eid = 0x48534D" "$out_dir" >/dev/null
rg -n "fid = 0x0" "$out_dir" >/dev/null
rg -n "arg1 = 0x80200000" "$out_dir" >/dev/null
rg -n "eid = 0x4442434E" "$out_dir" >/dev/null
rg -n "eid = 0x504D55" "$out_dir" >/dev/null
rg -n "arg2 = 0x8" "$out_dir" >/dev/null

echo "linux corpus import test passed"


if python3 "$repo_root/scripts/import-linux-sbi-corpus.py"   "$repo_root/tests/fixtures/linux-corpus/invalid_sbi_calls.c"   "$out_dir/invalid"; then
  echo "expected invalid corpus import to fail" >&2
  exit 1
fi

echo "linux corpus negative import test passed"
