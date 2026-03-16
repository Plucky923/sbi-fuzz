#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/host_harness/fuzz/corpus}"

rm -rf "$OUT_DIR"
cargo run -q -p helper -- export-fuzz-corpus "$OUT_DIR"

echo "Prepared host fuzz corpus at $OUT_DIR"
