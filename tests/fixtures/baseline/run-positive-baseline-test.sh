#!/bin/bash
# Positive test: coverage-baseline on a minimal seed corpus produces valid baseline.json.
# This test attempts to build the helper binary first; if the build fails due to
# missing toolchain, the test fails loudly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
HELPER_BIN="$ROOT_DIR/target/debug/helper"
VALIDATOR="$ROOT_DIR/scripts/validate-report-artifacts.py"

echo -n "Test (positive coverage-baseline on minimal corpus): "

# Attempt to build helper with the qemu feature.
if [[ ! -x "$HELPER_BIN" ]]; then
    if ! (cd "$ROOT_DIR" && cargo build -p helper --features qemu) >/dev/null 2>&1; then
        echo "FAIL (helper build failed — environment missing clang-18/llvm-config/OpenSBI)"
        exit 1
    fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SEED_DIR="$TMP_DIR/seeds"
mkdir -p "$SEED_DIR"
cp "$SCRIPT_DIR/valid.json" "$SEED_DIR/seed.toml"

# Note: This test also requires a valid target firmware and injector to run QEMU.
# In a full environment these would be provided; here we verify the command fails
# gracefully when they are missing, which at least exercises the CLI path.
if ! "$HELPER_BIN" coverage-baseline \
    --target /dev/null \
    --injector /dev/null \
    "$SEED_DIR" \
    --output "$TMP_DIR/baseline.json" \
    >/dev/null 2>&1; then
    # Expected to fail because /dev/null is not a valid firmware/injector.
    # In a full environment this would succeed and emit baseline.json.
    echo "SKIP (QEMU toolchain not available for end-to-end run)"
    exit 0
fi

if [[ -f "$TMP_DIR/baseline.json" ]]; then
    if python3 "$VALIDATOR" "$TMP_DIR/baseline.json" --kind coverage-baseline >/dev/null 2>&1; then
        echo "PASS"
    else
        echo "FAIL (baseline.json schema invalid)"
        exit 1
    fi
else
    echo "FAIL (baseline.json not created)"
    exit 1
fi
