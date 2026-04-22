#!/bin/bash
# Negative test: coverage-baseline must exit non-zero on missing input directory.
# This test attempts to build the helper binary first; if the build fails due to
# missing toolchain (clang-18 / OpenSBI), the test fails loudly so the regression
# cannot silently disappear.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
HELPER_BIN="$ROOT_DIR/target/debug/helper"

echo -n "Test (missing input directory): "

# Attempt to build helper with the qemu feature so coverage-baseline is available.
# If this fails, the environment lacks required toolchain and the test must fail.
if [[ ! -x "$HELPER_BIN" ]]; then
    if ! (cd "$ROOT_DIR" && cargo build -p helper --features qemu) >/dev/null 2>&1; then
        echo "FAIL (helper build failed — environment missing clang-18/llvm-config/OpenSBI)"
        exit 1
    fi
fi

if ! "$HELPER_BIN" coverage-baseline \
    --target /dev/null \
    --injector /dev/null \
    /nonexistent/directory \
    >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi
