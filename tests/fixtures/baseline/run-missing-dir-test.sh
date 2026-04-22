#!/bin/bash
# Negative test: coverage-baseline must exit non-zero on missing input directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_BIN="${SCRIPT_DIR}/../../../target/debug/helper"

echo -n "Test (missing input directory): "

# Skip if helper binary is not available (toolchain not built)
if [[ ! -x "$HELPER_BIN" ]]; then
    echo "SKIP (helper binary not built)"
    exit 0
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
