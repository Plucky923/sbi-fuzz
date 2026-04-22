#!/bin/bash
# Fixture-based validation tests for coverage-baseline schema
# Returns 0 if all tests pass, 1 otherwise

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR="${SCRIPT_DIR}/../../../scripts/validate-report-artifacts.py"

echo "=== Baseline Schema Fixture Tests ==="

# Test 1: valid baseline should pass
echo -n "Test 1 (valid baseline): "
if python3 "$VALIDATOR" "$SCRIPT_DIR/valid.json" --kind coverage-baseline >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi

# Test 2: missing schema_version should fail
echo -n "Test 2 (missing schema_version): "
if ! python3 "$VALIDATOR" "$SCRIPT_DIR/invalid-missing-schema.json" --kind coverage-baseline >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi

# Test 3: non-integer stat field should fail
echo -n "Test 3 (non-integer unique_pcs): "
if ! python3 "$VALIDATOR" "$SCRIPT_DIR/invalid-string-pcs.json" --kind coverage-baseline >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi

# Test 4: boolean stat field should fail (bool is subclass of int in Python)
echo -n "Test 4 (boolean unique_pcs): "
if ! python3 "$VALIDATOR" "$SCRIPT_DIR/invalid-bool-pcs.json" --kind coverage-baseline >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi

echo "=== All fixture tests passed ==="
