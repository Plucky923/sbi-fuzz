#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_host_case() {
    local input="$1"
    local expected_classification="${2:-ok}"
    local out="$TMP_DIR/host.json"
    cargo run -q -p helper -- run-host-harness "$input" --json-out "$out" >/dev/null
    python3 - "$out" "$expected_classification" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
expected = sys.argv[2]
assert not data["spec_violations"], data
assert not data["memory_violations"], data
assert data["report"]["classification"] == expected, data["report"]
PY
}

run_convert_case() {
    local input="$1"
    local out="$TMP_DIR/converted.exec"
    cargo run -q -p helper -- convert-host-crash-to-exec "$input" "$out" >/dev/null
    python3 - "$out" <<'PY'
import sys, pathlib
data = pathlib.Path(sys.argv[1]).read_bytes()
assert data.startswith(b"SBIEXEC1"), data[:8]
PY
}

run_sequence_case() {
    local input="$1"
    local out="$TMP_DIR/sequence.json"
    cargo run -q -p helper -- diff-sequence "$input" --json-out "$out" >/dev/null
    python3 - "$out" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["classification"] in {"match", "capability_mismatch"}, data
PY
}

run_host_case "$ROOT_DIR/tests/regression/host/base_get_spec_version.json"
run_host_case "$ROOT_DIR/tests/regression/host/pmu_counter_out_of_range.json" "sbi_error:invalid_param"
run_convert_case "$ROOT_DIR/tests/regression/host/console_write.json"
run_sequence_case "$ROOT_DIR/tests/regression/sequence/shared_base_hsm_status.json"

echo "regression tests passed"
