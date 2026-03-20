#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USE_FIXTURES="${SBIFUZZ_USE_FIXTURES:-0}"
HOST_OUT_ROOT="$ROOT_DIR/output/host_fuzz"
FIXTURE_ROOT="$ROOT_DIR/tests/fixtures/workflow"
TRIAGE_PARTS_DIR="$HOST_OUT_ROOT/triage-parts"
OPENSBI_TRIAGE_JSON="$HOST_OUT_ROOT/opensbi.triage.json"
OPENSBI_TRIAGE_MD="$HOST_OUT_ROOT/opensbi.triage.md"
OPENSBI_BUG_JSON="$HOST_OUT_ROOT/opensbi.bugs.json"
OPENSBI_BUG_MD="$HOST_OUT_ROOT/opensbi.bugs.md"
OPENSBI_BUG_STDOUT="$HOST_OUT_ROOT/opensbi.bugs.stdout.json"

reset_dir() {
    local dir="$1"
    mkdir -p "$dir"
    find "$dir" -mindepth 1 -delete 2>/dev/null || true
}

validate_outputs() {
    python3 "$ROOT_DIR/scripts/validate-report-artifacts.py" "$HOST_OUT_ROOT/triage.json" --kind host-triage
    python3 "$ROOT_DIR/scripts/validate-report-artifacts.py" "$OPENSBI_BUG_JSON" --kind bug-report
    python3 "$ROOT_DIR/scripts/validate-report-artifacts.py" "$HOST_OUT_ROOT/cross-layer.json" --kind cross-layer
    python3 "$ROOT_DIR/scripts/validate-report-artifacts.py" "$HOST_OUT_ROOT/quality_gate.json" --kind quality-gate
}

require_smoke_inputs() {
    local required=(
        "$HOST_OUT_ROOT/logs/fuzz_ecall_opensbi.log"
        "$HOST_OUT_ROOT/logs/fuzz_ecall_rustsbi.log"
        "$HOST_OUT_ROOT/logs/fuzz_sequence_both.log"
        "$HOST_OUT_ROOT/logs/fuzz_diff_ecall.log"
        "$HOST_OUT_ROOT/logs/fuzz_diff_sequence.log"
        "$HOST_OUT_ROOT/fuzz_ecall_opensbi"
        "$HOST_OUT_ROOT/fuzz_ecall_rustsbi"
        "$HOST_OUT_ROOT/fuzz_sequence_both"
        "$HOST_OUT_ROOT/fuzz_diff_ecall"
        "$HOST_OUT_ROOT/fuzz_diff_sequence"
    )
    local missing=0
    for path in "${required[@]}"; do
        if [[ ! -e "$path" ]]; then
            echo "missing smoke artifact: $path" >&2
            missing=1
        fi
    done
    if [[ $missing -ne 0 ]]; then
        echo "run \`make smoke-all\` before \`make report-all\`" >&2
        exit 1
    fi
}

prepare_triage_parts_dir() {
    mkdir -p "$TRIAGE_PARTS_DIR"
    find "$TRIAGE_PARTS_DIR" -mindepth 1 -delete 2>/dev/null || true
}

generate_opensbi_bug_report() {
    python3 "$ROOT_DIR/scripts/host-triage-to-bug-report.py" \
        "$OPENSBI_TRIAGE_JSON" \
        --json-out "$OPENSBI_BUG_JSON" \
        --md-out "$OPENSBI_BUG_MD" \
        --label "OpenSBI Host" \
        > "$OPENSBI_BUG_STDOUT"
}

run_quality_gate() {
    local gate_rc=0
    set +e
    python3 "$ROOT_DIR/scripts/campaign-quality-gate.py" \
        --metrics "$HOST_OUT_ROOT/metrics.json" \
        --triage "$HOST_OUT_ROOT/triage.json" \
        --min-total-runs "${SBIFUZZ_REPORT_MIN_TOTAL_RUNS:-0}" \
        --min-confirmed-ratio "${SBIFUZZ_REPORT_MIN_CONFIRMED_RATIO:-0}" \
        --min-peak-exec-per-sec "${SBIFUZZ_REPORT_MIN_PEAK_EXEC_PER_SEC:-0}" \
        --min-new-events "${SBIFUZZ_REPORT_MIN_NEW_EVENTS:-0}" \
        --min-buckets "${SBIFUZZ_REPORT_MIN_BUCKETS:-0}" \
        --json-out "$HOST_OUT_ROOT/quality_gate.json" \
        > "$HOST_OUT_ROOT/quality_gate.stdout.json"
    gate_rc=$?
    set -e
    return "$gate_rc"
}

if [[ "$USE_FIXTURES" == "1" ]]; then
    mkdir -p "$HOST_OUT_ROOT"
    prepare_triage_parts_dir

    cp "$FIXTURE_ROOT/opensbi-host-triage.json" "$TRIAGE_PARTS_DIR/fuzz_ecall_opensbi.json"
    cp "$FIXTURE_ROOT/host-triage.json" "$TRIAGE_PARTS_DIR/fuzz_ecall_rustsbi.json"
    cp "$FIXTURE_ROOT/sequence-host-triage.json" "$TRIAGE_PARTS_DIR/fuzz_sequence_both.json"
    cp "$FIXTURE_ROOT/diff-ecall-host-triage.json" "$TRIAGE_PARTS_DIR/fuzz_diff_ecall.json"
    cp "$FIXTURE_ROOT/diff-sequence-host-triage.json" "$TRIAGE_PARTS_DIR/fuzz_diff_sequence.json"
    cp "$FIXTURE_ROOT/opensbi-host-triage.json" "$OPENSBI_TRIAGE_JSON"
    cat > "$OPENSBI_TRIAGE_MD" <<'EOF'
# OpenSBI Host Fuzz Triage

- Fixture OpenSBI host triage summary for deterministic S0 validation.
EOF
    python3 "$ROOT_DIR/scripts/merge-host-triage.py" \
        "$TRIAGE_PARTS_DIR/fuzz_ecall_opensbi.json" \
        "$TRIAGE_PARTS_DIR/fuzz_ecall_rustsbi.json" \
        "$TRIAGE_PARTS_DIR/fuzz_sequence_both.json" \
        "$TRIAGE_PARTS_DIR/fuzz_diff_ecall.json" \
        "$TRIAGE_PARTS_DIR/fuzz_diff_sequence.json" \
        --json-out "$HOST_OUT_ROOT/triage.json" \
        --md-out "$HOST_OUT_ROOT/triage.md" \
        > "$HOST_OUT_ROOT/triage.stdout.json"

    python3 "$ROOT_DIR/scripts/collect-metrics.py" --log-dir "$HOST_OUT_ROOT/logs" --json-out "$HOST_OUT_ROOT/metrics.json" > "$HOST_OUT_ROOT/metrics.stdout.json"
    generate_opensbi_bug_report
    python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" \
        "$HOST_OUT_ROOT/triage.json" \
        "$OPENSBI_BUG_JSON" \
        --json-out "$HOST_OUT_ROOT/cross-layer.json" \
        > "$HOST_OUT_ROOT/cross-layer.stdout.json"
    gate_rc=0
    run_quality_gate || gate_rc=$?
    validate_outputs
    exit "$gate_rc"
fi

require_smoke_inputs
prepare_triage_parts_dir

python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_ecall_rustsbi" \
    --all \
    --json-out "$TRIAGE_PARTS_DIR/fuzz_ecall_rustsbi.json" \
    --md-out "$TRIAGE_PARTS_DIR/fuzz_ecall_rustsbi.md" \
    > "$TRIAGE_PARTS_DIR/fuzz_ecall_rustsbi.stdout.json"
python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_ecall_opensbi" \
    --all \
    --json-out "$OPENSBI_TRIAGE_JSON" \
    --md-out "$OPENSBI_TRIAGE_MD" \
    > "$HOST_OUT_ROOT/opensbi.triage.stdout.json"
cp "$OPENSBI_TRIAGE_JSON" "$TRIAGE_PARTS_DIR/fuzz_ecall_opensbi.json"
cp "$OPENSBI_TRIAGE_MD" "$TRIAGE_PARTS_DIR/fuzz_ecall_opensbi.md"
python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_sequence_both" \
    --all \
    --json-out "$TRIAGE_PARTS_DIR/fuzz_sequence_both.json" \
    --md-out "$TRIAGE_PARTS_DIR/fuzz_sequence_both.md" \
    > "$TRIAGE_PARTS_DIR/fuzz_sequence_both.stdout.json"
python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_diff_ecall" \
    --all \
    --json-out "$TRIAGE_PARTS_DIR/fuzz_diff_ecall.json" \
    --md-out "$TRIAGE_PARTS_DIR/fuzz_diff_ecall.md" \
    > "$TRIAGE_PARTS_DIR/fuzz_diff_ecall.stdout.json"
python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_diff_sequence" \
    --all \
    --json-out "$TRIAGE_PARTS_DIR/fuzz_diff_sequence.json" \
    --md-out "$TRIAGE_PARTS_DIR/fuzz_diff_sequence.md" \
    > "$TRIAGE_PARTS_DIR/fuzz_diff_sequence.stdout.json"
python3 "$ROOT_DIR/scripts/merge-host-triage.py" \
    "$TRIAGE_PARTS_DIR/fuzz_ecall_opensbi.json" \
    "$TRIAGE_PARTS_DIR/fuzz_ecall_rustsbi.json" \
    "$TRIAGE_PARTS_DIR/fuzz_sequence_both.json" \
    "$TRIAGE_PARTS_DIR/fuzz_diff_ecall.json" \
    "$TRIAGE_PARTS_DIR/fuzz_diff_sequence.json" \
    --json-out "$HOST_OUT_ROOT/triage.json" \
    --md-out "$HOST_OUT_ROOT/triage.md" \
    > "$HOST_OUT_ROOT/triage.stdout.json"
python3 "$ROOT_DIR/scripts/collect-metrics.py" --log-dir "$HOST_OUT_ROOT/logs" --json-out "$HOST_OUT_ROOT/metrics.json" > "$HOST_OUT_ROOT/metrics.stdout.json"

generate_opensbi_bug_report
python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" \
    "$HOST_OUT_ROOT/triage.json" \
    "$OPENSBI_BUG_JSON" \
    --json-out "$HOST_OUT_ROOT/cross-layer.json" \
    > "$HOST_OUT_ROOT/cross-layer.stdout.json"
gate_rc=0
run_quality_gate || gate_rc=$?

validate_outputs
exit "$gate_rc"
