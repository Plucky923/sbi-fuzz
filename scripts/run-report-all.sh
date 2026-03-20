#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USE_FIXTURES="${SBIFUZZ_USE_FIXTURES:-0}"
HOST_OUT_ROOT="$ROOT_DIR/output/host_fuzz"
FIXTURE_ROOT="$ROOT_DIR/tests/fixtures/workflow"
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

generate_opensbi_bug_report() {
    python3 "$ROOT_DIR/scripts/host-triage-to-bug-report.py" \
        "$OPENSBI_TRIAGE_JSON" \
        --json-out "$OPENSBI_BUG_JSON" \
        --md-out "$OPENSBI_BUG_MD" \
        --label "OpenSBI Host" \
        > "$OPENSBI_BUG_STDOUT"
}

run_quality_gate() {
    python3 "$ROOT_DIR/scripts/campaign-quality-gate.py" \
        --metrics "$HOST_OUT_ROOT/metrics.json" \
        --triage "$HOST_OUT_ROOT/triage.json" \
        --min-total-runs "${SBIFUZZ_REPORT_MIN_TOTAL_RUNS:-0}" \
        --min-confirmed-ratio "${SBIFUZZ_REPORT_MIN_CONFIRMED_RATIO:-0}" \
        --json-out "$HOST_OUT_ROOT/quality_gate.json" \
        > "$HOST_OUT_ROOT/quality_gate.stdout.json"
}

if [[ "$USE_FIXTURES" == "1" ]]; then
    mkdir -p "$HOST_OUT_ROOT"

    cp "$FIXTURE_ROOT/host-triage.json" "$HOST_OUT_ROOT/triage.json"
    cp "$FIXTURE_ROOT/opensbi-host-triage.json" "$OPENSBI_TRIAGE_JSON"
    cat > "$HOST_OUT_ROOT/triage.md" <<'EOF'
# Host Fuzz Triage

- Fixture workflow triage summary for deterministic S0 validation.
EOF
    cat > "$OPENSBI_TRIAGE_MD" <<'EOF'
# OpenSBI Host Fuzz Triage

- Fixture OpenSBI host triage summary for deterministic S0 validation.
EOF

    python3 "$ROOT_DIR/scripts/collect-metrics.py" --log-dir "$HOST_OUT_ROOT/logs" --json-out "$HOST_OUT_ROOT/metrics.json" > "$HOST_OUT_ROOT/metrics.stdout.json"
    generate_opensbi_bug_report
    python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" \
        "$HOST_OUT_ROOT/triage.json" \
        "$OPENSBI_BUG_JSON" \
        --json-out "$HOST_OUT_ROOT/cross-layer.json" \
        > "$HOST_OUT_ROOT/cross-layer.stdout.json"
    run_quality_gate
    validate_outputs
    exit 0
fi

python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_ecall_rustsbi" \
    --all \
    --json-out "$HOST_OUT_ROOT/triage.json" \
    --md-out "$HOST_OUT_ROOT/triage.md"
python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_ecall_opensbi" \
    --all \
    --json-out "$OPENSBI_TRIAGE_JSON" \
    --md-out "$OPENSBI_TRIAGE_MD"
python3 "$ROOT_DIR/scripts/collect-metrics.py" --log-dir "$HOST_OUT_ROOT/logs" --json-out "$HOST_OUT_ROOT/metrics.json" > "$HOST_OUT_ROOT/metrics.stdout.json"

generate_opensbi_bug_report
python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" \
    "$HOST_OUT_ROOT/triage.json" \
    "$OPENSBI_BUG_JSON" \
    --json-out "$HOST_OUT_ROOT/cross-layer.json" \
    > "$HOST_OUT_ROOT/cross-layer.stdout.json"
run_quality_gate

validate_outputs
