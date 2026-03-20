#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USE_FIXTURES="${SBIFUZZ_USE_FIXTURES:-0}"
HOST_OUT_ROOT="$ROOT_DIR/output/host_fuzz"
FIXTURE_ROOT="$ROOT_DIR/tests/fixtures/workflow"
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
    python3 "$ROOT_DIR/scripts/report-opensbi-bugs.py" \
        "$FIXTURE_ROOT/opensbi-replay.json" \
        --hang-stability "$FIXTURE_ROOT/opensbi-hang-stability.json" \
        --hang-minimize "$FIXTURE_ROOT/opensbi-hang-minimize.json" \
        --json-out "$OPENSBI_BUG_JSON" \
        --md-out "$OPENSBI_BUG_MD" \
        > "$OPENSBI_BUG_STDOUT"
}

if [[ "$USE_FIXTURES" == "1" ]]; then
    mkdir -p "$HOST_OUT_ROOT"

    cp "$FIXTURE_ROOT/host-triage.json" "$HOST_OUT_ROOT/triage.json"
    cat > "$HOST_OUT_ROOT/triage.md" <<'EOF'
# Host Fuzz Triage

- Fixture workflow triage summary for deterministic S0 validation.
EOF

    python3 "$ROOT_DIR/scripts/collect-metrics.py" --log-dir "$HOST_OUT_ROOT/logs" --json-out "$HOST_OUT_ROOT/metrics.json" > "$HOST_OUT_ROOT/metrics.stdout.json"
    generate_opensbi_bug_report
    python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" \
        "$HOST_OUT_ROOT/triage.json" \
        "$OPENSBI_BUG_JSON" \
        --json-out "$HOST_OUT_ROOT/cross-layer.json" \
        > "$HOST_OUT_ROOT/cross-layer.stdout.json"
    python3 "$ROOT_DIR/scripts/campaign-quality-gate.py" \
        --metrics "$HOST_OUT_ROOT/metrics.json" \
        --triage "$HOST_OUT_ROOT/triage.json" \
        --json-out "$HOST_OUT_ROOT/quality_gate.json" \
        > "$HOST_OUT_ROOT/quality_gate.stdout.json"
    validate_outputs
    exit 0
fi

python3 "$ROOT_DIR/scripts/triage-host-fuzz-results.py" \
    "$ROOT_DIR/output/host_fuzz/fuzz_ecall_rustsbi" \
    --json-out "$HOST_OUT_ROOT/triage.json" \
    --md-out "$HOST_OUT_ROOT/triage.md"
python3 "$ROOT_DIR/scripts/collect-metrics.py" --log-dir "$HOST_OUT_ROOT/logs" --json-out "$HOST_OUT_ROOT/metrics.json" > "$HOST_OUT_ROOT/metrics.stdout.json"

make -C "$ROOT_DIR/playground/opensbi-fuzz" bug-report
cp "$ROOT_DIR/playground/opensbi-fuzz/output/bugs/result.bugs.json" "$OPENSBI_BUG_JSON"
cp "$ROOT_DIR/playground/opensbi-fuzz/output/bugs/result.bugs.md" "$OPENSBI_BUG_MD"
cp "$ROOT_DIR/playground/opensbi-fuzz/output/bugs/result.bugs.stdout.json" "$OPENSBI_BUG_STDOUT"

python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" \
    "$HOST_OUT_ROOT/triage.json" \
    "$OPENSBI_BUG_JSON" \
    --json-out "$HOST_OUT_ROOT/cross-layer.json" \
    > "$HOST_OUT_ROOT/cross-layer.stdout.json"
python3 "$ROOT_DIR/scripts/campaign-quality-gate.py" \
    --metrics "$HOST_OUT_ROOT/metrics.json" \
    --triage "$HOST_OUT_ROOT/triage.json" \
    --json-out "$HOST_OUT_ROOT/quality_gate.json" \
    > "$HOST_OUT_ROOT/quality_gate.stdout.json"

validate_outputs
