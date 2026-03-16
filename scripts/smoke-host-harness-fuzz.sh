#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${SBIFUZZ_OUT_ROOT:-$ROOT_DIR/output/host_fuzz_smoke}"
export SBIFUZZ_OUT_ROOT="$OUT_ROOT"
export SBIFUZZ_FUZZ_JOBS="${SBIFUZZ_FUZZ_JOBS:-1}"
export SBIFUZZ_FUZZ_WORKERS="${SBIFUZZ_FUZZ_WORKERS:-1}"

rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT"

set +e
SBIFUZZ_FUZZ_DURATION_SECS=1 "$ROOT_DIR/scripts/run-host-harness-fuzz.sh" fuzz_harness_smoke -runs=1
SMOKE_RC=$?
set -e

if [[ $SMOKE_RC -eq 0 ]]; then
    echo "intentional smoke crash did not trigger" >&2
    exit 1
fi

run_target_smoke() {
    local target="$1"
    local target_out="$OUT_ROOT/$target"
    set +e
    SBIFUZZ_FUZZ_DURATION_SECS="${SBIFUZZ_SMOKE_DURATION_SECS:-10}" \
        "$ROOT_DIR/scripts/run-host-harness-fuzz.sh" "$target"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        return 0
    fi
    if find "$target_out" -maxdepth 1 -type f \( -name 'crash-*' -o -name 'timeout-*' -o -name 'leak-*' \) | grep -q .; then
        echo "smoke note: $target reported a finding and wrote an artifact; treating as infrastructure success" >&2
        return 0
    fi
    echo "smoke failure: $target exited with $rc and produced no artifact" >&2
    return "$rc"
}

for target in fuzz_ecall_opensbi fuzz_ecall_rustsbi fuzz_sequence_both fuzz_diff_ecall fuzz_diff_sequence; do
    run_target_smoke "$target"
done

echo "Host fuzz smoke completed. Logs: $OUT_ROOT/logs"
