#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_OUT="${1:?usage: run-host-harness-overnight.sh <base-out> [duration-secs] [target ...]}"
DURATION_SECS="${2:-36000}"
shift 2 || true
if [[ $# -gt 0 ]]; then
    TARGETS=("$@")
else
    TARGETS=(
        fuzz_ecall_opensbi
        fuzz_ecall_rustsbi
        fuzz_sequence_both
        fuzz_diff_ecall
        fuzz_diff_sequence
    )
fi

mkdir -p "$BASE_OUT"
END_TS=$(( $(date +%s) + DURATION_SECS ))
ITER=0

echo "base_out=$BASE_OUT" | tee -a "$BASE_OUT/supervisor.log"
echo "targets=${TARGETS[*]}" | tee -a "$BASE_OUT/supervisor.log"
echo "duration_secs=$DURATION_SECS" | tee -a "$BASE_OUT/supervisor.log"
echo "end_ts=$END_TS" | tee -a "$BASE_OUT/supervisor.log"

while [[ $(date +%s) -lt "$END_TS" ]]; do
    ITER=$((ITER + 1))
    OUT_ROOT="$BASE_OUT/iter_$ITER"
    mkdir -p "$OUT_ROOT"
    echo "=== iteration=$ITER start=$(date -Is) out_root=$OUT_ROOT ===" | tee -a "$BASE_OUT/supervisor.log"

    for TARGET_NAME in "${TARGETS[@]}"; do
        if [[ $(date +%s) -ge "$END_TS" ]]; then
            break
        fi

        TARGET_OUT="$OUT_ROOT/$TARGET_NAME"
        mkdir -p "$TARGET_OUT"
        echo "--- iteration=$ITER target=$TARGET_NAME start=$(date -Is) ---" | tee -a "$BASE_OUT/supervisor.log"

        MAX_LEN=512
        SEQUENCE_SMP=4
        if [[ "$TARGET_NAME" == "fuzz_sequence_both" || "$TARGET_NAME" == "fuzz_diff_sequence" ]]; then
            MAX_LEN=4096
            SEQUENCE_SMP=60
        fi

        set +e
        env \
            SBIFUZZ_OUT_ROOT="$TARGET_OUT" \
            SBIFUZZ_FUZZ_JOBS=60 \
            SBIFUZZ_FUZZ_WORKERS=60 \
            SBIFUZZ_FUZZ_DURATION_SECS=600 \
            SBIFUZZ_HOST_SEQUENCE_SMP="$SEQUENCE_SMP" \
            SBIFUZZ_MAX_LEN="$MAX_LEN" \
            "$ROOT_DIR/scripts/run-host-harness-fuzz.sh" "$TARGET_NAME" \
            -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1 \
            >> "$BASE_OUT/supervisor.log" 2>&1
        RC=$?
        set -e

        echo "--- iteration=$ITER target=$TARGET_NAME end=$(date -Is) rc=$RC ---" | tee -a "$BASE_OUT/supervisor.log"
        sleep 5
    done

    echo "=== iteration=$ITER end=$(date -Is) ===" | tee -a "$BASE_OUT/supervisor.log"
    sleep 5
done
