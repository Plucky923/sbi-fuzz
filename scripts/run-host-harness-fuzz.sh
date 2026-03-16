#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_NAME="${1:-fuzz_ecall_rustsbi}"
shift || true

CORPUS_ROOT="${SBIFUZZ_CORPUS_ROOT:-$ROOT_DIR/host_harness/fuzz/corpus}"
OUT_ROOT="${SBIFUZZ_OUT_ROOT:-$ROOT_DIR/output/host_fuzz}"
LOG_DIR="$OUT_ROOT/logs"
TARGET_CORPUS="$CORPUS_ROOT/$TARGET_NAME"
TARGET_OUT="$OUT_ROOT/$TARGET_NAME"
DICT_PATH="$ROOT_DIR/host_harness/fuzz/dict/sbi.dict"
MAX_TOTAL_TIME="${SBIFUZZ_FUZZ_DURATION_SECS:-30}"
JOBS="${SBIFUZZ_FUZZ_JOBS:-1}"
WORKERS="${SBIFUZZ_FUZZ_WORKERS:-1}"
TIMEOUT_SECS="${SBIFUZZ_FUZZ_TIMEOUT_SECS:-5}"
MAX_LEN="${SBIFUZZ_MAX_LEN:-512}"
RSS_LIMIT_MB="${SBIFUZZ_RSS_LIMIT_MB:-4096}"
SEQUENCE_SMP="${SBIFUZZ_HOST_SEQUENCE_SMP:-4}"
LEAK_DETECT="${SBIFUZZ_HOST_FUZZ_DETECT_LEAKS:-0}"
LOG_PATH="$LOG_DIR/${TARGET_NAME}.log"

if [[ "$TARGET_NAME" == "fuzz_sequence_both" || "$TARGET_NAME" == "fuzz_diff_sequence" ]]; then
    MAX_LEN="${SBIFUZZ_MAX_LEN:-2048}"
fi

mkdir -p "$TARGET_CORPUS" "$TARGET_OUT" "$LOG_DIR"

"$ROOT_DIR/scripts/ensure-host-fuzz-toolchain.sh"
"$ROOT_DIR/scripts/prepare-host-fuzz-corpus.sh" "$CORPUS_ROOT"

export CC="${CC:-clang-18}"
export CXX="${CXX:-clang++-18}"
export SBIFUZZ_HOST_C_SANITIZERS="${SBIFUZZ_HOST_C_SANITIZERS:-address}"
export SBIFUZZ_HOST_SEQUENCE_SMP="$SEQUENCE_SMP"
# LeakSanitizer fatals under ptrace in this environment, which turns every
# libFuzzer run into a false crash. Keep leak detection disabled by default.
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=$LEAK_DETECT"

CMD=(
    cargo +nightly fuzz run "$TARGET_NAME"
    "$TARGET_CORPUS"
    --
    "-artifact_prefix=$TARGET_OUT/"
    "-max_total_time=$MAX_TOTAL_TIME"
    "-jobs=$JOBS"
    "-workers=$WORKERS"
    "-timeout=$TIMEOUT_SECS"
    "-rss_limit_mb=$RSS_LIMIT_MB"
    "-max_len=$MAX_LEN"
)

if [[ -f "$DICT_PATH" && "$TARGET_NAME" != "fuzz_harness_smoke" ]]; then
    CMD+=("-dict=$DICT_PATH")
fi

if [[ $# -gt 0 ]]; then
    CMD+=("$@")
fi

{
    echo "[$(date -Is)] target=$TARGET_NAME corpus=$TARGET_CORPUS artifacts=$TARGET_OUT jobs=$JOBS workers=$WORKERS max_total_time=$MAX_TOTAL_TIME sequence_smp=$SEQUENCE_SMP detect_leaks=$LEAK_DETECT"
    printf 'Command:'
    printf ' %q' "${CMD[@]}"
    printf '\n'
    (
        cd "$ROOT_DIR/host_harness/fuzz"
        "${CMD[@]}"
    )
} 2>&1 | tee "$LOG_PATH"
