#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USE_FIXTURES="${SBIFUZZ_USE_FIXTURES:-0}"
SMOKE_ROOT="${SBIFUZZ_OUT_ROOT:-$ROOT_DIR/output/host_fuzz_smoke}"
HOST_OUT_ROOT="$ROOT_DIR/output/host_fuzz"

reset_dir() {
    local dir="$1"
    mkdir -p "$dir"
    find "$dir" -mindepth 1 -delete 2>/dev/null || true
}

if [[ "$USE_FIXTURES" == "1" ]]; then
    reset_dir "$SMOKE_ROOT"
    mkdir -p "$SMOKE_ROOT/logs" "$HOST_OUT_ROOT/logs"

    for target in fuzz_ecall_opensbi fuzz_ecall_rustsbi fuzz_sequence_both fuzz_diff_ecall fuzz_diff_sequence; do
        mkdir -p "$SMOKE_ROOT/$target"
        cat > "$SMOKE_ROOT/logs/$target.log" <<EOF
[fixture] target=$target mode=smoke
[fixture] artifact_root=$SMOKE_ROOT/$target
EOF
        printf 'fixture smoke artifact for %s\n' "$target" > "$SMOKE_ROOT/$target/fixture-artifact.txt"
    done

    cat > "$HOST_OUT_ROOT/logs/fuzz_ecall_rustsbi.log" <<'EOF'
[2026-03-20T00:00:00+00:00] target=fuzz_ecall_rustsbi corpus=fixture artifacts=output/host_fuzz/fuzz_ecall_rustsbi jobs=1 workers=1 max_total_time=10
#1 INITED cov: 10 ft: 10 corp: 1/1b exec/s: 50 rss: 100Mb
#2 NEW cov: 11 ft: 11 corp: 2/2b exec/s: 55 rss: 110Mb
Done 1500 runs in 30 second(s)
EOF

    echo "Fixture smoke completed. Logs: $SMOKE_ROOT/logs"
    exit 0
fi

"$ROOT_DIR/scripts/prepare-host-fuzz-corpus.sh"
"$ROOT_DIR/scripts/smoke-host-harness-fuzz.sh"
