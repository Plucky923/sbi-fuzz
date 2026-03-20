#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
s0_root="$repo_root/output/host_fuzz_smoke"

mkdir -p "$repo_root/output/host_fuzz" "$repo_root/output/host_fuzz_smoke"
find "$repo_root/output/host_fuzz" -mindepth 1 -delete 2>/dev/null || true
find "$repo_root/output/host_fuzz_smoke" -mindepth 1 -delete 2>/dev/null || true

SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" preflight
SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" smoke-all
printf 'sentinel\n' > "$s0_root/logs/report-all-preserves-smoke.log"
SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" report-all

test -f "$s0_root/logs/fuzz_ecall_opensbi.log"
test -f "$s0_root/logs/fuzz_ecall_rustsbi.log"
test -f "$s0_root/logs/fuzz_sequence_both.log"
test -f "$s0_root/logs/fuzz_diff_ecall.log"
test -f "$s0_root/logs/fuzz_diff_sequence.log"
test -f "$s0_root/logs/report-all-preserves-smoke.log"
test -f "$s0_root/triage.json"
test -f "$s0_root/triage.md"
test -f "$s0_root/triage-parts/fuzz_diff_sequence.json"
test -f "$s0_root/opensbi.triage.json"
test -f "$s0_root/opensbi.triage.md"
test -f "$s0_root/metrics.json"
test -f "$s0_root/opensbi.bugs.json"
test -f "$s0_root/opensbi.bugs.md"
test -f "$s0_root/cross-layer.json"
test -f "$s0_root/quality_gate.json"

python3 "$repo_root/scripts/validate-report-artifacts.py" "$s0_root/triage.json" --kind host-triage >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$s0_root/opensbi.bugs.json" --kind bug-report >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$s0_root/cross-layer.json" --kind cross-layer >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$s0_root/quality_gate.json" --kind quality-gate >/dev/null
rg -n '"total_cases": 6' "$s0_root/triage.json" >/dev/null

echo "s0 workflow test passed"
