#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$repo_root/output/host_fuzz" "$repo_root/output/host_fuzz_smoke"
find "$repo_root/output/host_fuzz" -mindepth 1 -delete 2>/dev/null || true
find "$repo_root/output/host_fuzz_smoke" -mindepth 1 -delete 2>/dev/null || true

SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" preflight
SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" smoke-all
SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" report-all

test -f "$repo_root/output/host_fuzz/logs/fuzz_ecall_opensbi.log"
test -f "$repo_root/output/host_fuzz/logs/fuzz_ecall_rustsbi.log"
test -f "$repo_root/output/host_fuzz/logs/fuzz_sequence_both.log"
test -f "$repo_root/output/host_fuzz/logs/fuzz_diff_ecall.log"
test -f "$repo_root/output/host_fuzz/logs/fuzz_diff_sequence.log"
test -f "$repo_root/output/host_fuzz/triage.json"
test -f "$repo_root/output/host_fuzz/triage.md"
test -f "$repo_root/output/host_fuzz/opensbi.triage.json"
test -f "$repo_root/output/host_fuzz/opensbi.triage.md"
test -f "$repo_root/output/host_fuzz/metrics.json"
test -f "$repo_root/output/host_fuzz/opensbi.bugs.json"
test -f "$repo_root/output/host_fuzz/opensbi.bugs.md"
test -f "$repo_root/output/host_fuzz/cross-layer.json"
test -f "$repo_root/output/host_fuzz/quality_gate.json"

python3 "$repo_root/scripts/validate-report-artifacts.py" "$repo_root/output/host_fuzz/triage.json" --kind host-triage >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$repo_root/output/host_fuzz/opensbi.bugs.json" --kind bug-report >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$repo_root/output/host_fuzz/cross-layer.json" --kind cross-layer >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$repo_root/output/host_fuzz/quality_gate.json" --kind quality-gate >/dev/null

echo "s0 workflow test passed"
