#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
s0_root="$repo_root/output/host_fuzz_smoke"
fixture_json="$repo_root/tests/fixtures/workflow/opensbi-host-triage.json"
fixture_backup="$(mktemp)"

cp "$fixture_json" "$fixture_backup"
cleanup() {
    cp "$fixture_backup" "$fixture_json"
    rm -f "$fixture_backup"
}
trap cleanup EXIT

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

python3 - "$fixture_json" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, "r", encoding="utf-8"))
bucket = next(iter(data["buckets"].values()))
bucket["classification"] = "crash"
bucket["impact"] = "crash"
bucket["violation_type"] = "crash"
bucket["dedup_key"] = "opensbi|16|0|crash|semantic:hart0:raw->base_get_spec_version"
json.dump(data, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)
open(path, "a", encoding="utf-8").write("\n")
PY

SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" smoke-all >/dev/null
set +e
SBIFUZZ_USE_FIXTURES=1 make -C "$repo_root" report-all >/dev/null
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "report-all unexpectedly passed despite a crash-like fixture finding" >&2
    exit 1
fi

python3 "$repo_root/scripts/validate-report-artifacts.py" "$s0_root/quality_gate.json" --kind quality-gate >/dev/null
rg -n '"code": "new_high_severity_bugs"' "$s0_root/quality_gate.json" >/dev/null

echo "s0 workflow test passed"
