#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp_dir=$(mktemp -d /tmp/sbifuzz-quality-gate-XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT

metrics_json="$tmp_dir/metrics.json"
triage_json="$tmp_dir/triage.json"
pass_json="$tmp_dir/pass.json"
fail_json="$tmp_dir/fail.json"

cat >"$metrics_json" <<'EOF'
{
  "targets": {
    "fuzz_ecall_rustsbi": {
      "peak_exec_per_sec": 6400,
      "total_runs": 1200,
      "new_events": 3,
      "crash_artifacts": 1,
      "last": {
        "coverage": 77
      }
    },
    "fuzz_diff_ecall": {
      "peak_exec_per_sec": 3100,
      "total_runs": 800,
      "new_events": 1,
      "crash_artifacts": 0,
      "last": {
        "coverage": 51
      }
    }
  }
}
EOF

cat >"$triage_json" <<'EOF'
{
  "total_cases": 3,
  "results": [
    { "confirmed": true },
    { "confirmed": true },
    { "confirmed": false }
  ],
  "buckets": {
    "bucket-a": {},
    "bucket-b": {}
  },
  "by_violation_type": {
    "spec_violation": 2,
    "memory_violation": 1
  }
}
EOF

python3 "$repo_root/scripts/campaign-quality-gate.py" \
  --metrics "$metrics_json" \
  --triage "$triage_json" \
  --json-out "$pass_json"

rg -n '"status": "pass"' "$pass_json" >/dev/null
rg -n '"total_runs": 2000' "$pass_json" >/dev/null
rg -n '"actual": 0.6667' "$pass_json" >/dev/null

set +e
python3 "$repo_root/scripts/campaign-quality-gate.py" \
  --metrics "$metrics_json" \
  --triage "$triage_json" \
  --json-out "$fail_json" \
  --min-total-runs 3000
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  echo "quality gate unexpectedly passed strict threshold" >&2
  exit 1
fi

rg -n '"status": "fail"' "$fail_json" >/dev/null
rg -n '"threshold": 3000' "$fail_json" >/dev/null

echo "campaign quality gate test passed"
