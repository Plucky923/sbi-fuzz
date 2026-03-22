#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

log_dir="$out_dir/logs"
metrics_json="$out_dir/metrics.json"
triage_json="$out_dir/triage.json"
cross_json="$out_dir/cross.json"
summary_json="$out_dir/summary.json"

mkdir -p "$log_dir"

cat >"$log_dir/fuzz_ecall_rustsbi.log" <<'EOF'
#1 INITED cov: 10 ft: 20 corp: 1/1Kb exec/s: 100 rss: 64Mb
#20 NEW cov: 11 ft: 21 corp: 2/2Kb exec/s: 200 rss: 65Mb
Test unit written to ./crash-123
Done 100 runs in 5 second(s)
EOF

cat >"$metrics_json" <<'EOF'
{}
EOF

cat >"$triage_json" <<'EOF'
{
  "results": [
    { "confirmed": true },
    { "confirmed": false },
    { "confirmed": true }
  ],
  "buckets": {
    "a": {},
    "b": {}
  },
  "by_violation_type": {
    "spec_violation": 2,
    "memory_violation": 1
  }
}
EOF

cat >"$cross_json" <<'EOF'
{
  "total_unique": 3,
  "bugs": {
    "bug-a": { "sources": ["host", "sequence"] },
    "bug-b": { "sources": ["host"] },
    "bug-c": { "sources": ["host", "qemu"] }
  }
}
EOF

python3 "$repo_root/scripts/collect-metrics.py" \
  --log-dir "$log_dir" \
  --triage-json "$triage_json" \
  --cross-layer-json "$cross_json" \
  --json-out "$summary_json" >/dev/null

python3 - "$summary_json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
target = data["targets"]["fuzz_ecall_rustsbi"]
assert target["peak_exec_per_sec"] == 200, target
assert target["total_runs"] == 100, target
assert target["estimated_time_to_first_new_secs"] == 1.0, target
assert target["estimated_time_to_first_crash_secs"] == 1.0, target

triage = data["triage"]
assert triage["confirmed_cases"] == 2, triage
assert triage["confirmed_ratio"] == 0.6667, triage
assert triage["unique_violation_types"] == 2, triage

cross = data["cross_layer"]
assert cross["cross_layer_confirmed"] == 2, cross
assert cross["cross_layer_confirmation_rate"] == 0.6667, cross
assert cross["single_layer_only"] == 1, cross
PY

echo "collect metrics test passed"
