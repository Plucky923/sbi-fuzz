#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cp "$repo_root/Makefile" "$tmp_dir/Makefile"
cp -R "$repo_root/scripts" "$tmp_dir/scripts"

mkdir -p "$tmp_dir/output/host_fuzz/logs"

cat >"$tmp_dir/output/host_fuzz/logs/fuzz_ecall_rustsbi.log" <<'EOF'
#1 INITED cov: 10 ft: 20 corp: 1/1Kb exec/s: 100 rss: 64Mb
#20 NEW cov: 11 ft: 21 corp: 2/2Kb exec/s: 200 rss: 65Mb
Test unit written to ./crash-123
Done 100 runs in 5 second(s)
EOF

cat >"$tmp_dir/output/host_fuzz/triage.json" <<'JSON'
{
  "results": [
    { "confirmed": true }
  ],
  "buckets": {
    "a": {}
  },
  "by_violation_type": {
    "spec_violation": 1
  }
}
JSON

cat >"$tmp_dir/output/host_fuzz/cross-layer.json" <<'JSON'
{
  "total_unique": 1,
  "bugs": {
    "bug-a": { "sources": ["host", "sequence"] }
  }
}
JSON

make -C "$tmp_dir" collect-metrics >/dev/null

python3 - "$tmp_dir/output/host_fuzz/metrics.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["triage"]["confirmed_cases"] == 1, data
assert data["cross_layer"]["cross_layer_confirmed"] == 1, data
PY

echo "default collect metrics test passed"
