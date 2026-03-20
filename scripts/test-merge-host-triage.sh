#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

input_json="$out_dir/triage.json"
cat > "$input_json" <<'JSON'
{
  "schema_version": 1,
  "generated_at_utc": "2026-03-20T00:00:00Z",
  "report_type": "host_triage",
  "total_cases": 1,
  "by_target": {
    "rustsbi": 1
  },
  "by_violation_type": {
    "spec_violation": 1
  },
  "results": [
    {
      "affected_target": "rustsbi",
      "bug_id": "bug-crash-severity",
      "classification": "crash",
      "confirmed": true,
      "dedup_key": "rustsbi|0x10|0x0|crash|semantic:crash",
      "eid": "0x10",
      "fid": "0x0",
      "first_seen": "2026-03-20T00:00:00Z",
      "hash": "crashseverity01",
      "impact": "spec_violation",
      "last_seen": "2026-03-20T00:00:00Z",
      "path": "fixture-crash.host",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      },
      "target_kind": "rustsbi",
      "violation_detail": "semantic:crash",
      "violation_type": "spec_violation"
    }
  ],
  "buckets": {}
}
JSON

json_out="$out_dir/merged.json"
python3 "$repo_root/scripts/merge-host-triage.py" "$input_json" --json-out "$json_out" >/dev/null
rg -n '"impact": "crash"' "$json_out" >/dev/null

echo "merge host triage test passed"
