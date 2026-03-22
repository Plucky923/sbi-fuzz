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
  "total_cases": 3,
  "by_target": {
    "rustsbi": 3
  },
  "by_violation_type": {
    "spec_violation": 3
  },
  "results": [],
  "buckets": {
    "rustsbi|0x10|0x0|crash|semantic:crash": {
      "affected_target": "rustsbi",
      "bug_id": "bug-crash-severity",
      "classification": "crash",
      "count": 3,
      "dedup_key": null,
      "eid": "0x10",
      "fid": "0x0",
      "first_seen": null,
      "hashes": ["crashseverity01"],
      "impact": "spec_violation",
      "last_seen": null,
      "repro_stability": null,
      "reproducer": "fixture-crash.host",
      "target_kind": "rustsbi",
      "violation_detail": "semantic:crash",
      "violation_type": "spec_violation"
    }
  }
}
JSON

json_out="$out_dir/merged.json"
python3 "$repo_root/scripts/merge-host-triage.py" "$input_json" --json-out "$json_out" >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$json_out" --kind host-triage >/dev/null
rg -n '"impact": "crash"' "$json_out" >/dev/null
rg -n '"confirmed": true' "$json_out" >/dev/null
rg -n '"count": 3' "$json_out" >/dev/null
rg -n '"total_cases": 3' "$json_out" >/dev/null
rg -n '"dedup_key": "rustsbi\|16\|0\|spec_violation\|semantic:crash"' "$json_out" >/dev/null
! rg -n '"repro_stability": null' "$json_out" >/dev/null
! rg -n '"first_seen": null' "$json_out" >/dev/null
! rg -n '"last_seen": null' "$json_out" >/dev/null

echo "merge host triage test passed"
