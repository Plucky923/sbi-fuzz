#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

triage_json="$out_dir/triage.json"
cat > "$triage_json" <<'JSON'
{
  "buckets": {
    "opensbi|16|0|spec_violation|semantic:base": {
      "affected_target": "opensbi",
      "bug_id": "bug-host-bucket",
      "classification": "spec_violation",
      "count": 3,
      "dedup_key": "opensbi|16|0|spec_violation|semantic:base",
      "eid": 16,
      "fid": 0,
      "first_seen": "2026-03-20T00:00:00Z",
      "impact": "spec_violation",
      "last_seen": "2026-03-20T00:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      },
      "reproducer": "fixture-base.host",
      "target_kind": "opensbi",
      "violation_detail": "semantic:base",
      "violation_type": "spec_violation"
    }
  },
  "generated_at_utc": "2026-03-20T00:00:00Z",
  "report_type": "host_triage",
  "schema_version": 1,
  "total_cases": 3
}
JSON

json_out="$out_dir/bugs.json"
python3 "$repo_root/scripts/host-triage-to-bug-report.py" "$triage_json" --json-out "$json_out" >/dev/null
rg -n '"candidate_count": 3' "$json_out" >/dev/null
rg -n '"spec_violation": 3' "$json_out" >/dev/null
rg -n '"opensbi\|16\|0\|spec_violation\|semantic:base": 3' "$json_out" >/dev/null

echo "host triage to bug report test passed"
