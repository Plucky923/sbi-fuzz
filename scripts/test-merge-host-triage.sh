#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

legacy_json="$out_dir/legacy-triage.json"
cat > "$legacy_json" <<'JSON'
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
      "dedup_key": "rustsbi|0x10|0x0|crash|semantic:crash",
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

current_json="$out_dir/current-triage.json"
cat > "$current_json" <<'JSON'
{
  "schema_version": 1,
  "generated_at_utc": "2026-03-21T00:00:00Z",
  "report_type": "host_triage",
  "total_cases": 1,
  "by_target": {
    "rustsbi": 1
  },
  "by_violation_type": {
    "crash": 1
  },
  "results": [],
  "buckets": {
    "rustsbi|16|0|crash|semantic:crash": {
      "affected_target": "rustsbi",
      "classification": "crash",
      "count": 1,
      "dedup_key": "rustsbi|16|0|crash|semantic:crash",
      "eid": 16,
      "fid": 0,
      "first_seen": "2026-03-21T00:00:00Z",
      "hashes": ["crashseverity02"],
      "impact": "crash",
      "last_seen": "2026-03-21T00:00:00Z",
      "repro_stability": {
        "attempts": 2,
        "label": "stable_replay",
        "stable_ratio": 1.0
      },
      "reproducer": "fixture-crash-current.host",
      "target_kind": "rustsbi",
      "violation_detail": "semantic:crash",
      "violation_type": "crash"
    }
  }
}
JSON

json_out="$out_dir/merged.json"
python3 "$repo_root/scripts/merge-host-triage.py" "$legacy_json" "$current_json" --json-out "$json_out" >/dev/null
python3 "$repo_root/scripts/validate-report-artifacts.py" "$json_out" --kind host-triage >/dev/null
python3 - "$json_out" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["total_cases"] == 4, data
assert len(data["buckets"]) == 1, data
bucket = next(iter(data["buckets"].values()))
assert bucket["count"] == 4, bucket
assert bucket["impact"] == "crash", bucket
assert bucket["dedup_key"] == "rustsbi|16|0|crash|semantic:crash", bucket
assert bucket["hashes"] == ["crashseverity01", "crashseverity02"], bucket
assert bucket["repro_stability"]["label"] == "single_replay", bucket
assert bucket["first_seen"], bucket
assert bucket["last_seen"], bucket
assert bucket["first_seen"] <= bucket["last_seen"], bucket
PY

echo "merge host triage test passed"
