#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

metrics_json="$out_dir/metrics.json"
cat > "$metrics_json" <<'JSON'
{
  "targets": {
    "fuzz_ecall_rustsbi": {
      "crash_artifacts": 0,
      "duration_secs": 30,
      "last": {
        "coverage": 123,
        "exec_per_sec": 99
      },
      "new_events": 3,
      "peak_exec_per_sec": 99,
      "total_runs": 5000
    }
  }
}
JSON

previous_triage_json="$out_dir/previous-triage.json"
cat > "$previous_triage_json" <<'JSON'
{
  "schema_version": 1,
  "generated_at_utc": "2026-03-20T00:00:00Z",
  "report_type": "host_triage",
  "total_cases": 1,
  "results": [
    {
      "confirmed": true
    }
  ],
  "by_violation_type": {
    "memory_violation": 1
  },
  "buckets": {
    "rustsbi|0x10|0x0|memory_violation|old": {
      "affected_target": "rustsbi",
      "classification": "crash",
      "dedup_key": "rustsbi|0x10|0x0|memory_violation|old",
      "first_seen": "2026-03-19T00:00:00Z",
      "impact": "crash",
      "last_seen": "2026-03-19T00:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      }
    }
  }
}
JSON

triage_json="$out_dir/triage.json"
cat > "$triage_json" <<'JSON'
{
  "schema_version": 1,
  "generated_at_utc": "2026-03-20T01:00:00Z",
  "report_type": "host_triage",
  "total_cases": 4,
  "results": [
    {
      "confirmed": true
    },
    {
      "confirmed": true
    },
    {
      "confirmed": true
    },
    {
      "confirmed": true
    }
  ],
  "by_violation_type": {
    "hang": 1,
    "memory_violation": 2,
    "spec_violation": 1
  },
  "buckets": {
    "rustsbi|0x10|0x0|memory_violation|old": {
      "affected_target": "rustsbi",
      "classification": "crash",
      "dedup_key": "rustsbi|16|0|memory_violation|old",
      "first_seen": "2026-03-19T00:00:00Z",
      "impact": "crash",
      "last_seen": "2026-03-20T01:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      }
    },
    "rustsbi|0x10|0x1|memory_violation|new": {
      "affected_target": "rustsbi",
      "bug_id": "bug-new-crash",
      "classification": "crash",
      "dedup_key": "rustsbi|0x10|0x1|memory_violation|new",
      "first_seen": "2026-03-20T01:00:00Z",
      "impact": "crash",
      "last_seen": "2026-03-20T01:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      }
    },
    "rustsbi|0x10|0x2|spec_violation|reopened": {
      "affected_target": "rustsbi",
      "classification": "spec_violation",
      "dedup_key": "rustsbi|0x10|0x2|spec_violation|reopened",
      "eid": "0x10",
      "fid": "0x2",
      "first_seen": "2026-03-18T00:00:00Z",
      "impact": "spec_violation",
      "last_seen": "2026-03-20T01:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      },
      "signature": "reopened"
    },
    "rustsbi|0x10|0x3|hang|slow": {
      "affected_target": "rustsbi",
      "bug_id": "bug-hang",
      "classification": "hang",
      "dedup_key": "rustsbi|0x10|0x3|hang|slow",
      "first_seen": "2026-03-20T01:00:00Z",
      "impact": "hang",
      "last_seen": "2026-03-20T01:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      }
    }
  }
}
JSON

closed_json="$out_dir/closed.json"
cat > "$closed_json" <<'JSON'
{
  "buckets": {
    "closed-bucket": {
      "affected_target": "rustsbi",
      "classification": "spec_violation",
      "eid": "0x10",
      "fid": "0x2",
      "signature": "reopened"
    }
  },
  "candidate_count": 1,
  "generated_at_utc": "2026-03-19T00:00:00Z",
  "report_type": "bug_report",
  "schema_version": 1,
  "total_results": 1
}
JSON

gate_json="$out_dir/quality-gate.json"
set +e
python3 "$repo_root/scripts/campaign-quality-gate.py" \
  --metrics "$metrics_json" \
  --triage "$triage_json" \
  --previous-triage "$previous_triage_json" \
  --closed-bugs "$closed_json" \
  --max-hang-bucket-ratio 0.2 \
  --json-out "$gate_json" > "$out_dir/stdout.json"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "quality gate unexpectedly passed despite blockers" >&2
    exit 1
fi

python3 "$repo_root/scripts/validate-report-artifacts.py" "$gate_json" --kind quality-gate >/dev/null

rg -n '"status": "fail"' "$gate_json" >/dev/null
rg -n '"code": "new_high_severity_bugs"' "$gate_json" >/dev/null
rg -n '"code": "reopened_bugs"' "$gate_json" >/dev/null
rg -n '"bug-.*"' "$gate_json" >/dev/null
rg -n '"code": "high_hang_bucket_ratio"' "$gate_json" >/dev/null
python3 - "$gate_json" <<'PY'
import json
import sys

report = json.loads(open(sys.argv[1]).read())
for blocker in report["blockers"]:
    if blocker["code"] == "new_high_severity_bugs":
        assert blocker["bug_ids"] == ["bug-new-crash"], blocker
        break
else:
    raise AssertionError("new_high_severity_bugs blocker missing")
PY

echo "campaign quality gate test passed"
