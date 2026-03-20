#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

host_json="$out_dir/host-triage.json"
cat > "$host_json" <<'JSON'
{
  "schema_version": 1,
  "generated_at_utc": "2026-03-20T00:00:00Z",
  "report_type": "host_triage",
  "buckets": {
    "rustsbi|0x10|0x0|memory_violation|same-root-cause": {
      "affected_target": "rustsbi",
      "bug_id": "bug-host",
      "classification": "crash",
      "dedup_key": "rustsbi|crash|semantic:same-root-cause",
      "eid": "0x10",
      "fid": "0x0",
      "first_seen": "2026-03-20T00:00:00Z",
      "impact": "crash",
      "last_seen": "2026-03-20T00:00:00Z",
      "reproducer": "host-case.host",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      }
    }
  }
}
JSON

bug_json="$out_dir/bugs.json"
cat > "$bug_json" <<'JSON'
{
  "schema_version": 1,
  "generated_at_utc": "2026-03-20T01:00:00Z",
  "report_type": "bug_report",
  "buckets": {
    "crash|semantic:same-root-cause": {
      "affected_target": "rustsbi",
      "bug_id": "bug-system",
      "classification": "crash",
      "count": 1,
      "dedup_key": "rustsbi|crash|semantic:same-root-cause",
      "eid": "0x10",
      "fid": "0x0",
      "first_seen": "2026-03-20T01:00:00Z",
      "impact": "crash",
      "input": "system-case.exec",
      "last_seen": "2026-03-20T01:00:00Z",
      "repro_stability": {
        "attempts": 1,
        "label": "single_replay",
        "stable_ratio": 1.0
      }
    },
    "hang|semantic:other-root-cause": {
      "affected_target": "opensbi",
      "bug_id": "bug-other",
      "classification": "hang",
      "count": 1,
      "dedup_key": "opensbi|hang|semantic:other-root-cause",
      "eid": "0x20",
      "fid": "0x0",
      "first_seen": "2026-03-20T01:00:00Z",
      "impact": "hang",
      "input": "other-case.exec",
      "last_seen": "2026-03-20T01:00:00Z",
      "repro_stability": {
        "attempts": 3,
        "label": "stable_hang",
        "stable_ratio": 1.0
      }
    }
  }
}
JSON

json_out="$out_dir/cross-layer.json"
python3 "$repo_root/scripts/cross-layer-dedup.py" "$host_json" "$bug_json" --json-out "$json_out" > "$out_dir/stdout.json"

rg -n '"schema_version": 1' "$json_out" >/dev/null
rg -n '"report_type": "cross_layer_dedup"' "$json_out" >/dev/null
rg -n '"total_unique": 2' "$json_out" >/dev/null
rg -n '"affected_target": "rustsbi"' "$json_out" >/dev/null
rg -n '"sources": \[' "$json_out" >/dev/null
rg -n '"host-triage"' "$json_out" >/dev/null
rg -n '"bugs"' "$json_out" >/dev/null
rg -n '"system-case.exec"' "$json_out" >/dev/null
rg -n '"host-case.host"' "$json_out" >/dev/null

echo "cross-layer dedup test passed"
