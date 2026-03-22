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
    "rustsbi|0x10|0x0|crash|same-root-cause": {
      "affected_target": "rustsbi",
      "bug_id": "bug-host",
      "classification": "crash",
      "dedup_key": "rustsbi|16|0|crash|same-root-cause",
      "eid": 16,
      "fid": 0,
      "first_seen": "2026-03-20T00:00:00Z",
      "impact": "crash",
      "last_seen": "2026-03-20T00:00:00Z",
      "reproducer": "host-case.host",
      "violation_detail": "same-root-cause",
      "violation_type": "crash",
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
      "signature": "same-root-cause",
      "raw_signature": "same-root-cause",
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

python3 - "$json_out" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["schema_version"] == 1, data
assert data["report_type"] == "cross_layer_dedup", data
assert data["total_unique"] == 2, data

rustsbi_bug = None
for bug in data["bugs"].values():
    if bug["affected_target"] == "rustsbi":
        rustsbi_bug = bug
        break

assert rustsbi_bug is not None, data
assert rustsbi_bug["count"] == 2, rustsbi_bug
assert sorted(rustsbi_bug["sources"]) == ["bugs", "host-triage"], rustsbi_bug
assert "host-case.host" in rustsbi_bug["reproducers"], rustsbi_bug
assert "system-case.exec" in rustsbi_bug["reproducers"], rustsbi_bug
assert rustsbi_bug["bug_id"] not in {"bug-host", "bug-system"}, rustsbi_bug
PY

single_json="$out_dir/cross-layer-single.json"
python3 "$repo_root/scripts/cross-layer-dedup.py" "$host_json" --json-out "$single_json" > "$out_dir/stdout-single.json"
rg -n '"total_unique": 1' "$single_json" >/dev/null

echo "cross-layer dedup test passed"
