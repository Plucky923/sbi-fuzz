#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

host_json="$out_dir/host.json"
sequence_json="$out_dir/sequence.json"
dedup_json="$out_dir/dedup.json"

cat >"$host_json" <<'JSON'
{
  "buckets": {
    "host-a": {
      "target_kind": "rustsbi",
      "eid": 1053059182,
      "fid": 0,
      "violation_type": "spec_violation",
      "violation_detail": "{\"WrongErrorCode\":{\"expected\":-2}}",
      "reproducer": "output/host/very-long-reproducer-name.host"
    },
    "host-b": {
      "target_kind": "rustsbi",
      "eid": 1053059182,
      "fid": 0,
      "violation_type": "spec_violation",
      "violation_detail": "{\"WrongErrorCode\":{\"expected\":-2}}",
      "reproducer": "output/host/a.host"
    }
  }
}
JSON

cat >"$sequence_json" <<'JSON'
{
  "results": [
    {
      "target_kind": "rustsbi",
      "eid": 1053059182,
      "fid": 0,
      "violation_type": "spec_violation",
      "violation_detail": "{\"WrongErrorCode\":{\"expected\":-2}}",
      "input": "output/seq/case.seq"
    }
  ]
}
JSON

python3 "$repo_root/scripts/cross-layer-dedup.py" \
  "$host_json" \
  "$sequence_json" \
  --json-out "$dedup_json" >/dev/null

python3 - "$dedup_json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["total_unique"] == 1, data
bug = next(iter(data["bugs"].values()))
assert bug["count"] == 3, bug
assert bug["sources"] == ["host", "sequence"], bug
assert bug["source_reproducers"]["host"] == "output/host/a.host", bug
assert bug["source_reproducers"]["sequence"] == "output/seq/case.seq", bug
assert bug["reproducers"] == [
    "output/host/a.host",
    "output/host/very-long-reproducer-name.host",
    "output/seq/case.seq",
], bug
PY

echo "cross-layer dedup test passed"
