#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cp "$repo_root/Makefile" "$tmp_dir/Makefile"
cp -R "$repo_root/scripts" "$tmp_dir/scripts"

mkdir -p "$tmp_dir/output/host_fuzz" \
  "$tmp_dir/output/sequence/campaigns/seq-run" \
  "$tmp_dir/playground/opensbi-fuzz/output/bugs" \
  "$tmp_dir/playground/rustsbi-fuzz/output/campaigns/run-1"

cat >"$tmp_dir/output/host_fuzz/triage.json" <<'JSON'
{
  "buckets": {
    "host-a": {
      "target_kind": "rustsbi",
      "eid": 16,
      "fid": 0,
      "violation_type": "spec_violation",
      "violation_detail": "{\"WrongErrorCode\":{\"expected\":0}}",
      "reproducer": "output/host_fuzz/a.json"
    }
  }
}
JSON

cat >"$tmp_dir/output/sequence/campaigns/seq-run/triage.json" <<'JSON'
{
  "buckets": {
    "seq-a": {
      "target_kind": "rustsbi",
      "eid": 16,
      "fid": 0,
      "violation_type": "spec_violation",
      "violation_detail": "{\"WrongErrorCode\":{\"expected\":0}}",
      "reproducer": "output/sequence/seq.json"
    }
  }
}
JSON

cat >"$tmp_dir/playground/opensbi-fuzz/output/bugs/result.bugs.json" <<'JSON'
{
  "buckets": {
    "qemu-a": {
      "impl_kind": "rustsbi",
      "eid": 16,
      "fid": 0,
      "classification": "spec_violation",
      "raw_signature": "{\"WrongErrorCode\":{\"expected\":0}}",
      "input": "output/bugs/qemu.exec"
    }
  }
}
JSON

cat >"$tmp_dir/playground/opensbi-fuzz/output/bugs/result.replay.json" <<'JSON'
{
  "results": [
    {
      "target_kind": "rustsbi",
      "eid": 16,
      "fid": 0,
      "classification": "replay_only",
      "signature": "should-not-be-consumed",
      "input": "output/bugs/ignored.exec"
    }
  ]
}
JSON

cat >"$tmp_dir/playground/rustsbi-fuzz/output/campaigns/run-1/bugs.json" <<'JSON'
{
  "buckets": {
    "qemu-b": {
      "impl_kind": "rustsbi",
      "eid": 16,
      "fid": 0,
      "classification": "spec_violation",
      "raw_signature": "{\"WrongErrorCode\":{\"expected\":0}}",
      "input": "output/bugs/campaign.exec"
    }
  }
}
JSON

make -C "$tmp_dir" cross-layer-dedup >/dev/null

python3 - "$tmp_dir/output/host_fuzz/cross-layer.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert data["total_unique"] == 1, data
bug = next(iter(data["bugs"].values()))
assert bug["sources"] == ["host", "qemu", "sequence"], bug
assert bug["source_reproducers"]["host"] == "output/host_fuzz/a.json", bug
assert bug["source_reproducers"]["sequence"] == "output/sequence/seq.json", bug
assert bug["source_reproducers"]["qemu"] == "output/bugs/qemu.exec", bug
assert "output/bugs/ignored.exec" not in bug["reproducers"], bug
assert "output/bugs/campaign.exec" in bug["reproducers"], bug
PY

echo "default cross-layer dedup test passed"
