#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$repo_root" <<'PY'
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
sys.path.insert(0, str(repo_root / "scripts"))

from campaign_utils import bug_ids_from_summary, compute_finding_sets  # noqa: E402

current_bugs = {
    "buckets": {
        "a": {"bug_id": "bug-a"},
        "b": {"bug_id": "bug-b"},
    }
}
previous_summary = {
    "finding_sets": {
        "current_bug_ids": ["bug-a", "bug-old"],
        "fixed_bug_ids": ["bug-b"],
    }
}

current_ids = bug_ids_from_summary(current_bugs)
assert current_ids == ["bug-a", "bug-b"], current_ids
finding_sets = compute_finding_sets(current_ids, previous_summary)
assert finding_sets["current_bug_ids"] == ["bug-a", "bug-b"], finding_sets
assert finding_sets["persisting_bug_ids"] == ["bug-a"], finding_sets
assert finding_sets["fixed_bug_ids"] == ["bug-old"], finding_sets
assert finding_sets["regressed_bug_ids"] == ["bug-b"], finding_sets
assert finding_sets["new_bug_ids"] == [], finding_sets
PY

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

prev_firmware_summary="$tmp_dir/prev-firmware-summary.json"
cat > "$prev_firmware_summary" <<'JSON'
{
  "finding_sets": {
    "current_bug_ids": ["bug-prev"],
    "fixed_bug_ids": ["bug-regressed"]
  }
}
JSON

target_bin="$tmp_dir/target.bin"
injector_elf="$tmp_dir/injector.elf"
seed_dir="$tmp_dir/seeds"
result_dir="$tmp_dir/results"
summary_json="$tmp_dir/summary.json"
mkdir -p "$seed_dir" "$result_dir"
: > "$target_bin"
: > "$injector_elf"

python3 "$repo_root/scripts/run-sbi-fuzz-campaign.py" \
  smoke-profile \
  "$target_bin" \
  "$injector_elf" \
  "$seed_dir" \
  "$result_dir" \
  --profile single-hart-fast \
  --fuzzer-bin /bin/true \
  --helper-bin /bin/true \
  --previous-summary "$prev_firmware_summary" \
  --json-out "$summary_json" >/dev/null

rg -n '"finding_sets":' "$summary_json" >/dev/null
rg -n '"fixed_bug_ids": \[' "$summary_json" >/dev/null

prev_sequence_summary="$tmp_dir/prev-sequence-summary.json"
cat > "$prev_sequence_summary" <<JSON
{
  "artifacts": {
    "bug_json": "$repo_root/tests/fixtures/workflow/sequence-bugs-previous.json"
  }
}
JSON

sequence_dir="$tmp_dir/sequences"
mkdir -p "$sequence_dir"
summary_sequence_json="$tmp_dir/sequence-summary.json"
python3 "$repo_root/scripts/run-sequence-campaign.py" \
  smoke-sequence \
  opensbi \
  "$sequence_dir" \
  --profile host-sequence \
  --helper-bin /bin/true \
  --previous-summary "$prev_sequence_summary" \
  --json-out "$summary_sequence_json" >/dev/null

rg -n '"finding_sets":' "$summary_sequence_json" >/dev/null

replay_json="$tmp_dir/replay.json"
cat > "$replay_json" <<'JSON'
{
  "results": [
    {
      "actual": "Crash",
      "classification": "crash",
      "expected": "Timeout",
      "extension": "hsm",
      "fid": "0x0",
      "hash": "labelaaaa1111",
      "input": "label-case.exec",
      "interesting": true,
      "notes": [],
      "output_excerpt": "crash",
      "eid": "0x48534D",
      "signals": [],
      "signature": "exit:Crash",
      "trap": null
    }
  ]
}
JSON

canonical_json="$tmp_dir/canonical.json"
python3 "$repo_root/scripts/report-sbi-bugs.py" \
  "$replay_json" \
  --label rustsbi-prototyper \
  --json-out "$canonical_json" >/dev/null

rg -n '"affected_target": "rustsbi"' "$canonical_json" >/dev/null
rg -n '"dedup_key": "rustsbi\|' "$canonical_json" >/dev/null

echo "campaign summary delta test passed"
