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

rg -n '"finding_sets"' "$repo_root/scripts/run-sbi-fuzz-campaign.py" >/dev/null
rg -n '"finding_sets"' "$repo_root/scripts/run-sequence-campaign.py" >/dev/null

echo "campaign summary delta test passed"
