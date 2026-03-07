#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
input_json="$(mktemp)"
out_md="$(mktemp)"
trap 'rm -f "$input_json" "$out_md"' EXIT

cat > "$input_json" <<'JSON'
{
  "results": [
    {"expected": "Timeout", "actual": "Timeout", "match": true, "timed_out": false},
    {"expected": "Timeout", "actual": "Ok", "match": false, "timed_out": false},
    {"expected": "Crash", "actual": "TimeoutExpired", "match": false, "timed_out": true}
  ]
}
JSON

python3 "$repo_root/scripts/summarize-replay-opensbi-results.py" "$input_json" --md-out "$out_md" > /tmp/replay-summary.stdout.json
rg -n '"total": 3' /tmp/replay-summary.stdout.json >/dev/null
rg -n '"matching": 1' /tmp/replay-summary.stdout.json >/dev/null
rg -n '"timed_out": 1' /tmp/replay-summary.stdout.json >/dev/null
rg -n 'OpenSBI Replay Summary' "$out_md" >/dev/null

echo "opensbi replay summary test passed"
