#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
good_doc="$(mktemp "$repo_root/.tmp-docs-good-XXXX.md")"
bad_doc="$(mktemp "$repo_root/.tmp-docs-bad-XXXX.md")"
trap 'rm -f "$good_doc" "$bad_doc"' EXIT

cat > "$good_doc" <<'MD'
# Good Doc

See `docs/runbook.md` and `docs/plan.md`.

```bash
make preflight
make -C playground/rustsbi-fuzz campaign
```
MD

python3 "$repo_root/scripts/check-docs.py" "$good_doc" >/dev/null

cat > "$bad_doc" <<'MD'
# Bad Doc

See `missing-plan.md`.

```bash
make not-a-real-target
```
MD

set +e
stderr_path="$(mktemp)"
python3 "$repo_root/scripts/check-docs.py" "$bad_doc" >/dev/null 2>"$stderr_path"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
    echo "docs check unexpectedly passed on invalid input" >&2
    exit 1
fi

rg -n 'missing local doc reference `missing-plan.md`' "$stderr_path" >/dev/null
rg -n 'unknown target `not-a-real-target`' "$stderr_path" >/dev/null
rm -f "$stderr_path"

echo "docs check test passed"
