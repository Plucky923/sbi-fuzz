#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-$ROOT_DIR/output/host_fuzz/cross-layer.json}"

args=()

add_source_if_exists() {
    local label="$1"
    local path="$2"
    if [[ -f "$path" ]]; then
        args+=(--source "${label}=${path}")
    fi
}

add_source_if_exists host "$ROOT_DIR/output/host_fuzz/triage.json"

while IFS= read -r path; do
    args+=(--source "sequence=${path}")
done < <(find "$ROOT_DIR/output/sequence" -type f -name 'triage.json' 2>/dev/null | sort)

while IFS= read -r path; do
    args+=(--source "qemu=${path}")
done < <(find "$ROOT_DIR/output/bugs" -maxdepth 1 -type f -name '*.bugs.json' 2>/dev/null | sort)

while IFS= read -r path; do
    args+=(--source "qemu=${path}")
done < <(find "$ROOT_DIR/playground" -path '*/output/bugs/*.bugs.json' -type f 2>/dev/null | sort)

while IFS= read -r path; do
    label="qemu"
    if [[ "$path" == *"/output/sequence/"* ]]; then
        label="sequence"
    fi
    args+=(--source "${label}=${path}")
done < <(find "$ROOT_DIR" -path '*/campaigns/*/bugs.json' -type f 2>/dev/null | sort)

if [[ ${#args[@]} -eq 0 ]]; then
    echo "no cross-layer inputs found under standard output locations" >&2
    exit 1
fi

python3 "$ROOT_DIR/scripts/cross-layer-dedup.py" "${args[@]}" --json-out "$OUTPUT_PATH"
