#!/usr/bin/env python3
"""Validate a coverage-baseline JSON artifact.

Usage:
    validate-coverage-baseline.py <baseline.json>

Enforces AC-1 schema requirements:
- schema_version must be present and equal to "1.0.0"
- entries must be an object mapping eid/fid keys to stat objects
- each entry must contain: unique_pcs, total_pcs, semantic_signature_count, timeout_count
"""

import json
import sys


def validate(path: str) -> int:
    with open(path, "r") as f:
        data = json.load(f)

    errors = []

    # schema_version check
    if "schema_version" not in data:
        errors.append("missing required field: schema_version")
    elif data["schema_version"] != "1.0.0":
        errors.append(f"schema_version must be '1.0.0', got: {data['schema_version']!r}")

    # entries check
    if "entries" not in data:
        errors.append("missing required field: entries")
    elif not isinstance(data["entries"], dict):
        errors.append("entries must be an object")
    else:
        required_fields = {"unique_pcs", "total_pcs", "semantic_signature_count", "timeout_count"}
        for key, entry in data["entries"].items():
            if not isinstance(entry, dict):
                errors.append(f"entries[{key!r}] must be an object")
                continue
            missing = required_fields - set(entry.keys())
            if missing:
                errors.append(f"entries[{key!r}] missing fields: {sorted(missing)}")
            for field in required_fields:
                if field in entry and not isinstance(entry[field], int):
                    errors.append(f"entries[{key!r}].{field} must be an integer")

    if errors:
        print(f"VALIDATION FAILED: {path}")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"VALIDATION PASSED: {path}")
    print(f"  schema_version: {data.get('schema_version')}")
    print(f"  entries: {len(data.get('entries', {}))}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <baseline.json>")
        sys.exit(2)
    sys.exit(validate(sys.argv[1]))
