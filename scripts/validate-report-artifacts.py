#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

COMMON_BUCKET_FIELDS = {
    "affected_target",
    "bug_id",
    "classification",
    "dedup_key",
    "first_seen",
    "impact",
    "last_seen",
    "repro_stability",
}


def fail(message: str) -> None:
    raise ValueError(message)


def require_keys(data: dict, required: set[str], context: str) -> None:
    missing = sorted(key for key in required if key not in data)
    if missing:
        fail(f"{context}: missing keys {missing}")


def validate_repro_stability(data: dict, context: str) -> None:
    if not isinstance(data, dict):
        fail(f"{context}: repro_stability must be an object")
    require_keys(data, {"attempts", "label", "stable_ratio"}, context)


def validate_common_bucket(bucket: dict, context: str) -> None:
    require_keys(bucket, COMMON_BUCKET_FIELDS, context)
    if not bucket["bug_id"]:
        fail(f"{context}: bug_id must be non-empty")
    if not bucket["dedup_key"]:
        fail(f"{context}: dedup_key must be non-empty")
    validate_repro_stability(bucket["repro_stability"], context)


def validate_host_triage(data: dict) -> None:
    require_keys(
        data,
        {"buckets", "generated_at_utc", "report_type", "schema_version", "total_cases"},
        "host triage summary",
    )
    if data["report_type"] != "host_triage":
        fail("host triage summary: report_type must be `host_triage`")
    if not isinstance(data["buckets"], dict):
        fail("host triage summary: buckets must be an object")
    for key, bucket in data["buckets"].items():
        validate_common_bucket(bucket, f"host triage bucket `{key}`")


def validate_bug_report(data: dict) -> None:
    require_keys(
        data,
        {
            "buckets",
            "by_classification",
            "candidate_count",
            "generated_at_utc",
            "report_type",
            "schema_version",
            "total_results",
        },
        "bug report summary",
    )
    if data["report_type"] != "bug_report":
        fail("bug report summary: report_type must be `bug_report`")
    if not isinstance(data["buckets"], dict):
        fail("bug report summary: buckets must be an object")
    for key, bucket in data["buckets"].items():
        validate_common_bucket(bucket, f"bug report bucket `{key}`")


def validate_quality_gate(data: dict) -> None:
    require_keys(
        data,
        {"blockers", "checks", "generated_at_utc", "schema_version", "status", "warnings"},
        "quality gate report",
    )
    if data["status"] not in {"pass", "fail"}:
        fail("quality gate report: status must be `pass` or `fail`")
    if not isinstance(data["blockers"], list):
        fail("quality gate report: blockers must be a list")
    if not isinstance(data["warnings"], list):
        fail("quality gate report: warnings must be a list")


def validate_cross_layer(data: dict) -> None:
    require_keys(
        data,
        {"bugs", "generated_at_utc", "report_type", "schema_version", "total_unique"},
        "cross-layer report",
    )
    if data["report_type"] != "cross_layer_dedup":
        fail("cross-layer report: report_type must be `cross_layer_dedup`")
    if not isinstance(data["bugs"], dict):
        fail("cross-layer report: bugs must be an object")
    for key, bug in data["bugs"].items():
        require_keys(
            bug,
            {
                "affected_target",
                "bug_id",
                "classification",
                "dedup_key",
                "impact",
                "reproducers",
            },
            f"cross-layer bug `{key}`",
        )
        if not isinstance(bug["reproducers"], list):
            fail(f"cross-layer bug `{key}`: reproducers must be a list")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate generated report artifacts")
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--kind",
        choices=["bug-report", "cross-layer", "host-triage", "quality-gate"],
        required=True,
    )
    args = parser.parse_args()

    data = json.loads(args.input.read_text())
    validators = {
        "bug-report": validate_bug_report,
        "cross-layer": validate_cross_layer,
        "host-triage": validate_host_triage,
        "quality-gate": validate_quality_gate,
    }
    try:
        validators[args.kind](data)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"{args.kind} validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
