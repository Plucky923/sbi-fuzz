#!/usr/bin/env python3
import json
import sys
import hashlib
import subprocess
import time
import tomllib
from pathlib import Path


DEFAULT_PROFILE_DIR = Path("config/campaign-profiles")


def load_profile(repo_root: Path, profile_ref: str | None, section: str):
    if not profile_ref:
        return {}, None, None, None

    profile_path = Path(profile_ref)
    if not profile_path.exists():
        candidate = repo_root / DEFAULT_PROFILE_DIR / profile_ref
        if candidate.suffix != ".toml":
            candidate = candidate.with_suffix(".toml")
        profile_path = candidate

    if not profile_path.exists():
        raise FileNotFoundError(
            f"profile {profile_ref!r} not found; expected a path or {DEFAULT_PROFILE_DIR / (profile_ref + '.toml')}"
        )

    raw = tomllib.loads(profile_path.read_text())
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    section_data = raw.get(section)
    if isinstance(section_data, dict):
        profile = dict(section_data)
    else:
        profile = {
            key: value
            for key, value in raw.items()
            if key != "metadata" and not isinstance(value, dict)
        }

    profile_name = metadata.get("name") or profile_path.stem
    return profile, profile_path.resolve(), profile_name, raw


def resolve_setting(cli_value, profile: dict, key: str, default):
    if cli_value is not None:
        return cli_value
    if key in profile and profile[key] is not None:
        return profile[key]
    return default


def prepare_env(base_env: dict):
    env = base_env.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")
    return env


def selected_environment(env: dict):
    return {
        key: env[key]
        for key in ["LLVM_CONFIG_PATH", "CC", "CXX", "LIBCLANG_PATH"]
        if key in env
    }


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _git_output(repo_root: Path, args: list[str]):
    proc = subprocess.run(
        ["git", "-C", str(repo_root)] + args,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def collect_repo_metadata(repo_root: Path):
    head = _git_output(repo_root, ["rev-parse", "HEAD"])
    if head is None:
        return None
    branch = _git_output(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"])
    status = _git_output(repo_root, ["status", "--short"])
    return {
        "head": head,
        "short_head": head[:12],
        "branch": branch,
        "dirty": bool(status),
        "status_short": status.splitlines() if status else [],
    }


def path_metadata(path: Path):
    exists = path.exists()
    info = {
        "path": str(path),
        "exists": exists,
        "kind": "missing",
    }
    if not exists:
        return info

    if path.is_dir():
        info["kind"] = "dir"
        return info

    info["kind"] = "file"
    info["size"] = path.stat().st_size
    return info


def write_json(path: Path, payload: dict):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_optional_json(path: Path | None):
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(
            f"warning: ignoring malformed JSON at {path}: {exc}",
            file=sys.stderr,
        )
        return None


def bug_ids_from_summary(summary: dict | None, parent_summary: dict | None = None):
    if not summary:
        return []
    buckets = summary.get("buckets")
    if isinstance(buckets, dict):
        return sorted(
            {
                bug_id_from_bucket(parent_summary or summary, key, bucket)
                for key, bucket in buckets.items()
            }
        )
    return []


def normalize_summary_target(summary: dict | None):
    if not summary:
        return "unknown"
    candidates = [
        summary.get("target_kind"),
        summary.get("name"),
        summary.get("label"),
        summary.get("target"),
    ]
    for value in candidates:
        normalized = str(value or "").strip().lower()
        if "opensbi" in normalized or "open_sbi" in normalized or "open-sbi" in normalized:
            return "opensbi"
        if "rustsbi" in normalized or "rust_sbi" in normalized or "rust-sbi" in normalized:
            return "rustsbi"
    return "unknown"


def canonical_bug_id_from_legacy_bucket(summary: dict | None, key: str, bucket: dict):
    dedup_key = bucket.get("dedup_key")
    if not dedup_key:
        affected_target = normalize_summary_target(summary)
        classification = bucket.get("classification", "unknown")
        signature = bucket.get("signature") or bucket.get("raw_signature") or bucket.get("violation_detail") or key
        dedup_key = f"{affected_target}|{classification}|{signature}"
    return f"bug-{hashlib.sha256(str(dedup_key).encode()).hexdigest()[:12]}"


def bug_id_from_bucket(summary: dict | None, key: str, bucket: dict):
    if bucket.get("bug_id"):
        return str(bucket["bug_id"])
    dedup_key = bucket.get("dedup_key")
    if not dedup_key:
        affected_target = bucket.get("affected_target") or bucket.get("target_kind")
        if not affected_target:
            affected_target = normalize_summary_target(summary)
        dedup_key = "|".join(
            [
                str(affected_target or "unknown"),
                str(bucket.get("eid", 0)),
                str(bucket.get("fid", 0)),
                str(bucket.get("classification") or bucket.get("violation_type") or "unknown"),
                str(bucket.get("violation_detail") or bucket.get("raw_signature") or bucket.get("signature") or key),
            ]
        )
    return f"bug-{hashlib.sha256(str(dedup_key).encode()).hexdigest()[:12]}"


def previous_bug_ids(summary: dict | None, summary_path: Path | None = None):
    if not summary:
        return set(), set()
    finding_sets = summary.get("finding_sets") if isinstance(summary.get("finding_sets"), dict) else {}
    current_ids = finding_sets.get("current_bug_ids")
    fixed_ids = finding_sets.get("fixed_bug_ids")

    if current_ids is None:
        if isinstance(summary.get("current_bug_ids"), list):
            current_ids = summary["current_bug_ids"]
        elif isinstance(summary.get("confirmed_bug_like_buckets"), dict):
            current_ids = [
                bug_id_from_bucket(summary, key, bucket)
                for key, bucket in summary["confirmed_bug_like_buckets"].items()
            ]
        elif isinstance(summary.get("artifacts"), dict) and summary["artifacts"].get("bug_json"):
            bug_json_path = Path(summary["artifacts"]["bug_json"])
            if not bug_json_path.is_absolute() and summary_path:
                bug_json_path = (summary_path.parent / bug_json_path).resolve()
            if bug_json_path.exists():
                current_ids = bug_ids_from_summary(json.loads(bug_json_path.read_text()), summary)
            else:
                current_ids = []
        else:
            current_ids = []

    if fixed_ids is None:
        fixed_ids = []

    return set(current_ids), set(fixed_ids)


def compute_finding_sets(current_bug_ids: list[str], previous_summary: dict | None, previous_summary_path: Path | None = None):
    current = set(current_bug_ids)
    previous_current, previous_fixed = previous_bug_ids(previous_summary, previous_summary_path)
    regressed = current & previous_fixed
    persisting = current & previous_current
    new = current - previous_current - regressed
    fixed = previous_current - current
    return {
        "current_bug_ids": sorted(current),
        "new_bug_ids": sorted(new),
        "fixed_bug_ids": sorted(fixed),
        "regressed_bug_ids": sorted(regressed),
        "persisting_bug_ids": sorted(persisting),
    }
