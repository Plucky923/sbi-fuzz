#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from pathlib import Path

from campaign_utils import (
    collect_repo_metadata,
    load_profile,
    path_metadata,
    prepare_env,
    resolve_setting,
    selected_environment,
    utc_now,
    write_json,
)


def run_cmd(cmd, *, stdout_path: Path | None = None, cwd: Path | None = None, env=None):
    if stdout_path is None:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
        )
    else:
        with stdout_path.open("w") as output_fp:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                stdout=output_fp,
                stderr=subprocess.STDOUT,
                text=True,
            )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr)
    return proc


def select_representatives(triage: dict, limit: int, target_kind: str):
    reps = []
    for bucket, rep in triage.get("representatives", {}).items():
        flags = rep.get("flags", [])
        impl_hints = [flag.split(":", 1)[1] for flag in flags if flag.startswith("impl_hint:")]
        if impl_hints and all(hint.replace("_", "").lower() != target_kind.lower() for hint in impl_hints):
            continue
        reps.append(
            {
                "bucket": bucket,
                "path": rep["path"],
                "priority": (
                    0 if rep.get("input_kind") == "sequence" else 1,
                    0 if "multi_hart" in flags else 1,
                    0 if "has_memory_objects" in flags else 1,
                    bucket,
                ),
            }
        )
    reps.sort(key=lambda item: item["priority"])
    return reps[:limit] if limit > 0 else reps


def materialize_subset(selected, subset_dir: Path):
    subset_dir.mkdir(parents=True, exist_ok=True)
    for item in selected:
        src = Path(item["path"])
        dst = subset_dir / src.name
        if not dst.exists():
            os.symlink(src.resolve(), dst)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Run a single-target sequence campaign with triage, replay, and bug reporting")
    parser.add_argument("name", help="Campaign name, e.g. opensbi-sequence or rustsbi-sequence")
    parser.add_argument("target_kind", choices=["opensbi", "rustsbi"])
    parser.add_argument("sequence_dir", type=Path)
    parser.add_argument("--profile", help="Profile name under config/campaign-profiles/ or an explicit TOML path")
    parser.add_argument("--helper-bin")
    parser.add_argument("--replay-limit", type=int)
    parser.add_argument("--timeout-secs", type=int)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--prepare-cmd")
    args = parser.parse_args()

    profile, profile_path, profile_name, profile_raw = load_profile(
        repo_root,
        args.profile,
        "sequence",
    )
    helper_bin = resolve_setting(args.helper_bin, profile, "helper_bin", "target/release/helper")
    replay_limit = resolve_setting(args.replay_limit, profile, "replay_limit", 64)
    timeout_secs = resolve_setting(args.timeout_secs, profile, "timeout_secs", 20)
    prepare_cmd = resolve_setting(args.prepare_cmd, profile, "prepare_cmd", None)

    if prepare_cmd:
        subprocess.run(prepare_cmd, shell=True, check=True)

    env = prepare_env(os.environ)
    helper_bin_arg = helper_bin
    if helper_bin_arg == "target/release/helper" and not Path(helper_bin_arg).exists():
        helper_bin_arg = None

    campaign_root = args.sequence_dir / "campaigns"
    campaign_root.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    campaign_dir = campaign_root / run_id
    campaign_dir.mkdir()

    triage_cmd = [
        "python3",
        str(repo_root / "scripts/triage-sequence-results.py"),
        str(args.sequence_dir),
        "--label",
        args.name,
        "--json-out",
        str(campaign_dir / "triage.json"),
        "--md-out",
        str(campaign_dir / "triage.md"),
    ]
    replay_cmd = [
        "python3",
        str(repo_root / "scripts/replay-sequence-results.py"),
        args.target_kind,
        str(campaign_dir / "replay-inputs"),
        "--all",
        "--timeout-secs",
        str(timeout_secs),
        "--label",
        args.name,
        "--log-dir",
        str(campaign_dir / "replay-logs"),
        "--json-out",
        str(campaign_dir / "replay.json"),
    ] + (["--helper-bin", helper_bin_arg] if helper_bin_arg else [])
    bug_cmd = [
        "python3",
        str(repo_root / "scripts/report-sequence-bugs.py"),
        str(campaign_dir / "replay.json"),
        "--label",
        args.name,
        "--json-out",
        str(campaign_dir / "bugs.json"),
        "--md-out",
        str(campaign_dir / "bugs.md"),
    ]
    manifest_path = campaign_dir / "run-manifest.json"
    write_json(
        manifest_path,
        {
            "schema_version": 1,
            "script": "run-sequence-campaign.py",
            "created_at_utc": utc_now(),
            "run_id": run_id,
            "campaign_name": args.name,
            "target_kind": args.target_kind,
            "profile_name": profile_name,
            "profile_path": str(profile_path) if profile_path else None,
            "profile": profile_raw,
            "repo": collect_repo_metadata(repo_root),
            "inputs": {
                "sequence_dir": path_metadata(args.sequence_dir),
            },
            "execution": {
                "helper_bin": helper_bin,
                "resolved_helper_bin": helper_bin_arg,
                "replay_limit": replay_limit,
                "timeout_secs": timeout_secs,
                "prepare_cmd": prepare_cmd,
            },
            "environment": selected_environment(env),
            "commands": {
                "triage": triage_cmd,
                "replay": replay_cmd,
                "bug_report": bug_cmd,
            },
        },
    )

    triage_json = campaign_dir / "triage.json"
    triage_md = campaign_dir / "triage.md"
    run_cmd(
        triage_cmd,
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "triage.stdout.json",
    )
    triage = json.loads(triage_json.read_text())

    selected = select_representatives(triage, replay_limit, args.target_kind)
    subset_dir = campaign_dir / "replay-inputs"
    materialize_subset(selected, subset_dir)

    replay_json = campaign_dir / "replay.json"
    replay_cmd[3] = str(subset_dir)
    run_cmd(
        replay_cmd,
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "replay.stdout.json",
    )
    replay = json.loads(replay_json.read_text())

    bug_json = campaign_dir / "bugs.json"
    bug_md = campaign_dir / "bugs.md"
    run_cmd(
        bug_cmd,
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "bugs.stdout.json",
    )
    bugs = json.loads(bug_json.read_text())

    summary = {
        "name": args.name,
        "target_kind": args.target_kind,
        "profile_name": profile_name,
        "profile_path": str(profile_path) if profile_path else None,
        "sequence_dir": str(args.sequence_dir),
        "campaign_dir": str(campaign_dir),
        "timeout_secs": timeout_secs,
        "replay_limit": replay_limit,
        "triage_total_cases": triage.get("total_cases", 0),
        "replayed_sequences": replay.get("total", 0),
        "interesting_replays": replay.get("interesting", 0),
        "candidate_count": bugs.get("candidate_count", 0),
        "by_classification": replay.get("by_classification", {}),
        "bug_signatures": bugs.get("by_signature", {}),
        "selected_inputs": [item["path"] for item in selected],
        "artifacts": {
            "triage_json": str(triage_json),
            "triage_md": str(triage_md),
            "replay_json": str(replay_json),
            "replay_log_dir": str(campaign_dir / "replay-logs"),
            "bug_json": str(bug_json),
            "bug_md": str(bug_md),
            "run_manifest": str(manifest_path),
        },
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
