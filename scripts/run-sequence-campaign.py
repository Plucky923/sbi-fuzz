#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from pathlib import Path


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
    parser.add_argument("--helper-bin", default="target/release/helper")
    parser.add_argument("--replay-limit", type=int, default=64)
    parser.add_argument("--timeout-secs", type=int, default=20)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--prepare-cmd")
    args = parser.parse_args()

    if args.prepare_cmd:
        subprocess.run(args.prepare_cmd, shell=True, check=True)

    env = os.environ.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")
    helper_bin = args.helper_bin
    if helper_bin == "target/release/helper" and not Path(helper_bin).exists():
        helper_bin = None

    campaign_root = args.sequence_dir / "campaigns"
    campaign_root.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    campaign_dir = campaign_root / run_id
    campaign_dir.mkdir()

    triage_json = campaign_dir / "triage.json"
    triage_md = campaign_dir / "triage.md"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/triage-sequence-results.py"),
            str(args.sequence_dir),
            "--label",
            args.name,
            "--json-out",
            str(triage_json),
            "--md-out",
            str(triage_md),
        ],
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "triage.stdout.json",
    )
    triage = json.loads(triage_json.read_text())

    selected = select_representatives(triage, args.replay_limit, args.target_kind)
    subset_dir = campaign_dir / "replay-inputs"
    materialize_subset(selected, subset_dir)

    replay_json = campaign_dir / "replay.json"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/replay-sequence-results.py"),
            args.target_kind,
            str(subset_dir),
            "--all",
            "--timeout-secs",
            str(args.timeout_secs),
            "--label",
            args.name,
            "--log-dir",
            str(campaign_dir / "replay-logs"),
            "--json-out",
            str(replay_json),
        ]
        + (["--helper-bin", helper_bin] if helper_bin else []),
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "replay.stdout.json",
    )
    replay = json.loads(replay_json.read_text())

    bug_json = campaign_dir / "bugs.json"
    bug_md = campaign_dir / "bugs.md"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/report-sequence-bugs.py"),
            str(replay_json),
            "--label",
            args.name,
            "--json-out",
            str(bug_json),
            "--md-out",
            str(bug_md),
        ],
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "bugs.stdout.json",
    )
    bugs = json.loads(bug_json.read_text())

    summary = {
        "name": args.name,
        "target_kind": args.target_kind,
        "sequence_dir": str(args.sequence_dir),
        "campaign_dir": str(campaign_dir),
        "triage_total_cases": triage.get("total_cases", 0),
        "replayed_sequences": replay.get("total", 0),
        "interesting_replays": replay.get("interesting", 0),
        "candidate_count": bugs.get("candidate_count", 0),
        "by_classification": replay.get("by_classification", {}),
        "bug_signatures": bugs.get("by_signature", {}),
        "selected_inputs": [item["path"] for item in selected],
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
