#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path


STATUS_PRIORITY = {"Crash": 0, "Timeout": 1, "Unknown": 2}


def count_result_dir(result_dir: Path):
    return {
        "toml": len(list(result_dir.glob("*.toml"))),
        "raw": len(list((result_dir / ".raw").glob("*"))) if (result_dir / ".raw").exists() else 0,
        "corpus": len(list((result_dir / ".corpus").glob("*"))) if (result_dir / ".corpus").exists() else 0,
    }


def find_free_tcp_port() -> int:
    explicit = os.environ.get("SBIFUZZ_BROKER_PORT")
    if explicit:
        return int(explicit)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    except PermissionError:
        # Some sandboxed environments disallow Python from probing an ephemeral
        # port even though the later broker bind still succeeds when given an
        # explicit port. Fall back to a deterministic high port.
        return 19000 + (os.getpid() % 1000)


def run_cmd(cmd, *, stdout_path: Path | None = None, cwd: Path | None = None, env=None, timeout=None):
    if stdout_path is None:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
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
                timeout=timeout,
            )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr)
    return proc


def select_representatives(triage: dict, replay_max_buckets: int):
    reps = []
    for bucket, rep in triage.get("representatives", {}).items():
        status = bucket.rsplit(":", 1)[-1]
        flags = rep.get("flags", [])
        reps.append(
            {
                "bucket": bucket,
                "path": rep["path"],
                "status": status,
                "priority": (
                    STATUS_PRIORITY.get(status, 99),
                    0 if "unknown:" in bucket else 1,
                    0 if rep.get("raw_exec_exists") else 1,
                    -len(flags),
                    bucket,
                ),
            }
        )
    reps.sort(key=lambda item: item["priority"])
    return reps[:replay_max_buckets]


def materialize_subset(selected, subset_dir: Path):
    (subset_dir / ".raw").mkdir(parents=True, exist_ok=True)
    for item in selected:
        src = Path(item["path"])
        dst = subset_dir / src.name
        if not dst.exists():
            os.symlink(src.resolve(), dst)
        stem_hash = src.stem.split("-")[-1]
        raw_src = src.parent / ".raw" / f"{stem_hash}.exec"
        raw_dst = subset_dir / ".raw" / raw_src.name
        if raw_src.exists() and not raw_dst.exists():
            os.symlink(raw_src.resolve(), raw_dst)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Run a full SBI fuzz campaign with triage, replay, and bug reporting")
    parser.add_argument("name", help="Campaign name, e.g. opensbi or rustsbi-prototyper")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("seed_dir", type=Path)
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--duration-secs", type=int, default=300)
    parser.add_argument("--timeout-ms", type=int, default=100)
    parser.add_argument("--smp", type=int, default=1)
    parser.add_argument("--broker-port", type=int)
    parser.add_argument("--replay-timeout-secs", type=int, default=12)
    parser.add_argument("--replay-max-buckets", type=int, default=64)
    parser.add_argument("--hang-stability-attempts", type=int, default=3)
    parser.add_argument("--helper-bin", default="target/release/helper")
    parser.add_argument("--fuzzer-bin", default="cargo")
    parser.add_argument("--skip-halt", action="store_true", default=True)
    parser.add_argument("--cores", default="1")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--prepare-cmd")
    args = parser.parse_args()

    if args.prepare_cmd:
        subprocess.run(args.prepare_cmd, shell=True, check=True)

    args.result_dir.mkdir(parents=True, exist_ok=True)
    campaign_root = args.result_dir / "campaigns"
    campaign_root.mkdir(exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    campaign_dir = campaign_root / run_id
    campaign_dir.mkdir()

    env = os.environ.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")

    helper_bin_path = Path(args.helper_bin)
    if helper_bin_path.as_posix() == "target/release/helper" and not helper_bin_path.exists():
        subprocess.run(["cargo", "build", "-p", "helper", "--release"], check=True, env=env)

    broker_port = args.broker_port or find_free_tcp_port()

    before = count_result_dir(args.result_dir)
    fuzz_log = campaign_dir / "fuzz.log"
    fuzz_csv = campaign_dir / "fuzz.csv"
    fuzzer_cmd = [
        "timeout",
        f"{args.duration_secs}s",
        args.fuzzer_bin,
    ]
    if Path(args.fuzzer_bin).name == "cargo":
        fuzzer_cmd.append("fuzzer")
    fuzzer_cmd.extend(
        [
            "--target",
            str(args.target),
            "--injector",
            str(args.injector),
            "--seed",
            str(args.seed_dir),
            "--output",
            str(args.result_dir),
            "--cores",
            args.cores,
            "--timeout",
            str(args.timeout_ms),
            "--smp",
            str(args.smp),
            "--broker-port",
            str(broker_port),
            "--csv-stats",
            str(fuzz_csv),
        ]
    )
    if args.skip_halt:
        fuzzer_cmd.append("--skip-halt")

    with fuzz_log.open("w") as fuzz_fp:
        fuzz_proc = subprocess.run(
            fuzzer_cmd,
            env=env,
            stdout=fuzz_fp,
            stderr=subprocess.STDOUT,
            text=True,
        )
    after = count_result_dir(args.result_dir)

    triage_json = campaign_dir / "triage.json"
    triage_md = campaign_dir / "triage.md"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/triage-sbi-results.py"),
            str(args.result_dir),
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

    selected = select_representatives(triage, args.replay_max_buckets)
    subset_dir = campaign_dir / "replay-inputs"
    materialize_subset(selected, subset_dir)
    replay_json = campaign_dir / "replay.json"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/replay-sbi-results.py"),
            str(args.target),
            str(args.injector),
            str(subset_dir),
            "--all",
            "--prefer-raw-exec",
            "--helper-bin",
            args.helper_bin,
            "--timeout-secs",
            str(args.replay_timeout_secs),
            "--smp",
            str(args.smp),
            "--log-dir",
            str(campaign_dir / "replay-logs"),
            "--label",
            args.name,
            "--json-out",
            str(replay_json),
        ],
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "replay.stdout.json",
    )
    hang_stability_json = campaign_dir / "hang-stability.json"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/check-sbi-hang-stability.py"),
            str(args.target),
            str(args.injector),
            str(replay_json),
            "--helper-bin",
            args.helper_bin,
            "--timeout-secs",
            str(args.replay_timeout_secs),
            "--smp",
            str(args.smp),
            "--attempts",
            str(args.hang_stability_attempts),
            "--label",
            args.name,
            "--log-dir",
            str(campaign_dir / "hang-stability-logs"),
            "--json-out",
            str(hang_stability_json),
        ],
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "hang-stability.stdout.json",
    )
    hang_stability = json.loads(hang_stability_json.read_text())
    hang_minimize_json = campaign_dir / "hang-minimize.json"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/minimize-sbi-hangs.py"),
            str(args.target),
            str(args.injector),
            str(hang_stability_json),
            "--helper-bin",
            args.helper_bin,
            "--timeout-ms",
            str(args.replay_timeout_secs * 1000),
            "--attempts",
            str(args.hang_stability_attempts),
            "--smp",
            str(args.smp),
            "--output-dir",
            str(campaign_dir / "hang-minimized"),
            "--label",
            args.name,
            "--json-out",
            str(hang_minimize_json),
        ],
        cwd=Path.cwd(),
        env=env,
        stdout_path=campaign_dir / "hang-minimize.stdout.json",
    )
    hang_minimize = json.loads(hang_minimize_json.read_text())

    bug_json = campaign_dir / "bugs.json"
    bug_md = campaign_dir / "bugs.md"
    run_cmd(
        [
            "python3",
            str(repo_root / "scripts/report-sbi-bugs.py"),
            str(replay_json),
            "--hang-stability",
            str(hang_stability_json),
            "--hang-minimize",
            str(hang_minimize_json),
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
        "run_id": run_id,
        "target": str(args.target),
        "injector": str(args.injector),
        "broker_port": broker_port,
        "smp": args.smp,
        "seed_dir": str(args.seed_dir),
        "result_dir": str(args.result_dir),
        "campaign_dir": str(campaign_dir),
        "before": before,
        "after": after,
        "fuzz_exit_code": fuzz_proc.returncode,
        "runstate_warnings": fuzz_log.read_text().count("invalid runstate transition"),
        "snapshot_errors": fuzz_log.read_text().count("Could not save snapshot") + fuzz_log.read_text().count("no block device can store vmstate"),
        "triage_total_cases": triage.get("total_cases", 0),
        "triage_bucket_count": len(triage.get("representatives", {})),
        "replayed_buckets": len(selected),
        "bug_candidate_count": bugs.get("candidate_count", 0),
        "bug_by_classification": bugs.get("by_classification", {}),
        "stable_hang_cases": hang_stability.get("stable_hang_cases", 0),
        "flaky_hang_cases": hang_stability.get("flaky_hang_cases", 0),
        "minimized_hang_cases": hang_minimize.get("minimized_cases", 0),
        "reduced_hang_cases": hang_minimize.get("reduced_cases", 0),
        "confirmed_bug_like_buckets": {
            key: value
            for key, value in bugs.get("buckets", {}).items()
            if value.get("classification") in {"sanitizer", "crash"} or value.get("signals") or value.get("hang_stability", {}).get("label") == "stable_hang"
        },
        "artifacts": {
            "fuzz_log": str(fuzz_log),
            "fuzz_csv": str(fuzz_csv),
            "triage_json": str(triage_json),
            "triage_md": str(triage_md),
            "replay_json": str(replay_json),
            "replay_log_dir": str(campaign_dir / "replay-logs"),
            "hang_stability_json": str(hang_stability_json),
            "hang_minimize_json": str(hang_minimize_json),
            "bug_json": str(bug_json),
            "bug_md": str(bug_md),
        },
    }

    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
