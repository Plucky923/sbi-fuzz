#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

STATUS_RE = re.compile(r"Run finish\. Exit kind: (\w+)")
SOURCE_RE = re.compile(r"fuzz-([0-9a-f]+)-(\w+)$")
RUNSTATE_RE = re.compile(r"invalid runstate transition", re.I)
INVALID_INPUT_RE = re.compile(r"Reject invalid input .*?: (.+)", re.I)
MEPC_RE = re.compile(r"\bmepc\b\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", re.I)
MCAUSE_RE = re.compile(r"\bmcause\b\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", re.I)
MTVAL_RE = re.compile(r"\bmtval\b\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", re.I)
HART_RE = re.compile(r"\bhart(?:\s+id)?\b\s*[:=]\s*(\d+)", re.I)
ADDRESS_KINDS = {"address", "address_low", "address_high", "hart_mask_address"}
KNOWN_EIDS = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    0x10,
    0x54494D45,
    0x735049,
    0x52464E43,
    0x48534D,
    0x53525354,
    0x504D55,
    0x4442434E,
    0x53555350,
    0x43505043,
    0x535345,
    0x46574654,
    0x44425452,
    0x4D505859,
}
PATTERNS = {
    "oracle": re.compile(r"Oracle failure|oracle=", re.I),
    "kasan": re.compile(r"KASAN|heap-buffer-overflow|slab-out-of-bounds", re.I),
    "ubsan": re.compile(
        r"UBSAN|integer overflow|signed integer overflow|undefined behavior",
        re.I,
    ),
    "panic": re.compile(r"panic|BUG:", re.I),
    "assert": re.compile(r"assert|assertion failed", re.I),
    "illegal_instruction": re.compile(r"illegal instruction", re.I),
    "access_fault": re.compile(
        r"access fault|load access fault|store access fault",
        re.I,
    ),
    "page_fault": re.compile(
        r"page fault|instruction page fault|load page fault|store page fault",
        re.I,
    ),
}


def load_case(path: Path):
    data = tomllib.loads(path.read_text())
    metadata = data.get("metadata", {})
    args = data.get("args", {})
    schema = metadata.get("schema") or {}
    source = metadata.get("source", "")
    match = SOURCE_RE.search(source)
    hash_value = match.group(1) if match else path.stem.split("-")[-1]
    status = match.group(2) if match else "Unknown"

    arg_values = [args.get(f"arg{i}", 0) for i in range(6)]
    schema_values = [schema.get(f"arg{i}", "value") for i in range(6)]
    address_slots = [i for i, kind in enumerate(schema_values) if kind in ADDRESS_KINDS]
    nonzero_slots = [i for i, value in enumerate(arg_values) if value != 0]
    eid = args.get("eid", 0)
    fid = args.get("fid", 0)

    flags = []
    if all(value == 0 for value in arg_values):
        flags.append("all_zero_args")
    if any(value == 0xFFFFFFFFFFFFFFFF for value in arg_values):
        flags.append("u64_max_arg")
    if address_slots and any(arg_values[i] == 0 for i in address_slots):
        flags.append("zero_address_arg")
    if any(value & 0x7 for value in arg_values if value != 0):
        flags.append("unaligned_value")
    if eid not in KNOWN_EIDS:
        flags.append("unknown_eid")

    raw_exec = path.parent / ".raw" / f"{hash_value}.exec"
    return {
        "path": str(path),
        "toml": path,
        "raw_exec": raw_exec if raw_exec.exists() else None,
        "raw_exec_exists": raw_exec.exists(),
        "hash": hash_value,
        "status": status,
        "expected": status,
        "extension": metadata.get("extension_name", "unknown"),
        "source": source,
        "eid": eid,
        "fid": fid,
        "args": arg_values,
        "schema": schema_values,
        "address_slots": address_slots,
        "nonzero_slots": nonzero_slots,
        "flags": flags,
    }


def resolve_helper_cmd(explicit: str | None):
    if explicit:
        return [explicit]
    built = Path("target/release/helper")
    if built.exists():
        return [str(built)]
    return ["cargo", "run", "-q", "-p", "helper", "--"]


def classify_output(output: str, actual: str, expected: str):
    invalid_input = INVALID_INPUT_RE.search(output)
    if invalid_input:
        reason = invalid_input.group(1).strip()
        return {
            "signals": [],
            "trap": None,
            "notes": ["invalid_exec_input"],
            "classification": "invalid_input",
            "signature": f"invalid_input:{reason}",
            "interesting": False,
        }

    signals = [name for name, pattern in PATTERNS.items() if pattern.search(output)]
    trap = {}
    for key, pattern in {
        "mepc": MEPC_RE,
        "mcause": MCAUSE_RE,
        "mtval": MTVAL_RE,
    }.items():
        match = pattern.search(output)
        if match:
            trap[key] = match.group(1)
    if trap:
        hart_match = HART_RE.search(output)
        if hart_match:
            trap["hart_id"] = hart_match.group(1)

    notes = []
    if RUNSTATE_RE.search(output):
        notes.append("qemu_runstate_warning")

    if "kasan" in signals or "ubsan" in signals:
        classification = "sanitizer"
    elif signals or trap or actual == "Crash":
        classification = "crash"
    elif actual in {"Timeout", "TimeoutExpired"}:
        classification = "hang"
    elif actual != expected:
        classification = "mismatch"
    else:
        classification = "ok"

    if trap:
        signature = "trap:" + ":".join(
            [
                trap.get("mcause", "?"),
                trap.get("mepc", "?"),
                trap.get("mtval", "?"),
                ",".join(signals) or actual,
            ]
        )
    elif signals:
        signature = "signals:" + ",".join(sorted(signals))
    else:
        signature = f"exit:{actual}"

    return {
        "signals": signals,
        "trap": trap or None,
        "notes": notes,
        "classification": classification,
        "signature": signature,
        "interesting": classification != "ok",
    }


def summarize_triage(cases):
    by_status = Counter(case["status"] for case in cases)
    by_extension = Counter(case["extension"] for case in cases)
    by_bucket = Counter(
        f"{case['extension']}:{case['fid']:x}:{case['status']}" for case in cases
    )
    flag_counts = Counter(flag for case in cases for flag in case["flags"])

    representatives = {}
    for case in cases:
        bucket = f"{case['extension']}:{case['fid']:x}:{case['status']}"
        representatives.setdefault(bucket, case)

    return {
        "total_cases": len(cases),
        "by_status": dict(by_status),
        "by_extension": dict(by_extension),
        "by_bucket": dict(by_bucket),
        "flag_counts": dict(flag_counts),
        "representatives": {
            bucket: {
                "path": rep["path"],
                "eid": f"0x{rep['eid']:X}",
                "fid": f"0x{rep['fid']:X}",
                "flags": rep["flags"],
                "raw_exec_exists": rep["raw_exec_exists"],
            }
            for bucket, rep in sorted(representatives.items())
        },
    }


def write_triage_markdown(summary, output: Path, label: str):
    lines = [
        f"# {label} Triage Summary",
        "",
        f"- Total cases: {summary['total_cases']}",
        "",
        "## By Status",
        "",
    ]
    for key, value in sorted(summary["by_status"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## By Extension", ""]
    for key, value in sorted(summary["by_extension"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Flags", ""]
    for key, value in sorted(summary["flag_counts"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Representative Buckets", ""]
    for bucket, rep in summary["representatives"].items():
        lines.append(
            f"- `{bucket}` -> `{rep['path']}` | eid={rep['eid']} fid={rep['fid']} | flags={','.join(rep['flags']) or 'none'} | raw_exec={rep['raw_exec_exists']}"
        )
    output.write_text("\n".join(lines) + "\n")


def write_replay_log(log_dir: Path | None, case: dict, output: str):
    if log_dir is None:
        return None
    log_dir.mkdir(parents=True, exist_ok=True)
    fid = case.get("fid", 0)
    if isinstance(fid, str):
        fid_label = fid.lower().removeprefix("0x")
    else:
        fid_label = f"{fid:x}"
    log_path = log_dir / f"{case['extension']}-{fid_label}-{case['hash']}.log"
    log_path.write_text(output)
    return str(log_path)


def run_helper_input(helper_cmd, target: Path, injector: Path, input_path: Path, timeout_secs: int, smp: int):
    env = os.environ.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")
    cmd = helper_cmd + [
        "run",
        str(target),
        str(injector),
        str(input_path),
        "--smp",
        str(max(1, smp)),
        "--timeout-ms",
        str(max(1, timeout_secs) * 1000),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_secs + 30,
        )
        output = proc.stdout + proc.stderr
        actual = STATUS_RE.search(output)
        actual_kind = actual.group(1) if actual else "Unknown"
        timed_out = False
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = stdout + stderr
        actual_kind = "TimeoutExpired"
        timed_out = True
        returncode = None

    return {
        "output": output,
        "actual_kind": actual_kind,
        "timed_out": timed_out,
        "returncode": returncode,
    }


def build_replay_result(case: dict, input_path: Path, used_raw_exec: bool, run_result: dict, log_dir: Path | None):
    classification = classify_output(
        run_result["output"],
        run_result["actual_kind"],
        case["expected"],
    )
    eid = case.get("eid", 0)
    fid = case.get("fid", 0)
    if isinstance(eid, str):
        eid = eid
    else:
        eid = f"0x{eid:X}"
    if isinstance(fid, str):
        fid = fid
    else:
        fid = f"0x{fid:X}"

    return {
        "input": str(input_path),
        "used_raw_exec": used_raw_exec,
        "expected": case["expected"],
        "actual": run_result["actual_kind"],
        "match": run_result["actual_kind"] == case["expected"],
        "returncode": run_result["returncode"],
        "hash": case["hash"],
        "extension": case["extension"],
        "eid": eid,
        "fid": fid,
        "timed_out": run_result["timed_out"],
        "signals": classification["signals"],
        "trap": classification["trap"],
        "notes": classification["notes"],
        "classification": classification["classification"],
        "signature": classification["signature"],
        "interesting": classification["interesting"],
        "log_path": write_replay_log(log_dir, case, run_result["output"]),
        "output_excerpt": run_result["output"][-4000:],
    }


def replay_case(
    case: dict,
    target: Path,
    injector: Path,
    use_raw: bool,
    helper_cmd,
    timeout_secs: int,
    smp: int,
    log_dir: Path | None,
):
    input_path = case["raw_exec"] if use_raw and case["raw_exec"] is not None else case["toml"]
    run_result = run_helper_input(helper_cmd, target, injector, input_path, timeout_secs, smp)
    return build_replay_result(
        case,
        input_path,
        bool(use_raw and case["raw_exec"] is not None),
        run_result,
        log_dir,
    )


def replay_result_entry(
    entry: dict,
    target: Path,
    injector: Path,
    helper_cmd,
    timeout_secs: int,
    smp: int,
    log_dir: Path | None,
):
    input_path = Path(entry["input"])
    case = {
        "expected": entry.get("expected", "Unknown"),
        "hash": entry.get("hash", input_path.stem),
        "extension": entry.get("extension", "unknown"),
        "eid": entry.get("eid", "0x0"),
        "fid": entry.get("fid", "0x0"),
    }
    run_result = run_helper_input(helper_cmd, target, injector, input_path, timeout_secs, smp)
    return build_replay_result(
        case,
        input_path,
        bool(entry.get("used_raw_exec", False)),
        run_result,
        log_dir,
    )


def summarize_bug_report(results, hang_stability=None, hang_minimize=None):
    candidates = [item for item in results if item.get("interesting")]

    def hang_stability_entry(item: dict):
        if not hang_stability:
            return None
        return hang_stability.get("cases_by_hash", {}).get(item.get("hash"))

    def hang_minimize_entry(item: dict):
        if not hang_minimize:
            return None
        return hang_minimize.get("cases_by_hash", {}).get(item.get("hash"))

    def bucket_signature(item: dict):
        raw_signature = item.get("signature", "unknown")
        if item.get("classification") != "hang":
            return raw_signature
        stability = hang_stability_entry(item) or {}
        minimized = hang_minimize_entry(item) or {}
        semantic_signature = minimized.get("semantic_signature")
        if stability.get("label") == "stable_hang" and semantic_signature:
            return f"{raw_signature}|semantic:{semantic_signature}"
        return raw_signature

    by_classification = Counter(
        item.get("classification", "unknown") for item in candidates
    )
    by_signal = Counter(
        signal for item in candidates for signal in item.get("signals", [])
    )
    by_signature = Counter(
        f"{item.get('classification', 'unknown')}|{bucket_signature(item)}"
        for item in candidates
    )

    buckets = {}
    grouped = defaultdict(list)
    for item in candidates:
        key = (
            f"{item.get('classification', 'unknown')}|"
            f"{bucket_signature(item)}"
        )
        grouped[key].append(item)

    for key, items in sorted(grouped.items()):
        rep = items[0]
        buckets[key] = {
            "count": len(items),
            "classification": rep.get("classification"),
            "signature": bucket_signature(rep),
            "raw_signature": rep.get("signature"),
            "signals": rep.get("signals", []),
            "actual": rep.get("actual"),
            "expected": rep.get("expected"),
            "hash": rep.get("hash"),
            "input": rep.get("input"),
            "extension": rep.get("extension"),
            "eid": rep.get("eid"),
            "fid": rep.get("fid"),
            "trap": rep.get("trap"),
            "notes": rep.get("notes", []),
            "log_path": rep.get("log_path"),
            "output_excerpt": rep.get("output_excerpt", "")[-1200:],
        }
        stability = hang_stability_entry(rep)
        if stability:
            buckets[key]["hang_stability"] = stability
        minimized = hang_minimize_entry(rep)
        if minimized:
            buckets[key]["hang_minimize"] = minimized

    summary = {
        "total_results": len(results),
        "candidate_count": len(candidates),
        "by_classification": dict(by_classification),
        "by_signal": dict(by_signal),
        "by_signature": dict(by_signature),
        "buckets": buckets,
    }
    if hang_stability:
        summary["hang_stability"] = {
            "total_cases": hang_stability.get("total_cases", 0),
            "stable_hang_cases": hang_stability.get("stable_hang_cases", 0),
            "flaky_hang_cases": hang_stability.get("flaky_hang_cases", 0),
            "non_hang_cases": hang_stability.get("non_hang_cases", 0),
        }
    if hang_minimize:
        summary["hang_minimize"] = {
            "total_cases": hang_minimize.get("total_cases", 0),
            "successful_cases": hang_minimize.get("successful_cases", 0),
            "failed_cases": hang_minimize.get("failed_cases", 0),
            "minimized_cases": hang_minimize.get("minimized_cases", 0),
            "unique_semantic_signatures": hang_minimize.get("unique_semantic_signatures", 0),
            "reduced_cases": hang_minimize.get("reduced_cases", 0),
        }
    return summary


def write_replay_summary_markdown(summary, output: Path, label: str):
    lines = [
        f"# {label} Replay Summary",
        "",
        f"- Total cases: {summary['total']}",
        f"- Exact matches: {summary['matching']}",
        f"- Timed out replays: {summary['timed_out']}",
        f"- Interesting candidates: {summary['interesting']}",
        "",
        "## Expected",
        "",
    ]
    for key, value in sorted(summary["by_expected"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Actual", ""]
    for key, value in sorted(summary["by_actual"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Classification", ""]
    for key, value in sorted(summary["by_classification"].items()):
        lines.append(f"- `{key}`: {value}")
    output.write_text("\n".join(lines) + "\n")


def write_bug_markdown(summary, output: Path, label: str):
    lines = [
        f"# {label} Bug Report",
        "",
        f"- Total replayed cases: {summary['total_results']}",
        f"- Bug candidates: {summary['candidate_count']}",
        "",
        "## By Classification",
        "",
    ]
    for key, value in sorted(summary["by_classification"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## By Signal", ""]
    for key, value in sorted(summary["by_signal"].items()):
        lines.append(f"- `{key}`: {value}")
    if summary.get("hang_stability"):
        lines += ["", "## Hang Stability", ""]
        for key, value in sorted(summary["hang_stability"].items()):
            lines.append(f"- `{key}`: {value}")
    if summary.get("hang_minimize"):
        lines += ["", "## Hang Minimization", ""]
        for key, value in sorted(summary["hang_minimize"].items()):
            lines.append(f"- `{key}`: {value}")
    lines += ["", "## Representative Buckets", ""]
    for key, bucket in summary["buckets"].items():
        trap = bucket.get("trap") or {}
        trap_text = ", ".join(f"{name}={value}" for name, value in trap.items()) or "none"
        log_path = bucket.get("log_path") or "none"
        hang_stability = bucket.get("hang_stability")
        stability_text = "none"
        if hang_stability:
            stability_text = (
                f"{hang_stability.get('label', 'unknown')} "
                f"{hang_stability.get('hang_count', 0)}/{hang_stability.get('attempts', 0)}"
            )
        hang_minimize = bucket.get("hang_minimize")
        minimize_text = "none"
        if hang_minimize:
            minimize_text = (
                f"{hang_minimize.get('status', 'unknown')} "
                f"{hang_minimize.get('original_instruction_count', 0)}->"
                f"{hang_minimize.get('minimized_instruction_count', 0)} "
                f"{hang_minimize.get('output', 'none')}"
            )
        semantic_text = (
            hang_minimize.get("semantic_signature", "none")
            if hang_minimize
            else "none"
        )
        lines.append(
            f"- `{key}` x{bucket['count']} -> `{bucket['input']}` | actual={bucket['actual']} expected={bucket['expected']} | signals={','.join(bucket['signals']) or 'none'} | trap={trap_text} | stability={stability_text} | semantic={semantic_text} | minimized={minimize_text} | log={log_path}"
        )
    output.write_text("\n".join(lines) + "\n")


def triage_cli(default_label: str = "SBI") -> int:
    parser = argparse.ArgumentParser(description="Triage SBI sbifuzz result directories")
    parser.add_argument("result_dir", type=Path, help="Result directory containing *.toml and .raw/")
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary path")
    parser.add_argument("--md-out", type=Path, help="Optional Markdown summary path")
    parser.add_argument("--label", default=default_label, help="Label used in Markdown headings")
    args = parser.parse_args()

    cases = [load_case(path) for path in sorted(args.result_dir.glob("*.toml"))]
    summary = summarize_triage(cases)
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    if args.md_out:
        write_triage_markdown(summary, args.md_out, args.label)

    print(encoded, end="")
    return 0


def replay_cli(default_label: str = "SBI") -> int:
    parser = argparse.ArgumentParser(description="Replay SBI result directories using helper run")
    parser.add_argument("target", type=Path)
    parser.add_argument("injector", type=Path)
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument("--all", action="store_true", help="Replay all TOML cases in the result directory")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--prefer-raw-exec", action="store_true")
    parser.add_argument("--helper-bin", help="Path to a prebuilt helper binary")
    parser.add_argument("--timeout-secs", type=int, default=20)
    parser.add_argument("--smp", type=int, default=1, help="Replay with the same QEMU -smp topology")
    parser.add_argument("--log-dir", type=Path, help="Optional directory to store full replay logs")
    parser.add_argument("--label", default=default_label, help="Reserved label for downstream tooling")
    args = parser.parse_args()

    cases = [load_case(path) for path in sorted(args.result_dir.glob("*.toml"))]
    if not args.all:
        cases = cases[: args.limit]

    helper_cmd = resolve_helper_cmd(args.helper_bin)
    results = [
        replay_case(
            case,
            args.target,
            args.injector,
            args.prefer_raw_exec,
            helper_cmd,
            args.timeout_secs,
            args.smp,
            args.log_dir,
        )
        for case in cases
    ]
    summary = {
        "label": args.label,
        "result_dir": str(args.result_dir),
        "total": len(results),
        "matching": sum(1 for item in results if item["match"]),
        "interesting": sum(1 for item in results if item["interesting"]),
        "by_actual": dict(Counter(item["actual"] for item in results)),
        "by_classification": dict(Counter(item["classification"] for item in results)),
        "results": results,
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


def summarize_replay_cli(default_label: str = "SBI") -> int:
    parser = argparse.ArgumentParser(description="Summarize replay-sbi-results JSON output")
    parser.add_argument("input", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--label", default=default_label, help="Label used in Markdown headings")
    args = parser.parse_args()

    data = json.loads(args.input.read_text())
    results = data.get("results", [])
    by_expected = Counter(item.get("expected", "Unknown") for item in results)
    by_actual = Counter(item.get("actual", "Unknown") for item in results)
    by_classification = Counter(item.get("classification", "unknown") for item in results)
    exact_matches = sum(1 for item in results if item.get("match"))
    timed_out = sum(1 for item in results if item.get("timed_out"))
    interesting = sum(1 for item in results if item.get("interesting"))

    summary = {
        "total": len(results),
        "matching": exact_matches,
        "interesting": interesting,
        "timed_out": timed_out,
        "by_expected": dict(by_expected),
        "by_actual": dict(by_actual),
        "by_classification": dict(by_classification),
    }

    if args.md_out:
        write_replay_summary_markdown(summary, args.md_out, args.label)

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def report_bugs_cli(default_label: str = "SBI") -> int:
    parser = argparse.ArgumentParser(description="Summarize replay-sbi-results JSON into bug buckets")
    parser.add_argument("input", type=Path)
    parser.add_argument("--hang-stability", type=Path)
    parser.add_argument("--hang-minimize", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--label", default=default_label, help="Label used in Markdown headings")
    args = parser.parse_args()

    data = json.loads(args.input.read_text())
    results = data.get("results", [])
    hang_stability = (
        json.loads(args.hang_stability.read_text()) if args.hang_stability else None
    )
    hang_minimize = (
        json.loads(args.hang_minimize.read_text()) if args.hang_minimize else None
    )
    summary = summarize_bug_report(results, hang_stability, hang_minimize)
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    if args.md_out:
        write_bug_markdown(summary, args.md_out, args.label)
    print(encoded, end="")
    return 0
