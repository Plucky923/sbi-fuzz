#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import subprocess
import tomllib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

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
SEQUENCE_MAGIC = b"SBISEQ\x00\x00"
SEQUENCE_RESULT_KINDS = {"ok", "interesting", "expectation_failed", "match", "divergence", "capability_mismatch"}
ARGUMENT_KIND_CODES = {
    "value": "v",
    "address": "a",
    "address_low": "l",
    "address_high": "h",
    "size": "s",
    "count": "c",
    "flags": "f",
    "hart_id": "i",
    "hart_mask_address": "m",
    "suspend_type": "t",
    "opaque": "o",
}
CLASSIFICATION_PRIORITY = {
    "sanitizer": 0,
    "crash": 1,
    "hang": 2,
    "mismatch": 3,
    "invalid_input": 4,
    "ok": 5,
}


def get_extension_name(eid: int) -> str:
    return {
        0x10: "base",
        0x54494D45: "time",
        0x735049: "ipi",
        0x52464E43: "rfence",
        0x48534D: "hsm",
        0x53525354: "reset",
        0x4442434E: "console",
        0x504D55: "pmu",
    }.get(eid, "unknown")


def format_hex_u64(value: int) -> str:
    return f"0x{int(value):X}"


def schema_compact_signature(schema_values: list[str]) -> str:
    return "".join(ARGUMENT_KIND_CODES.get(kind, "v") for kind in schema_values)


def nonzero_mask(arg_values: list[int]) -> str:
    return "".join("1" if value != 0 else "0" for value in arg_values)


def address_value_class(value: int) -> str:
    if value == 0:
        return "z"
    if value & 0x7:
        return "u"
    if value & 0xFFF == 0:
        return "p"
    return "n"


def address_mask(schema_values: list[str], arg_values: list[int]) -> str:
    encoded = []
    for kind, value in zip(schema_values, arg_values):
        if kind in ADDRESS_KINDS:
            encoded.append(address_value_class(value))
        else:
            encoded.append("-")
    return "".join(encoded)


def build_legacy_semantic_signature(eid: int, fid: int, schema_values: list[str], arg_values: list[int]) -> str:
    return (
        f"call:{format_hex_u64(eid)}:{format_hex_u64(fid)}:"
        f"schema={schema_compact_signature(schema_values)}:"
        f"nz={nonzero_mask(arg_values)}:"
        f"addr={address_mask(schema_values, arg_values)}"
    )


def sequence_step_summary(step: dict) -> str:
    kind = step.get("kind", "unknown")
    label = step.get("label", "")
    if kind == "call":
        return f"call:{format_hex_u64(step.get('eid', 0))}:{format_hex_u64(step.get('fid', 0))}:{label}"
    if kind in {"set_target_hart", "set_hart_state"}:
        return f"{kind}:{step.get('hart_id', '?')}:{label}"
    if kind == "parse_fdt":
        return f"parse_fdt:{step.get('object', '')}:{label}"
    if kind == "busy_wait":
        return f"busy_wait:{step.get('iterations', 0)}"
    if kind == "set_platform_fault":
        return f"set_platform_fault:{step.get('profile', {}).get('mode', '')}"
    if kind == "set_privilege":
        return f"set_privilege:{step.get('privilege', '')}"
    return f"{kind}:{label}"


def build_sequence_semantic_signature(steps: list[dict]) -> str:
    return ";".join(sequence_step_summary(step) for step in steps)


def build_sequence_temporal_signature(steps: list[dict]) -> str:
    material = ";".join(sequence_step_summary(step) for step in steps)
    digest = hashlib.sha256(material.encode()).hexdigest()[:12]
    return f"seq:{len(steps)}:{digest}"


def stability_details(item: dict, stability: dict | None = None) -> tuple[str, float]:
    if stability:
        score = stability.get("stability_score")
        if score is None:
            score = stability.get("stable_ratio", 0.0)
        return stability.get("label", "unknown"), float(score)
    if item.get("interesting") and item.get("classification") != "hang":
        return "single_replay", 1.0
    return "unrated", 0.0


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_affected_target(value: str | None) -> str:
    normalized = (value or "unknown").strip().lower()
    if "opensbi" in normalized or "open_sbi" in normalized or "open-sbi" in normalized:
        return "opensbi"
    if "rustsbi" in normalized or "rust_sbi" in normalized or "rust-sbi" in normalized:
        return "rustsbi"
    if normalized in {"open_sbi", "opensbi", "open-sbi"}:
        return "opensbi"
    if normalized in {"rust_sbi", "rustsbi", "rust-sbi"}:
        return "rustsbi"
    if normalized in {"both", "diff"}:
        return "both"
    return normalized or "unknown"


def infer_firmware_target_kind(target: Path) -> str:
    target_text = str(target).lower()
    if "opensbi" in target_text or "fw_dynamic.bin" in target_text:
        return "opensbi"
    if "rustsbi" in target_text or "prototyper" in target_text:
        return "rustsbi"
    return "unknown"


def affected_target_for_item(item: dict, target_hint: str | None = None) -> str:
    classification = item.get("classification", "unknown")
    if classification in {"mismatch", "match", "capability_mismatch"}:
        return "both"
    normalized = normalize_affected_target(
        item.get("affected_target") or item.get("impl_kind") or item.get("target_kind")
    )
    if normalized == "unknown" and target_hint:
        return normalize_affected_target(target_hint)
    return normalized


def impact_for_classification(classification: str | None) -> str:
    if classification in {"sanitizer", "crash"}:
        return "crash"
    if classification == "hang":
        return "hang"
    if classification in {
        "mismatch",
        "capability_mismatch",
        "expectation_failed",
        "invalid_input",
        "non_standard_error",
        "fdt_error",
    }:
        return "spec_violation"
    return classification or "unknown"


def bug_id_for_dedup_key(dedup_key: str) -> str:
    return f"bug-{hashlib.sha256(dedup_key.encode()).hexdigest()[:12]}"


def repro_stability_metadata(item: dict, stability: dict | None = None) -> dict:
    label, stable_ratio = stability_details(item, stability)
    attempts = 0
    if stability:
        attempts = int(stability.get("attempts") or 0)
    elif label == "single_replay":
        attempts = 1
    return {
        "attempts": attempts,
        "label": label,
        "stable_ratio": stable_ratio,
    }


def load_sequence_program(path: Path):
    raw = path.read_bytes()
    if raw.startswith(SEQUENCE_MAGIC):
        if len(raw) < len(SEQUENCE_MAGIC) + 4:
            raise ValueError(f"sequence input too short: {path}")
        payload_len = int.from_bytes(raw[len(SEQUENCE_MAGIC):len(SEQUENCE_MAGIC) + 4], "little")
        payload = raw[len(SEQUENCE_MAGIC) + 4:]
        if len(payload) != payload_len:
            raise ValueError(
                f"sequence payload length mismatch for {path}: header={payload_len} actual={len(payload)}"
            )
        return json.loads(payload.decode())
    return json.loads(raw.decode())


def load_case(path: Path):
    if path.suffix == ".seq":
        return load_sequence_case(path)

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
    semantic_signature = build_legacy_semantic_signature(eid, fid, schema_values, arg_values)
    return {
        "path": str(path),
        "input_kind": "legacy_call",
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
        "instruction_signature": None,
        "semantic_signature": semantic_signature,
        "temporal_signature": f"single:{format_hex_u64(eid)}:{format_hex_u64(fid)}",
        "state_signature": None,
        "memory_signature": None,
    }


def load_sequence_case(path: Path):
    data = load_sequence_program(path)
    metadata = data.get("metadata", {})
    env = data.get("env", {})
    steps = data.get("steps", [])
    first_call = next((step for step in steps if step.get("kind") == "call"), None)
    source = metadata.get("source", "")
    match = SOURCE_RE.search(source)
    hash_value = (
        match.group(1)
        if match
        else hashlib.sha256(path.read_bytes()).hexdigest()[:8]
    )
    status = match.group(2) if match else "Ok"
    eid = first_call.get("eid", 0) if first_call else 0
    fid = first_call.get("fid", 0) if first_call else 0
    extension = get_extension_name(eid)
    flags = ["sequence"]
    if data.get("memory"):
        flags.append("has_memory_objects")
    if len([step for step in steps if step.get("kind") == "call"]) > 1:
        flags.append("multi_call")
    if env.get("smp", 1) > 1:
        flags.append("multi_hart")
    if any(step.get("kind") == "parse_fdt" for step in steps):
        flags.append("has_fdt")
    if any(step.get("kind") == "set_platform_fault" for step in steps):
        flags.append("platform_fault")
    if any(
        step.get("kind") in {"set_hart_state", "set_privilege", "set_platform_fault", "parse_fdt"}
        for step in steps
    ):
        flags.append("host_only_steps")
    impl_hint = env.get("impl_hint")
    if impl_hint:
        flags.append(f"impl_hint:{impl_hint}")
    semantic_signature = build_sequence_semantic_signature(steps)
    return {
        "path": str(path),
        "input_kind": "sequence",
        "sequence": path,
        "raw_exec": None,
        "raw_exec_exists": False,
        "hash": hash_value,
        "status": status,
        "expected": "ok",
        "extension": extension,
        "sequence_name": metadata.get("name") or path.stem,
        "source": source,
        "eid": eid,
        "fid": fid,
        "args": [0, 0, 0, 0, 0, 0],
        "schema": ["value"] * 6,
        "address_slots": [],
        "nonzero_slots": [],
        "flags": flags,
        "impl_hint": impl_hint,
        "instruction_signature": None,
        "semantic_signature": semantic_signature,
        "temporal_signature": build_sequence_temporal_signature(steps),
        "state_signature": None,
        "memory_signature": None,
    }


def sequence_target_matches(case: dict, target_kind: str):
    impl_hint = case.get("impl_hint")
    if not impl_hint:
        return True
    normalized = str(impl_hint).replace("_", "").lower()
    return normalized == target_kind.lower()


def collect_cases(result_dir: Path):
    cases = [load_case(path) for path in sorted(result_dir.glob("*.toml"))]
    cases.extend(load_case(path) for path in sorted(result_dir.glob("*.seq")))
    return cases


def helper_supports_subcommand(helper_path: str, subcommand: str) -> bool:
    proc = subprocess.run(
        [helper_path, "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    pattern = re.compile(rf"(?m)^  {re.escape(subcommand)}(?:\s|$)")
    return bool(pattern.search(proc.stdout))


def build_qemu_helper() -> str:
    subprocess.run(
        ["cargo", "build", "-q", "-p", "helper", "--release", "--features", "qemu"],
        cwd=REPO_ROOT,
        check=True,
    )
    return str(REPO_ROOT / "target/release/helper")


def resolve_helper_cmd(explicit: str | None, required_subcommand: str = "run"):
    helper_path = explicit or str(REPO_ROOT / "target/release/helper")
    if Path(helper_path).exists() and helper_supports_subcommand(helper_path, required_subcommand):
        return [helper_path]
    rebuilt = build_qemu_helper()
    if explicit and Path(helper_path).exists():
        return [explicit]
    return [rebuilt]


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
            "instruction_signature": f"invalid_input:{reason}",
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
        instruction_signature = "trap:" + ":".join(
            [
                trap.get("mcause", "?"),
                trap.get("mepc", "?"),
                trap.get("mtval", "?"),
                trap.get("hart_id", "?"),
                ",".join(signals) or actual,
            ]
        )
        signature = "trap:" + ":".join(
            [
                trap.get("mcause", "?"),
                trap.get("mepc", "?"),
                trap.get("mtval", "?"),
                ",".join(signals) or actual,
            ]
        )
    elif signals:
        instruction_signature = "signals:" + ",".join(sorted(signals))
        signature = "signals:" + ",".join(sorted(signals))
    else:
        instruction_signature = f"exit:{actual}"
        signature = f"exit:{actual}"

    return {
        "signals": signals,
        "trap": trap or None,
        "notes": notes,
        "classification": classification,
        "signature": signature,
        "instruction_signature": instruction_signature,
        "interesting": classification != "ok",
    }


def summarize_triage(cases):
    by_status = Counter(case["status"] for case in cases)
    by_extension = Counter(case["extension"] for case in cases)
    by_input_kind = Counter(case.get("input_kind", "legacy_call") for case in cases)
    by_bucket = Counter(bucket_name(case) for case in cases)
    flag_counts = Counter(flag for case in cases for flag in case["flags"])

    representatives = {}
    for case in cases:
        bucket = bucket_name(case)
        representatives.setdefault(bucket, case)

    return {
        "total_cases": len(cases),
        "by_status": dict(by_status),
        "by_extension": dict(by_extension),
        "by_input_kind": dict(by_input_kind),
        "by_bucket": dict(by_bucket),
        "flag_counts": dict(flag_counts),
        "representatives": {
            bucket: {
                "path": rep["path"],
                "input_kind": rep.get("input_kind", "legacy_call"),
                "eid": f"0x{rep['eid']:X}",
                "fid": f"0x{rep['fid']:X}",
                "flags": rep["flags"],
                "raw_exec_exists": rep["raw_exec_exists"],
                "semantic_signature": rep.get("semantic_signature"),
                "temporal_signature": rep.get("temporal_signature"),
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
    lines += ["", "## By Input Kind", ""]
    for key, value in sorted(summary.get("by_input_kind", {}).items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Flags", ""]
    for key, value in sorted(summary["flag_counts"].items()):
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Representative Buckets", ""]
    for bucket, rep in summary["representatives"].items():
        lines.append(
            f"- `{bucket}` -> `{rep['path']}` | eid={rep['eid']} fid={rep['fid']} | flags={','.join(rep['flags']) or 'none'} | semantic={rep.get('semantic_signature') or 'none'} | temporal={rep.get('temporal_signature') or 'none'} | raw_exec={rep['raw_exec_exists']}"
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


def bucket_name(case: dict):
    if case.get("input_kind") == "sequence":
        return f"sequence:{case.get('sequence_name', 'unnamed')}:{case['status']}"
    return f"{case['extension']}:{case['fid']:x}:{case['status']}"


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


def extract_json_document(output: str):
    output = output.strip()
    if not output:
        return None
    start = output.find("{")
    end = output.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        return json.loads(output[start : end + 1])
    except json.JSONDecodeError:
        return None


def run_helper_sequence(helper_cmd, input_path: Path, target_kind: str, timeout_secs: int):
    env = os.environ.copy()
    env.setdefault("LLVM_CONFIG_PATH", "/usr/bin/llvm-config-18")
    env.setdefault("CC", "clang-18")
    env.setdefault("CXX", "clang++-18")
    env.setdefault("LIBCLANG_PATH", "/usr/lib/llvm-18/lib")
    cmd = helper_cmd + [
        "run-sequence",
        "--target-kind",
        target_kind,
        str(input_path),
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
        payload = extract_json_document(proc.stdout) or extract_json_document(output)
        actual_kind = payload.get("classification", "Unknown") if payload else "Unknown"
        timed_out = False
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = stdout + stderr
        payload = extract_json_document(output)
        actual_kind = "TimeoutExpired"
        timed_out = True
        returncode = None

    return {
        "output": output,
        "actual_kind": actual_kind,
        "timed_out": timed_out,
        "returncode": returncode,
        "payload": payload,
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
        "input_kind": case.get("input_kind", "legacy_call"),
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
        "instruction_signature": classification["instruction_signature"],
        "interesting": classification["interesting"],
        "impl_kind": None,
        "supported_by_target": None,
        "state_signature": case.get("state_signature"),
        "memory_signature": case.get("memory_signature"),
        "semantic_signature": case.get("semantic_signature"),
        "temporal_signature": case.get("temporal_signature"),
        "signature_layers": {
            "instruction": classification["instruction_signature"],
            "semantic": case.get("semantic_signature"),
            "temporal": case.get("temporal_signature"),
            "state": case.get("state_signature"),
            "memory": case.get("memory_signature"),
        },
        "log_path": write_replay_log(log_dir, case, run_result["output"]),
        "output_excerpt": run_result["output"][-4000:],
    }


def build_sequence_replay_result(case: dict, input_path: Path, run_result: dict, log_dir: Path | None):
    payload = run_result.get("payload") or {}
    instruction_signature = payload.get("instruction_signature", payload.get("signature", run_result["actual_kind"]))
    semantic_signature = payload.get("semantic_signature", case.get("semantic_signature"))
    temporal_signature = payload.get("temporal_signature", case.get("temporal_signature"))
    state_signature = payload.get("state_signature", case.get("state_signature"))
    memory_signature = payload.get("memory_signature", case.get("memory_signature"))
    return {
        "input": str(input_path),
        "input_kind": "sequence",
        "used_raw_exec": False,
        "expected": case["expected"],
        "actual": run_result["actual_kind"],
        "match": run_result["actual_kind"] == case["expected"],
        "returncode": run_result["returncode"],
        "hash": case["hash"],
        "extension": case["extension"],
        "eid": f"0x{case['eid']:X}",
        "fid": f"0x{case['fid']:X}",
        "timed_out": run_result["timed_out"],
        "signals": [],
        "trap": None,
        "notes": [],
        "classification": payload.get("classification", run_result["actual_kind"]),
        "signature": payload.get("signature", run_result["actual_kind"]),
        "instruction_signature": instruction_signature,
        "interesting": bool(payload.get("interesting", run_result["actual_kind"] != "ok")),
        "impl_kind": payload.get("impl_kind"),
        "supported_by_target": payload.get("supported_by_target"),
        "state_signature": state_signature,
        "memory_signature": memory_signature,
        "semantic_signature": semantic_signature,
        "temporal_signature": temporal_signature,
        "signature_layers": {
            "instruction": instruction_signature,
            "semantic": semantic_signature,
            "temporal": temporal_signature,
            "state": state_signature,
            "memory": memory_signature,
        },
        "step_count": payload.get("step_count"),
        "step_classifications": [step.get("classification") for step in payload.get("steps", [])],
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


def replay_sequence_case(
    case: dict,
    target_kind: str,
    helper_cmd,
    timeout_secs: int,
    log_dir: Path | None,
):
    input_path = case["sequence"]
    run_result = run_helper_sequence(helper_cmd, input_path, target_kind, timeout_secs)
    return build_sequence_replay_result(case, input_path, run_result, log_dir)


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
        "input_kind": entry.get("input_kind", "legacy_call"),
        "semantic_signature": entry.get("semantic_signature"),
        "temporal_signature": entry.get("temporal_signature"),
        "state_signature": entry.get("state_signature"),
        "memory_signature": entry.get("memory_signature"),
    }
    run_result = run_helper_input(helper_cmd, target, injector, input_path, timeout_secs, smp)
    return build_replay_result(
        case,
        input_path,
        bool(entry.get("used_raw_exec", False)),
        run_result,
        log_dir,
    )


def summarize_bug_report(results, hang_stability=None, hang_minimize=None, target_hint: str | None = None):
    candidates = [item for item in results if item.get("interesting")]
    observed_at = utc_now()

    def hang_stability_entry(item: dict):
        if not hang_stability:
            return None
        return hang_stability.get("cases_by_hash", {}).get(item.get("hash"))

    def hang_minimize_entry(item: dict):
        if not hang_minimize:
            return None
        return hang_minimize.get("cases_by_hash", {}).get(item.get("hash"))

    def resolved_signatures(item: dict):
        stability = hang_stability_entry(item) or {}
        minimized = hang_minimize_entry(item) or {}
        instruction_signature = item.get("instruction_signature") or item.get("signature", "unknown")
        semantic_signature = minimized.get("semantic_signature") or item.get("semantic_signature")
        temporal_signature = minimized.get("temporal_signature") or item.get("temporal_signature")
        state_signature = item.get("state_signature")
        memory_signature = item.get("memory_signature")
        stability_label, stability_score = stability_details(item, stability)
        return {
            "instruction_signature": instruction_signature,
            "semantic_signature": semantic_signature,
            "temporal_signature": temporal_signature,
            "state_signature": state_signature,
            "memory_signature": memory_signature,
            "stability_label": stability_label,
            "stability_score": stability_score,
        }

    def bucket_signature(item: dict):
        layers = resolved_signatures(item)
        parts = [layers["instruction_signature"]]
        if layers["semantic_signature"]:
            parts.append(f"semantic:{layers['semantic_signature']}")
        if item.get("input_kind") == "sequence" and layers["temporal_signature"]:
            parts.append(f"temporal:{layers['temporal_signature']}")
        return "|".join(parts)

    def representative_priority(item: dict):
        layers = resolved_signatures(item)
        trap = item.get("trap") or {}
        return (
            layers["stability_score"],
            1 if trap else 0,
            len(item.get("signals", [])),
            1 if layers["semantic_signature"] else 0,
            1 if layers["state_signature"] else 0,
            1 if layers["memory_signature"] else 0,
            item.get("hash", ""),
        )

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

    ordered_groups = []
    for key, items in grouped.items():
        rep = max(items, key=representative_priority)
        layers = resolved_signatures(rep)
        ordered_groups.append((key, items, rep, layers))

    ordered_groups.sort(
        key=lambda entry: (
            CLASSIFICATION_PRIORITY.get(entry[2].get("classification", "unknown"), 99),
            -entry[3]["stability_score"],
            -len(entry[1]),
            entry[0],
        )
    )

    for key, items, rep, layers in ordered_groups:
        stability = hang_stability_entry(rep)
        affected_target = affected_target_for_item(rep, target_hint)
        dedup_key = "|".join(
            [
                affected_target,
                rep.get("classification", "unknown"),
                bucket_signature(rep),
            ]
        )
        buckets[key] = {
            "count": len(items),
            "bug_id": bug_id_for_dedup_key(dedup_key),
            "classification": rep.get("classification"),
            "impact": impact_for_classification(rep.get("classification")),
            "affected_target": affected_target,
            "dedup_key": dedup_key,
            "signature": bucket_signature(rep),
            "raw_signature": rep.get("signature"),
            "instruction_signature": layers["instruction_signature"],
            "impl_kind": rep.get("impl_kind"),
            "input_kind": rep.get("input_kind"),
            "supported_by_target": rep.get("supported_by_target"),
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
            "state_signature": layers["state_signature"],
            "memory_signature": layers["memory_signature"],
            "semantic_signature": layers["semantic_signature"],
            "temporal_signature": layers["temporal_signature"],
            "stability_label": layers["stability_label"],
            "stability_score": layers["stability_score"],
            "repro_stability": repro_stability_metadata(rep, stability),
            "first_seen": observed_at,
            "last_seen": observed_at,
            "output_excerpt": rep.get("output_excerpt", "")[-1200:],
        }
        if stability:
            buckets[key]["hang_stability"] = stability
        minimized = hang_minimize_entry(rep)
        if minimized:
            buckets[key]["hang_minimize"] = minimized

    summary = {
        "schema_version": 1,
        "generated_at_utc": observed_at,
        "report_type": "bug_report",
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
            hang_minimize.get("semantic_signature", bucket.get("semantic_signature", "none"))
            if hang_minimize
            else bucket.get("semantic_signature", "none")
        )
        state_text = bucket.get("state_signature") or "none"
        memory_text = bucket.get("memory_signature") or "none"
        temporal_text = bucket.get("temporal_signature") or "none"
        lines.append(
            f"- `{bucket['bug_id']}` x{bucket['count']} -> `{bucket['input']}` | kind={bucket.get('input_kind', 'legacy_call')} impl={bucket.get('impl_kind') or 'none'} target={bucket.get('affected_target', 'unknown')} impact={bucket.get('impact', 'unknown')} actual={bucket['actual']} expected={bucket['expected']} | signals={','.join(bucket['signals']) or 'none'} | trap={trap_text} | instruction={bucket.get('instruction_signature') or bucket.get('raw_signature') or 'none'} | state={state_text} | memory={memory_text} | temporal={temporal_text} | stability={stability_text} score={bucket.get('stability_score', 0.0):.2f} | semantic={semantic_text} | minimized={minimize_text} | log={log_path}"
        )
    output.write_text("\n".join(lines) + "\n")


def triage_cli(default_label: str = "SBI") -> int:
    parser = argparse.ArgumentParser(description="Triage SBI sbifuzz result directories")
    parser.add_argument("result_dir", type=Path, help="Result directory containing *.toml and .raw/")
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary path")
    parser.add_argument("--md-out", type=Path, help="Optional Markdown summary path")
    parser.add_argument("--label", default=default_label, help="Label used in Markdown headings")
    args = parser.parse_args()

    cases = collect_cases(args.result_dir)
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

    cases = collect_cases(args.result_dir)
    if not args.all:
        cases = cases[: args.limit]

    helper_cmd = resolve_helper_cmd(args.helper_bin, required_subcommand="run")
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
    target_kind = infer_firmware_target_kind(args.target)
    if target_kind != "unknown":
        for item in results:
            if not item.get("impl_kind"):
                item["impl_kind"] = target_kind
    summary = {
        "label": args.label,
        "target_kind": target_kind,
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


def triage_sequence_cli(default_label: str = "SBI Sequence") -> int:
    parser = argparse.ArgumentParser(description="Triage sequence result directories")
    parser.add_argument("result_dir", type=Path, help="Result directory containing *.seq inputs")
    parser.add_argument("--json-out", type=Path, help="Optional JSON summary path")
    parser.add_argument("--md-out", type=Path, help="Optional Markdown summary path")
    parser.add_argument("--label", default=default_label, help="Label used in Markdown headings")
    args = parser.parse_args()

    cases = [load_sequence_case(path) for path in sorted(args.result_dir.glob("*.seq"))]
    summary = summarize_triage(cases)
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    if args.md_out:
        write_triage_markdown(summary, args.md_out, args.label)
    print(encoded, end="")
    return 0


def replay_sequence_cli(default_label: str = "SBI Sequence") -> int:
    parser = argparse.ArgumentParser(description="Replay sequence directories using helper run-sequence")
    parser.add_argument("target_kind", choices=["opensbi", "rustsbi"])
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--all", action="store_true", help="Replay all sequence inputs in the result directory")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--helper-bin", help="Path to a prebuilt helper binary")
    parser.add_argument("--timeout-secs", type=int, default=20)
    parser.add_argument("--log-dir", type=Path, help="Optional directory to store full replay logs")
    parser.add_argument("--label", default=default_label, help="Label used by downstream tooling")
    args = parser.parse_args()

    cases = [
        case
        for case in (load_sequence_case(path) for path in sorted(args.result_dir.glob("*.seq")))
        if sequence_target_matches(case, args.target_kind)
    ]
    if not args.all:
        cases = cases[: args.limit]

    helper_cmd = resolve_helper_cmd(args.helper_bin, required_subcommand="run-sequence")
    results = [
        replay_sequence_case(case, args.target_kind, helper_cmd, args.timeout_secs, args.log_dir)
        for case in cases
    ]
    summary = {
        "label": args.label,
        "target_kind": args.target_kind,
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
    target_hint = data.get("target_kind") or args.label
    summary = summarize_bug_report(results, hang_stability, hang_minimize, target_hint)
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded)
    if args.md_out:
        write_bug_markdown(summary, args.md_out, args.label)
    print(encoded, end="")
    return 0
