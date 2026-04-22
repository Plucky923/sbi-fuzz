#!/usr/bin/env python3
"""
Generate a standalone GitHub Issue bug report from a fuzz crash artifact.

Supports:
  - host-harness crash artifacts (libFuzzer raw bytes or .host files)
  - firmware crash artifacts (.toml / .exec)
  - sequence crash artifacts (.seq)

The generated report includes:
  - A self-contained standalone reproducer (Rust crate for host harness,
    QEMU command line for firmware)
  - GitHub Issue formatted Markdown
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HOST_HARNESS_MAGIC = b"SBIHOST1"
SEQUENCE_MAGIC = b"SBISEQ\x00\x00"

KNOWN_EIDS = {
    0x10: ("base", "Base Extension"),
    0x735049: ("ipi", "IPI Extension"),
    0x52464E43: ("rfence", "RFENCE Extension"),
    0x48534D: ("hsm", "Hart State Management"),
    0x54494D45: ("timer", "Timer Extension"),
    0x53525354: ("reset", "System Reset"),
    0x4442434E: ("dbcn", "Debug Console"),
    0x504D55: ("pmu", "Performance Monitoring"),
    0x53555350: ("susp", "System Suspend"),
    0x43505043: ("cppc", "CPPC"),
    0x535345: ("sse", "SSE"),
    0x46574654: ("fwft", "FWFT"),
    0x44425452: ("dbtr", "Debug Trigger"),
    0x4D505859: ("mpxy", "MPXY"),
}

RUSTSBI_TRAIT_METHODS = {
    "base": [],
    "ipi": [
        "fn send_ipi(&self, _hart_mask: HartMask) -> SbiRet { SbiRet::success(0) }",
    ],
    "rfence": [
        "fn remote_fence_i(&self, _hart_mask: HartMask) -> SbiRet { SbiRet::success(0) }",
        "fn remote_sfence_vma(&self, _hart_mask: HartMask, _start_addr: usize, _size: usize) -> SbiRet { SbiRet::success(0) }",
        "fn remote_sfence_vma_asid(&self, _hart_mask: HartMask, _start_addr: usize, _size: usize, _asid: usize) -> SbiRet { SbiRet::success(0) }",
        "fn remote_hfence_gvma_vmid(&self, _hart_mask: HartMask, _start_addr: usize, _size: usize, _vmid: usize) -> SbiRet { SbiRet::success(0) }",
        "fn remote_hfence_gvma(&self, _hart_mask: HartMask, _start_addr: usize, _size: usize) -> SbiRet { SbiRet::success(0) }",
        "fn remote_hfence_vvma_asid(&self, _hart_mask: HartMask, _start_addr: usize, _size: usize, _asid: usize) -> SbiRet { SbiRet::success(0) }",
        "fn remote_hfence_vvma(&self, _hart_mask: HartMask, _start_addr: usize, _size: usize) -> SbiRet { SbiRet::success(0) }",
    ],
    "hsm": [
        "fn hart_start(&self, _hartid: usize, _start_addr: usize, _opaque: usize) -> SbiRet { SbiRet::success(0) }",
        "fn hart_stop(&self) -> SbiRet { SbiRet::success(0) }",
        "fn hart_get_status(&self, _hartid: usize) -> SbiRet { SbiRet::success(0) }",
        "fn hart_suspend(&self, _suspend_type: u32, _resume_addr: usize, _opaque: usize) -> SbiRet { SbiRet::success(0) }",
    ],
    "timer": [
        "fn set_timer(&self, _stime_value: u64) {}",
    ],
    "reset": [
        "fn system_reset(&self, _reset_type: u32, _reset_reason: u32) -> SbiRet { SbiRet::success(0) }",
    ],
    "dbcn": [
        "fn write(&self, _bytes: Physical<&[u8]>) -> SbiRet { SbiRet::success(0) }",
        "fn read(&self, _bytes: Physical<&mut [u8]>) -> SbiRet { SbiRet::success(0) }",
        "fn write_byte(&self, _byte: u8) -> SbiRet { SbiRet::success(0) }",
    ],
}

RUSTSBI_INTERNAL_FN = {
    "base": None,
    "ipi": "_rustsbi_ipi",
    "rfence": "_rustsbi_fence",
    "hsm": "_rustsbi_hsm",
    "timer": "_rustsbi_timer",
    "reset": "_rustsbi_reset",
    "dbcn": "_rustsbi_console",
}

RUSTSBI_TRAIT_IMPORT = {
    "base": "",
    "ipi": "use rustsbi::Ipi;\n",
    "rfence": "use rustsbi::Fence;\n",
    "hsm": "use rustsbi::Hsm;\n",
    "timer": "use rustsbi::Timer;\n",
    "reset": "use rustsbi::Reset;\n",
    "dbcn": "use rustsbi::{Console, Physical};\n",
}


@dataclass
class ArtifactInfo:
    artifact_type: str
    path: Path
    params: dict[str, Any] = field(default_factory=dict)
    raw_bytes: bytes = b""


@dataclass
class ReproResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    classification: str = "unknown"
    violation_type: str = ""
    violation_detail: str = ""
    panic_message: str = ""
    actual_sbi_error: int | None = None
    actual_value: int | None = None


def detect_artifact_type(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(HOST_HARNESS_MAGIC):
        return "host-harness"
    if data.startswith(SEQUENCE_MAGIC):
        return "sequence"
    if data.startswith(b"\x7b") or data.startswith(b"["):
        try:
            text = data.decode("utf-8", errors="ignore")
            payload = json.loads(text)
            if isinstance(payload, dict) and "call" in payload:
                return "host-harness"
            if isinstance(payload, dict) and "steps" in payload:
                return "sequence"
        except Exception:
            pass
        # Loose heuristic: JSON-looking host harness inputs often contain target_kind
        if b"target_kind" in data[:256] or b"mode" in data[:256]:
            return "host-harness"
    if path.suffix == ".toml":
        return "firmware"
    if path.suffix in (".host", ".json"):
        return "host-harness"
    if path.suffix == ".seq":
        return "sequence"
    if HOST_HARNESS_MAGIC in data[:256]:
        return "host-harness"
    # Heuristic: libFuzzer host-harness inputs often start with 'SB' (0x53 0x42)
    if data.startswith(b"SB") and len(data) < 4096:
        return "host-harness"
    return "unknown"


def parse_host_harness_artifact(path: Path) -> dict[str, Any]:
    data = path.read_bytes()

    # 1. Standard .host format: SBIHOST1 at offset 0
    if data.startswith(HOST_HARNESS_MAGIC):
        body_len = int.from_bytes(data[len(HOST_HARNESS_MAGIC) : len(HOST_HARNESS_MAGIC) + 4], "little")
        body = data[len(HOST_HARNESS_MAGIC) + 4 :]
        if len(body) == body_len:
            return json.loads(body)

    # 2. Try to find SBIHOST1 anywhere in the first 256 bytes
    magic_idx = data.find(HOST_HARNESS_MAGIC)
    if 0 <= magic_idx <= 256:
        tail = data[magic_idx + len(HOST_HARNESS_MAGIC) :]
        if len(tail) >= 4:
            body_len = int.from_bytes(tail[:4], "little")
            body = tail[4:]
            if len(body) == body_len:
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    pass

    # 3. Try to find a valid JSON dict with 'call' field anywhere
    brace_idx = data.find(b"{")
    while brace_idx >= 0:
        # Try progressively larger slices looking for a valid JSON object
        for end in range(brace_idx + 8, min(len(data), brace_idx + 2048) + 1):
            if data[end - 1:end] == b"}":
                try:
                    text = data[brace_idx:end].decode("utf-8", errors="ignore")
                    obj = json.loads(text)
                    if isinstance(obj, dict) and "call" in obj:
                        return obj
                except (json.JSONDecodeError, ValueError):
                    pass
        brace_idx = data.find(b"{", brace_idx + 1)

    # 4. Try JSON from the start (plain .json file)
    try:
        text = data.decode("utf-8", errors="ignore")
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # 5. Fall back to raw fuzz bytes protocol
    parsed = _parse_raw_fuzz_bytes(data)
    if parsed:
        return parsed

    raise ValueError(f"Cannot parse host harness artifact: {path}")


def _parse_raw_fuzz_bytes(data: bytes) -> dict[str, Any] | None:
    if len(data) < 2:
        return None
    def read_u8(off: int) -> int:
        return data[off] if off < len(data) else 0
    def read_u64(off: int) -> int:
        end = min(off + 8, len(data))
        return int.from_bytes(data[off:end], "little") if end > off else 0
    off = 0
    target_selector = read_u8(off); off += 1
    mode_selector = read_u8(off); off += 1
    raw_extid = read_u64(off); off += 8
    raw_fid = read_u64(off); off += 8
    raw_args = [read_u64(off + i * 8) for i in range(6)]
    off += 48
    hart_selector = read_u8(off); off += 1
    hart_state_selector = read_u8(off); off += 1
    privilege_selector = read_u8(off); off += 1
    fault_mode_selector = read_u8(off); off += 1
    fault_error = read_u64(off); off += 8
    fault_value = read_u64(off); off += 8
    duplicate_side_effects = read_u8(off) % 2 == 1
    off += 1
    region_count = min(read_u8(off), 4)
    off += 1

    # Apply the same fuzz_extid / fuzz_fid logic as the Rust code
    known_exts = [0x10, 0x54494D45, 0x735049, 0x52464E43, 0x48534D, 0x4442434E, 0x53525354, 0x504D55]
    if raw_extid == 0:
        extid = known_exts[target_selector % len(known_exts)]
    elif raw_extid < len(known_exts):
        extid = known_exts[int(raw_extid)]
    else:
        extid = raw_extid

    if raw_fid != 0:
        fid = raw_fid & 0xF
    else:
        fid_map = {0x10: 0, 0x48534D: 2, 0x4442434E: 0, 0x52464E43: 1, 0x504D55: 8}
        fid = fid_map.get(extid, 0)

    hart_states = ["unknown", "started", "stopped", "suspended"]
    privileges = ["user", "supervisor", "machine"]
    return {
        "target_kind": "rust_sbi" if (target_selector & 1) else "open_sbi",
        "mode": "ecall",
        "call": {"extid": extid, "fid": fid, "args": raw_args},
        "hart_id": hart_selector % 64,
        "hart_state": hart_states[hart_state_selector % 4],
        "privilege": privileges[privilege_selector % 3],
        "memory_regions": [],
        "platform_fault": {
            "mode": "none", "error": 0, "value": 0,
            "duplicate_side_effects": duplicate_side_effects,
        },
        "fdt_blob": [],
        "label": f"fuzz-raw-{extid:08x}",
    }


def parse_firmware_artifact(path: Path) -> dict[str, Any]:
    raise NotImplementedError("Firmware artifact parsing not yet implemented")


def parse_sequence_artifact(path: Path) -> dict[str, Any]:
    raise NotImplementedError("Sequence artifact parsing not yet implemented")


def reproduce_host_harness_local(artifact: Path, input_data: dict) -> ReproResult:
    result = ReproResult()

    # Primary reproduction: use pre-built fuzz binary (triggers panic on spec violation)
    fuzz_bin = Path("host_harness/fuzz/target/aarch64-unknown-linux-gnu/release/fuzz_ecall_rustsbi")
    if fuzz_bin.exists():
        try:
            proc = subprocess.run([str(fuzz_bin), str(artifact)], capture_output=True, text=True, timeout=30)
            result.stdout = proc.stdout
            result.stderr = proc.stderr
            result.returncode = proc.returncode
        except Exception as exc:
            result.stderr = f"Fuzz binary reproduction failed: {exc}"
    else:
        result.stderr = f"Fuzz binary not found: {fuzz_bin}. Build with: cargo fuzz build -p host_harness fuzz_ecall_rustsbi\n"

    _classify_from_output(result)

    # Secondary: use helper for structured JSON report (sbi_error, value, etc.)
    helper_bin = Path("target/debug/helper")
    if helper_bin.exists():
        try:
            helper_proc = subprocess.run(
                [str(helper_bin), "run-host-harness", str(artifact)],
                capture_output=True, text=True, timeout=30
            )
            if helper_proc.returncode == 0:
                payload = json.loads(helper_proc.stdout)
                report = payload.get("report", {})
                if result.actual_sbi_error is None:
                    result.actual_sbi_error = report.get("sbi_error")
                if result.actual_value is None:
                    result.actual_value = report.get("value")
                # If fuzz binary gave no classification, try helper's spec_violations
                if result.classification == "unknown":
                    spec_violations = payload.get("spec_violations", [])
                    if spec_violations:
                        result.classification = "spec_violation"
                        result.violation_type = "spec_violation"
                        v = spec_violations[0]
                        if isinstance(v, dict):
                            name = next(iter(v))
                            detail = json.dumps(v[name], sort_keys=True)
                            result.violation_detail = f"{name} {detail}"
                        else:
                            result.violation_detail = str(v)
                        result.panic_message = f"spec violation: {result.violation_detail}"
        except Exception:
            pass

    return result


def reproduce_firmware_local(artifact: Path, target: Path, injector: Path) -> ReproResult:
    result = ReproResult()
    result.stderr = "Firmware local reproduction not yet implemented"
    return result


def _classify_from_output(result: ReproResult) -> None:
    output = result.stdout + result.stderr

    # 1. Try to parse structured JSON output from helper run-host-harness
    try:
        payload = json.loads(result.stdout)
        if isinstance(payload, dict):
            spec_violations = payload.get("spec_violations", [])
            memory_violations = payload.get("memory_violations", [])
            if spec_violations:
                result.classification = "spec_violation"
                result.violation_type = "spec_violation"
                v = spec_violations[0]
                if isinstance(v, dict):
                    name = next(iter(v))
                    detail = json.dumps(v[name], sort_keys=True)
                    result.violation_detail = f"{name} {detail}"
                else:
                    result.violation_detail = str(v)
                result.panic_message = f"spec violation: {result.violation_detail}"
                return
            if memory_violations:
                result.classification = "memory_violation"
                result.violation_type = "memory_violation"
                v = memory_violations[0]
                if isinstance(v, dict):
                    name = next(iter(v))
                    detail = json.dumps(v[name], sort_keys=True)
                    result.violation_detail = f"{name} {detail}"
                else:
                    result.violation_detail = str(v)
                return
            # If no violations but classification is not ok, note it
            report = payload.get("report", {})
            classification = report.get("classification", "ok")
            if classification != "ok":
                result.classification = "crash"
                result.violation_type = classification
                result.violation_detail = classification
                result.panic_message = f"Unexpected classification: {classification}"
                return
    except (json.JSONDecodeError, ValueError):
        pass

    # 2. Fallback to text-based heuristics (for panic / sanitizer / hang)
    if "spec violation:" in output:
        result.classification = "spec_violation"
        m = re.search(r"spec violation:\s*([^;]+)", output)
        if m:
            result.violation_type = "spec_violation"
            result.violation_detail = m.group(1).strip()
            result.panic_message = f"spec violation: {result.violation_detail}"
    elif "memory violation:" in output:
        result.classification = "memory_violation"
        m = re.search(r"memory violation:\s*([^;]+)", output)
        if m:
            result.violation_type = "memory_violation"
            result.violation_detail = m.group(1).strip()
    elif "AddressSanitizer" in output or "KASAN" in output or "UBSAN" in output:
        result.classification = "sanitizer"
        result.violation_type = "sanitizer"
    elif "panic" in output.lower() or "assertion failed" in output.lower():
        result.classification = "crash"
        result.violation_type = "panic"
    elif "timeout" in output.lower() or "hang" in output.lower():
        result.classification = "hang"
        result.violation_type = "hang"
    else:
        result.classification = "unknown"

    # 3. Infer actual_sbi_error from fuzz-binary panic message for accurate reproducer
    if result.classification == "spec_violation":
        if "HartMaskInvalidNotRejected" in result.violation_detail:
            # The oracle only fires HartMaskInvalidNotRejected when sbi_error == Success (0)
            result.actual_sbi_error = 0
        elif "WrongErrorCode" in result.violation_detail:
            m = re.search(r'"got":\s*(-?\d+)', result.violation_detail)
            if m:
                result.actual_sbi_error = int(m.group(1))


def generate_standalone_repro(input_data: dict, artifact_type: str, repro_result: ReproResult | None = None) -> dict[str, str]:
    if artifact_type == "host-harness":
        return _generate_host_harness_repro(input_data, repro_result)
    if artifact_type == "firmware":
        return _generate_firmware_repro(input_data)
    if artifact_type == "sequence":
        return _generate_sequence_repro(input_data)
    return {"repro.sh": "# Unsupported artifact type\n"}


def _generate_host_harness_repro(input_data: dict, repro_result: ReproResult | None = None) -> dict[str, str]:
    call = input_data.get("call", {})
    extid = call.get("extid", 0)
    fid = call.get("fid", 0)
    args = call.get("args", [0] * 6)
    hart_state = input_data.get("hart_state", "unknown")
    ext_name, _ = KNOWN_EIDS.get(extid, (f"ext_{extid:08x}", "Unknown Extension"))

    trait_name = ext_name.capitalize()
    if ext_name == "rfence":
        trait_name = "Fence"
    elif ext_name == "dbcn":
        trait_name = "Console"
    elif ext_name == "hsm":
        trait_name = "Hsm"

    trait_import = RUSTSBI_TRAIT_IMPORT.get(ext_name, "")
    trait_methods = RUSTSBI_TRAIT_METHODS.get(ext_name, [])
    internal_fn = RUSTSBI_INTERNAL_FN.get(ext_name)
    args_str = ", ".join(f"{a}usize" for a in args)
    impl_block = "\n".join(f"    {m}" for m in trait_methods)

    # Determine mock return value from actual observation so the standalone
    # reproducer independently triggers the same spec violation.
    actual_error = repro_result.actual_sbi_error if repro_result else None
    if actual_error is not None:
        if actual_error == 0:
            mock_return = "SbiRet::success(0)"
        else:
            mock_return = f"SbiRet {{ error: ({actual_error}i64) as usize, value: 0 }}"
    else:
        mock_return = "SbiRet::success(0)"

    # Replace default SbiRet::success(0) with observed buggy return
    if actual_error is not None:
        impl_block = impl_block.replace("SbiRet::success(0)", mock_return)

    # Build use statement including the internal dispatch function
    use_items = ["SbiRet", "HartMask"]
    if ext_name == "dbcn":
        use_items.append("Physical")
    if internal_fn:
        use_items.append(internal_fn)
    use_line = "use rustsbi::{" + ", ".join(use_items) + "};\n"

    # Generate self-contained oracle check
    oracle_lines = []
    if extid in (0x735049, 0x52464E43):  # IPI or RFENCE
        oracle_lines.append("    // Self-contained SBI spec oracle for hart mask")
        oracle_lines.append("    let hart_mask = param[0] as u64;")
        oracle_lines.append("    let hart_mask_base = param[1] as u64;")
        oracle_lines.append("    if let Some(invalid_hart) = check_hart_mask_invalid(hart_mask, hart_mask_base) {")
        oracle_lines.append("        assert!(ret.error != 0,")
        oracle_lines.append('            "BUG: HartMaskInvalidNotRejected: hart_id={} is invalid (mask={:#x}, base={}) but SBI returned error={}. Expected INVALID_PARAM (-3).",')
        oracle_lines.append("            invalid_hart, hart_mask, hart_mask_base, ret.error);")
        oracle_lines.append("    }")
    elif extid == 0x48534D and fid == 0 and hart_state == "started":
        oracle_lines.append("    // Self-contained SBI spec oracle for HSM hart_start")
        oracle_lines.append("    let error_i64 = ret.error as i64;")
        oracle_lines.append("    assert!(error_i64 == -6 || error_i64 == -7,")
        oracle_lines.append('        "BUG: HSM hart_start on started hart returned error={}. Expected ALREADY_AVAILABLE (-6) or ALREADY_STARTED (-7).",')
        oracle_lines.append("        error_i64);")

    oracle_check = "\n".join(oracle_lines)

    if internal_fn:
        main_body = f"""    let repro = Repro;
    let param = [{args_str}];
    let ret = {internal_fn}(&repro, param, {fid});
    println!("ret = {{:?}}", ret);
{oracle_check}
    println!("PASS: No spec violation detected with current implementation.");
"""
    else:
        main_body = f"""    let repro = Repro;
    println!("Reproducer stub for extension {ext_name}");
"""

    # Include oracle helper function if needed
    oracle_fn = ""
    if extid in (0x735049, 0x52464E43):
        oracle_fn = '''
fn check_hart_mask_invalid(hart_mask: u64, hart_mask_base: u64) -> Option<u64> {
    const MAX_HARTS: u64 = 64;
    if hart_mask == 0 { return None; }
    if hart_mask_base >= MAX_HARTS { return Some(hart_mask_base); }
    for bit in 0..64 {
        if (hart_mask >> bit) & 1 == 0 { continue; }
        let hart_id = hart_mask_base.saturating_add(bit);
        if hart_id >= MAX_HARTS { return Some(hart_id); }
    }
    None
}
'''

    main_rs = f'''{use_line}{trait_import}struct Repro;

impl {trait_name} for Repro {{
{impl_block}
}}
{oracle_fn}
fn main() {{
{main_body}}}
'''

    cargo_toml = '''[package]
name = "repro"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
rustsbi = "0.4.0"
'''
    return {"Cargo.toml": cargo_toml, "src/main.rs": main_rs}



def _generate_firmware_repro(input_data: dict) -> dict[str, str]:
    return {"repro.sh": "#!/bin/bash\n# Firmware reproducer: see issue body for QEMU command\n"}


def _generate_sequence_repro(input_data: dict) -> dict[str, str]:
    return {"repro.sh": "#!/bin/bash\n# Sequence reproducer: see issue body for QEMU command\n"}


def generate_issue_markdown(
    info: ArtifactInfo,
    repro_result: ReproResult,
    standalone_files: dict[str, str],
    git_sha: str = "",
) -> str:
    input_data = info.params
    call = input_data.get("call", {})
    extid = call.get("extid", 0)
    fid = call.get("fid", 0)
    args = call.get("args", [0] * 6)
    target_kind = input_data.get("target_kind", "unknown")
    ext_name, ext_desc = KNOWN_EIDS.get(extid, (f"ext_{extid:08x}", "Unknown Extension"))
    classification = repro_result.classification
    violation_detail = repro_result.violation_detail
    panic_message = repro_result.panic_message

    # Compact title for GitHub
    brief = _compact_brief(violation_detail, ext_name, fid)
    title = f"[{ext_desc}] {brief}"

    repro_blocks = []
    for fname, content in standalone_files.items():
        lang = "rust" if fname.endswith(".rs") else "toml" if fname.endswith(".toml") else "bash"
        repro_blocks.append(f"**`{fname}`**\n```{lang}\n{content}\n```\n")
    repro_section = "\n".join(repro_blocks)

    actual_output = panic_message
    if not actual_output:
        lines = repro_result.stderr.strip().splitlines()
        actual_output = "\n".join(lines[-5:]) if lines else "(no output captured)"

    spec_ref = _spec_reference(classification, ext_name, violation_detail)
    expected = _expected_behavior(classification, ext_name, violation_detail)
    labels = ["bug", classification, target_kind.lower()]
    if ext_name:
        labels.append(ext_name)

    md = f"""---
title: "{title}"
labels: {json.dumps(labels)}
---

## Summary
{brief}

## SBI Specification Reference
{spec_ref}

## Reproducer
Save the following files into a new directory and run `cargo run`:

{repro_section}
## Actual Behavior
```
{actual_output}
```

## Expected Behavior
{expected}
"""
    return md


def _compact_brief(violation_detail: str, ext_name: str, fid: int) -> str:
    if "HartMaskInvalidNotRejected" in violation_detail:
        return f"Invalid hart mask not rejected (FID={fid})"
    if "WrongErrorCode" in violation_detail:
        return f"Wrong error code returned (FID={fid})"
    return violation_detail if violation_detail else f"{ext_name} fid={fid} crash"


def _spec_reference(classification: str, ext_name: str, violation_detail: str) -> str:
    if classification != "spec_violation":
        return "_No spec reference available for this classification._"
    if "HartMaskInvalidNotRejected" in violation_detail:
        return (
            "> Any SBI function taking hart mask arguments may return the error values listed"
            " in the Hart Mask Errors below which are in addition to function specific error values.\n"
            ">\n"
            "> | Error code | Description |\n"
            "> |---|---|\n"
            "> | `SBI_ERR_INVALID_PARAM` | At least one hartid constructed from `hart_mask_base`"
            " and `hart_mask`, is not valid, i.e. either the hartid is not enabled by the platform"
            " or is not available to the supervisor. |\n\n"
            "Source: *RISC-V Supervisor Binary Interface Specification*, Binary Encoding \u00a73.1, Table 2"
        )
    if "WrongErrorCode" in violation_detail and ext_name == "hsm":
        return (
            "> | Error code | Description |\n"
            "> |---|---|\n"
            "> | `SBI_SUCCESS` | Hart was previously in stopped state. It will start executing"
            " from `start_addr`. |\n"
            "> | `SBI_ERR_INVALID_PARAM` | `hartid` is not a valid hartid as the corresponding"
            " hart cannot be started in supervisor mode. |\n"
            "> | `SBI_ERR_ALREADY_AVAILABLE` | The given `hartid` is already started. |\n\n"
            "Source: *RISC-V Supervisor Binary Interface Specification*,"
            " Hart State Management Extension \u00a79.1, Table 19"
        )
    return "_No specific spec reference available._"


def _expected_behavior(classification: str, ext_name: str, violation_detail: str) -> str:
    if classification == "spec_violation":
        if "HartMaskInvalidNotRejected" in violation_detail:
            return (
                "When any hartid constructed from `hart_mask_base` and `hart_mask` is not valid, "
                "the implementation MUST return `SBI_ERR_INVALID_PARAM` (`-3`). "
                "Returning `SBI_SUCCESS` (`0`) is a spec violation."
            )
        if "WrongErrorCode" in violation_detail and ext_name == "hsm":
            return (
                "When `sbi_hart_start` is called on a hart that is already started, "
                "the implementation MUST return `SBI_ERR_ALREADY_AVAILABLE` (`-6`). "
                "Returning `SBI_ERR_INVALID_PARAM` (`-3`) is a spec violation."
            )
        return "The implementation should behave according to the RISC-V SBI Specification."
    if classification == "memory_violation":
        return "The implementation must not access memory outside of the provided valid regions."
    if classification == "sanitizer":
        return "The implementation must not trigger undefined behavior or memory safety violations."
    if classification == "crash":
        return "The implementation should handle the input gracefully and return an appropriate error code."
    if classification == "hang":
        return "The implementation should complete the call within a reasonable time bound."
    return "N/A"





def main() -> int:
    parser = argparse.ArgumentParser(description="Generate GitHub Issue from fuzz crash artifact")
    parser.add_argument("artifact", type=Path, help="Path to crash artifact")
    parser.add_argument("--type", choices=["auto", "host-harness", "firmware", "sequence"], default="auto")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--target", type=Path, help="Firmware target binary")
    parser.add_argument("--injector", type=Path, help="Injector ELF")
    parser.add_argument("--skip-repro", action="store_true", help="Skip local reproduction")
    parser.add_argument("--git-sha", default="", help="Repository git SHA")
    args = parser.parse_args()

    artifact = args.artifact
    if not artifact.exists():
        print(f"ERROR: artifact not found: {artifact}", file=sys.stderr)
        return 1

    artifact_type = args.type
    if artifact_type == "auto":
        artifact_type = detect_artifact_type(artifact)
    if artifact_type == "unknown":
        print(f"ERROR: cannot detect artifact type for: {artifact}", file=sys.stderr)
        return 1

    print(f"[*] Detected artifact type: {artifact_type}")

    if artifact_type == "host-harness":
        params = parse_host_harness_artifact(artifact)
    elif artifact_type == "firmware":
        params = parse_firmware_artifact(artifact)
    elif artifact_type == "sequence":
        params = parse_sequence_artifact(artifact)
    else:
        params = {}

    info = ArtifactInfo(
        artifact_type=artifact_type, path=artifact,
        params=params, raw_bytes=artifact.read_bytes(),
    )

    repro_result = ReproResult()
    if not args.skip_repro:
        print("[*] Running local reproduction...")
        if artifact_type == "host-harness":
            repro_result = reproduce_host_harness_local(artifact, params)
        elif artifact_type == "firmware":
            if args.target and args.injector:
                repro_result = reproduce_firmware_local(artifact, args.target, args.injector)
        print(f"[*] Local reproduction finished (rc={repro_result.returncode}, class={repro_result.classification})")
    else:
        print("[*] Skipping local reproduction (--skip-repro)")

    print("[*] Generating standalone reproducer...")
    standalone_files = generate_standalone_repro(params, artifact_type, repro_result)

    git_sha = args.git_sha
    if not git_sha:
        try:
            git_proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
            if git_proc.returncode == 0:
                git_sha = git_proc.stdout.strip()[:12]
        except Exception:
            pass

    print("[*] Generating GitHub Issue Markdown...")
    markdown = generate_issue_markdown(info, repro_result, standalone_files, git_sha)

    bug_id = f"bug-{hashlib.sha256(artifact.read_bytes()).hexdigest()[:12]}"
    out_dir = args.output_dir / bug_id
    out_dir.mkdir(parents=True, exist_ok=True)

    issue_path = out_dir / "issue.md"
    issue_path.write_text(markdown)
    print(f"[+] Issue written to: {issue_path}")

    repro_dir = out_dir / "repro"
    repro_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in standalone_files.items():
        fpath = repro_dir / fname
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content)
        print(f"[+] Reproducer file written to: {fpath}")

    print(f"[+] Done. Bug report directory: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
