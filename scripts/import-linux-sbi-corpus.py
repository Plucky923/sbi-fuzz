#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

CONST_MAP = {
    "SBI_EXT_BASE": 0x10,
    "SBI_EXT_TIME": 0x54494D45,
    "SBI_EXT_IPI": 0x735049,
    "SBI_EXT_RFENCE": 0x52464E43,
    "SBI_EXT_HSM": 0x48534D,
    "SBI_EXT_SRST": 0x53525354,
    "SBI_EXT_PMU": 0x504D55,
    "SBI_EXT_DBCN": 0x4442434E,
    "SBI_EXT_SUSP": 0x53555350,
    "SBI_EXT_HSM_HART_START": 0,
    "SBI_EXT_HSM_HART_STOP": 1,
    "SBI_EXT_HSM_HART_STATUS": 2,
    "SBI_EXT_HSM_HART_SUSPEND": 3,
    "SBI_EXT_SRST_RESET": 0,
    "SBI_EXT_PMU_COUNTER_GET_INFO": 1,
    "SBI_EXT_PMU_SNAPSHOT_SET_SHMEM": 8,
    "SBI_EXT_DBCN_CONSOLE_WRITE": 0,
    "SBI_EXT_RFENCE_REMOTE_FENCE_I": 0,
    "SBI_EXT_RFENCE_REMOTE_SFENCE_VMA": 1,
    "SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID": 2,
}

ECALL_PATTERN = re.compile(r"sbi_ecall\s*\((.*?)\)", re.S)
IDENTIFIER_PATTERN = re.compile(r"[^A-Za-z0-9_]+")


def split_args(arg_string: str):
    parts = []
    current = []
    depth = 0
    for char in arg_string:
        if char == ',' and depth == 0:
            part = ''.join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth = max(depth - 1, 0)
        current.append(char)
    tail = ''.join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def resolve_value(token: str) -> int:
    token = token.strip()
    token = token.replace("UL", "").replace("ULL", "").replace("L", "")
    if token in CONST_MAP:
        return CONST_MAP[token]
    if token.startswith("0x") or token.startswith("0X"):
        return int(token, 16)
    if token.isdigit():
        return int(token)
    if token.startswith("(") and token.endswith(")"):
        return resolve_value(token[1:-1])
    return 0


def sanitize_name(token: str) -> str:
    token = token.strip()
    if token in CONST_MAP:
        token = token.lower()
    token = IDENTIFIER_PATTERN.sub("_", token).strip("_").lower()
    return token or "unknown"


def render_seed(eid_token: str, fid_token: str, values, source_name: str) -> str:
    eid = resolve_value(eid_token)
    fid = resolve_value(fid_token)
    return "\n".join([
        "[metadata]",
        f'extension_name = "{source_name}"',
        f'source = "linux-import-{sanitize_name(eid_token)}-{sanitize_name(fid_token)}"',
        "",
        "[args]",
        f"eid = 0x{eid:X}",
        f"fid = 0x{fid:X}",
        f"arg0 = 0x{values[0]:X}",
        f"arg1 = 0x{values[1]:X}",
        f"arg2 = 0x{values[2]:X}",
        f"arg3 = 0x{values[3]:X}",
        f"arg4 = 0x{values[4]:X}",
        f"arg5 = 0x{values[5]:X}",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Linux-style sbi_ecall invocations into sbifuzz TOML seeds")
    parser.add_argument("source", type=Path, help="Path to a Linux-like C source file")
    parser.add_argument("output", type=Path, help="Directory to write generated seed TOML files")
    args = parser.parse_args()

    source_text = args.source.read_text()
    matches = list(ECALL_PATTERN.finditer(source_text))
    args.output.mkdir(parents=True, exist_ok=True)

    count = 0
    for idx, match in enumerate(matches):
        parts = split_args(match.group(1))
        if len(parts) != 8:
            continue
        eid_token, fid_token = parts[0], parts[1]
        values = [resolve_value(part) for part in parts[2:8]]
        extension_name = sanitize_name(eid_token)
        fid_name = sanitize_name(fid_token)
        path = args.output / f"linux-{idx:03d}-{extension_name}-{fid_name}.toml"
        path.write_text(render_seed(eid_token, fid_token, values, extension_name))
        count += 1

    print(f"Imported {count} seed(s) from {args.source} into {args.output}")
    return 0 if count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
