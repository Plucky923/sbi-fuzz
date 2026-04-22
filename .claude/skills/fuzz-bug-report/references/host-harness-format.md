# Host Harness Crash Artifact Format Reference

## Overview
Host harness fuzz targets (`fuzz_ecall_rustsbi`, `fuzz_ecall_opensbi`, etc.) use libFuzzer. Crash artifacts can be in two formats:

1. **`.host` format** (preferred): `SBIHOST1` magic (8 bytes) + u32 LE payload length + JSON payload
2. **Raw fuzz bytes**: libFuzzer raw input following the `from_fuzz_bytes` protocol

## `.host` Format

```
0..7   : "SBIHOST1" (magic)
8..11  : payload length (u32 little-endian)
12..end: JSON payload (UTF-8)
```

The JSON payload is a serialized `HostHarnessInput`:

```json
{
  "target_kind": "rust_sbi",
  "mode": "ecall",
  "call": {
    "extid": 1380339267,
    "fid": 1,
    "args": [6076287494138254080, 8368386297538096177, 0, 0, 0, 0]
  },
  "hart_id": 35,
  "hart_state": "started",
  "privilege": "supervisor",
  "memory_regions": [],
  "platform_fault": {"mode": "none", "error": 0, "value": 0, "duplicate_side_effects": false},
  "fdt_blob": [],
  "label": "fuzz-136-1380339267"
}
```

## Raw Fuzz Bytes Format

Used when the artifact comes directly from libFuzzer (`crash-*` files). The bytes encode:

| Offset | Type | Description |
|--------|------|-------------|
| 0      | u8   | target selector (0=OpenSBI, 1=RustSBI) |
| 1      | u8   | mode selector (0=Ecall, 1=PlatformFault, 2=Fdt) |
| 2..9   | u64  | raw extension ID |
| 10..17 | u64  | raw function ID |
| 18..65 | u64x6| arguments |
| 66     | u8   | hart selector |
| 67     | u8   | hart state selector |
| 68     | u8   | privilege selector |
| 69     | u8   | fault mode selector |
| 70..77 | i64  | fault error |
| 78..85 | u64  | fault value |
| 86     | u8   | duplicate side effects flag |
| 87     | u8   | memory region count |

## Panic / Spec Violation Patterns

When `host_harness::run()` detects a violation, it panics with one of these prefixes:

- `spec violation: <ViolationDetail>` — The SBI call returned a value that violates the RISC-V SBI spec.
- `memory violation: <ViolationDetail>` — The implementation accessed memory outside provided valid regions.

Common `SpecViolation` variants:

- `HartMaskInvalidNotRejected { hart_id }` — An invalid hart ID in `hart_mask` was not rejected with `SBI_ERR_INVALID_PARAM`.
- `WrongValue { expected, got, context }` — A return value did not match the expected constant.
- `BaseSpecVersionTooLow { got }` — The reported SBI spec version is below the required minimum.

## Reproduction

### Using helper CLI (requires sbi-fuzz project)
```bash
cargo run -q -p helper -- run-host-harness input.json
```

### Using cargo-fuzz (requires sbi-fuzz project)
```bash
cd host_harness/fuzz
cargo +nightly fuzz run --no-default-features --features host-rustsbi \
  fuzz_ecall_rustsbi artifacts/fuzz_ecall_rustsbi/crash-<hash>
```

## Standalone Reproducer Strategy

The standalone reproducer uses `rustsbi = "0.4.0"` from crates.io and the internal dispatch functions (`_rustsbi_ipi`, `_rustsbi_fence`, etc.) to replay the exact call without needing the full sbi-fuzz project.
