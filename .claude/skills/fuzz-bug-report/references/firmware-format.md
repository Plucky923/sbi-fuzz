# Firmware Crash Artifact Format Reference

## Overview
Firmware fuzzing uses LibAFL + QEMU. Crash artifacts are stored as:

- `.toml` files: Human-readable test case descriptions
- `.raw/.exec` files: Binary execution programs for replay

## TOML Format

A firmware crash artifact is a TOML file describing the SBI call that triggered the crash:

```toml
[args]
eid = 0x52464E43
fid = 1
arg0 = 6076287494138254080
arg1 = 8368386297538096177

[metadata]
extension_name = "rfence"
source = "fuzz-136-Crash"
```

## Exec Format (`.exec`)

Binary format starting with magic `b"SBIFUZZ\0"` followed by a serialized execution program.

## Reproduction

### Using helper CLI (requires sbi-fuzz project)
```bash
cargo run -q -p helper -- run \
  <target_fw.bin> <injector.elf> <input.toml> \
  --smp 1 --timeout-ms 100
```

### Standalone Reproducer (QEMU)
For bug reports, provide the QEMU command line:
```bash
qemu-system-riscv64 \
  -M virt -smp 1 -m 256M \
  -bios fw_dynamic.bin \
  -kernel injector.elf \
  -monitor null -serial null -nographic
```

Note: The standalone firmware reproducer requires the actual `fw_dynamic.bin` and `injector.elf` binaries.
