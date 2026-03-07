# sbi-fuzz - RISC-V SBI Firmware Fuzzing

sbifuzz is a fuzzing framework designed to test RISC-V SBI (Supervisor Binary Interface) implementations. It helps discover potential vulnerabilities and abnormal behaviors in SBI implementations.

## Project Structure

```
sbifuzz/
├── common/          # Common libraries and utility functions
├── fuzzer/          # Core fuzzing logic
├── helper/          # Helper tools (seed generation, runners, etc.)
├── injector/        # Injector implementations
├── playground/      # Examples and test cases
└── Dockerfile.dev   # Development environment Dockerfile
```

## Key Features

- 🚀 Full support for all SBI extensions
- 🎯 Smart coverage-guided fuzzing
- 🔥 No firmware source needed
- ⚡ Fast execution with snapshotting and parallelization
- 🛡️ Built-in sanitizer support
- 📚 SBI doc-driven seed generation

## Quick Start

To get started with fuzzing RustSBI:

```bash
cd playground/rustsbi-fuzz
make
```

## Usage

1. Check the local environment:
```bash
make check-env
```

To run the build smoke checks after probing dependencies:
```bash
make check-env-smoke
```

`check-env` also verifies the required QEMU bridge development packages via `pkg-config`, including `glib-2.0` and `pixman-1`.

It also checks for the LLVM/Clang toolchain pieces required by bindgen and `libafl_qemu_sys`, including `llvm-config` and `clang`.

If `check-env-smoke` still fails in the QEMU bridge stage, install a system LLVM/Clang package that provides both `llvm-config` and `clang` before retrying.

On Ubuntu systems, `llvm-18 llvm-18-dev clang-18` is currently the safer practical fallback for the `libafl_qemu`/bindgen build path than `clang-20`.

The repository now also seeds these tool paths into `.cargo/config.toml`, so plain `cargo helper ...` and `cargo fuzzer ...` commands work without extra env vars on machines that have LLVM 18 installed.

2. Build the project:
```bash
make
```

3. Generate seed input:
```bash
cargo helper generate-seed output/seed
```

4. Run fuzzing:
```bash
cargo fuzzer --target <firmware> --injector <injector> --seed output/seed --output output/result
```
The Makefiles now export a preferred LLVM 18 / Clang 18 toolchain for the `libafl_qemu` build path automatically when those binaries are installed.


The default seed/wire format now uses a syzkaller-inspired exec stream instead of a single fixed 64-byte SBI call, while remaining backward-compatible with legacy raw inputs.

To convert a single TOML SBI call into the new exec format:

```bash
cargo helper encode-exec-input path/to/input.toml
```

To inspect the current exec call registry:

```bash
cargo helper list-calls
```

To import Linux-style `sbi_ecall(...)` samples into seed TOML files:

```bash
python3 scripts/import-linux-sbi-corpus.py path/to/linux/arch/riscv/kernel/sbi.c output/linux-seeds
```

The same import is also exposed through the helper CLI:

```bash
cargo helper import-linux-corpus path/to/linux/arch/riscv/kernel/sbi.c output/linux-seeds
```

For a real OpenSBI fuzz run:

```bash
make -C playground/opensbi-fuzz prepare
make -C playground/opensbi-fuzz run
```

A verified short smoke run now succeeds against `playground/opensbi-fuzz`, and sample findings are written under `playground/opensbi-fuzz/output/result-smoke`.

To triage existing OpenSBI findings:

```bash
make -C playground/opensbi-fuzz triage
```

To replay representative OpenSBI findings:

```bash
make -C playground/opensbi-fuzz replay
```

Replay prefers the saved `.exec` inputs over `.toml` because they preserve the full syzkaller-style bytecode program. Replay results may still differ from fuzz-time classification, which is itself useful triage signal.

To summarize replay results into Markdown/JSON:

```bash
make -C playground/opensbi-fuzz replay-summary
```

To run the fixed OpenSBI sanitizer demo samples:

```bash
make -C playground/opensbi-sanitizer-demo verify
```

## Examples

Example test cases for OpenSBI and RustSBI are provided in the `playground` directory.

## Roadmap

See `TODO.md` for the threat model and phased implementation plan covering memory safety, hart-state races, resource exhaustion, and vendor-specific SBI extensions.

See `SYZKALLER_MIGRATION_PLAN.md` for the detailed next-step migration plan and per-step test strategy.

## Development Environment

We provides a VSCode dev container configuration for easy setup. To use it, see https://aka.ms/vscode-remote/containers.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
