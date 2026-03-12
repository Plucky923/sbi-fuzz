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
You can also raise the target complexity with multiple emulated harts and multi-call scenario seeds:

```bash
cargo fuzzer --target <firmware> --injector <injector> --seed output/seed-complex --output output/result-complex --smp 4
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

For the new host-side layered harness, generate structured `.host` seeds for either `opensbi` or `rustsbi` and any of the `ecall`, `platform-fault`, or `fdt` modes:

```bash
cargo helper generate-host-seeds --target-kind opensbi --mode ecall /tmp/host-seeds-opensbi-ecall
cargo helper generate-host-seeds --target-kind rustsbi --mode fdt /tmp/host-seeds-rustsbi-fdt
```

To run one host-side harness input and emit a JSON summary:

```bash
cargo helper run-host-harness /tmp/host-seeds-opensbi-ecall/base-get-spec-version.host
```

The host harness compiles a small in-process adapter for OpenSBI and RustSBI, so it exercises ecall dispatch, platform-fault injection, and target-specific FDT parsing without booting the full QEMU firmware image. This is intended to complement, not replace, the existing `playground/opensbi-fuzz` and `playground/rustsbi-fuzz` system-level paths.

To generate RustSBI-oriented multi-call `.exec` seeds that exercise HSM, IPI, RFENCE, Console, and PMU flows:

```bash
cargo helper generate-rustsbi-scenarios playground/rustsbi-fuzz/output/seed-complex
```

The fuzzer now accepts both `.toml` and `.exec` files in a seed directory, so structured multi-call programs can participate in the initial corpus directly.

These RustSBI scenario seeds also use `setprops` metadata inside the exec stream to switch the calling hart (`target_hart`) and inject bounded spin windows (`busy_wait`) between calls, so `-smp` now affects more than just target topology.

The injector now also embeds semantic RustSBI oracles that are independent from fuzz input bytes: it checks that `hsm_hart_status(0)` always reports hart0 as started, and that repeated Base extension identity queries with identical arguments stay stable across harts. When one of these invariants breaks, replay output includes an `Oracle failure ...` line and the case is bucketed with the `oracle` signal.

To import Linux-style `sbi_ecall(...)` samples into seed TOML files:

```bash
python3 scripts/import-linux-sbi-corpus.py path/to/linux/arch/riscv/kernel/sbi.c output/linux-seeds
```

The same import is also exposed through the helper CLI:

```bash
cargo helper import-linux-corpus path/to/linux/arch/riscv/kernel/sbi.c output/linux-seeds
```

For direct replay of potentially hanging RustSBI scenarios without relying on an external shell timeout:

```bash
cargo helper run <firmware> <injector> playground/rustsbi-fuzz/output/seed-complex/base-identity-cross-hart.exec --smp 4 --timeout-ms 1000
```

The same native timeout is available for coverage export, which is useful when a candidate only manifests as a hang:

```bash
cargo helper collect-coverage <firmware> <injector> playground/rustsbi-fuzz/output/seed-complex/base-identity-cross-hart.exec --smp 4 --timeout-ms 1000 --json-out /tmp/hang.cover.json
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

To export one run's shared-memory coverage as `cover.raw` / `cover.json`:

```bash
cargo helper collect-coverage \
  playground/opensbi-fuzz/output/opensbi/build/platform/generic/firmware/fw_dynamic.bin \
  injector/build/injector.elf \
  playground/opensbi-fuzz/output/seed/ext-base-get_impl_version.toml \
  --raw-out /tmp/cover.raw \
  --json-out /tmp/cover.json
```

To run the built-in OpenSBI coverage smoke/stability check:

```bash
make test-opensbi-coverage
```

To replay current findings and bucket likely bug candidates:

```bash
make -C playground/opensbi-fuzz bug-report
```

This produces `output/bugs/result.replay.json` plus `output/bugs/result.bugs.json` / `.md`, which are intended to separate likely sanitizer/trap/hang buckets from plain replay noise.

To run the full OpenSBI fuzz → triage → replay → bug-report campaign in one command:

```bash
make campaign-opensbi
```

To run the same automated campaign against the pinned RustSBI prototyper target:

```bash
make campaign-rustsbi
```

To run the more complex RustSBI campaign with scenario seeds and `-smp 4` by default:

```bash
make campaign-rustsbi-complex
```

These campaign targets write machine-readable summaries under `output/campaign/`, including `latest.json` for the baseline RustSBI run and `latest-complex.json` for the multi-call/multi-hart-oriented RustSBI run. Replay now inherits the same `--smp` value as fuzzing, so multi-hart RustSBI findings are replayed under the same topology instead of silently collapsing back to single-hart QEMU. Full replay logs are archived under each campaign's `replay-logs/`, and replay-derived `confirmed_bug_like_buckets` is included when sanitizer/trap-style candidates are found.

Hang candidates are now replayed multiple times during bug reporting and campaigns. The resulting `hang-stability.json` distinguishes `stable_hang` from flaky one-off timeouts, so repeatable RustSBI hangs can be promoted alongside crash-like buckets instead of being treated as undifferentiated timeout noise. Stable hangs are then fed through `scripts/minimize-sbi-hangs.py`, which calls `helper minimize-hang` to shrink them into shorter `.exec` reproducers and stores the result in `hang-minimize.json`. Bug bucketing also consumes each minimized hang's semantic signature, so two repeatable `Timeout` cases with different hart/call sequences no longer collapse into one generic hang bucket.

To triage, replay, and bucket RustSBI findings outside the full campaign:

```bash
make -C playground/rustsbi-fuzz triage
make -C playground/rustsbi-fuzz replay
make -C playground/rustsbi-fuzz bug-report
```

For the multi-call / multi-hart corpus, use the `-complex` variants so replay also keeps `--smp 4` by default:

```bash
make -C playground/rustsbi-fuzz triage-complex
make -C playground/rustsbi-fuzz replay-complex
make -C playground/rustsbi-fuzz bug-report-complex
```

The generic `scripts/triage-sbi-results.py`, `scripts/replay-sbi-results.py`, `scripts/summarize-replay-sbi-results.py`, and `scripts/report-sbi-bugs.py` can also be used directly when you want the same result-processing pipeline for RustSBI or OpenSBI without relying on target-specific script names.

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
