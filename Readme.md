# sbi-fuzz - RISC-V SBI Firmware Fuzzing

sbifuzz is a fuzzing framework designed to test RISC-V SBI (Supervisor Binary Interface) implementations. It helps discover potential vulnerabilities and abnormal behaviors in SBI implementations.

## Project Structure

```
sbifuzz/
├── common/                 # Shared wire formats, schema registry, oracle helpers
├── host_harness/           # Host-side OpenSBI/RustSBI harness and cargo-fuzz targets
├── helper/                 # CLI for seed generation, replay, sequence runs, triage helpers
├── config/                 # Locked doc revisions, schemas, campaign profiles
├── scripts/                # Campaign, triage, metrics, and regression automation
├── playground/             # System-level OpenSBI/RustSBI/QEMU entry points
├── fuzzer/                 # QEMU/system-level fuzzing loop
├── injector/               # Injector implementations
└── Dockerfile.dev          # Development environment Dockerfile
```

## Key Features

- 🚀 Full support for all SBI extensions
- 🎯 Smart coverage-guided fuzzing
- 🔥 No firmware source needed
- ⚡ Fast execution with snapshotting and parallelization
- 🛡️ Built-in sanitizer support
- 📚 SBI doc-driven seed generation

## Quick Start

Recommended flow:

1. Start with the host-side harness for fast validation and replay.
2. Escalate to the QEMU/system-level playgrounds only after the host-side path is healthy.

For a fresh machine that does not have an OpenSBI source tree prepared yet, validate the RustSBI-only host path first:

```bash
cargo test -p common -p host_harness --no-default-features --features host-rustsbi
```

To enable the full host-side harness with both RustSBI and OpenSBI backends:

```bash
make -C playground/opensbi-fuzz prepare
make test-host-harness
```

To move up to the system-level RustSBI playground:

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

For reproducible seed generation, pass an explicit lock file and commit override when needed:

```bash
cargo helper generate-seed output/seed --lock-file config/locks/riscv-sbi-doc.lock
cargo helper generate-seed output/seed --commit <pinned-commit>
```

`generate-seed` now also writes `seed-source.json` into the output directory so the source repo and resolved commit are preserved alongside the generated corpus.

It also emits a small set of schema-driven `.toml` variants per call, keeping the original baseline filename while adding argument-specific suffixes such as `-arg1-guest` or `-arg0-hart1` for higher-risk parameter classes.

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

`list-calls` now shows the active schema source and a compact six-slot schema column. The default runtime lookup order is:

1. `SBIFUZZ_SCHEMA_DIR` if set
2. `config/schemas/` discovered from the current working directory or its parents
3. the repository default under `config/schemas/`

The initial external schema registry for high-risk extensions lives under `config/schemas/` and currently covers `hsm`, `ipi`, `rfence`, `console`, and `pmu`.

For the new host-side layered harness, generate structured `.host` seeds for either `opensbi` or `rustsbi` and any of the `ecall`, `platform-fault`, or `fdt` modes:

```bash
cargo helper generate-host-seeds --target-kind opensbi --mode ecall /tmp/host-seeds-opensbi-ecall
cargo helper generate-host-seeds --target-kind rustsbi --mode fdt /tmp/host-seeds-rustsbi-fdt
```

To run one host-side harness input and emit a JSON summary:

```bash
cargo helper run-host-harness /tmp/host-seeds-opensbi-ecall/base-get-spec-version.host
```

`run-host-harness` now also accepts raw libFuzzer crash files produced by the host-side fuzz targets and replays them by decoding the same structured `from_fuzz_bytes()` format used in-process.

The host harness compiles a small in-process adapter for OpenSBI and RustSBI, so it exercises ecall dispatch, platform-fault injection, and target-specific FDT parsing without booting the full QEMU firmware image. This is intended to complement, not replace, the existing `playground/opensbi-fuzz` and `playground/rustsbi-fuzz` system-level paths.

For the host-side `cargo-fuzz` loop under `host_harness/fuzz/`, first generate the libFuzzer corpus and run a short smoke:

```bash
make host-fuzz-corpus
make host-fuzz-smoke
```

For the documented S0 local regression loop, use:

```bash
make preflight
make smoke-all
make report-all
```

The scenario-to-command mapping and expected artifact paths are documented in `docs/runbook.md`.
`make report-all` summarizes the latest S0 smoke outputs; it does not start a second smoke run.

For deterministic workflow validation in review or CI environments that do not have the full host fuzz and playground toolchain available, use:

```bash
SBIFUZZ_USE_FIXTURES=1 make preflight
SBIFUZZ_USE_FIXTURES=1 make smoke-all
SBIFUZZ_USE_FIXTURES=1 make report-all
```

This fixture mode exercises the same top-level orchestration and validates the generated artifact contract without requiring a live long-running fuzz campaign.

The integrated S0 path now uses the dedicated `output/host_fuzz_smoke/` root, so `smoke-all` and `report-all` operate on the same smoke outputs without overwriting the longer-lived host campaign artifacts under `output/host_fuzz/`.

This smoke run performs six checks in order:

1. an intentional `fuzz_harness_smoke` crash to verify the libFuzzer crash/artifact pipeline;
2. a short single-worker `fuzz_ecall_opensbi` run;
3. a short single-worker `fuzz_ecall_rustsbi` run;
4. a short single-worker `fuzz_sequence_both` run;
5. a short single-worker `fuzz_diff_ecall` run;
6. a short single-worker `fuzz_diff_sequence` run.

To launch the long-running 60-worker RustSBI host-side campaign after the smokes pass:

```bash
make host-fuzz-60
```

To summarize a host-side campaign and enforce a minimum quality bar:

```bash
make triage-host-fuzz
make collect-metrics
make quality-gate
```

`make report-all` now writes the integrated S0 artifacts under `output/host_fuzz_smoke/` and returns a non-zero exit status only when the quality gate intentionally blocks on findings or the generated artifacts fail validation.

For the more complex multi-hart host-side sequence campaign, use:

```bash
make host-fuzz-60-complex
```

To run the host-side differential target that compares OpenSBI and RustSBI on the same structured inputs:

```bash
make host-fuzz-diff
```

`make host-fuzz-diff` runs both `fuzz_diff_ecall` and `fuzz_diff_sequence`, so the public differential workflow covers both single-call and sequence-oriented mismatch hunting.

The sequence-oriented host-side targets now accept `SBIFUZZ_HOST_SEQUENCE_SMP`, so `make host-fuzz-60-complex` drives structured `.seq` inputs with up to 60 modeled harts instead of the older fixed 4-hart topology. Host-side fuzz runs also disable LeakSanitizer by default (`SBIFUZZ_HOST_FUZZ_DETECT_LEAKS=0`) because this environment trips the known `LeakSanitizer does not work under ptrace` fatal and otherwise turns clean runs into false crashes.

The host-side fuzz logs live under `output/host_fuzz/logs/`, while generated artifacts and crashes are written under `output/host_fuzz/<target>/`.

To generate RustSBI-oriented multi-call `.exec` seeds that exercise HSM, IPI, RFENCE, Console, and PMU flows:

```bash
cargo helper generate-rustsbi-scenarios playground/rustsbi-fuzz/output/seed-complex
```

The fuzzer now accepts both `.toml` and `.exec` files in a seed directory, so structured multi-call programs can participate in the initial corpus directly.

These RustSBI scenario seeds also use `setprops` metadata inside the exec stream to switch the calling hart (`target_hart`) and inject bounded spin windows (`busy_wait`) between calls, so `-smp` now affects more than just target topology.

The injector now also embeds semantic RustSBI oracles that are independent from fuzz input bytes: it checks that `hsm_hart_status(0)` always reports hart0 as started, and that repeated Base extension identity queries with identical arguments stay stable across harts. When one of these invariants breaks, replay output includes an `Oracle failure ...` line and the case is bucketed with the `oracle` signal.

For stateful single-target fuzzing, the helper now also supports a unified `sequence` wire format (`.seq`). It can describe memory objects, target-hart changes, busy waits, host-side hart state changes, FDT parses, and multi-call SBI sequences for either OpenSBI or RustSBI.

To generate a starter corpus for both implementations:

```bash
cargo helper generate-sequence-seeds --target-kind both /tmp/sequence-seeds
```

The generated `.seq` corpus now includes schema-driven single-call semantic templates for high-risk SBI paths such as HSM, IPI, RFENCE, Console, and PMU, in addition to the earlier shared and FDT-oriented examples.

To inspect one generated sequence:

```bash
cargo helper describe-sequence /tmp/sequence-seeds/shared-base-hsm-status.seq
```

To run the same sequence on one host-side backend:

```bash
cargo helper run-sequence --target-kind opensbi /tmp/sequence-seeds/shared-base-hsm-status.seq
cargo helper run-sequence --target-kind rustsbi /tmp/sequence-seeds/shared-base-hsm-status.seq
```

The existing `helper run`, `collect-coverage`, `minimize-hang`, and the main fuzzer bootstrap path now also accept `.seq` inputs when the sequence can be lowered into the current firmware-side `.exec` program subset.

To replay a whole `.seq` directory against one target and summarize the interesting cases:

```bash
python3 scripts/replay-sequence-results.py opensbi /tmp/sequence-seeds --all --json-out /tmp/sequence.replay.json
python3 scripts/report-sequence-bugs.py /tmp/sequence.replay.json --json-out /tmp/sequence.bugs.json --md-out /tmp/sequence.bugs.md
```

To run the same flow as a single-target campaign:

```bash
python3 scripts/run-sequence-campaign.py opensbi-sequence opensbi /tmp/sequence-seeds --profile host-sequence --json-out /tmp/sequence.campaign.json
python3 scripts/run-sequence-campaign.py rustsbi-sequence rustsbi /tmp/sequence-seeds --profile host-sequence --json-out /tmp/sequence.campaign.json
```

Both campaign runners now accept `--profile <name>` for reproducible settings under `config/campaign-profiles/` and emit `run-manifest.json` under each `campaigns/<run-id>/` directory.

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

For direct script-level control with an explicit firmware profile:

```bash
python3 scripts/run-sbi-fuzz-campaign.py \
  opensbi \
  playground/opensbi-fuzz/output/opensbi/build/platform/generic/firmware/fw_dynamic.bin \
  injector/build/injector.elf \
  playground/opensbi-fuzz/output/seed \
  playground/opensbi-fuzz/output/result \
  --profile multi-hart-race \
  --json-out /tmp/opensbi.campaign.json
```

To run the same automated campaign against the pinned RustSBI prototyper target:

```bash
make campaign-rustsbi
```

For RustSBI system-level fuzzing and replay with the external `injector.elf`, the target artifact must be the dynamic prototyper build (`rustsbi-prototyper-dynamic.bin`). Using the plain `rustsbi-prototyper.bin` image can violate the boot contract for an external next-stage payload and produce harness-level false positives instead of target bugs.

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

See `docs/plan.md` for the current repository-scoped implementation plan.

See `docs/runbook.md` for the supported S0-S4 workflows, expected artifacts, and escalation paths.

## Development Environment

We provides a VSCode dev container configuration for easy setup. To use it, see https://aka.ms/vscode-remote/containers.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
