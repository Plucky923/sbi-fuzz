---
name: fuzz-bug-report
description: >
  Generate self-contained GitHub Issue bug reports from fuzz crash artifacts.
  Use when the user asks to: (1) create a bug report from a crash, (2) generate
  a GitHub Issue for a fuzz finding, (3) write a reproducer for a PoC, (4) format
  a crash artifact into a standalone bug report, or (5) automate fuzz bug reporting.
  Works with host-harness libFuzzer crashes, firmware LibAFL crashes, and sequence
  fuzz artifacts. Produces standalone reproducers that only depend on crates.io or
  standard tools — no sbi-fuzz project source required.
---

# Fuzz Bug Report Skill

## Quick Start

1. Parse the crash artifact:
   ```bash
   python3 scripts/generate-github-issue.py \
     <crash-file> \
     --output-dir reports/
   ```

2. The script writes:
   - `reports/<bug-id>/issue.md` — GitHub Issue Markdown
   - `reports/<bug-id>/repro/` — Standalone reproducer (Rust crate or QEMU script)

3. Verify the reproducer compiles and runs independently:
   ```bash
   cd reports/<bug-id>/repro
   cargo run   # for host-harness crashes
   ```

## Workflow

When asked to generate a bug report, follow this pipeline:

### 1. Detect Artifact Type
Run `scripts/generate-github-issue.py` with `--type auto` (default). It inspects magic bytes and file extensions to determine if the artifact is:
- `host-harness` — libFuzzer crash from `host_harness/fuzz/`
- `firmware` — LibAFL crash from firmware fuzzing (`.toml` / `.exec`)
- `sequence` — Sequence fuzz crash (`.seq`)

If auto-detection fails, ask the user to specify `--type`.

### 2. Extract PoC Parameters
The script decodes the artifact into structured parameters (e.g., `HostHarnessInput` JSON). For host-harness artifacts, it supports:
- `.host` files (`SBIHOST1` magic + JSON)
- Raw JSON files
- Raw libFuzzer bytes (`from_fuzz_bytes` protocol)

### 3. Local Reproduction (Optional)
By default, the script runs local reproduction to confirm the crash and capture the exact panic message. Use `--skip-repro` to skip this step.

- **Host harness**: Runs the pre-built fuzz binary (`host_harness/fuzz/target/.../fuzz_ecall_rustsbi <artifact>`) to trigger the panic, then falls back to `helper run-host-harness` for structured JSON metadata.
- **Firmware**: Requires `--target` and `--injector`; runs `helper run <target> <injector> <input>`.

### 4. Generate Standalone Reproducer
The script generates a self-contained reproducer that does **not** require the sbi-fuzz project:

- **Host harness (RustSBI)**: A Rust crate (`Cargo.toml` + `src/main.rs`) depending only on `rustsbi = "0.4.0"`. It uses rustsbi's public internal dispatch functions (`_rustsbi_fence`, `_rustsbi_ipi`, etc.) with a mock backend that simulates the observed buggy return value. The reproducer includes an embedded SBI spec oracle — running `cargo run` will panic with a clear `BUG: ...` message if the return value violates the spec.
- **Firmware**: A QEMU command-line script (`repro.sh`).

### 5. Generate GitHub Issue Markdown
The script renders a GitHub Issue with:
- Title: `[<Extension>] <brief description>`
- Summary line
- **SBI Specification Reference**: Direct quote from the RISC-V SBI Specification (chapter + table) showing the mandated behavior
- Standalone reproducer code blocks (`Cargo.toml` + `src/main.rs`)
- Actual Behavior: the exact spec violation from the fuzzer panic
- Expected Behavior: concise description of what the spec requires

## Key Design Decisions

- **No Jinja2**: The script uses pure Python f-strings to avoid external dependencies.
- **Self-contained spec oracle**: Standalone reproducers embed the SBI spec checking logic (e.g., hart mask validity rules) so they can detect violations without the sbi-fuzz oracle.
- **Spec-first reporting**: Every issue includes a direct citation from the RISC-V SBI Specification, not just a generic "should follow the spec" statement.
- `--skip-repro`: Use when running in CI or when the build environment is not available.

## Reference Files

- `references/host-harness-format.md` — Host harness artifact formats, panic patterns, reproduction commands
- `references/firmware-format.md` — Firmware TOML/exec formats, QEMU reproduction
- `references/sbi-extension-reference.md` — EID/FID mapping, rustsbi trait/internal-fn mapping, common spec violations

Load these references when you need detailed schema information or when extending the script to support new extensions.
