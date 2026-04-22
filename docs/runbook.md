# sbi-fuzz Scenario Runbook

This runbook maps the repository's supported workflows to concrete commands, expected artifacts, and escalation paths.

## Scope

- S0 covers the minimum local regression path for repository changes.
- S1 through S3 stay on the host-side harness for faster fuzzing and replay.
- S4 escalates to the system-level playgrounds once the host-side path is healthy.

## Prerequisites

Run the local probes first:

```bash
make preflight
```

This checks the environment, validates repository docs, and runs deterministic tests before fuzzing.

Success criteria:

- `make preflight` exits with status `0`
- docs validation passes
- deterministic regression targets pass

## S0: Quick Regression

Use S0 before opening a PR or after touching the harness, replay scripts, or report pipeline.

```bash
make smoke-all
make report-all
```

`make report-all` summarizes the latest S0 smoke outputs. It does not launch a fresh smoke run on its own.

Expected outputs:

- `output/host_fuzz_smoke/logs/` for integrated S0 smoke and report logs
- `output/host_fuzz_smoke/fuzz_ecall_opensbi/`
- `output/host_fuzz_smoke/fuzz_ecall_rustsbi/`
- `output/host_fuzz_smoke/fuzz_sequence_both/`
- `output/host_fuzz_smoke/fuzz_diff_ecall/`
- `output/host_fuzz_smoke/fuzz_diff_sequence/`
- `output/host_fuzz_smoke/triage.json`
- `output/host_fuzz_smoke/triage.md`
- `output/host_fuzz_smoke/opensbi.triage.json`
- `output/host_fuzz_smoke/opensbi.triage.md`
- `output/host_fuzz_smoke/metrics.json`
- `output/host_fuzz_smoke/opensbi.bugs.json`
- `output/host_fuzz_smoke/opensbi.bugs.md`
- `output/host_fuzz_smoke/cross-layer.json`
- `output/host_fuzz_smoke/quality_gate.json`

Success criteria:

- `make smoke-all` exits with status `0`
- smoke logs exist for `fuzz_ecall_opensbi`, `fuzz_ecall_rustsbi`, `fuzz_sequence_both`, `fuzz_diff_ecall`, and `fuzz_diff_sequence`
- `make report-all` writes the documented artifacts even when the quality gate blocks on findings
- `make report-all` exits with status `0` only when the quality gate passes; blocker findings are expected to return non-zero
- the generated `triage.json`, `opensbi.bugs.json`, `cross-layer.json`, and `quality_gate.json` all pass schema validation

Escalation:

- If `make smoke-all` fails before fuzzing starts, fix the local environment or deterministic tests first.
- If `make smoke-all` reports a finding and writes an artifact, treat that as an infrastructure success and continue to reporting.
- If `make report-all` fails validation, inspect the generated JSON schema before running longer campaigns.

Deterministic review mode:

```bash
SBIFUZZ_USE_FIXTURES=1 make preflight
SBIFUZZ_USE_FIXTURES=1 make smoke-all
SBIFUZZ_USE_FIXTURES=1 make report-all
```

Use this when the full host fuzz and OpenSBI toolchain is unavailable but you still need to verify the documented orchestration and artifact contract end to end.

## S0.5: Coverage Baseline Measurement

Use S0.5 to establish a per-extension/function coverage baseline before running longer campaigns.

```bash
# Build the helper with QEMU feature (requires clang/clang++ and OpenSBI source tree)
cargo build -p helper --features qemu --release

# Run baseline over seed directories
./target/release/helper coverage-baseline \
    fw_dynamic.bin \
    injector.elf \
    output/seed output/seed-complex \
    --output baseline.json \
    --timeout-ms 30000
```

Expected outputs:

- `baseline.json` containing `schema_version: "1.0.0"` and per `eid/fid` statistics:
  - `unique_pcs`, `total_pcs`, `semantic_signature_count`, `timeout_count`

Validation:

```bash
python3 scripts/validate-coverage-baseline.py baseline.json
# or via the unified validator:
python3 scripts/validate-report-artifacts.py baseline.json --kind coverage-baseline
```

Success criteria:

- `baseline.json` passes schema validation
- Files with recognized extensions (`.toml`, `.exec`, `.seq`) are processed; unrecognized files are ignored during scanning
- Parse or classification failures for recognized seeds cause a non-zero exit
- No coverage parse errors or fallback QEMU edges are accepted

Escalation:

- If `coverage-baseline` exits with "target firmware does not exist", verify `fw_dynamic.bin` and `injector.elf` are built.
- If `coverage-baseline` exits with "coverage parse error", check the injector/shared-buffer compatibility.
- If `coverage-baseline` exits with "fallback QEMU edges", verify the injector ELF exports `SBI_COVERAGE_BUFFER`.

## S1: Single-Implementation Host Fuzzing

Use S1 for fast RustSBI-oriented discovery after S0 is green.

```bash
make host-fuzz-rustsbi
make triage-host-fuzz
make collect-metrics
make quality-gate
```

Expected outputs:

- `output/host_fuzz/fuzz_ecall_rustsbi/`
- `output/host_fuzz/logs/fuzz_ecall_rustsbi.log`
- `output/host_fuzz/triage.json`
- `output/host_fuzz/metrics.json`
- `output/host_fuzz/quality_gate.json`

Escalation:

- If the fuzz target exits non-zero without an artifact, inspect `output/host_fuzz/logs/fuzz_ecall_rustsbi.log`.
- If the quality gate blocks on new crash-like findings, preserve the bug IDs and move the reproducer into follow-up replay or regression work.

## S2: Stateful Sequence Fuzzing

Use S2 for multi-hart and state-machine coverage.

```bash
make host-fuzz-sequence
make triage-host-fuzz
make collect-metrics
make quality-gate
```

Expected outputs:

- `output/host_fuzz/fuzz_sequence_both/`
- `output/host_fuzz/logs/fuzz_sequence_both.log`

Escalation:

- If sequence findings depend on a larger topology, rerun with `SBIFUZZ_HOST_SEQUENCE_SMP=<n>`.
- If hangs appear, preserve the sequence input and confirm whether the same topology is used during replay.

## S3: Differential Consistency Fuzzing

Use S3 when you need cross-implementation mismatch coverage. The public differential entry point runs both single-call and sequence-oriented targets.

```bash
make host-fuzz-diff
```

Expected outputs:

- `output/host_fuzz/fuzz_diff_ecall/`
- `output/host_fuzz/fuzz_diff_sequence/`
- `output/host_fuzz/logs/fuzz_diff_ecall.log`
- `output/host_fuzz/logs/fuzz_diff_sequence.log`

Escalation:

- If only one differential artifact family appears, treat that as an incomplete S3 run.
- Preserve mismatch reproducers together with their topology and sequence metadata before triage or replay.

## S4: System-Level Confirmation

Use S4 after host-side results are stable and reproducible.

```bash
make campaign-opensbi
make campaign-rustsbi
```

Expected outputs:

- `playground/opensbi-fuzz/output/campaign/latest.json`
- `playground/rustsbi-fuzz/output/campaign/latest.json`
- `playground/opensbi-fuzz/output/bugs/result.bugs.json`
- `playground/rustsbi-fuzz/output/bugs/result.bugs.json`

Escalation:

- If the target image is missing, run `make -C playground/opensbi-fuzz prepare` or `make -C playground/rustsbi-fuzz prepare`.
- If a host-side finding disappears at S4, keep both artifact paths and replay logs for cross-layer dedup instead of treating it as automatically resolved.

## Artifact Map

- Host smoke logs: `output/host_fuzz_smoke/logs/`
- Integrated S0 root: `output/host_fuzz_smoke/`
- Integrated S0 logs: `output/host_fuzz_smoke/logs/`
- Host triage outputs: `output/host_fuzz_smoke/triage.json`, `output/host_fuzz_smoke/triage.md`
- OpenSBI host triage mirror: `output/host_fuzz_smoke/opensbi.triage.json`, `output/host_fuzz_smoke/opensbi.triage.md`
- Host metrics: `output/host_fuzz_smoke/metrics.json`
- OpenSBI bug report mirror: `output/host_fuzz_smoke/opensbi.bugs.json`, `output/host_fuzz_smoke/opensbi.bugs.md`
- Cross-layer dedup output: `output/host_fuzz_smoke/cross-layer.json`
- Host gate result: `output/host_fuzz_smoke/quality_gate.json`
- Long-lived host campaign root: `output/host_fuzz/`
- OpenSBI campaign summary: `playground/opensbi-fuzz/output/campaign/latest.json`
- RustSBI campaign summary: `playground/rustsbi-fuzz/output/campaign/latest.json`

## Supported Entry Points

```bash
make preflight
make smoke-all
make report-all
make host-fuzz-rustsbi
make host-fuzz-sequence
make host-fuzz-diff
make campaign-opensbi
make campaign-rustsbi
```
