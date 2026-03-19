# SBI-Fuzz Layered Implementation Plan

## Goal Description

This plan reconciles `PLAN.md` with the current repository state. The repository already contains host-side fuzz targets, structured `.host` and `.seq` formats, spec and memory oracles, diff policy helpers, triage scripts, metrics collection, and regression entry points. The remaining work is to harden those capabilities into a layered fuzzing program that reliably finds, classifies, replays, and tracks SBI firmware bugs across host-side, stateful sequence, differential, and L3/QEMU paths.

The implementation should prioritize the bug classes described in the draft: memory safety, address and length validation, HSM state-machine violations, platform-fault rollback issues, return-code mismatches, hart-mask decoding bugs, partial I/O semantic errors, and multi-hart state corruption.

## Acceptance Criteria

- AC-1: Repository baseline and automation are aligned with the real codebase rather than the older draft assumptions.
  - Positive Tests (expected to PASS):
    - `make host-fuzz-smoke` exercises `fuzz_harness_smoke`, `fuzz_ecall_opensbi`, `fuzz_ecall_rustsbi`, and `fuzz_sequence_both`.
    - `cargo helper run-host-harness <artifact>` replays both serialized `.host` inputs and raw libFuzzer artifacts that rely on `HostHarnessInput::from_fuzz_bytes()`.
    - Setup and smoke commands fail with explicit dependency guidance when OpenSBI sources or host fuzz tooling are missing.
  - Negative Tests (expected to FAIL):
    - Documentation or scripts still reference non-existent mandatory targets, directories, or commands.
    - Baseline automation silently skips a target instead of reporting it.

- AC-2: Structured host input decoding and corpus generation are robust under malformed and boundary-case inputs.
  - Positive Tests (expected to PASS):
    - `cargo test -p common --test host_format`
    - Boundary fixtures cover empty inputs, truncated inputs, maximum region count, region length clamping, and FDT-mode payload decoding.
    - `make host-fuzz-corpus` generates current corpora for OpenSBI, RustSBI, diff, and sequence targets from the active schema registry.
  - Negative Tests (expected to FAIL):
    - Malformed byte streams trigger panics, unbounded allocation, or out-of-range region growth.
    - Corpus export accepts unknown extension/schema combinations without a clear error.

- AC-3: Spec and memory oracles cover the highest-value SBI semantics with low false-positive rates.
  - Positive Tests (expected to PASS):
    - `cargo test -p common --test spec_oracle --test memory_oracle`
    - Fixtures exist for Base, HSM, Console, IPI/RFENCE, and PMU semantics, including success paths and known-invalid calls.
    - `make triage-host-fuzz` classifies oracle-triggered artifacts into stable signatures and report categories.
  - Negative Tests (expected to FAIL):
    - Implementation-defined or whitelisted behaviors are misclassified as spec violations.
    - Illegal memory writes to read-only or unrelated regions escape detection.

- AC-4: Stateful sequence fuzzing remains bounded, reproducible, and semantically meaningful.
  - Positive Tests (expected to PASS):
    - `cargo test -p common --test sequence_format --test sequence_mutation --test hsm_tracker`
    - `make host-fuzz-sequence` drives the current combined sequence target with mutation and crossover enabled.
    - At least one deterministic regression fixture requires two or more sequence steps to reproduce the issue.
  - Negative Tests (expected to FAIL):
    - Invalid sequence byte streams panic instead of decoding into a bounded fallback program.
    - Step count, memory object count, or per-step payload size can grow past configured limits.

- AC-5: Differential fuzzing reports actionable OpenSBI vs RustSBI mismatches without drowning in known noise.
  - Positive Tests (expected to PASS):
    - `cargo test -p common --test diff_policy`
    - `make host-fuzz-diff` runs with categorized output that distinguishes spec-relevant differences from implementation-defined or accepted ones.
    - Fixture coverage includes at least one ignored known difference and one actionable differential case.
  - Negative Tests (expected to FAIL):
    - Whitelisted differences are still surfaced as crashes or top-level bugs.
    - Dual-failure cases are reported as meaningful differentials when both targets failed equivalently.

- AC-6: Host-side findings can be promoted into L3 replay and regression assets.
  - Positive Tests (expected to PASS):
    - A documented helper flow exists to convert a host-side artifact into a replayable `.exec` or equivalent L3 regression input.
    - `make test-regression` includes at least one case sourced from a host-side or differential artifact.
    - Injector-side oracle or buffer extensions remain compatible with current replay and reporting tools.
  - Negative Tests (expected to FAIL):
    - Unsupported host-only artifacts are silently converted into broken L3 inputs.
    - L3 replay plumbing changes unrelated `.exec` semantics or breaks existing regression cases.

- AC-7: Triage, deduplication, and minimization work across host, sequence, and L3 layers with a shared signature model.
  - Positive Tests (expected to PASS):
    - Fixture-based script checks cover `triage-host-fuzz-results.py`, `cross-layer-dedup.py`, `collect-metrics.py`, and sequence minimization paths.
    - Equivalent findings discovered at multiple layers collapse into one logical bug while preserving per-layer reproducer references.
    - JSON and Markdown reports include layer, target, oracle type, EID/FID, normalized signature, and minimal reproducer path.
  - Negative Tests (expected to FAIL):
    - Duplicate artifacts from the same root cause remain counted as separate unique bugs.
    - Malformed report inputs are accepted without an actionable parsing error.

- AC-8: Metrics and quality gates are reproducible, configurable, and honest about missing data.
  - Positive Tests (expected to PASS):
    - `make collect-metrics` and `make quality-gate` produce machine-readable outputs from the current host fuzz and replay logs.
    - Reports capture throughput, time-to-first-crash, time-to-first-spec-violation, unique findings, and coverage trends when those inputs exist.
    - Thresholds are configurable by profile or environment and documented with sane defaults.
  - Negative Tests (expected to FAIL):
    - Missing optional metrics are fabricated instead of reported as unavailable.
    - Correctness-focused CI jobs fail only because a host machine is slower than the reference benchmark.

## Path Boundaries

### Upper Bound (Maximum Scope)

- Deliver a stable layered pipeline covering host ecall fuzzing, stateful sequence fuzzing, differential fuzzing, host-to-L3 replay, triage, minimization, regression, and metrics.
- Close semantic coverage for Base, HSM, Console, IPI, RFENCE, and PMU, with memory-oracle enforcement where address and length semantics matter.
- Produce machine-readable artifacts so campaign results can be compared across runs and across layers.

### Lower Bound (Minimum Scope)

- Preserve the existing host-side architecture and combined sequence target shape.
- Reach deterministic host-side single-call, sequence, and diff smokes with strong tests around the highest-value bug classes: Console, HSM, and hart-mask/address validation.
- Deliver repeatable triage and regression outputs even if some L3 feedback work lands after the host-side stack is already stable.

### Repository Paths in Scope

- `common/src` and `common/tests`
- `host_harness/src` and `host_harness/fuzz`
- `helper/src`
- `scripts`
- `tests/fixtures` and `tests/regression`
- `injector/src` and `fuzzer/src` only for host-to-L3 replay and oracle feedback plumbing

### Allowed Choices

- Can reuse and refine current files under `common/`, `host_harness/fuzz/`, `helper/`, `scripts/`, and `tests/` instead of creating new modules named in the older draft.
- Can keep `fuzz_sequence_both.rs` plus `support.rs` as the shared sequence entrypoint if separate per-backend targets do not add value.
- Can use fixture-based script tests and smoke campaigns for CI, while reserving overnight and multi-worker runs for evaluation environments.
- Can treat throughput numbers from the draft as reference-machine trend targets rather than universal hard gates. This is an inference from the draft because no stricter requirement is stated.
- Cannot introduce a parallel wire format that duplicates `.host`, `.seq`, or `.exec` without a compatibility reason.
- Cannot let milestone names, phase names, or `AC-*` labels leak into production code, report schemas, or user-facing error strings.

### Explicit Non-Goals

- Replacing `cargo-fuzz` or libFuzzer with a different fuzzing engine
- Redesigning the `playground/` boot and preparation flows beyond what is needed for L3 replay
- Adding new firmware implementations beyond OpenSBI and RustSBI in this plan

## Dependencies and Sequence

### Milestones

1. Milestone 1: Reconcile the baseline and stabilize current automation
   - Phase A: Map draft items to the current repository, remove stale assumptions, and document authoritative setup, smoke, corpus, and replay commands.
   - Phase B: Tighten failure modes so missing sources, toolchains, or corpora produce direct remediation steps.
   - Exit Criteria: Host smoke, corpus generation, and replay entry points are trustworthy and current.

2. Milestone 2: Harden structured inputs and high-value oracles
   - Phase A: Tighten `HostHarnessInput::from_fuzz_bytes()` and corpus export around truncation, bounds, schema-driven edge cases, and FDT payload handling.
   - Phase B: Close spec-oracle and memory-oracle gaps for Base, Console, HSM, IPI/RFENCE, and PMU with unit tests plus targeted fixtures.
   - Exit Criteria: Single-call host fuzzing has high-confidence semantic and memory checks with manageable false-positive rates.

3. Milestone 3: Stabilize stateful and differential fuzzing
   - Phase A: Strengthen sequence decoding, mutation, HSM state tracking, and multi-hart fixtures around bounded but meaningful stateful programs.
   - Phase B: Refine diff policy, whitelisting, and reporting so only actionable OpenSBI vs RustSBI mismatches survive long runs.
   - Exit Criteria: Overnight host sequence and diff jobs produce triageable results with controlled noise.

4. Milestone 4: Connect host findings to L3 replay
   - Phase A: Add or finalize host-artifact to `.exec` conversion and the injector or oracle plumbing needed to replay those findings on the L3 path.
   - Phase B: Promote confirmed issues into deterministic regression inputs that can be replayed at host and L3 layers.
   - Exit Criteria: At least one host-side or differential finding is reproducible through the L3 path.

5. Milestone 5: Unify triage, minimization, and metrics
   - Phase A: Normalize signatures, deduplication, and minimization across host, sequence, and L3 outputs.
   - Phase B: Finalize metrics collection and quality gates around stable log and report formats.
   - Exit Criteria: Campaign runs emit JSON and Markdown reports plus regression-ready artifacts without manual spreadsheet work.

### Dependency Notes

- Milestone 1 must complete before later throughput or oracle-coverage claims can be trusted.
- Milestone 2 must land before long-running sequence and differential campaigns, otherwise signal quality will be too noisy.
- Milestone 4 depends on stable host artifact formats and signature rules from Milestones 2 and 3.
- Milestone 5 depends on report and log formats being stable enough to avoid recurring parser churn.

## Feasibility Hints

- Reuse the existing `host_harness/fuzz` workspace, corpus layout, and `support.rs` helpers instead of recreating them.
- Prefer fixture-based tests in `common/tests/`, `tests/fixtures/`, and script smoke tests over relying on long fuzz runs for correctness.
- Use RustSBI-first validation whenever OpenSBI sanitizer or source-tree setup blocks iteration.
- Focus extension priority in this order: Console, HSM, IPI/RFENCE, PMU. This preserves the draft's bug-density rationale while matching the current schema coverage.
- For performance reporting, record host single-call and diff targets on one reference machine. Draft values above `5000 exec/s` for single-call and above `1000 exec/s` for sequence are useful guardrails, but they should be treated as performance goals unless explicitly promoted to hard release gates.
- Keep report fields stable across layers: target, layer, oracle type, EID/FID, signature, reproducibility status, and minimal reproducer path.

## Implementation Notes

- This plan is intentionally written in English to unify the output language. The source draft mixes Chinese and English, but the repository's public-facing docs and CLI examples are primarily English.
- If a deliverable already exists in the repository, the task becomes gap analysis, hardening, tests, and automation rather than file creation.
- Prefer enhancing existing modules over adding near-duplicate replacements with overlapping responsibility.
- Code and emitted report formats should not contain milestone names, phase numbers, or `AC-*` labels.
