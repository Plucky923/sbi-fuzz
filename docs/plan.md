# sbi-fuzz Multi-Scenario Fuzzing and Bug Reporting Plan

## Goal Description
Turn the repository's existing host-side and system-level fuzzing capabilities into a repeatable, documented, and testable defect-discovery pipeline. The plan should close the gaps that are visible in the current tree instead of rebuilding existing pieces: fix README drift, define the minimum reproducible paths for S0-S4, standardize bug-report fields on top of the current triage and reporting scripts, make differential and sequence coverage first-class entry points, and raise regression plus quality-gate checks to release-facing enforcement.

This plan is intentionally repository-native. It assumes the current `Makefile`, `scripts/`, `playground/`, and `tests/regression/` layout stays in place. Quantitative numbers in the draft, such as "10 to 30 minutes" or phase-by-week language, are treated as planning targets unless they are backed by deterministic automation.

## Acceptance Criteria

Following TDD philosophy, each criterion includes positive and negative tests for deterministic verification.

- AC-1: Documentation and user-facing entry points match the repository's real commands, outputs, and prerequisites.
  - Positive Tests (expected to PASS):
    - `Readme.md` no longer references missing planning files such as `TODO.md`, and instead points to existing docs under `docs/`.
    - A runbook under `docs/` maps S0-S4 to concrete commands, expected outputs, and escalation rules using current entry points such as `make host-fuzz-smoke`, `make host-fuzz-rustsbi`, `make host-fuzz-sequence`, `make host-fuzz-diff`, `make campaign-opensbi`, and `make campaign-rustsbi`.
    - The documented S0 path produces the advertised artifacts, including `triage.json`, `metrics.json`, and `quality_gate.json`, in the documented output locations.
  - Negative Tests (expected to FAIL):
    - A docs check fails if `Readme.md` links to non-existent local files or documents commands that do not exist in the tree.
    - The documented quick path fails validation if a required artifact path is missing or renamed without the runbook being updated.

- AC-2: The repository exposes one minimal local validation chain for preflight, smoke, and report generation, with optional CI wiring built on the same chain.
  - Positive Tests (expected to PASS):
    - Aggregated entry points such as `make preflight`, `make smoke-all`, and `make report-all` (or equivalently named targets documented in the plan) execute the intended sequence using existing scripts and stop on the first failing stage.
    - The minimal gate covers environment checks, deterministic tests, host fuzz smoke, and schema validation for generated bug-report artifacts.
    - If CI is added, it reuses the same local commands rather than a second, divergent workflow definition.
  - Negative Tests (expected to FAIL):
    - The aggregate gate must exit non-zero when an upstream stage fails, when a required report file is missing, or when schema validation fails.
    - A CI or local gate configuration that skips regression or smoke coverage without an explicit, documented exception fails review.

- AC-3: Host, sequence, and system-level reports share a schema-v1 contract with stable bug identity and reproducibility metadata.
  - Positive Tests (expected to PASS):
    - Outputs from the current reporting stack include a required core field set such as `bug_id`, `dedup_key`, `classification`, `impact`, `affected_target`, `repro_stability`, `first_seen`, and `last_seen`, with versioned schema validation.
    - The existing cross-layer dedup flow merges the same root cause across host and QEMU layers into one primary bug card while preserving all reproducer references.
    - Representative fixtures for host, sequence, and QEMU reports pass schema tests and preserve backwards-compatible migration behavior where needed.
  - Negative Tests (expected to FAIL):
    - A report missing a required field or using an enum outside the allowed set fails schema validation.
    - Two reports with the same dedup identity incorrectly surviving as separate primary bugs fail dedup regression tests.

- AC-4: Differential and stateful scenarios are first-class campaign inputs rather than side paths.
  - Positive Tests (expected to PASS):
    - The supported smoke or nightly path includes both `fuzz_diff_ecall` and `fuzz_diff_sequence`, or an explicit documented replacement that covers equivalent sequence-level differential behavior.
    - Sequence and differential campaigns preserve topology and profile metadata so replay runs under the same effective scenario, including multi-hart settings where applicable.
    - Generated summaries expose scenario-specific counts and mismatch classifications instead of collapsing all differential results into one generic bucket.
  - Negative Tests (expected to FAIL):
    - A workflow that claims S3 differential coverage but only exercises the single-call ecall path fails validation.
    - Replay that silently changes `--smp`, drops sequence metadata, or loses mismatch context fails regression.

- AC-5: Quality gates and regression tests enforce real bug history, not only aggregate statistics.
  - Positive Tests (expected to PASS):
    - The quality gate distinguishes blockers from warnings, including at minimum new sanitizer or crash findings, re-opened bugs, and hang instability beyond a configured threshold.
    - Confirmed findings can be promoted into `tests/regression/`, and `scripts/test-regression.sh` exercises those fixtures as part of the standard validation path.
    - Campaign summaries provide both the current snapshot and a delta against a prior comparable run so "new", "fixed", and "regressed" findings are explicit.
  - Negative Tests (expected to FAIL):
    - A reintroduced regression that maps to a previously closed bug does not block the gate.
    - A severe finding disappears from summary output because history or schema inputs are missing, stale, or incompatible.

## Path Boundaries

Path boundaries define the acceptable range of implementation quality and choices.

### Upper Bound (Maximum Acceptable Scope)
The implementation fixes the README drift, adds a scenario runbook, introduces aggregate local validation targets, standardizes report schema and stable bug identities across host, sequence, and QEMU layers, broadens differential coverage to include stateful sequence comparison, adds delta-aware campaign summaries, promotes blocker versus warning quality-gate policy, extends `tests/regression/` with real findings, and optionally wires the same checks into a lightweight GitHub Actions workflow.

### Lower Bound (Minimum Acceptable Scope)
The implementation fixes broken roadmap links, adds one accurate runbook for the existing command surface, creates one aggregate local validation path, defines and validates a schema-v1 contract for current report outputs, introduces stable bug identity plus reproducibility metadata on top of the existing reporting scripts, and enforces blocker rules for new high-severity findings and reopened regressions using the current output directories.

### Allowed Choices
- Can use: existing `Makefile` targets, Python report scripts under `scripts/`, JSON or TOML-backed schema/config files under `config/`, Markdown docs under `docs/`, and optional GitHub Actions under `.github/workflows/`.
- Can use: migration shims or schema versioning if existing JSON consumers need a compatibility window.
- Cannot use: replacing the current fuzzing architecture, requiring a new external service or dashboard before the local workflow works, or breaking existing report consumers without a documented migration path.
- Cannot use: code or comments that embed plan-only labels such as `AC-` or milestone names.

## Feasibility Hints and Suggestions

> **Note**: This section is for reference and understanding only. These are conceptual suggestions, not prescriptive requirements.

### Conceptual Approach
Start by normalizing the documentation surface, because artifact names and command flow should be stable before schema and gate work rely on them. Then define a report schema contract around the current scripts rather than inventing a parallel reporting stack. After stable identities and required fields exist, broaden scenario coverage and history-aware summaries. Only then tighten quality gates and CI, because those stages depend on reliable output names, metadata, and dedup behavior.

One practical sequence is:

1. Replace the broken roadmap link in `Readme.md` and add one scenario runbook under `docs/`.
2. Introduce aggregate local targets in `Makefile` that compose existing checks instead of reimplementing them.
3. Add schema validation and stable identity fields to `scripts/report-*.py`, `scripts/cross-layer-dedup.py`, and related helpers.
4. Promote `fuzz_diff_sequence` into the supported smoke or campaign path and ensure replay preserves scenario metadata.
5. Extend `scripts/campaign-quality-gate.py` and `scripts/test-regression.sh` so bug history and real regression fixtures become blocking signals.

### Relevant References
- `Readme.md` - current user-facing documentation, including the stale `TODO.md` roadmap link.
- `Makefile` - existing local entry points for host fuzzing, reporting, campaigns, and regression checks.
- `scripts/triage-host-fuzz-results.py` - current host-side triage output path.
- `scripts/report-sbi-bugs.py`, `scripts/report-sequence-bugs.py`, `scripts/report-opensbi-bugs.py` - current report producers that should converge on schema v1.
- `scripts/cross-layer-dedup.py` - current dedup entry point that should become the stable bug-card merge layer.
- `scripts/campaign-quality-gate.py` - current quality-gate logic to evolve from aggregate metrics into blocker and warning policy.
- `scripts/test-regression.sh` and `tests/regression/` - existing regression surface that can absorb confirmed fuzz findings.
- `playground/opensbi-fuzz/Makefile` and `playground/rustsbi-fuzz/Makefile` - current system-level campaign entry points and `latest.json` outputs.

## Dependencies and Sequence

### Milestones
1. Milestone 1: Normalize the public workflow surface.
   - Replace broken or stale roadmap references in `Readme.md`.
   - Add one accurate runbook for S0-S4 with commands, prerequisites, outputs, and failure interpretation.
   - Add aggregate local entry points that wrap the already supported checks.
2. Milestone 2: Establish a stable bug-report contract.
   - Define schema v1 and required fields for host, sequence, and QEMU report outputs.
   - Update dedup and report generation so one root cause maps to one stable bug identity with reproducibility metadata.
   - Add schema and dedup regression tests using checked-in fixtures.
3. Milestone 3: Raise scenario coverage and campaign summaries.
   - Promote sequence differential coverage from an ancillary target into a supported workflow.
   - Preserve replay metadata such as topology, profile, and scenario class across campaign stages.
   - Generate current-versus-prior summaries that classify findings as new, fixed, or regressed.
4. Milestone 4: Enforce quality policy with regression evidence.
   - Convert blocker and warning rules into quality-gate checks.
   - Promote representative confirmed findings into `tests/regression/`.
   - Optionally add CI that reuses the same local validation path.

Milestone 1 should land before Milestones 2 through 4 because naming and artifact locations need to stop drifting first. Milestone 2 is a prerequisite for Milestones 3 and 4 because stable schemas and bug identities are required before delta summaries, reopened-bug detection, and blocker policies are trustworthy.

## Implementation Notes

### Working Assumptions
- Language is unified to English in this generated plan to match the repository's existing top-level documentation.
- Draft time windows are treated as target budgets, not hard acceptance thresholds, unless the repository gains deterministic timing checks.
- Existing regression fixtures and campaign summaries mean the plan should extend current mechanisms instead of reintroducing them from scratch.

### Code Style Requirements
- Implementation code and comments must NOT contain plan-specific terminology such as `AC-`, `Milestone`, `Step`, `Phase`, or similar workflow markers.
- These terms are for plan documentation only, not for the resulting codebase.
- Use descriptive, domain-appropriate naming in code instead.

## Source Draft

The original design draft used to generate this plan is preserved verbatim in `PLAN.md` at the repository root. The generated plan above intentionally normalizes terminology and language to fit the current repository documentation style while keeping the source draft available for traceability.
