LLVM_CONFIG_PATH ?= $(shell command -v llvm-config-18 2>/dev/null || command -v llvm-config 2>/dev/null)
CC ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo cc)
CXX ?= $(shell command -v clang++-18 2>/dev/null || command -v clang++ 2>/dev/null || echo c++)
LIBCLANG_PATH ?= $(shell if [ -d /usr/lib/llvm-18/lib ]; then echo /usr/lib/llvm-18/lib; elif [ -d /usr/lib/llvm-20/lib ]; then echo /usr/lib/llvm-20/lib; fi)
export LLVM_CONFIG_PATH CC CXX LIBCLANG_PATH

all: compile

compile: helper injector
	@echo ">>> All components built successfully"

docs-check:
	@python3 ./scripts/check-docs.py ./Readme.md ./docs/runbook.md

preflight-real:
	@$(MAKE) docs-check
	@$(MAKE) check-env
	@$(MAKE) test-common
	@$(MAKE) test-host-harness
	@$(MAKE) test-regression

preflight-fixture:
	@$(MAKE) docs-check
	@$(MAKE) test-docs-check
	@$(MAKE) test-campaign-quality-gate
	@$(MAKE) test-cross-layer-dedup
	@$(MAKE) test-opensbi-bug-report
	@$(MAKE) test-sequence-bug-report
	@$(MAKE) test-sbi-hang-semantic-buckets
	@$(MAKE) test-coverage-baseline

check-env:
	@./scripts/check-env.sh

check-env-smoke:
	@./scripts/check-env.sh --full-smoke

preflight:
	@if [ "$${SBIFUZZ_USE_FIXTURES:-0}" = "1" ]; then \
		$(MAKE) preflight-fixture; \
	else \
		$(MAKE) preflight-real; \
	fi

test-common:
	@cargo test -p common

test-host-harness:
	@cargo test -p common -p host_harness
	@cargo check -p helper

test-regression:
	@bash ./scripts/test-regression.sh

test-docs-check:
	@bash ./scripts/test-docs-check.sh

test-campaign-quality-gate:
	@bash ./scripts/test-campaign-quality-gate.sh

test-cross-layer-dedup:
	@bash ./scripts/test-cross-layer-dedup.sh

test-collect-metrics:
	@./scripts/test-collect-metrics.sh

test-triage-host-fuzz-results:
	@./scripts/test-triage-host-fuzz-results.sh

test-minimize-spec-violation:
	@./scripts/test-minimize-spec-violation.sh

test-default-cross-layer-dedup:
	@./scripts/test-default-cross-layer-dedup.sh

test-default-collect-metrics:
	@./scripts/test-default-collect-metrics.sh

test-s0-workflow:
	@bash ./scripts/test-s0-workflow.sh

test-sequence-bug-report:
	@bash ./scripts/test-report-sequence-bugs.sh

test-coverage-baseline:
	@bash ./tests/fixtures/baseline/run-validation-tests.sh
	@bash ./tests/fixtures/baseline/run-missing-dir-test.sh
	@bash ./tests/fixtures/baseline/run-positive-baseline-test.sh

test-campaign-summary-delta:
	@bash ./scripts/test-campaign-summary-delta.sh

test-merge-host-triage:
	@bash ./scripts/test-merge-host-triage.sh

test-host-triage-to-bug-report:
	@bash ./scripts/test-host-triage-to-bug-report.sh

triage-host-fuzz:
	@python3 ./scripts/triage-host-fuzz-results.py ./output/host_fuzz/fuzz_ecall_rustsbi --json-out ./output/host_fuzz/triage.json --md-out ./output/host_fuzz/triage.md

collect-metrics:
	@python3 ./scripts/collect-metrics.py --log-dir ./output/host_fuzz/logs --triage-json ./output/host_fuzz/triage.json --cross-layer-json ./output/host_fuzz/cross-layer.json --json-out ./output/host_fuzz/metrics.json

quality-gate:
	@python3 ./scripts/campaign-quality-gate.py --metrics ./output/host_fuzz/metrics.json --triage ./output/host_fuzz/triage.json --json-out ./output/host_fuzz/quality_gate.json

campaign-quality-gate: quality-gate

cross-layer-dedup:
	@./scripts/run-default-cross-layer-dedup.sh

host-fuzz-corpus:
	@./scripts/prepare-host-fuzz-corpus.sh

smoke-all:
	@./scripts/run-smoke-all.sh

host-fuzz-smoke:
	@./scripts/smoke-host-harness-fuzz.sh

host-fuzz-rustsbi:
	@./scripts/run-host-harness-fuzz.sh fuzz_ecall_rustsbi

host-fuzz-sequence:
	@./scripts/run-host-harness-fuzz.sh fuzz_sequence_both

host-fuzz-diff: host-fuzz-diff-ecall host-fuzz-diff-sequence

host-fuzz-diff-ecall:
	@./scripts/run-host-harness-fuzz.sh fuzz_diff_ecall

host-fuzz-diff-sequence:
	@./scripts/run-host-harness-fuzz.sh fuzz_diff_sequence

report-all:
	@./scripts/run-report-all.sh

host-fuzz-60:
	@SBIFUZZ_FUZZ_JOBS=60 SBIFUZZ_FUZZ_WORKERS=60 SBIFUZZ_FUZZ_DURATION_SECS=$${SBIFUZZ_FUZZ_DURATION_SECS:-300} ./scripts/run-host-harness-fuzz.sh fuzz_ecall_rustsbi

host-fuzz-60-complex:
	@SBIFUZZ_FUZZ_JOBS=60 SBIFUZZ_FUZZ_WORKERS=60 SBIFUZZ_FUZZ_DURATION_SECS=$${SBIFUZZ_FUZZ_DURATION_SECS:-300} SBIFUZZ_HOST_SEQUENCE_SMP=$${SBIFUZZ_HOST_SEQUENCE_SMP:-60} SBIFUZZ_MAX_LEN=$${SBIFUZZ_MAX_LEN:-4096} ./scripts/run-host-harness-fuzz.sh fuzz_sequence_both

test-linux-corpus-import:
	@./scripts/test-import-linux-sbi-corpus.sh

test-opensbi-triage:
	@./scripts/test-triage-opensbi-results.sh

test-opensbi-replay:
	@./scripts/test-replay-opensbi-results.sh

test-opensbi-replay-summary:
	@./scripts/test-summarize-replay-opensbi-results.sh

test-opensbi-sanitizer-demo:
	@python3 ./scripts/run-opensbi-sanitizer-demo.py playground/opensbi-sanitizer-demo/output/opensbi/build/platform/generic/firmware/fw_dynamic.bin injector/build/injector.elf playground/opensbi-sanitizer-demo/test-heap-overflow.toml playground/opensbi-sanitizer-demo/test-integer-overflow.toml --helper-bin target/release/helper --timeout-secs 10 --json-out /tmp/opensbi-sanitizer-demo.json > /tmp/opensbi-sanitizer-demo.stdout.json

test-opensbi-coverage:
	@./scripts/test-opensbi-coverage.sh

test-opensbi-bug-report:
	@./scripts/test-report-opensbi-bugs.sh

test-rustsbi-scenarios:
	@cargo test -p helper scenario_generator::tests

test-rustsbi-replay:
	@./scripts/test-rustsbi-replay.sh

test-rustsbi-helper-timeout:
	@./scripts/test-rustsbi-helper-timeout.sh

test-rustsbi-collect-coverage-timeout:
	@./scripts/test-rustsbi-collect-coverage-timeout.sh

test-rustsbi-hang-stability:
	@./scripts/test-rustsbi-hang-stability.sh

test-rustsbi-hang-minimize:
	@./scripts/test-rustsbi-hang-minimize.sh

test-sbi-hang-semantic-buckets:
	@./scripts/test-sbi-hang-semantic-buckets.sh

test-rustsbi-fuzz-finds-bug:
	@./scripts/test-rustsbi-fuzz-finds-bug.sh

test-sequence-replay:
	@./scripts/test-replay-sequence-results.sh

sequence-seeds:
	@cargo run -q -p helper -- generate-sequence-seeds --target-kind both ./output/sequence

campaign-sequence-opensbi: sequence-seeds
	@PREV_SUMMARY=""; \
	if [ -f ./output/sequence/opensbi-sequence.campaign.json ]; then PREV_SUMMARY="--previous-summary ./output/sequence/opensbi-sequence.campaign.json"; fi; \
	python3 ./scripts/run-sequence-campaign.py opensbi-sequence opensbi ./output/sequence $$PREV_SUMMARY --json-out ./output/sequence/opensbi-sequence.campaign.json

campaign-sequence-rustsbi: sequence-seeds
	@PREV_SUMMARY=""; \
	if [ -f ./output/sequence/rustsbi-sequence.campaign.json ]; then PREV_SUMMARY="--previous-summary ./output/sequence/rustsbi-sequence.campaign.json"; fi; \
	python3 ./scripts/run-sequence-campaign.py rustsbi-sequence rustsbi ./output/sequence $$PREV_SUMMARY --json-out ./output/sequence/rustsbi-sequence.campaign.json

campaign-opensbi:
	@$(MAKE) -C playground/opensbi-fuzz campaign

campaign-rustsbi:
	@$(MAKE) -C playground/rustsbi-fuzz campaign

campaign-rustsbi-complex:
	@$(MAKE) -C playground/rustsbi-fuzz campaign-complex

fuzzer:
	@echo ">>> Building fuzzer package..."
	cargo build --package fuzzer --release
	@echo ">>> Fuzzer build completed"

helper:
	@echo ">>> Building helper package..."
	cargo build --package helper --release
	@echo ">>> Helper build completed"

injector:
	@echo ">>> Building injector..."
	cd injector && make PREFIX="==>"
	@echo ">>> Injector build completed"

clean: clean-cargo clean-injector clean-playgrounds clean-generated
	@echo ">>> All clean operations completed"

clean-cargo:
	@echo ">>> Cleaning workspace build artifacts..."
	@rm -rf target
	@echo ">>> Workspace build cleanup completed"

clean-injector:
	@echo ">>> Cleaning injector build artifacts..."
	cd injector && make PREFIX="==>" clean
	@echo ">>> Injector clean completed"

clean-playgrounds:
	@echo ">>> Cleaning playground outputs..."
	@$(MAKE) -C playground/opensbi-fuzz clean
	@$(MAKE) -C playground/opensbi-sanitizer-demo clean
	@$(MAKE) -C playground/rustsbi-fuzz clean
	@echo ">>> Playground cleanup completed"

clean-generated:
	@echo ">>> Cleaning generated local artifacts..."
	@rm -f ./exec-program-*.txt ./base-*.toml ./console-*.toml ./fence-*.toml ./hsm-*.toml ./ipi-*.toml ./legacy-*.toml ./reset-*.toml ./timer-*.toml ./unknown-*.toml
	@rm -rf ./reports ./scripts/__pycache__
	@echo ">>> Generated artifact cleanup completed"

help:
	@echo "Available targets:"
	@echo "  all (default)          - Build all components"
	@echo "  compile                - Same as 'all'"
	@echo "  docs-check             - Validate README and runbook links plus documented make targets"
	@echo "  check-env              - Probe required and optional tooling"
	@echo "  check-env-smoke        - Probe tooling and run build smoke checks"
	@echo "  preflight              - Run docs validation, environment checks, and deterministic tests"
	@echo "  test-common            - Run common crate automated tests"
	@echo "  test-host-harness      - Validate the host-side OpenSBI layered harness and helper CLI"
	@echo "  test-regression        - Run deterministic host-side regression checks"
	@echo "  test-docs-check        - Verify docs validation catches stale links and bad make targets"
	@echo "  test-campaign-quality-gate - Verify quality gate blockers and warnings from synthetic history"
	@echo "  test-cross-layer-dedup - Verify stable bug IDs merge across host and system report inputs"
	@echo "  test-collect-metrics   - Verify metrics aggregation from logs, triage, and cross-layer output"
	@echo "  test-triage-host-fuzz-results - Verify host triage bucketing from regression artifacts"
	@echo "  test-minimize-spec-violation - Verify spec-violation minimization removes irrelevant steps"
	@echo "  test-default-cross-layer-dedup - Verify default cross-layer source discovery and grouping"
	@echo "  test-default-collect-metrics - Verify default collect-metrics paths consume triage and cross-layer data"
	@echo "  test-sequence-bug-report - Verify sequence bug reports satisfy the shared schema contract"
	@echo "  test-campaign-summary-delta - Verify campaign summaries compute new/fixed/regressed/persisting finding sets"
	@echo "  test-merge-host-triage - Verify merged host triage preserves crash severity semantics"
	@echo "  test-host-triage-to-bug-report - Verify mirrored host bug reports preserve per-bucket counts"
	@echo "  test-s0-workflow       - Run the documented preflight/smoke/report chain in deterministic fixture mode"
	@echo "  triage-host-fuzz       - Triage host_harness fuzz artifacts into JSON/Markdown"
	@echo "  collect-metrics        - Summarize libFuzzer metrics from host-side logs"
	@echo "  quality-gate           - Evaluate host-side campaign metrics and triage against thresholds"
	@echo "  campaign-quality-gate  - Alias for 'quality-gate'"
	@echo "  cross-layer-dedup      - Deduplicate host triage and mirrored OpenSBI bug-report outputs"
	@echo "  host-fuzz-corpus       - Generate libFuzzer corpora for host_harness fuzz targets"
	@echo "  smoke-all              - Run the documented S0 smoke path (supports deterministic fixture mode)"
	@echo "  host-fuzz-smoke        - Verify crash-capture chain and run short host_harness fuzz smokes"
	@echo "  host-fuzz-rustsbi      - Run the RustSBI host_harness libFuzzer target"
	@echo "  host-fuzz-sequence     - Run the sequence-oriented dual-backend host_harness target"
	@echo "  host-fuzz-diff         - Run both host-side differential fuzz targets (ecall and sequence)"
	@echo "  host-fuzz-diff-ecall   - Run the host-side differential ecall fuzz target"
	@echo "  host-fuzz-diff-sequence - Run the host-side differential sequence fuzz target"
	@echo "  report-all             - Summarize the latest S0 smoke outputs and validate generated artifacts"
	@echo "  host-fuzz-60           - Launch a 60-worker RustSBI host_harness fuzz campaign"
	@echo "  host-fuzz-60-complex   - Launch a 60-worker multi-hart sequence campaign"
	@echo "  test-linux-corpus-import - Validate Linux-style SBI corpus import"
	@echo "  test-opensbi-triage    - Triage current OpenSBI result directories"
	@echo "  test-opensbi-replay    - Replay representative OpenSBI findings"
	@echo "  test-opensbi-replay-summary - Summarize replay JSON output"
	@echo "  test-opensbi-sanitizer-demo - Run fixed OpenSBI sanitizer demo samples"
	@echo "  test-opensbi-coverage  - Export and summarize OpenSBI shared coverage"
	@echo "  test-opensbi-bug-report - Bucket replay results into bug candidates"
	@echo "  test-rustsbi-scenarios - Validate generated RustSBI complex exec seeds"
	@echo "  test-rustsbi-replay   - Replay one RustSBI complex exec seed with --smp"
	@echo "  test-rustsbi-helper-timeout - Verify helper run native timeout on a hanging RustSBI seed"
	@echo "  test-rustsbi-collect-coverage-timeout - Verify helper collect-coverage native timeout JSON on a hanging RustSBI seed"
	@echo "  test-rustsbi-hang-stability - Verify repeated hang replay classification on a RustSBI hanging seed"
	@echo "  test-rustsbi-hang-minimize - Verify stable RustSBI hangs are auto-minimized into shorter .exec PoCs"
	@echo "  test-sbi-hang-semantic-buckets - Verify stable hangs split into semantic buckets instead of one Timeout bucket"
	@echo "  test-rustsbi-fuzz-finds-bug - Run a short RustSBI complex campaign and require a real bug-like finding"
	@echo "  test-sequence-replay   - Replay and campaign unified .seq inputs against a single target"
	@echo "  sequence-seeds         - Generate unified .seq seeds for OpenSBI and RustSBI"
	@echo "  campaign-sequence-opensbi - Run host-side .seq campaign against OpenSBI"
	@echo "  campaign-sequence-rustsbi - Run host-side .seq campaign against RustSBI"
	@echo "  campaign-opensbi      - Run full OpenSBI fuzz/triage/replay/report campaign"
	@echo "  campaign-rustsbi      - Run full RustSBI prototyper fuzz campaign"
	@echo "  campaign-rustsbi-complex - Run RustSBI multi-call/multi-hart-oriented campaign"
	@echo "  fuzzer                 - Build only the fuzzer package"
	@echo "  helper                 - Build only the helper package"
	@echo "  injector               - Build only the injector"
	@echo "  clean                  - Clean all build artifacts"
	@echo "  clean-cargo            - Clean only workspace build artifacts"
	@echo "  clean-injector         - Clean only injector build artifacts"
	@echo "  clean-playgrounds      - Clean playground output directories"
	@echo "  clean-generated        - Clean generated local samples and reports"
	@echo "  help                   - Display this help message"

.PHONY: all compile docs-check preflight-real preflight-fixture check-env check-env-smoke preflight test-common test-host-harness test-regression test-docs-check test-campaign-quality-gate test-cross-layer-dedup test-collect-metrics test-triage-host-fuzz-results test-minimize-spec-violation test-default-cross-layer-dedup test-default-collect-metrics test-sequence-bug-report test-campaign-summary-delta test-merge-host-triage test-host-triage-to-bug-report test-s0-workflow test-linux-corpus-import test-opensbi-triage test-opensbi-replay test-opensbi-replay-summary test-opensbi-sanitizer-demo test-opensbi-coverage test-opensbi-bug-report test-rustsbi-scenarios test-rustsbi-replay test-rustsbi-helper-timeout test-rustsbi-collect-coverage-timeout test-rustsbi-hang-stability test-rustsbi-hang-minimize test-sbi-hang-semantic-buckets test-rustsbi-fuzz-finds-bug test-sequence-replay triage-host-fuzz collect-metrics quality-gate campaign-quality-gate cross-layer-dedup host-fuzz-corpus smoke-all host-fuzz-smoke host-fuzz-rustsbi host-fuzz-sequence host-fuzz-diff host-fuzz-diff-ecall host-fuzz-diff-sequence report-all host-fuzz-60 host-fuzz-60-complex sequence-seeds campaign-sequence-opensbi campaign-sequence-rustsbi campaign-opensbi campaign-rustsbi campaign-rustsbi-complex fuzzer helper injector clean clean-cargo clean-injector clean-playgrounds clean-generated help
