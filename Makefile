LLVM_CONFIG_PATH ?= $(shell command -v llvm-config-18 2>/dev/null || command -v llvm-config 2>/dev/null)
CC ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo cc)
CXX ?= $(shell command -v clang++-18 2>/dev/null || command -v clang++ 2>/dev/null || echo c++)
LIBCLANG_PATH ?= $(shell if [ -d /usr/lib/llvm-18/lib ]; then echo /usr/lib/llvm-18/lib; elif [ -d /usr/lib/llvm-20/lib ]; then echo /usr/lib/llvm-20/lib; fi)
export LLVM_CONFIG_PATH CC CXX LIBCLANG_PATH

all: compile

compile: helper injector
	@echo ">>> All components built successfully"

check-env:
	@./scripts/check-env.sh

check-env-smoke:
	@./scripts/check-env.sh --full-smoke

test-common:
	@cargo test -p common

test-host-harness:
	@cargo test -p common -p host_harness
	@cargo check -p helper

test-regression:
	@bash ./scripts/test-regression.sh

test-campaign-quality-gate:
	@./scripts/test-campaign-quality-gate.sh

test-cross-layer-dedup:
	@./scripts/test-cross-layer-dedup.sh

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

triage-host-fuzz:
	@python3 ./scripts/triage-host-fuzz-results.py ./output/host_fuzz/fuzz_ecall_rustsbi --json-out ./output/host_fuzz/triage.json --md-out ./output/host_fuzz/triage.md

collect-metrics:
	@python3 ./scripts/collect-metrics.py --log-dir ./output/host_fuzz/logs --triage-json ./output/host_fuzz/triage.json --cross-layer-json ./output/host_fuzz/cross-layer.json --json-out ./output/host_fuzz/metrics.json

quality-gate:
	@python3 ./scripts/campaign-quality-gate.py --metrics ./output/host_fuzz/metrics.json --triage ./output/host_fuzz/triage.json --json-out ./output/host_fuzz/quality-gate.json

campaign-quality-gate: quality-gate

cross-layer-dedup:
	@./scripts/run-default-cross-layer-dedup.sh

host-fuzz-corpus:
	@./scripts/prepare-host-fuzz-corpus.sh

host-fuzz-smoke:
	@./scripts/smoke-host-harness-fuzz.sh

host-fuzz-rustsbi:
	@./scripts/run-host-harness-fuzz.sh fuzz_ecall_rustsbi

host-fuzz-sequence:
	@./scripts/run-host-harness-fuzz.sh fuzz_sequence_both

host-fuzz-diff:
	@./scripts/run-host-harness-fuzz.sh fuzz_diff_ecall

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
	@python3 ./scripts/run-sequence-campaign.py opensbi-sequence opensbi ./output/sequence --json-out ./output/sequence/opensbi-sequence.campaign.json

campaign-sequence-rustsbi: sequence-seeds
	@python3 ./scripts/run-sequence-campaign.py rustsbi-sequence rustsbi ./output/sequence --json-out ./output/sequence/rustsbi-sequence.campaign.json

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
	@echo "  check-env              - Probe required and optional tooling"
	@echo "  check-env-smoke        - Probe tooling and run build smoke checks"
	@echo "  test-common            - Run common crate automated tests"
	@echo "  test-host-harness      - Validate the host-side OpenSBI layered harness and helper CLI"
	@echo "  test-regression        - Run deterministic host-side regression checks"
	@echo "  test-campaign-quality-gate - Validate host-side campaign quality thresholds"
	@echo "  test-cross-layer-dedup - Validate cross-layer dedup keeps per-source minimal reproducers"
	@echo "  test-collect-metrics   - Validate combined log, triage, and cross-layer metric summaries"
	@echo "  test-triage-host-fuzz-results - Validate host fuzz triage bucketing and markdown output"
	@echo "  test-minimize-spec-violation - Validate sequence spec-violation minimization"
	@echo "  test-default-cross-layer-dedup - Validate the default make target aggregates host/sequence/qemu inputs"
	@echo "  test-default-collect-metrics - Validate the default make target includes companion triage/cross-layer files"
	@echo "  triage-host-fuzz       - Triage host_harness fuzz artifacts into JSON/Markdown"
	@echo "  collect-metrics        - Summarize libFuzzer metrics from host-side logs"
	@echo "  quality-gate           - Evaluate host-side metrics and triage against quality thresholds"
	@echo "  campaign-quality-gate  - Alias for 'quality-gate'"
	@echo "  cross-layer-dedup      - Deduplicate available host/sequence/QEMU reports"
	@echo "  host-fuzz-corpus       - Generate libFuzzer corpora for host_harness fuzz targets"
	@echo "  host-fuzz-smoke        - Verify crash-capture chain and run short host_harness fuzz smokes"
	@echo "  host-fuzz-rustsbi      - Run the RustSBI host_harness libFuzzer target"
	@echo "  host-fuzz-sequence     - Run the sequence-oriented dual-backend host_harness target"
	@echo "  host-fuzz-diff         - Run the host-side differential ecall fuzz target"
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

.PHONY: all compile check-env check-env-smoke test-common test-host-harness test-regression test-campaign-quality-gate test-cross-layer-dedup test-collect-metrics test-triage-host-fuzz-results test-minimize-spec-violation test-default-cross-layer-dedup test-default-collect-metrics test-linux-corpus-import test-opensbi-triage test-opensbi-replay test-opensbi-replay-summary test-opensbi-sanitizer-demo test-opensbi-coverage test-opensbi-bug-report test-rustsbi-scenarios test-rustsbi-replay test-rustsbi-helper-timeout test-rustsbi-collect-coverage-timeout test-rustsbi-hang-stability test-rustsbi-hang-minimize test-sbi-hang-semantic-buckets test-rustsbi-fuzz-finds-bug test-sequence-replay triage-host-fuzz collect-metrics quality-gate campaign-quality-gate cross-layer-dedup host-fuzz-corpus host-fuzz-smoke host-fuzz-rustsbi host-fuzz-sequence host-fuzz-diff host-fuzz-60 host-fuzz-60-complex sequence-seeds campaign-sequence-opensbi campaign-sequence-rustsbi campaign-opensbi campaign-rustsbi campaign-rustsbi-complex fuzzer helper injector clean clean-cargo clean-injector clean-playgrounds clean-generated help
