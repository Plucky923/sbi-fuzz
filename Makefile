LLVM_CONFIG_PATH ?= $(shell command -v llvm-config-18 2>/dev/null || command -v llvm-config 2>/dev/null)
CC ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo cc)
CXX ?= $(shell command -v clang++-18 2>/dev/null || command -v clang++ 2>/dev/null || echo c++)
LIBCLANG_PATH ?= $(shell if [ -d /usr/lib/llvm-18/lib ]; then echo /usr/lib/llvm-18/lib; elif [ -d /usr/lib/llvm-20/lib ]; then echo /usr/lib/llvm-20/lib; fi)
export LLVM_CONFIG_PATH CC CXX LIBCLANG_PATH

all: compile

compile: fuzzer helper injector
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

.PHONY: all compile check-env check-env-smoke test-common test-host-harness test-linux-corpus-import test-opensbi-triage test-opensbi-replay test-opensbi-replay-summary test-opensbi-sanitizer-demo test-opensbi-coverage test-opensbi-bug-report test-rustsbi-scenarios test-rustsbi-replay test-rustsbi-helper-timeout test-rustsbi-collect-coverage-timeout test-rustsbi-hang-stability test-rustsbi-hang-minimize test-sbi-hang-semantic-buckets test-rustsbi-fuzz-finds-bug campaign-opensbi campaign-rustsbi campaign-rustsbi-complex fuzzer helper injector clean clean-cargo clean-injector clean-playgrounds clean-generated help
