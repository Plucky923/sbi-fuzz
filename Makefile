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

clean: clean-cargo clean-injector
	@echo ">>> All clean operations completed"

clean-cargo:
	@echo ">>> Cleaning cargo build artifacts..."
	cargo clean
	@echo ">>> Cargo clean completed"

clean-injector:
	@echo ">>> Cleaning injector build artifacts..."
	cd injector && make PREFIX="==>" clean
	@echo ">>> Injector clean completed"

help:
	@echo "Available targets:"
	@echo "  all (default)          - Build all components"
	@echo "  compile                - Same as 'all'"
	@echo "  check-env              - Probe required and optional tooling"
	@echo "  check-env-smoke        - Probe tooling and run build smoke checks"
	@echo "  test-common            - Run common crate automated tests"
	@echo "  test-linux-corpus-import - Validate Linux-style SBI corpus import"
	@echo "  test-opensbi-triage    - Triage current OpenSBI result directories"
	@echo "  test-opensbi-replay    - Replay representative OpenSBI findings"
	@echo "  test-opensbi-replay-summary - Summarize replay JSON output"
	@echo "  test-opensbi-sanitizer-demo - Run fixed OpenSBI sanitizer demo samples"
	@echo "  fuzzer                 - Build only the fuzzer package"
	@echo "  helper                 - Build only the helper package"
	@echo "  injector               - Build only the injector"
	@echo "  clean                  - Clean all build artifacts"
	@echo "  clean-cargo            - Clean only cargo build artifacts"
	@echo "  clean-injector         - Clean only injector build artifacts"
	@echo "  help                   - Display this help message"

.PHONY: all compile check-env check-env-smoke test-common test-linux-corpus-import test-opensbi-triage test-opensbi-replay test-opensbi-replay-summary test-opensbi-sanitizer-demo fuzzer helper injector clean clean-cargo clean-injector help
