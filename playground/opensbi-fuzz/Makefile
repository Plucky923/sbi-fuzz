LLVM_CONFIG_PATH ?= $(shell command -v llvm-config-18 2>/dev/null || command -v llvm-config 2>/dev/null)
CC ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo cc)
CXX ?= $(shell command -v clang++-18 2>/dev/null || command -v clang++ 2>/dev/null || echo c++)
LIBCLANG_PATH ?= $(shell if [ -d /usr/lib/llvm-18/lib ]; then echo /usr/lib/llvm-18/lib; elif [ -d /usr/lib/llvm-20/lib ]; then echo /usr/lib/llvm-20/lib; fi)
export LLVM_CONFIG_PATH CC CXX LIBCLANG_PATH

.PHONY: all prepare run triage replay replay-summary clean

all: prepare run

prepare:
	@if [ ! -d "output" ]; then \
		echo "> Preparing environment..." && \
		mkdir -p output && \
		(cd ../.. && make) && \
		git clone https://github.com/riscv-software-src/opensbi.git output/opensbi && \
		(cd output/opensbi && git checkout v1.6) && \
		cargo helper instrument-kasan output/opensbi && \
		bash compile-opensbi.sh && \
		cargo helper generate-seed output/seed && \
		echo "> Preparation completed"; \
	else \
		echo "> Output directory already exists, skipping preparation. If you want to rebuild, run 'make clean' first"; \
	fi

run:
	@echo "> Running fuzzer..."
	cargo fuzzer --target output/opensbi/build/platform/generic/firmware/fw_dynamic.bin --injector ../../injector/build/injector.elf \
      --seed output/seed --output output/result

triage:
	@echo "> Triaging OpenSBI results..."
	@mkdir -p output/triage
	python3 ../../scripts/triage-opensbi-results.py output/result --json-out output/triage/result.json --md-out output/triage/result.md > output/triage/result.stdout.json
	python3 ../../scripts/triage-opensbi-results.py output/result-smoke --json-out output/triage/result-smoke.json --md-out output/triage/result-smoke.md > output/triage/result-smoke.stdout.json
	python3 ../../scripts/triage-opensbi-results.py output/result-recheck --json-out output/triage/result-recheck.json --md-out output/triage/result-recheck.md > output/triage/result-recheck.stdout.json

replay:
	@echo "> Replaying representative OpenSBI findings..."
	@mkdir -p output/replay
	python3 ../../scripts/replay-opensbi-results.py output/opensbi/build/platform/generic/firmware/fw_dynamic.bin ../../injector/build/injector.elf output/result-smoke --limit 2 --prefer-raw-exec --helper-bin ../../target/release/helper --timeout-secs 15 --json-out output/replay/result-smoke.json > output/replay/result-smoke.stdout.json
	python3 ../../scripts/replay-opensbi-results.py output/opensbi/build/platform/generic/firmware/fw_dynamic.bin ../../injector/build/injector.elf output/result-recheck --limit 3 --prefer-raw-exec --helper-bin ../../target/release/helper --timeout-secs 15 --json-out output/replay/result-recheck.json > output/replay/result-recheck.stdout.json

replay-summary:
	@echo "> Summarizing replay outputs..."
	@mkdir -p output/replay
	python3 ../../scripts/summarize-replay-opensbi-results.py output/replay/result-smoke.json --md-out output/replay/result-smoke.md > output/replay/result-smoke.summary.json
	python3 ../../scripts/summarize-replay-opensbi-results.py output/replay/result-recheck.json --md-out output/replay/result-recheck.md > output/replay/result-recheck.summary.json

clean:
	@echo "> Cleaning up..."
	rm -rf output
	@echo "> Cleanup completed"
