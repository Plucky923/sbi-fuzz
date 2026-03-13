LLVM_CONFIG_PATH ?= $(shell command -v llvm-config-18 2>/dev/null || command -v llvm-config 2>/dev/null)
CC ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo cc)
CXX ?= $(shell command -v clang++-18 2>/dev/null || command -v clang++ 2>/dev/null || echo c++)
LIBCLANG_PATH ?= $(shell if [ -d /usr/lib/llvm-18/lib ]; then echo /usr/lib/llvm-18/lib; elif [ -d /usr/lib/llvm-20/lib ]; then echo /usr/lib/llvm-20/lib; fi)
export LLVM_CONFIG_PATH CC CXX LIBCLANG_PATH

RUSTSBI_TARGET := output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper-dynamic.bin

.PHONY: all prepare complex-seeds run run-complex triage triage-complex replay replay-complex replay-summary replay-summary-complex bug-report bug-report-complex campaign campaign-complex clean

all: prepare run

prepare:
	@if [ ! -d "output/rustsbi" ]; then \
		echo "> Preparing environment..." && \
		mkdir -p output && \
		(cd ../.. && make) && \
		cargo install cargo-binutils && \
		git clone https://github.com/rustsbi/rustsbi.git output/rustsbi && \
		(cd output/rustsbi && git checkout eb5a100f81e96d6bde0ce7f6bee1969d60427d1a) && \
		(cd output/rustsbi && cargo xtask prototyper) && \
		cargo helper generate-seed output/seed && \
		cargo helper generate-rustsbi-scenarios output/seed-complex && \
		echo "> Preparation completed"; \
	else \
		echo "> RustSBI output already exists, skipping preparation. If you want to rebuild, run 'make clean' first"; \
	fi

complex-seeds:
	@mkdir -p output
	@echo "> Refreshing RustSBI scenario seeds..."
	cargo helper generate-rustsbi-scenarios output/seed-complex

run:
	@echo "> Running fuzzer..."
	@if [ ! -d "output/rustsbi" ]; then $(MAKE) prepare; fi
	cargo fuzzer --target $(RUSTSBI_TARGET) \
	  --injector ../../injector/build/injector.elf --seed $${SEED_DIR:-output/seed} --output $${RESULT_DIR:-output/result} --smp $${SMP:-1}

run-complex: complex-seeds
	@echo "> Running RustSBI complex-scenario fuzzing..."
	@if [ ! -d "output/rustsbi" ]; then $(MAKE) prepare; fi
	cargo fuzzer --target $(RUSTSBI_TARGET) \
	  --injector ../../injector/build/injector.elf --seed output/seed-complex --output output/result-complex --smp $${SMP:-4}

triage:
	@echo "> Triaging RustSBI results..."
	@mkdir -p output/triage
	python3 ../../scripts/triage-sbi-results.py output/result --label RustSBI --json-out output/triage/result.json --md-out output/triage/result.md > output/triage/result.stdout.json

triage-complex:
	@echo "> Triaging RustSBI complex-scenario results..."
	@mkdir -p output/triage
	python3 ../../scripts/triage-sbi-results.py output/result-complex --label RustSBI --json-out output/triage/result-complex.json --md-out output/triage/result-complex.md > output/triage/result-complex.stdout.json

replay:
	@echo "> Replaying RustSBI findings..."
	@mkdir -p output/replay output/replay/logs
	python3 ../../scripts/replay-sbi-results.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/result --label RustSBI --limit 3 --prefer-raw-exec --helper-bin ../../target/release/helper --timeout-secs 15 --smp $${SMP:-1} --log-dir output/replay/logs --json-out output/replay/result.json > output/replay/result.stdout.json

replay-complex:
	@echo "> Replaying RustSBI complex-scenario findings..."
	@mkdir -p output/replay output/replay/logs-complex
	python3 ../../scripts/replay-sbi-results.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/result-complex --label RustSBI --limit 3 --prefer-raw-exec --helper-bin ../../target/release/helper --timeout-secs 15 --smp $${SMP:-4} --log-dir output/replay/logs-complex --json-out output/replay/result-complex.json > output/replay/result-complex.stdout.json

replay-summary:
	@echo "> Summarizing RustSBI replay output..."
	@mkdir -p output/replay
	python3 ../../scripts/summarize-replay-sbi-results.py output/replay/result.json --label RustSBI --md-out output/replay/result.md > output/replay/result.summary.json

replay-summary-complex:
	@echo "> Summarizing RustSBI complex replay output..."
	@mkdir -p output/replay
	python3 ../../scripts/summarize-replay-sbi-results.py output/replay/result-complex.json --label RustSBI --md-out output/replay/result-complex.md > output/replay/result-complex.summary.json

bug-report:
	@echo "> Bucketing RustSBI findings into bug candidates..."
	@mkdir -p output/bugs output/bugs/replay-logs output/bugs/hang-stability-logs output/bugs/hang-minimized
	python3 ../../scripts/replay-sbi-results.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/result --label RustSBI --all --prefer-raw-exec --helper-bin ../../target/release/helper --timeout-secs 15 --smp $${SMP:-1} --log-dir output/bugs/replay-logs --json-out output/bugs/result.replay.json > output/bugs/result.replay.stdout.json
	python3 ../../scripts/check-sbi-hang-stability.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/bugs/result.replay.json --label RustSBI --helper-bin ../../target/release/helper --timeout-secs 15 --smp $${SMP:-1} --attempts 3 --log-dir output/bugs/hang-stability-logs --json-out output/bugs/result.hang-stability.json > output/bugs/result.hang-stability.stdout.json
	python3 ../../scripts/minimize-sbi-hangs.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/bugs/result.hang-stability.json --label RustSBI --helper-bin ../../target/release/helper --timeout-ms 15000 --smp $${SMP:-1} --attempts 3 --output-dir output/bugs/hang-minimized --json-out output/bugs/result.hang-minimize.json > output/bugs/result.hang-minimize.stdout.json
	python3 ../../scripts/report-sbi-bugs.py output/bugs/result.replay.json --hang-stability output/bugs/result.hang-stability.json --hang-minimize output/bugs/result.hang-minimize.json --label RustSBI --json-out output/bugs/result.bugs.json --md-out output/bugs/result.bugs.md > output/bugs/result.bugs.stdout.json

bug-report-complex:
	@echo "> Bucketing RustSBI complex-scenario findings into bug candidates..."
	@mkdir -p output/bugs output/bugs/replay-logs-complex output/bugs/hang-stability-logs-complex output/bugs/hang-minimized-complex
	python3 ../../scripts/replay-sbi-results.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/result-complex --label RustSBI --all --prefer-raw-exec --helper-bin ../../target/release/helper --timeout-secs 15 --smp $${SMP:-4} --log-dir output/bugs/replay-logs-complex --json-out output/bugs/result-complex.replay.json > output/bugs/result-complex.replay.stdout.json
	python3 ../../scripts/check-sbi-hang-stability.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/bugs/result-complex.replay.json --label RustSBI --helper-bin ../../target/release/helper --timeout-secs 15 --smp $${SMP:-4} --attempts 3 --log-dir output/bugs/hang-stability-logs-complex --json-out output/bugs/result-complex.hang-stability.json > output/bugs/result-complex.hang-stability.stdout.json
	python3 ../../scripts/minimize-sbi-hangs.py $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/bugs/result-complex.hang-stability.json --label RustSBI --helper-bin ../../target/release/helper --timeout-ms 15000 --smp $${SMP:-4} --attempts 3 --output-dir output/bugs/hang-minimized-complex --json-out output/bugs/result-complex.hang-minimize.json > output/bugs/result-complex.hang-minimize.stdout.json
	python3 ../../scripts/report-sbi-bugs.py output/bugs/result-complex.replay.json --hang-stability output/bugs/result-complex.hang-stability.json --hang-minimize output/bugs/result-complex.hang-minimize.json --label RustSBI --json-out output/bugs/result-complex.bugs.json --md-out output/bugs/result-complex.bugs.md > output/bugs/result-complex.bugs.stdout.json

campaign:
	@echo "> Running automated RustSBI prototyper fuzz campaign..."
	@if [ ! -d "output/rustsbi" ]; then $(MAKE) prepare; fi
	@mkdir -p output/campaign
	python3 ../../scripts/run-sbi-fuzz-campaign.py rustsbi-prototyper $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/seed output/result --duration-secs $${DURATION_SECS:-300} --cores $${CORES:-1} --smp $${SMP:-1} --replay-max-buckets $${REPLAY_MAX_BUCKETS:-64} --helper-bin ../../target/release/helper --json-out output/campaign/latest.json > output/campaign/latest.stdout.json

campaign-complex: complex-seeds
	@echo "> Running automated RustSBI complex-scenario campaign..."
	@if [ ! -d "output/rustsbi" ]; then $(MAKE) prepare; fi
	@mkdir -p output/campaign
	python3 ../../scripts/run-sbi-fuzz-campaign.py rustsbi-prototyper-complex $(RUSTSBI_TARGET) ../../injector/build/injector.elf output/seed-complex output/result-complex --duration-secs $${DURATION_SECS:-300} --cores $${CORES:-1} --smp $${SMP:-4} --replay-max-buckets $${REPLAY_MAX_BUCKETS:-64} --helper-bin ../../target/release/helper --json-out output/campaign/latest-complex.json > output/campaign/latest-complex.stdout.json

clean:
	@echo "> Cleaning up..."
	rm -rf output
	@echo "> Cleanup completed"
