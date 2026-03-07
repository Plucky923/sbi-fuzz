LLVM_CONFIG_PATH ?= $(shell command -v llvm-config-18 2>/dev/null || command -v llvm-config 2>/dev/null)
CC ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo cc)
CXX ?= $(shell command -v clang++-18 2>/dev/null || command -v clang++ 2>/dev/null || echo c++)
LIBCLANG_PATH ?= $(shell if [ -d /usr/lib/llvm-18/lib ]; then echo /usr/lib/llvm-18/lib; elif [ -d /usr/lib/llvm-20/lib ]; then echo /usr/lib/llvm-20/lib; fi)
export LLVM_CONFIG_PATH CC CXX LIBCLANG_PATH

.PHONY: all prepare run verify clean

all: prepare run

prepare:
	@if [ ! -d "output" ]; then \
		echo "> Preparing environment..." && \
		mkdir -p output && \
		(cd ../.. && make) && \
		git clone https://github.com/riscv-software-src/opensbi.git output/opensbi && \
		(cd output/opensbi && git checkout v1.6) && \
		cargo helper instrument-kasan output/opensbi && \
		(cd output/opensbi && git apply ../../kasan-test.patch) && \
		bash compile-opensbi.sh && \
		(cargo helper generate-seed output/seed || (echo "> Seed generation failed, trying fallback from ../opensbi-fuzz/output/seed..." && cp -r ../opensbi-fuzz/output/seed output/seed)) && \
		echo "> Preparation completed"; \
	else \
		echo "> Output directory already exists, skipping preparation. If you want to rebuild, run 'make clean' first"; \
	fi

run:
	@echo "> Running fuzzer..."
	cargo fuzzer --target output/opensbi/build/platform/generic/firmware/fw_dynamic.bin --injector ../../injector/build/injector.elf \
      --seed output/seed --output output/result --skip-halt --skip-inputs 4,5,6,7,0x504D55:2

clean:
	@echo "> Cleaning up..."
	rm -rf output
	@echo "> Cleanup completed"

verify: prepare
	@echo "> Running sanitizer demo checks..."
	@mkdir -p output/verify
	python3 ../../scripts/run-opensbi-sanitizer-demo.py output/opensbi/build/platform/generic/firmware/fw_dynamic.bin ../../injector/build/injector.elf test-heap-overflow.toml test-integer-overflow.toml --helper-bin ../../target/release/helper --json-out output/verify/sanitizer.json > output/verify/sanitizer.stdout.json

run-demo: prepare
ifndef TARGET
	$(error TARGET is not set)
endif
	@echo "> Running demo..."
	cargo helper run output/opensbi/build/platform/generic/firmware/fw_dynamic.bin ../../injector/build/injector.elf $(TARGET)
