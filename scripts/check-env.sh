#!/usr/bin/env bash
set -u

run_full_smoke=0
verbose=0

usage() {
  cat <<'USAGE'
Usage: scripts/check-env.sh [--full-smoke] [--verbose]

Options:
  --full-smoke   Run build smoke checks after probing dependencies
  --verbose      Print first-line version info for detected tools
  -h, --help     Show this help message
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --full-smoke)
      run_full_smoke=1
      ;;
    --verbose)
      verbose=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

missing_required=0
missing_optional=0

print_section() {
  printf '\n== %s ==\n' "$1"
}

print_status() {
  printf '%-12s %s\n' "$1" "$2"
}

show_version() {
  local tool="$1"
  local line
  line="$($tool --version 2>/dev/null | head -n 1 || true)"
  if [ -n "$line" ]; then
    printf '           %s\n' "$line"
  fi
}

check_cmd() {
  local level="$1"
  local tool="$2"
  local reason="$3"
  if command -v "$tool" >/dev/null 2>&1; then
    local path
    path="$(command -v "$tool")"
    print_status "[OK]" "$tool -> $path"
    if [ "$verbose" -eq 1 ]; then
      show_version "$tool"
    fi
  else
    if [ "$level" = "required" ]; then
      missing_required=1
      print_status "[MISSING]" "$tool (required) - $reason"
    else
      missing_optional=1
      print_status "[OPTIONAL]" "$tool - $reason"
    fi
  fi
}

run_smoke() {
  print_section "Smoke Checks"
  print_status "[RUN]" "cargo check -p common"
  if ! cargo check -p common; then
    print_status "[FAIL]" "cargo check -p common"
    return 1
  fi

  print_status "[RUN]" "make -C injector compile PREFIX='>>>'"
  if ! make -C injector compile PREFIX='>>>'; then
    print_status "[FAIL]" "injector build"
    return 1
  fi

  print_status "[RUN]" "cargo check -p helper -p fuzzer"
  if ! cargo check -p helper -p fuzzer; then
    print_status "[FAIL]" "helper/fuzzer build"
    return 1
  fi

  print_status "[PASS]" "all smoke checks passed"
}

print_section "Core Build Tools"
check_cmd required bash "required to run repository scripts"
check_cmd required git "required for fetching SBI docs and targets"
check_cmd required make "required by the top-level build and playgrounds"
check_cmd required cargo "required to build Rust crates"
check_cmd required rustc "required to compile Rust crates"
check_cmd required python3 "required by libafl_qemu/QEMU build helpers"
check_cmd required cc "required for native dependencies"
check_cmd required c++ "required for native dependencies"
check_cmd required pkg-config "required by native dependency discovery"

print_section "LLVM Tooling"
rustc_llvm_version="$(rustc -Vv 2>/dev/null | awk -F': ' '/^LLVM version:/ {print $2}' || true)"
rustc_llvm_major="${rustc_llvm_version%%.*}"
llvm_config_path=""
for candidate in "llvm-config-18" "llvm-config-${rustc_llvm_major}" llvm-config; do
  if command -v "$candidate" >/dev/null 2>&1; then
    llvm_config_path="$(command -v "$candidate")"
    break
  fi
done
if [ -z "$llvm_config_path" ]; then
  llvm_config_path="$(compgen -c | rg '^llvm-config-[0-9]+$' | sort -Vr | head -n 1 || true)"
  if [ -n "$llvm_config_path" ]; then
    llvm_config_path="$(command -v "$llvm_config_path")"
  fi
fi
if [ -n "$llvm_config_path" ]; then
  print_status "[OK]" "llvm-config -> $llvm_config_path"
  if [ "$verbose" -eq 1 ]; then
    "$llvm_config_path" --version 2>/dev/null | head -n 1 | sed 's/^/           /'
  fi
else
  missing_required=1
  print_status "[MISSING]" "llvm-config (required) - install an LLVM package matching rustc LLVM ${rustc_llvm_version:-unknown}"
fi

clang_path=""
for candidate in "clang-18" "clang-${rustc_llvm_major}" clang; do
  if command -v "$candidate" >/dev/null 2>&1; then
    clang_path="$(command -v "$candidate")"
    break
  fi
done
if [ -z "$clang_path" ]; then
  clang_path="$(compgen -c | rg '^clang-[0-9]+$' | sort -Vr | head -n 1 || true)"
  if [ -n "$clang_path" ]; then
    clang_path="$(command -v "$clang_path")"
  fi
fi
if [ -n "$clang_path" ]; then
  print_status "[OK]" "clang -> $clang_path"
  if [ "$verbose" -eq 1 ]; then
    "$clang_path" --version 2>/dev/null | head -n 1 | sed 's/^/           /'
  fi
else
  missing_required=1
  print_status "[MISSING]" "clang (required) - install a Clang package that provides builtin/system headers for bindgen"
fi

print_section "QEMU Bridge Libraries"
if pkg-config --exists glib-2.0; then
  print_status "[OK]" "glib-2.0 development files detected"
else
  missing_required=1
  print_status "[MISSING]" "glib-2.0 development files (required) - install libglib2.0-dev for libafl_qemu_sys"
fi
if pkg-config --exists pixman-1; then
  print_status "[OK]" "pixman-1 development files detected"
else
  missing_required=1
  print_status "[MISSING]" "pixman-1 development files (required) - install libpixman-1-dev for the QEMU bridge"
fi

print_section "Target Execution Tools"
check_cmd required qemu-system-riscv64 "required to boot SBI firmware under QEMU"
check_cmd required ninja "required by libafl_qemu_sys when building the QEMU bridge"
check_cmd required riscv64-unknown-elf-gcc "required to build injector/src/injector.c"
check_cmd required riscv64-unknown-elf-ld "required to link the injector ELF"

print_section "Optional Debugging Tools"
check_cmd optional gdb-multiarch "recommended for helper debug and crash triage"
check_cmd optional rg "recommended for fast log/code search"
check_cmd optional riscv64-unknown-elf-objdump "recommended for firmware and injector inspection"

print_section "Summary"
if [ "$missing_required" -eq 0 ]; then
  print_status "[PASS]" "required environment looks complete"
else
  print_status "[FAIL]" "required tools are missing"
fi
if [ "$missing_optional" -eq 0 ]; then
  print_status "[PASS]" "optional debug tools look complete"
else
  print_status "[WARN]" "some optional debug tools are missing"
fi

if [ "$run_full_smoke" -eq 1 ]; then
  if [ "$missing_required" -ne 0 ]; then
    print_status "[SKIP]" "full smoke checks skipped because required tools are missing"
  else
    run_smoke || exit 1
  fi
fi

if [ "$missing_required" -ne 0 ]; then
  exit 1
fi
exit 0
