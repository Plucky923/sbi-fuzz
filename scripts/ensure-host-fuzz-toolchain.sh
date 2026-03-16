#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found in PATH" >&2
    exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup not found in PATH" >&2
    exit 1
fi

if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cargo install --locked cargo-fuzz
fi

if ! rustup toolchain list | grep -q '^nightly'; then
    rustup toolchain install nightly --profile minimal
fi

rustup component add rust-src --toolchain nightly >/dev/null
