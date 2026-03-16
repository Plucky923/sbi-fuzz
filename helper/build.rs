use libafl_qemu_build::build_libafl_qemu;

/// Build script for the libafl-qemu crate
/// This script is responsible for building the libafl-qemu library and linking it with the fuzzer.
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_QEMU");
    if std::env::var_os("CARGO_FEATURE_QEMU").is_some() {
        build_libafl_qemu();
    }
}
