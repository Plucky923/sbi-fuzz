#![no_main]

mod support;

use common::HostTargetKind;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    support::run_ecall_target(data, HostTargetKind::OpenSbi);
});
