#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data == b"SBI_FUZZ_SMOKE_CRASH" {
        panic!("intentional smoke crash");
    }
});
