#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::{fuzz_crossover, fuzz_mutator};

fuzz_target!(|data: &[u8]| {
    support::run_sequence_both(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    support::mutate_sequence_input(data, size, max_size, seed)
});

fuzz_crossover!(|data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32| {
    support::crossover_sequence_inputs(data1, data2, out, seed)
});
