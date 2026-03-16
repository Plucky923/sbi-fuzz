use common::{
    DiffPolicy, HostCall, HostHarnessInput, HostHarnessMode, HostHarnessResult, HostHartState,
    HostMemoryRegion, HostPlatformFaultProfile, HostPrivilegeState, HostTargetKind, MemoryOracle,
    SequenceArg, SequenceMemoryObject, SequenceProgram, SequenceStep, check_host_report,
    diff_host_reports, host_harness_input_from_bytes, mutate_sequence_program,
    sequence_memory_guest_addr, sequence_program_from_bytes, sequence_program_to_bytes,
    validate_sequence_program,
};
use libfuzzer_sys::fuzzer_mutate;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const DEFAULT_SEQUENCE_FUZZ_SMP: u16 = 4;
const MAX_SEQUENCE_FUZZ_SMP: u16 = 64;
const MAX_MUTATED_SEQUENCE_STEPS: usize = 64;
const MAX_MUTATED_MEMORY_OBJECTS: usize = 16;
const MAX_MUTATED_MEMORY_BYTES: usize = 256;

pub fn decode_host_input(bytes: &[u8]) -> HostHarnessInput {
    host_harness_input_from_bytes(bytes).unwrap_or_else(|_| HostHarnessInput::from_fuzz_bytes(bytes))
}

pub fn run_ecall_target(bytes: &[u8], target_kind: HostTargetKind) {
    let mut input = decode_host_input(bytes);
    input.target_kind = target_kind;
    input.mode = HostHarnessMode::Ecall;
    input.fdt_blob.clear();
    input.platform_fault = HostPlatformFaultProfile::none();
    let _ = run_host_input(&input);
}

pub fn run_sequence_both(bytes: &[u8]) {
    let program = SequenceProgram::from_fuzz_bytes(bytes, sequence_fuzz_smp());
    execute_sequence(&program, HostTargetKind::OpenSbi);
    execute_sequence(&program, HostTargetKind::RustSbi);
}

pub fn run_diff_ecall(bytes: &[u8]) {
    let mut input = decode_host_input(bytes);
    input.mode = HostHarnessMode::Ecall;
    input.fdt_blob.clear();
    input.platform_fault = HostPlatformFaultProfile::none();
    let opensbi = run_host_input_with_target(&input, HostTargetKind::OpenSbi);
    let rustsbi = run_host_input_with_target(&input, HostTargetKind::RustSbi);
    let diffs = diff_host_reports(&input, &opensbi, &rustsbi, &DiffPolicy::default());
    if !diffs.is_empty() {
        panic!("diff violation: {:?}", diffs[0]);
    }
}

pub fn run_diff_sequence(bytes: &[u8]) {
    let program = SequenceProgram::from_fuzz_bytes(bytes, sequence_fuzz_smp());
    let memory_map = program
        .memory
        .iter()
        .map(|memory| (memory.id.clone(), memory))
        .collect::<BTreeMap<_, _>>();
    let mut opensbi_state = SequenceExecutionState::new(&program);
    let mut rustsbi_state = SequenceExecutionState::new(&program);
    let policy = DiffPolicy::default();

    for (index, step) in program.steps.iter().enumerate() {
        match step {
            SequenceStep::SetTargetHart { hart_id } => {
                opensbi_state.active_hart = *hart_id;
                rustsbi_state.active_hart = *hart_id;
            }
            SequenceStep::SetHartState { hart_id, state } => {
                opensbi_state.hart_states.insert(*hart_id, *state);
                rustsbi_state.hart_states.insert(*hart_id, *state);
            }
            SequenceStep::SetPrivilege { privilege } => {
                opensbi_state.privilege = *privilege;
                rustsbi_state.privilege = *privilege;
            }
            SequenceStep::SetPlatformFault { profile } => {
                opensbi_state.platform_fault = *profile;
                rustsbi_state.platform_fault = *profile;
            }
            SequenceStep::BusyWait { .. } => {}
            SequenceStep::Call {
                label,
                eid,
                fid,
                args,
                ..
            } => {
                let opensbi_input = build_sequence_call_input(
                    &memory_map,
                    &opensbi_state,
                    HostTargetKind::OpenSbi,
                    *eid,
                    *fid,
                    args,
                    index,
                    label,
                );
                let rustsbi_input = build_sequence_call_input(
                    &memory_map,
                    &rustsbi_state,
                    HostTargetKind::RustSbi,
                    *eid,
                    *fid,
                    args,
                    index,
                    label,
                );
                let opensbi_report = run_host_input(&opensbi_input);
                let rustsbi_report = run_host_input(&rustsbi_input);
                let diffs = diff_host_reports(&opensbi_input, &opensbi_report, &rustsbi_report, &policy);
                if !diffs.is_empty() {
                    panic!("sequence diff violation at step {index}: {:?}", diffs[0]);
                }

                if !opensbi_report.post_memory_regions.is_empty() {
                    opensbi_state.memory_regions = opensbi_report.post_memory_regions.clone();
                }
                if !rustsbi_report.post_memory_regions.is_empty() {
                    rustsbi_state.memory_regions = rustsbi_report.post_memory_regions.clone();
                }
                let opensbi_args = materialize_args(args, &memory_map, &opensbi_state, index);
                let rustsbi_args = materialize_args(args, &memory_map, &rustsbi_state, index);
                update_call_state(
                    &mut opensbi_state,
                    *eid,
                    *fid,
                    &opensbi_args,
                    &opensbi_report.result,
                );
                update_call_state(
                    &mut rustsbi_state,
                    *eid,
                    *fid,
                    &rustsbi_args,
                    &rustsbi_report.result,
                );
            }
            SequenceStep::ParseFdt { label, object, .. } => {
                let memory = memory_map
                    .get(object)
                    .unwrap_or_else(|| panic!("unknown sequence memory object {object}"));
                let opensbi_input = HostHarnessInput {
                    target_kind: HostTargetKind::OpenSbi,
                    mode: HostHarnessMode::Fdt,
                    call: HostCall::new(0, 0, [0; 6]),
                    hart_id: opensbi_state.active_hart,
                    hart_state: opensbi_state.hart_state(opensbi_state.active_hart),
                    privilege: opensbi_state.privilege,
                    memory_regions: Vec::new(),
                    platform_fault: HostPlatformFaultProfile::none(),
                    fdt_blob: memory.bytes.clone(),
                    label: if label.trim().is_empty() {
                        format!("fdt-{index}")
                    } else {
                        label.clone()
                    },
                };
                let rustsbi_input = HostHarnessInput {
                    target_kind: HostTargetKind::RustSbi,
                    ..opensbi_input.clone()
                };
                let opensbi_report = run_host_input(&opensbi_input);
                let rustsbi_report = run_host_input(&rustsbi_input);
                let diffs = diff_host_reports(&opensbi_input, &opensbi_report, &rustsbi_report, &policy);
                if !diffs.is_empty() {
                    panic!("sequence diff violation at step {index}: {:?}", diffs[0]);
                }
            }
        }
    }
}

pub fn mutate_sequence_input(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let mut program = decode_sequence_input(&data[..size]);
    let mutation_budget = rng.gen_range(1..=4);
    let mut changed = false;
    for _ in 0..mutation_budget {
        if mutate_sequence_program(&mut program, &mut rng).is_some() {
            changed = true;
        }
    }
    if !changed {
        return fuzzer_mutate(data, size, max_size);
    }

    let encoded = encode_sequence_for_fuzz(program, max_size);
    data[..encoded.len()].copy_from_slice(&encoded);
    encoded.len()
}

pub fn crossover_sequence_inputs(data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32) -> usize {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let left = decode_sequence_input(data1);
    let right = decode_sequence_input(data2);

    let left_split = if left.steps.is_empty() {
        0
    } else {
        rng.gen_range(0..=left.steps.len())
    };
    let right_split = if right.steps.is_empty() {
        0
    } else {
        rng.gen_range(0..=right.steps.len())
    };

    let mut program = left.clone();
    program.metadata.name = if !left.metadata.name.is_empty() {
        left.metadata.name
    } else {
        right.metadata.name
    };
    program.metadata.source = "custom_crossover".to_string();
    program.env.smp = left.env.smp.max(right.env.smp).max(1);

    let mut memory = left.memory.clone();
    for object in right.memory {
        if memory.iter().any(|existing| existing.id == object.id) {
            continue;
        }
        memory.push(object);
        if memory.len() >= MAX_MUTATED_MEMORY_OBJECTS {
            break;
        }
    }
    program.memory = memory;

    let mut steps = left.steps[..left_split].to_vec();
    steps.extend_from_slice(&right.steps[right_split..]);
    if steps.is_empty() {
        steps.push(SequenceStep::BusyWait {
            iterations: rng.gen_range(1..=64),
        });
    }
    program.steps = steps;

    let encoded = encode_sequence_for_fuzz(program, out.len());
    out[..encoded.len()].copy_from_slice(&encoded);
    encoded.len()
}

fn sequence_fuzz_smp() -> u16 {
    static SEQUENCE_SMP: OnceLock<u16> = OnceLock::new();
    *SEQUENCE_SMP.get_or_init(|| {
        std::env::var("SBIFUZZ_HOST_SEQUENCE_SMP")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .map(|value| value.clamp(1, MAX_SEQUENCE_FUZZ_SMP))
            .unwrap_or(DEFAULT_SEQUENCE_FUZZ_SMP)
    })
}

fn decode_sequence_input(bytes: &[u8]) -> SequenceProgram {
    sequence_program_from_bytes(bytes)
        .unwrap_or_else(|_| SequenceProgram::from_fuzz_bytes(bytes, sequence_fuzz_smp()))
}

fn encode_sequence_for_fuzz(mut program: SequenceProgram, max_size: usize) -> Vec<u8> {
    program.metadata.note.clear();
    if program.metadata.source.len() > 32 {
        program.metadata.source.truncate(32);
    }
    if program.memory.len() > MAX_MUTATED_MEMORY_OBJECTS {
        program.memory.truncate(MAX_MUTATED_MEMORY_OBJECTS);
    }
    for object in &mut program.memory {
        if object.bytes.len() > MAX_MUTATED_MEMORY_BYTES {
            object.bytes.truncate(MAX_MUTATED_MEMORY_BYTES);
        }
    }
    if program.steps.len() > MAX_MUTATED_SEQUENCE_STEPS {
        program.steps.truncate(MAX_MUTATED_SEQUENCE_STEPS);
    }

    while validate_sequence_program(&program).is_err() && !program.steps.is_empty() {
        program.steps.pop();
    }
    if program.steps.is_empty() {
        program.steps.push(SequenceStep::BusyWait { iterations: 1 });
    }

    loop {
        let encoded = sequence_program_to_bytes(&program);
        if encoded.len() <= max_size || (program.steps.len() == 1 && program.memory.is_empty()) {
            return if encoded.len() <= max_size {
                encoded
            } else {
                let fallback = sequence_program_to_bytes(&SequenceProgram::from_fuzz_bytes(
                    &encoded[..max_size.min(encoded.len())],
                    sequence_fuzz_smp(),
                ));
                fallback[..fallback.len().min(max_size)].to_vec()
            };
        }
        if program.steps.len() > 1 {
            program.steps.pop();
            continue;
        }
        if let Some(object) = program.memory.last_mut()
            && object.bytes.len() > 8
        {
            object.bytes.truncate(object.bytes.len() / 2);
            continue;
        }
        if !program.memory.is_empty() {
            program.memory.pop();
            continue;
        }
        return encoded[..encoded.len().min(max_size)].to_vec();
    }
}

pub fn run_host_input(input: &HostHarnessInput) -> host_harness::HostHarnessReport {
    let mem_oracle = MemoryOracle::snapshot_before(&input.memory_regions);
    let report = host_harness::run(input)
        .unwrap_or_else(|err| panic!("host harness run failed: {err}; input={input:?}"));
    let verdict = check_host_report(input, &report);
    if !verdict.passed {
        panic!(
            "spec violation: {:?}; input={input:?}; signature={}",
            verdict.violations[0], report.signature
        );
    }
    let mem_violations = mem_oracle.check_after(input, &report);
    if !mem_violations.is_empty() {
        panic!(
            "memory violation: {:?}; input={input:?}; signature={}",
            mem_violations[0], report.signature
        );
    }
    report
}

fn run_host_input_with_target(
    input: &HostHarnessInput,
    target_kind: HostTargetKind,
) -> host_harness::HostHarnessReport {
    let mut adjusted = input.clone();
    adjusted.target_kind = target_kind;
    run_host_input(&adjusted)
}

#[derive(Clone)]
struct SequenceExecutionState {
    active_hart: u64,
    privilege: HostPrivilegeState,
    platform_fault: HostPlatformFaultProfile,
    hart_states: BTreeMap<u64, HostHartState>,
    call_results: Vec<u64>,
    memory_regions: Vec<HostMemoryRegion>,
}

impl SequenceExecutionState {
    fn new(program: &SequenceProgram) -> Self {
        let mut hart_states = BTreeMap::new();
        for hart_id in 0..program.env.smp {
            hart_states.insert(
                u64::from(hart_id),
                if hart_id == 0 {
                    HostHartState::Started
                } else {
                    HostHartState::Stopped
                },
            );
        }
        Self {
            active_hart: 0,
            privilege: HostPrivilegeState::Supervisor,
            platform_fault: HostPlatformFaultProfile::none(),
            hart_states,
            call_results: Vec::new(),
            memory_regions: sequence_memory_regions(program),
        }
    }

    fn hart_state(&self, hart_id: u64) -> HostHartState {
        self.hart_states
            .get(&hart_id)
            .copied()
            .unwrap_or(HostHartState::Unknown)
    }
}

fn execute_sequence(program: &SequenceProgram, target_kind: HostTargetKind) {
    let memory_map = program
        .memory
        .iter()
        .map(|memory| (memory.id.clone(), memory))
        .collect::<BTreeMap<_, _>>();
    let mut state = SequenceExecutionState::new(program);

    for (index, step) in program.steps.iter().enumerate() {
        match step {
            SequenceStep::SetTargetHart { hart_id } => {
                state.active_hart = *hart_id;
            }
            SequenceStep::SetHartState { hart_id, state: hart } => {
                state.hart_states.insert(*hart_id, *hart);
            }
            SequenceStep::SetPrivilege { privilege } => {
                state.privilege = *privilege;
            }
            SequenceStep::SetPlatformFault { profile } => {
                state.platform_fault = *profile;
            }
            SequenceStep::BusyWait { .. } => {}
            SequenceStep::Call {
                label,
                eid,
                fid,
                args,
                ..
            } => {
                let materialized = materialize_args(args, &memory_map, &state, index);
                let input = build_sequence_call_input(
                    &memory_map,
                    &state,
                    target_kind,
                    *eid,
                    *fid,
                    args,
                    index,
                    label,
                );
                let report = run_host_input(&input);
                if !report.post_memory_regions.is_empty() {
                    state.memory_regions = report.post_memory_regions.clone();
                }
                update_call_state(&mut state, *eid, *fid, &materialized, &report.result);
            }
            SequenceStep::ParseFdt { label, object, .. } => {
                let memory = memory_map
                    .get(object)
                    .unwrap_or_else(|| panic!("unknown sequence memory object {object}"));
                let input = HostHarnessInput {
                    target_kind,
                    mode: HostHarnessMode::Fdt,
                    call: HostCall::new(0, 0, [0; 6]),
                    hart_id: state.active_hart,
                    hart_state: state.hart_state(state.active_hart),
                    privilege: state.privilege,
                    memory_regions: Vec::new(),
                    platform_fault: HostPlatformFaultProfile::none(),
                    fdt_blob: memory.bytes.clone(),
                    label: if label.trim().is_empty() {
                        format!("fdt-{index}")
                    } else {
                        label.clone()
                    },
                };
                let _ = run_host_input(&input);
            }
        }
    }
}

fn build_sequence_call_input(
    memory_map: &BTreeMap<String, &SequenceMemoryObject>,
    state: &SequenceExecutionState,
    target_kind: HostTargetKind,
    eid: u64,
    fid: u64,
    args: &[SequenceArg],
    index: usize,
    label: &str,
) -> HostHarnessInput {
    let materialized = materialize_args(args, memory_map, state, index);
    HostHarnessInput {
        target_kind,
        mode: if state.platform_fault.is_active() {
            HostHarnessMode::PlatformFault
        } else {
            HostHarnessMode::Ecall
        },
        call: HostCall::new(
            eid,
            fid,
            [
                materialized[0],
                materialized[1],
                materialized[2],
                materialized[3],
                materialized[4],
                materialized[5],
            ],
        ),
        hart_id: state.active_hart,
        hart_state: state.hart_state(state.active_hart),
        privilege: state.privilege,
        memory_regions: state.memory_regions.clone(),
        platform_fault: state.platform_fault,
        fdt_blob: Vec::new(),
        label: if label.trim().is_empty() {
            format!("call-{index}")
        } else {
            label.to_string()
        },
    }
}

fn materialize_args(
    args: &[SequenceArg],
    memory_map: &BTreeMap<String, &SequenceMemoryObject>,
    state: &SequenceExecutionState,
    index: usize,
) -> Vec<u64> {
    args.iter()
        .map(|arg| materialize_arg(arg, memory_map, state))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|err| panic!("materialize sequence arg failed at step {index}: {err}"))
}

fn sequence_memory_regions(program: &SequenceProgram) -> Vec<HostMemoryRegion> {
    program
        .memory
        .iter()
        .map(|memory| HostMemoryRegion {
            guest_addr: sequence_memory_guest_addr(memory),
            read: memory.read,
            write: memory.write,
            execute: memory.execute,
            bytes: memory.bytes.clone(),
        })
        .collect()
}

fn materialize_arg(
    arg: &SequenceArg,
    memory_map: &BTreeMap<String, &SequenceMemoryObject>,
    state: &SequenceExecutionState,
) -> Result<u64, String> {
    Ok(match arg {
        SequenceArg::Const { value } => *value,
        SequenceArg::MemoryAddr { object } | SequenceArg::MemoryAddrLow { object } => {
            sequence_memory_guest_addr(
                memory_map
                    .get(object)
                    .ok_or_else(|| format!("unknown memory object {object}"))?,
            )
        }
        SequenceArg::MemoryAddrHigh { .. } => 0,
        SequenceArg::MemoryLen { object } => memory_map
            .get(object)
            .ok_or_else(|| format!("unknown memory object {object}"))?
            .bytes
            .len() as u64,
        SequenceArg::CallResult {
            call_index,
            op_div,
            op_add,
            default,
        } => state
            .call_results
            .get(*call_index as usize)
            .copied()
            .map(|value| value / (*op_div).max(1) + *op_add)
            .unwrap_or(*default),
    })
}

fn update_call_state(
    state: &mut SequenceExecutionState,
    eid: u64,
    fid: u64,
    args: &[u64],
    result: &HostHarnessResult,
) {
    let HostHarnessResult::Ecall(report) = result else {
        state.call_results.push(0);
        return;
    };
    let wire_result = if report.sbi_error == 0 {
        report.value
    } else {
        report.sbi_error as u64
    };
    state.call_results.push(wire_result);
    if report.sbi_error != 0 {
        return;
    }
    if eid == 0x4853_4d {
        match fid {
            0 => {
                if let Some(target_hart) = args.first() {
                    state.hart_states.insert(*target_hart, HostHartState::Started);
                }
            }
            1 => {
                state
                    .hart_states
                    .insert(state.active_hart, HostHartState::Stopped);
            }
            3 => {
                state
                    .hart_states
                    .insert(state.active_hart, HostHartState::Suspended);
            }
            _ => {}
        }
    }
}
