use crate::{
    HostHartState, HostPlatformFaultMode, HostPlatformFaultProfile, SequenceArg, SequenceProgram,
    SequenceStep, SbiError,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequenceMutationOperation {
    InsertBusyWait { index: usize, iterations: u64 },
    RemoveStep { index: usize },
    DuplicateStep { index: usize },
    SwapSteps { left: usize, right: usize },
    MutateStepArgs { index: usize },
    MutateStepEidFid { index: usize, eid: u64, fid: u64 },
    InsertTargetHart { index: usize, hart_id: u64 },
    InsertHartState { index: usize, hart_id: u64, state: HostHartState },
    InjectFault { index: usize, mode: HostPlatformFaultMode },
    MutateMemoryObject { object: String },
    SpliceSequence { index: usize, len: usize },
}

pub fn mutate_sequence_program<R: Rng>(
    program: &mut SequenceProgram,
    rng: &mut R,
) -> Option<SequenceMutationOperation> {
    if program.steps.is_empty() {
        program.steps.push(SequenceStep::BusyWait {
            iterations: u64::from(rng.gen_range(1..=32_u16)),
        });
        return Some(SequenceMutationOperation::InsertBusyWait {
            index: 0,
            iterations: match &program.steps[0] {
                SequenceStep::BusyWait { iterations } => *iterations,
                _ => 0,
            },
        });
    }

    match rng.gen_range(0..11) {
        0 => {
            let index = rng.gen_range(0..=program.steps.len());
            let iterations = u64::from(rng.gen_range(1..=256_u16));
            program.steps.insert(index, SequenceStep::BusyWait { iterations });
            Some(SequenceMutationOperation::InsertBusyWait { index, iterations })
        }
        1 if program.steps.len() > 1 => {
            let index = rng.gen_range(0..program.steps.len());
            program.steps.remove(index);
            Some(SequenceMutationOperation::RemoveStep { index })
        }
        2 => {
            let index = rng.gen_range(0..program.steps.len());
            let duplicate = program.steps[index].clone();
            program.steps.insert(index + 1, duplicate);
            Some(SequenceMutationOperation::DuplicateStep { index })
        }
        3 if program.steps.len() > 1 => {
            let left = rng.gen_range(0..program.steps.len());
            let mut right = rng.gen_range(0..program.steps.len());
            if left == right {
                right = (right + 1) % program.steps.len();
            }
            program.steps.swap(left, right);
            Some(SequenceMutationOperation::SwapSteps { left, right })
        }
        4 => mutate_random_call_args(program, rng),
        5 => mutate_random_call_target(program, rng),
        6 => {
            let index = rng.gen_range(0..=program.steps.len());
            let hart_limit = u64::from(program.env.smp.max(1));
            let hart_id = rng.gen_range(0..hart_limit);
            program.steps.insert(index, SequenceStep::SetTargetHart { hart_id });
            Some(SequenceMutationOperation::InsertTargetHart { index, hart_id })
        }
        7 => {
            let index = rng.gen_range(0..=program.steps.len());
            let hart_limit = u64::from(program.env.smp.max(1));
            let hart_id = rng.gen_range(0..hart_limit);
            let state = match rng.gen_range(0..3) {
                0 => HostHartState::Started,
                1 => HostHartState::Stopped,
                _ => HostHartState::Suspended,
            };
            program
                .steps
                .insert(index, SequenceStep::SetHartState { hart_id, state });
            Some(SequenceMutationOperation::InsertHartState {
                index,
                hart_id,
                state,
            })
        }
        8 => {
            let index = rng.gen_range(0..=program.steps.len());
            let mode = match rng.gen_range(0..3) {
                0 => HostPlatformFaultMode::ReturnSbiError,
                1 => HostPlatformFaultMode::ReturnRawError,
                _ => HostPlatformFaultMode::OverrideValue,
            };
            let profile = match mode {
                HostPlatformFaultMode::ReturnSbiError => {
                    HostPlatformFaultProfile::sbi_error(SbiError::InvalidParam)
                }
                HostPlatformFaultMode::ReturnRawError => HostPlatformFaultProfile::raw_error(-77),
                HostPlatformFaultMode::OverrideValue => HostPlatformFaultProfile {
                    mode,
                    error: 0,
                    value: 1_u64 << rng.gen_range(0..8),
                    duplicate_side_effects: false,
                },
                HostPlatformFaultMode::None => HostPlatformFaultProfile::none(),
            };
            program
                .steps
                .insert(index, SequenceStep::SetPlatformFault { profile });
            Some(SequenceMutationOperation::InjectFault { index, mode })
        }
        9 => mutate_memory_object(program, rng),
        10 if program.steps.len() > 1 => splice_sequence(program, rng),
        _ => None,
    }
}

pub fn mutate_call_arguments<R: Rng>(step: &mut SequenceStep, rng: &mut R) -> bool {
    let SequenceStep::Call { args, .. } = step else {
        return false;
    };
    if args.is_empty() {
        return false;
    }
    let index = rng.gen_range(0..args.len());
    let replacement = match &args[index] {
        SequenceArg::Const { value } => SequenceArg::Const {
            value: value.wrapping_add(1),
        },
        SequenceArg::MemoryLen { object } => SequenceArg::MemoryLen {
            object: object.clone(),
        },
        other => other.clone(),
    };
    args[index] = replacement;
    true
}

fn mutate_random_call_args<R: Rng>(
    program: &mut SequenceProgram,
    rng: &mut R,
) -> Option<SequenceMutationOperation> {
    let call_indexes = program
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| matches!(step, SequenceStep::Call { .. }).then_some(index))
        .collect::<Vec<_>>();
    let index = *call_indexes.get(rng.gen_range(0..call_indexes.len().max(1)))?;
    if mutate_call_arguments(&mut program.steps[index], rng) {
        Some(SequenceMutationOperation::MutateStepArgs { index })
    } else {
        None
    }
}

fn mutate_random_call_target<R: Rng>(
    program: &mut SequenceProgram,
    rng: &mut R,
) -> Option<SequenceMutationOperation> {
    let call_indexes = program
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| matches!(step, SequenceStep::Call { .. }).then_some(index))
        .collect::<Vec<_>>();
    let index = *call_indexes.get(rng.gen_range(0..call_indexes.len().max(1)))?;
    let interesting_calls = [
        (0x10, 0),
        (0x10, 3),
        (0x4853_4d, 0),
        (0x4853_4d, 2),
        (0x4853_4d, 3),
        (0x4442_434e, 0),
        (0x7350_49, 0),
        (0x5246_4e43, 1),
        (0x504d_55, 0),
        (0x504d_55, 8),
    ];
    let (eid, fid) = interesting_calls[rng.gen_range(0..interesting_calls.len())];
    let SequenceStep::Call {
        eid: step_eid,
        fid: step_fid,
        ..
    } = &mut program.steps[index]
    else {
        return None;
    };
    *step_eid = eid;
    *step_fid = fid;
    Some(SequenceMutationOperation::MutateStepEidFid { index, eid, fid })
}

fn mutate_memory_object<R: Rng>(
    program: &mut SequenceProgram,
    rng: &mut R,
) -> Option<SequenceMutationOperation> {
    let memory_len = program.memory.len();
    let object = program
        .memory
        .get_mut(rng.gen_range(0..memory_len.max(1)))?;
    match rng.gen_range(0..4) {
        0 => object.read = !object.read,
        1 => object.write = !object.write,
        2 => {
            let base = object.guest_addr.unwrap_or(0x8000_0000);
            object.guest_addr = Some(base.wrapping_add(0x1000));
        }
        _ => {
            if object.bytes.is_empty() {
                object.bytes.push(rng.gen_range(0..=u8::MAX));
            } else {
                let index = rng.gen_range(0..object.bytes.len());
                object.bytes[index] ^= 0xff;
            }
        }
    }
    Some(SequenceMutationOperation::MutateMemoryObject {
        object: object.id.clone(),
    })
}

fn splice_sequence<R: Rng>(
    program: &mut SequenceProgram,
    rng: &mut R,
) -> Option<SequenceMutationOperation> {
    if program.steps.len() < 2 {
        return None;
    }
    let from = rng.gen_range(0..program.steps.len());
    let max_len = (program.steps.len() - from).min(3);
    let len = rng.gen_range(1..=max_len);
    let insert_at = rng.gen_range(0..=program.steps.len());
    let slice = program.steps[from..from + len].to_vec();
    program.steps.splice(insert_at..insert_at, slice);
    Some(SequenceMutationOperation::SpliceSequence {
        index: insert_at,
        len,
    })
}
