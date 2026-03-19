use crate::{
    Args, ArgumentKind, EXEC_BUFFER_SIZE, ExecArg, ExecCallKind, ExecInstr, ExecProgram,
    HostHartState, HostPlatformFaultProfile, HostPrivilegeState, HostTargetKind, InputData,
    Metadata, exec_call_desc, exec_call_id_for, exec_program_describe, exec_program_primary_input,
    exec_prop_busy_wait, exec_prop_target_hart, fix_input_args,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SEQUENCE_MAGIC: &[u8; 8] = b"SBISEQ\0\0";
const DEFAULT_SEQUENCE_GUEST_BASE: u64 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SequenceProgram {
    #[serde(default)]
    pub metadata: SequenceMetadata,
    #[serde(default)]
    pub env: SequenceEnv,
    #[serde(default)]
    pub memory: Vec<SequenceMemoryObject>,
    #[serde(default)]
    pub steps: Vec<SequenceStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SequenceMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceEnv {
    #[serde(default = "default_sequence_smp")]
    pub smp: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impl_hint: Option<HostTargetKind>,
    #[serde(default)]
    pub platform: String,
}

impl Default for SequenceEnv {
    fn default() -> Self {
        Self {
            smp: default_sequence_smp(),
            impl_hint: None,
            platform: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceMemoryObject {
    pub id: String,
    #[serde(default)]
    pub slot_offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_addr: Option<u64>,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub execute: bool,
    #[serde(default)]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SequenceArg {
    Const {
        value: u64,
    },
    MemoryAddr {
        object: String,
    },
    MemoryAddrLow {
        object: String,
    },
    MemoryAddrHigh {
        object: String,
    },
    MemoryLen {
        object: String,
    },
    CallResult {
        call_index: u64,
        #[serde(default = "default_call_result_divisor")]
        op_div: u64,
        #[serde(default)]
        op_add: u64,
        #[serde(default)]
        default: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SequenceCallExpectation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbi_error: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SequenceFdtExpectation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hart_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SequenceStep {
    SetTargetHart {
        hart_id: u64,
    },
    SetHartState {
        hart_id: u64,
        state: HostHartState,
    },
    SetPrivilege {
        privilege: HostPrivilegeState,
    },
    SetPlatformFault {
        profile: HostPlatformFaultProfile,
    },
    BusyWait {
        iterations: u64,
    },
    Call {
        #[serde(default)]
        label: String,
        eid: u64,
        fid: u64,
        args: Vec<SequenceArg>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect: Option<SequenceCallExpectation>,
    },
    ParseFdt {
        #[serde(default)]
        label: String,
        object: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect: Option<SequenceFdtExpectation>,
    },
}

impl SequenceProgram {
    pub fn hash_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence_program_to_bytes(self));
        let result = hasher.finalize();
        result
            .iter()
            .take(4)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    pub fn from_fuzz_bytes(bytes: &[u8], smp: u16) -> Self {
        sequence_program_from_fuzz_bytes(bytes, smp)
    }
}

pub fn sequence_program_to_bytes(program: &SequenceProgram) -> Vec<u8> {
    let payload = serde_json::to_vec(program).expect("serialize sequence program");
    let mut bytes = Vec::with_capacity(SEQUENCE_MAGIC.len() + 4 + payload.len());
    bytes.extend_from_slice(SEQUENCE_MAGIC);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

pub fn sequence_program_from_bytes(bytes: &[u8]) -> Result<SequenceProgram, String> {
    if bytes.len() < SEQUENCE_MAGIC.len() + 4 {
        return Err("sequence input too short".to_string());
    }
    if &bytes[..SEQUENCE_MAGIC.len()] != SEQUENCE_MAGIC {
        return Err("invalid sequence magic".to_string());
    }
    let payload_len_offset = SEQUENCE_MAGIC.len();
    let payload_len = u32::from_le_bytes(
        bytes[payload_len_offset..payload_len_offset + 4]
            .try_into()
            .expect("sequence header length slice"),
    ) as usize;
    let payload = &bytes[payload_len_offset + 4..];
    if payload.len() != payload_len {
        return Err(format!(
            "sequence payload length mismatch: header={payload_len}, actual={}",
            payload.len()
        ));
    }
    let program: SequenceProgram =
        serde_json::from_slice(payload).map_err(|err| format!("parse sequence payload: {err}"))?;
    validate_sequence_program(&program)?;
    Ok(program)
}

pub fn sequence_program_from_fuzz_bytes(bytes: &[u8], smp: u16) -> SequenceProgram {
    if bytes.starts_with(SEQUENCE_MAGIC) {
        if let Ok(program) = sequence_program_from_bytes(bytes) {
            return program;
        }
    }

    let smp = smp.max(1);
    let mut cursor = SequenceFuzzCursor::new(bytes);
    let step_budget = usize::from(cursor.read_u16().clamp(1, 32));
    let memory_count = usize::from(cursor.read_u8().min(8));
    let mut memory = Vec::with_capacity(memory_count);

    for index in 0..memory_count {
        let raw_guest_addr = cursor.read_u64();
        let perm = cursor.read_u8();
        let mut len = usize::from(cursor.read_u16()).min(256);
        if len == 0 && index == 0 {
            len = 16;
        }
        let mut region_bytes = cursor.take_vec(len);
        while region_bytes.len() < len {
            region_bytes.push((index as u8).wrapping_add(region_bytes.len() as u8));
        }
        memory.push(SequenceMemoryObject {
            id: format!("obj{index}"),
            slot_offset: (index as u64) * 0x100,
            guest_addr: Some(match raw_guest_addr {
                0 => DEFAULT_SEQUENCE_GUEST_BASE + (index as u64 * 0x1000),
                value if value < 0x1000 => {
                    DEFAULT_SEQUENCE_GUEST_BASE + (index as u64 * 0x1000) + value * 8
                }
                value => value,
            }),
            read: perm == 0 || perm & 0b001 != 0,
            write: perm == 0 || perm & 0b010 != 0,
            execute: perm & 0b100 != 0,
            bytes: region_bytes,
        });
    }

    let mut steps = Vec::new();
    let mut call_count = 0_u64;
    for step_index in 0..step_budget {
        match cursor.read_u8() % 5 {
            0 => {
                let eid = fuzz_sequence_extid(cursor.read_u64());
                let fid = fuzz_sequence_fid(eid, cursor.read_u64());
                let mut raw_args = [0_u64; 6];
                for arg in &mut raw_args {
                    *arg = cursor.read_u64();
                }
                let caller_hart = u64::from(cursor.read_u8()) % u64::from(smp);
                steps.push(SequenceStep::SetTargetHart {
                    hart_id: caller_hart,
                });
                steps.push(SequenceStep::Call {
                    label: format!("fuzz-call-{step_index}"),
                    eid,
                    fid,
                    args: fuzz_sequence_args(eid, fid, raw_args, &memory, call_count),
                    expect: None,
                });
                call_count += 1;
            }
            1 => steps.push(SequenceStep::SetTargetHart {
                hart_id: u64::from(cursor.read_u8()) % u64::from(smp),
            }),
            2 => steps.push(SequenceStep::SetHartState {
                hart_id: u64::from(cursor.read_u8()) % u64::from(smp),
                state: match cursor.read_u8() % 4 {
                    0 => HostHartState::Unknown,
                    1 => HostHartState::Started,
                    2 => HostHartState::Stopped,
                    _ => HostHartState::Suspended,
                },
            }),
            3 => steps.push(SequenceStep::SetPlatformFault {
                profile: HostPlatformFaultProfile {
                    mode: match cursor.read_u8() % 4 {
                        0 => crate::HostPlatformFaultMode::None,
                        1 => crate::HostPlatformFaultMode::ReturnSbiError,
                        2 => crate::HostPlatformFaultMode::ReturnRawError,
                        _ => crate::HostPlatformFaultMode::OverrideValue,
                    },
                    error: cursor.read_i64(),
                    value: cursor.read_u64(),
                    duplicate_side_effects: cursor.read_u8() % 2 == 1,
                },
            }),
            _ => steps.push(SequenceStep::BusyWait {
                iterations: u64::from(cursor.read_u16()),
            }),
        }
    }

    if !steps
        .iter()
        .any(|step| matches!(step, SequenceStep::Call { .. } | SequenceStep::ParseFdt { .. }))
    {
        steps.push(SequenceStep::Call {
            label: "fuzz-default".to_string(),
            eid: if memory.is_empty() { 0x10 } else { 0x4442_434e },
            fid: 0,
            args: fuzz_sequence_args(
                if memory.is_empty() { 0x10 } else { 0x4442_434e },
                0,
                [0; 6],
                &memory,
                call_count,
            ),
            expect: None,
        });
    }

    let program = SequenceProgram {
        metadata: SequenceMetadata {
            name: "fuzz-sequence".to_string(),
            source: "structured-fuzz".to_string(),
            note: format!("len={}", bytes.len()),
        },
        env: SequenceEnv {
            smp,
            impl_hint: None,
            platform: "host-harness".to_string(),
        },
        memory,
        steps,
    };

    if validate_sequence_program(&program).is_ok() {
        program
    } else {
        SequenceProgram {
            metadata: SequenceMetadata {
                name: "fuzz-sequence-fallback".to_string(),
                source: "structured-fuzz".to_string(),
                note: String::new(),
            },
            env: SequenceEnv {
                smp,
                impl_hint: None,
                platform: "host-harness".to_string(),
            },
            memory: Vec::new(),
            steps: vec![SequenceStep::Call {
                label: "base-get-spec-version".to_string(),
                eid: 0x10,
                fid: 0,
                args: vec![
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                ],
                expect: None,
            }],
        }
    }
}

pub fn validate_sequence_program(program: &SequenceProgram) -> Result<(), String> {
    if program.env.smp == 0 {
        return Err("sequence env.smp must be greater than zero".to_string());
    }

    let mut ids = BTreeSet::new();
    for memory in &program.memory {
        if memory.id.trim().is_empty() {
            return Err("sequence memory object id must not be empty".to_string());
        }
        if !ids.insert(memory.id.clone()) {
            return Err(format!("duplicate sequence memory id: {}", memory.id));
        }
        let end = memory
            .slot_offset
            .checked_add(memory.bytes.len() as u64)
            .ok_or_else(|| format!("memory object {} slot range overflow", memory.id))?;
        if end as usize > EXEC_BUFFER_SIZE {
            return Err(format!(
                "memory object {} exceeds exec data buffer: end={} limit={}",
                memory.id, end, EXEC_BUFFER_SIZE
            ));
        }
    }

    let memory_map = sequence_memory_map(program);
    let mut call_count = 0_u64;
    for (index, step) in program.steps.iter().enumerate() {
        match step {
            SequenceStep::SetTargetHart { hart_id }
            | SequenceStep::SetHartState { hart_id, .. } => {
                if *hart_id >= u64::from(program.env.smp) {
                    return Err(format!(
                        "step[{index}] hart {} is outside env.smp={}",
                        hart_id, program.env.smp
                    ));
                }
            }
            SequenceStep::Call { args, .. } => {
                if args.len() != 6 {
                    return Err(format!(
                        "step[{index}] call arg count mismatch: got {} expected 6",
                        args.len()
                    ));
                }
                for (arg_index, arg) in args.iter().enumerate() {
                    validate_sequence_arg(arg, &memory_map, call_count)
                        .map_err(|err| format!("step[{index}] arg[{arg_index}] {err}"))?;
                }
                call_count += 1;
            }
            SequenceStep::ParseFdt { object, .. } => {
                if !memory_map.contains_key(object) {
                    return Err(format!(
                        "step[{index}] references unknown memory object {}",
                        object
                    ));
                }
            }
            SequenceStep::SetPrivilege { .. }
            | SequenceStep::SetPlatformFault { .. }
            | SequenceStep::BusyWait { .. } => {}
        }
    }

    Ok(())
}

struct SequenceFuzzCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SequenceFuzzCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn read_u16(&mut self) -> u16 {
        let mut raw = [0_u8; 2];
        let chunk = self.take_slice(2);
        raw[..chunk.len()].copy_from_slice(chunk);
        u16::from_le_bytes(raw)
    }

    fn read_u64(&mut self) -> u64 {
        let mut raw = [0_u8; 8];
        let chunk = self.take_slice(8);
        raw[..chunk.len()].copy_from_slice(chunk);
        u64::from_le_bytes(raw)
    }

    fn read_i64(&mut self) -> i64 {
        let mut raw = [0_u8; 8];
        let chunk = self.take_slice(8);
        raw[..chunk.len()].copy_from_slice(chunk);
        i64::from_le_bytes(raw)
    }

    fn take_vec(&mut self, len: usize) -> Vec<u8> {
        self.take_slice(len).to_vec()
    }

    fn take_slice(&mut self, len: usize) -> &'a [u8] {
        let start = self.offset.min(self.bytes.len());
        let end = start.saturating_add(len).min(self.bytes.len());
        self.offset = end;
        &self.bytes[start..end]
    }
}

fn fuzz_sequence_extid(raw_eid: u64) -> u64 {
    const KNOWN_EXTENSIONS: [u64; 8] = [
        0x10,
        0x5449_4d45,
        0x735049,
        0x5246_4e43,
        0x4853_4d,
        0x4442_434e,
        0x5352_5354,
        0x504d55,
    ];
    if raw_eid == 0 {
        0x10
    } else if raw_eid < KNOWN_EXTENSIONS.len() as u64 {
        KNOWN_EXTENSIONS[raw_eid as usize]
    } else {
        raw_eid
    }
}

fn fuzz_sequence_fid(extid: u64, raw_fid: u64) -> u64 {
    if raw_fid != 0 {
        return raw_fid & 0xf;
    }
    match extid {
        0x10 => 0,
        0x4442_434e => 0,
        0x4853_4d => 2,
        0x504d55 => 8,
        _ => 0,
    }
}

fn fuzz_sequence_args(
    eid: u64,
    fid: u64,
    raw_args: [u64; 6],
    memory: &[SequenceMemoryObject],
    call_count: u64,
) -> Vec<SequenceArg> {
    let mut args = raw_args
        .into_iter()
        .map(|value| SequenceArg::Const { value })
        .collect::<Vec<_>>();
    if let Some(object) = memory.first() {
        let object_id = object.id.clone();
        match (eid, fid) {
            (0x4442_434e, 0 | 1) => {
                args[0] = SequenceArg::MemoryLen {
                    object: object_id.clone(),
                };
                args[1] = SequenceArg::MemoryAddrLow {
                    object: object_id.clone(),
                };
                args[2] = SequenceArg::MemoryAddrHigh {
                    object: object_id,
                };
            }
            (0x504d55, 8) => {
                args[0] = SequenceArg::MemoryAddrLow {
                    object: object_id.clone(),
                };
                args[1] = SequenceArg::MemoryAddrHigh {
                    object: object_id,
                };
            }
            _ => {}
        }
    }

    if call_count > 0 && raw_args[5] % 2 == 1 {
        args[5] = SequenceArg::CallResult {
            call_index: (raw_args[5] % call_count).min(call_count - 1),
            op_div: 1,
            op_add: 0,
            default: 0,
        };
    }

    if eid == 0x4853_4d && fid == 0 {
        if matches!(args[0], SequenceArg::Const { value: 0 }) {
            args[0] = SequenceArg::Const { value: 1 };
        }
        if matches!(args[1], SequenceArg::Const { value: 0 }) {
            args[1] = SequenceArg::Const { value: 0x8020_0000 };
        }
    }

    args
}

pub fn sequence_program_primary_input(program: &SequenceProgram) -> Option<InputData> {
    let memory_map = sequence_memory_map(program);
    let mut call_results = Vec::new();
    for step in &program.steps {
        if let SequenceStep::Call {
            label,
            eid,
            fid,
            args,
            ..
        } = step
        {
            let values: Vec<u64> = args
                .iter()
                .map(|arg| materialize_sequence_arg(arg, &memory_map, &call_results))
                .collect();
            let mut input = InputData {
                metadata: Metadata::from_call(
                    *eid,
                    *fid,
                    format!("sequence-{}", label_or_unknown(label)),
                ),
                args: Args {
                    eid: *eid,
                    fid: *fid,
                    arg0: values.first().copied().unwrap_or(0),
                    arg1: values.get(1).copied().unwrap_or(0),
                    arg2: values.get(2).copied().unwrap_or(0),
                    arg3: values.get(3).copied().unwrap_or(0),
                    arg4: values.get(4).copied().unwrap_or(0),
                    arg5: values.get(5).copied().unwrap_or(0),
                },
            };
            input = fix_input_args(input);
            return Some(input);
        }
        if matches!(step, SequenceStep::ParseFdt { .. }) {
            call_results.push(0);
        }
    }
    None
}

pub fn sequence_program_to_exec(program: &SequenceProgram) -> Result<ExecProgram, String> {
    validate_sequence_program(program)?;
    let memory_map = sequence_memory_map(program);
    let mut instructions = Vec::new();
    for memory in &program.memory {
        if memory.bytes.is_empty() {
            continue;
        }
        instructions.push(ExecInstr::CopyIn {
            addr: memory.slot_offset,
            arg: ExecArg::Data(memory.bytes.clone()),
        });
    }

    let mut call_count = 0_u64;
    for (index, step) in program.steps.iter().enumerate() {
        match step {
            SequenceStep::SetTargetHart { hart_id } => instructions.push(ExecInstr::SetProps {
                value: exec_prop_target_hart(*hart_id),
            }),
            SequenceStep::BusyWait { iterations } => instructions.push(ExecInstr::SetProps {
                value: exec_prop_busy_wait(*iterations),
            }),
            SequenceStep::Call { eid, fid, args, .. } => {
                if call_count >= crate::EXEC_MAX_RESULTS as u64 {
                    return Err(format!(
                        "sequence call count {} exceeds exec result slot capacity {}",
                        call_count + 1,
                        crate::EXEC_MAX_RESULTS
                    ));
                }
                let call_id = exec_call_id_for(*eid, *fid).unwrap_or(0);
                let mut exec_args = Vec::with_capacity(if call_id == 0 { 8 } else { 6 });
                if call_id == 0 {
                    exec_args.push(ExecArg::Const {
                        size: 8,
                        value: *eid,
                    });
                    exec_args.push(ExecArg::Const {
                        size: 8,
                        value: *fid,
                    });
                }
                for arg in args {
                    exec_args.push(sequence_arg_to_exec_arg(arg, &memory_map)?);
                }
                instructions.push(ExecInstr::Call {
                    call_id,
                    copyout_index: call_count,
                    args: exec_args,
                });
                call_count += 1;
            }
            SequenceStep::SetHartState { .. }
            | SequenceStep::SetPrivilege { .. }
            | SequenceStep::SetPlatformFault { .. }
            | SequenceStep::ParseFdt { .. } => {
                return Err(format!(
                    "step[{index}] is not supported by the firmware exec compiler"
                ));
            }
        }
    }
    let compiled = ExecProgram { instructions };
    crate::validate_exec_program(&compiled)?;
    Ok(compiled)
}

pub fn sequence_program_from_exec(program: &ExecProgram) -> Result<SequenceProgram, String> {
    let mut memory = Vec::new();
    let mut memory_by_offset = BTreeMap::new();
    let mut steps = Vec::new();
    let mut next_memory_id = 0_u64;
    let mut max_hart = 0_u64;

    for instr in &program.instructions {
        if let ExecInstr::CopyIn { addr, arg } = instr {
            let id = format!("mem{next_memory_id}");
            next_memory_id += 1;
            let bytes = match arg {
                ExecArg::Data(bytes) => bytes.clone(),
                ExecArg::Const { size, value } => {
                    let width = (*size as usize).min(8);
                    let mut bytes = vec![0_u8; width];
                    for (index, byte) in bytes.iter_mut().enumerate() {
                        *byte = ((value >> (index * 8)) & 0xff) as u8;
                    }
                    bytes
                }
                ExecArg::Addr32 { .. } | ExecArg::Addr64 { .. } | ExecArg::Result { .. } => {
                    Vec::new()
                }
            };
            memory_by_offset.insert(*addr, id.clone());
            memory.push(SequenceMemoryObject {
                id,
                slot_offset: *addr,
                guest_addr: None,
                read: true,
                write: true,
                execute: false,
                bytes,
            });
        }
    }

    for instr in &program.instructions {
        match instr {
            ExecInstr::SetProps { value } => {
                let (kind, payload) = crate::decode_exec_prop(*value);
                match kind {
                    crate::EXEC_PROP_TARGET_HART => {
                        max_hart = max_hart.max(payload);
                        steps.push(SequenceStep::SetTargetHart { hart_id: payload });
                    }
                    crate::EXEC_PROP_BUSY_WAIT => {
                        steps.push(SequenceStep::BusyWait {
                            iterations: payload,
                        });
                    }
                    _ => {}
                }
            }
            ExecInstr::Call { call_id, args, .. } => {
                let (eid, fid, call_args) = match exec_call_desc(*call_id)
                    .ok_or_else(|| format!("unknown exec call id {call_id}"))?
                    .kind
                {
                    ExecCallKind::RawEcall => {
                        if args.len() != 8 {
                            return Err(format!(
                                "raw exec call id {call_id} has {} args, expected 8",
                                args.len()
                            ));
                        }
                        let eid = exec_arg_const_value(&args[0])
                            .ok_or_else(|| "raw exec eid must be a constant".to_string())?;
                        let fid = exec_arg_const_value(&args[1])
                            .ok_or_else(|| "raw exec fid must be a constant".to_string())?;
                        (eid, fid, &args[2..])
                    }
                    ExecCallKind::Fixed { eid, fid } => (eid, fid, args.as_slice()),
                };
                let mapped_args = call_args
                    .iter()
                    .map(|arg| sequence_arg_from_exec_arg(arg, &memory_by_offset))
                    .collect::<Result<Vec<_>, _>>()?;
                steps.push(SequenceStep::Call {
                    label: exec_call_desc(*call_id)
                        .map(|desc| desc.name.to_string())
                        .unwrap_or_else(|| format!("call-{call_id}")),
                    eid,
                    fid,
                    args: mapped_args,
                    expect: None,
                });
            }
            ExecInstr::CopyIn { .. } | ExecInstr::CopyOut { .. } => {}
        }
    }

    let sequence = SequenceProgram {
        metadata: SequenceMetadata {
            name: "imported-exec".to_string(),
            source: "exec-import".to_string(),
            note: exec_program_describe(program),
        },
        env: SequenceEnv {
            smp: (max_hart + 1).max(1) as u16,
            ..SequenceEnv::default()
        },
        memory,
        steps,
    };
    validate_sequence_program(&sequence)?;
    Ok(sequence)
}

pub fn sequence_program_describe(program: &SequenceProgram) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "sequence name={} smp={} impl_hint={} platform={}",
        label_or_unknown(&program.metadata.name),
        program.env.smp,
        program
            .env
            .impl_hint
            .map(sequence_impl_name)
            .unwrap_or("none"),
        if program.env.platform.is_empty() {
            "default"
        } else {
            &program.env.platform
        }
    ));
    if !program.metadata.note.is_empty() {
        lines.push(format!("note = {}", program.metadata.note));
    }
    lines.push(format!("memory_count = {}", program.memory.len()));
    for (index, memory) in program.memory.iter().enumerate() {
        lines.push(format!(
            "[mem:{index}] id={} slot=0x{:x} guest=0x{:x} perms={}{}{} size={}",
            memory.id,
            memory.slot_offset,
            sequence_memory_guest_addr(memory),
            if memory.read { "r" } else { "-" },
            if memory.write { "w" } else { "-" },
            if memory.execute { "x" } else { "-" },
            memory.bytes.len()
        ));
    }
    for (index, step) in program.steps.iter().enumerate() {
        match step {
            SequenceStep::SetTargetHart { hart_id } => {
                lines.push(format!("[step:{index}] set_target_hart hart={hart_id}"));
            }
            SequenceStep::SetHartState { hart_id, state } => {
                lines.push(format!(
                    "[step:{index}] set_hart_state hart={hart_id} state={state:?}"
                ));
            }
            SequenceStep::SetPrivilege { privilege } => {
                lines.push(format!("[step:{index}] set_privilege {privilege:?}"));
            }
            SequenceStep::SetPlatformFault { profile } => {
                lines.push(format!(
                    "[step:{index}] set_platform_fault mode={:?} error={} value=0x{:x}",
                    profile.mode, profile.error, profile.value
                ));
            }
            SequenceStep::BusyWait { iterations } => {
                lines.push(format!("[step:{index}] busy_wait iterations={iterations}"));
            }
            SequenceStep::Call {
                label,
                eid,
                fid,
                args,
                expect,
            } => {
                let args = args
                    .iter()
                    .map(sequence_arg_describe)
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!(
                    "[step:{index}] call label={} eid=0x{eid:x} fid=0x{fid:x} args=[{}]{}",
                    label_or_unknown(label),
                    args,
                    expect
                        .as_ref()
                        .map(|expect| format!(
                            " expect(error={:?}, value={:?}, found={:?}, class={:?})",
                            expect.sbi_error,
                            expect.value,
                            expect.extension_found,
                            expect.classification
                        ))
                        .unwrap_or_default()
                ));
            }
            SequenceStep::ParseFdt {
                label,
                object,
                expect,
            } => {
                lines.push(format!(
                    "[step:{index}] parse_fdt label={} object={}{}",
                    label_or_unknown(label),
                    object,
                    expect
                        .as_ref()
                        .map(|expect| format!(
                            " expect(status={:?}, harts={:?}, class={:?})",
                            expect.status, expect.hart_count, expect.classification
                        ))
                        .unwrap_or_default()
                ));
            }
        }
    }
    lines.join("\n")
}

pub fn sequence_program_semantic_signature(program: &SequenceProgram) -> String {
    let mut steps = Vec::new();
    for step in &program.steps {
        let token = match step {
            SequenceStep::SetTargetHart { hart_id } => format!("hart:{hart_id}"),
            SequenceStep::SetHartState { hart_id, state } => {
                format!("state:{hart_id}:{state:?}")
            }
            SequenceStep::SetPrivilege { privilege } => format!("priv:{privilege:?}"),
            SequenceStep::SetPlatformFault { profile } => {
                format!("fault:{:?}:{}", profile.mode, profile.error)
            }
            SequenceStep::BusyWait { iterations } => format!("wait:{iterations}"),
            SequenceStep::Call { eid, fid, args, .. } => format!(
                "call:{eid:x}:{fid:x}:{}",
                args.iter()
                    .map(sequence_arg_describe)
                    .collect::<Vec<_>>()
                    .join("|")
            ),
            SequenceStep::ParseFdt { object, .. } => format!("fdt:{object}"),
        };
        steps.push(token);
    }
    steps.join(";")
}

pub fn sequence_memory_guest_addr(memory: &SequenceMemoryObject) -> u64 {
    memory
        .guest_addr
        .unwrap_or(DEFAULT_SEQUENCE_GUEST_BASE + memory.slot_offset)
}

fn default_sequence_smp() -> u16 {
    1
}

fn default_call_result_divisor() -> u64 {
    1
}

fn validate_sequence_arg(
    arg: &SequenceArg,
    memory_map: &BTreeMap<String, &SequenceMemoryObject>,
    call_count: u64,
) -> Result<(), String> {
    match arg {
        SequenceArg::Const { .. } => Ok(()),
        SequenceArg::MemoryAddr { object }
        | SequenceArg::MemoryAddrLow { object }
        | SequenceArg::MemoryAddrHigh { object }
        | SequenceArg::MemoryLen { object } => {
            if memory_map.contains_key(object) {
                Ok(())
            } else {
                Err(format!("references unknown memory object {object}"))
            }
        }
        SequenceArg::CallResult {
            call_index, op_div, ..
        } => {
            if *call_index >= call_count {
                return Err(format!(
                    "references unavailable prior call result {} (have {})",
                    call_index, call_count
                ));
            }
            if *op_div == 0 {
                return Err("op_div must be greater than zero".to_string());
            }
            Ok(())
        }
    }
}

fn sequence_memory_map(program: &SequenceProgram) -> BTreeMap<String, &SequenceMemoryObject> {
    program
        .memory
        .iter()
        .map(|memory| (memory.id.clone(), memory))
        .collect()
}

fn sequence_arg_to_exec_arg(
    arg: &SequenceArg,
    memory_map: &BTreeMap<String, &SequenceMemoryObject>,
) -> Result<ExecArg, String> {
    Ok(match arg {
        SequenceArg::Const { value } => ExecArg::Const {
            size: 8,
            value: *value,
        },
        SequenceArg::MemoryAddr { object } | SequenceArg::MemoryAddrLow { object } => {
            let memory = memory_map
                .get(object)
                .ok_or_else(|| format!("unknown memory object {object}"))?;
            ExecArg::Addr64 {
                offset: memory.slot_offset,
            }
        }
        SequenceArg::MemoryAddrHigh { .. } => ExecArg::Const { size: 8, value: 0 },
        SequenceArg::MemoryLen { object } => {
            let memory = memory_map
                .get(object)
                .ok_or_else(|| format!("unknown memory object {object}"))?;
            ExecArg::Const {
                size: 8,
                value: memory.bytes.len() as u64,
            }
        }
        SequenceArg::CallResult {
            call_index,
            op_div,
            op_add,
            default,
        } => ExecArg::Result {
            size: 8,
            index: *call_index,
            op_div: *op_div,
            op_add: *op_add,
            default: *default,
        },
    })
}

fn materialize_sequence_arg(
    arg: &SequenceArg,
    memory_map: &BTreeMap<String, &SequenceMemoryObject>,
    call_results: &[u64],
) -> u64 {
    match arg {
        SequenceArg::Const { value } => *value,
        SequenceArg::MemoryAddr { object } | SequenceArg::MemoryAddrLow { object } => memory_map
            .get(object)
            .map(|memory| sequence_memory_guest_addr(memory))
            .unwrap_or(0),
        SequenceArg::MemoryAddrHigh { .. } => 0,
        SequenceArg::MemoryLen { object } => memory_map
            .get(object)
            .map(|memory| memory.bytes.len() as u64)
            .unwrap_or(0),
        SequenceArg::CallResult {
            call_index,
            op_div,
            op_add,
            default,
        } => call_results
            .get(*call_index as usize)
            .copied()
            .map(|value| value / (*op_div).max(1) + *op_add)
            .unwrap_or(*default),
    }
}

fn exec_arg_const_value(arg: &ExecArg) -> Option<u64> {
    match arg {
        ExecArg::Const { value, .. } => Some(*value),
        _ => None,
    }
}

fn sequence_arg_from_exec_arg(
    arg: &ExecArg,
    memory_by_offset: &BTreeMap<u64, String>,
) -> Result<SequenceArg, String> {
    Ok(match arg {
        ExecArg::Const { value, .. } => SequenceArg::Const { value: *value },
        ExecArg::Addr32 { offset } | ExecArg::Addr64 { offset } => {
            let object = memory_by_offset
                .get(offset)
                .cloned()
                .unwrap_or_else(|| format!("slot-{offset:x}"));
            SequenceArg::MemoryAddr { object }
        }
        ExecArg::Result {
            index,
            op_div,
            op_add,
            default,
            ..
        } => SequenceArg::CallResult {
            call_index: *index,
            op_div: (*op_div).max(1),
            op_add: *op_add,
            default: *default,
        },
        ExecArg::Data(_) => {
            return Err("data arguments are only valid for copyin instructions".to_string());
        }
    })
}

fn sequence_arg_describe(arg: &SequenceArg) -> String {
    match arg {
        SequenceArg::Const { value } => format!("const(0x{value:x})"),
        SequenceArg::MemoryAddr { object } => format!("addr({object})"),
        SequenceArg::MemoryAddrLow { object } => format!("addr_low({object})"),
        SequenceArg::MemoryAddrHigh { object } => format!("addr_high({object})"),
        SequenceArg::MemoryLen { object } => format!("len({object})"),
        SequenceArg::CallResult {
            call_index,
            op_div,
            op_add,
            default,
        } => format!(
            "result(call={}, div={}, add={}, default=0x{:x})",
            call_index, op_div, op_add, default
        ),
    }
}

fn label_or_unknown(value: &str) -> &str {
    if value.trim().is_empty() {
        "unnamed"
    } else {
        value
    }
}

fn sequence_impl_name(kind: HostTargetKind) -> &'static str {
    match kind {
        HostTargetKind::OpenSbi => "opensbi",
        HostTargetKind::RustSbi => "rustsbi",
    }
}

pub fn sequence_program_from_toml_input(input: &InputData) -> SequenceProgram {
    let exec = crate::normalize_exec_program(crate::exec_program_from_input(input));
    sequence_program_from_exec(&exec).unwrap_or_else(|_| SequenceProgram {
        metadata: SequenceMetadata {
            name: input.metadata.extension_name.clone(),
            source: input.metadata.source.clone(),
            note: String::new(),
        },
        env: SequenceEnv::default(),
        memory: Vec::new(),
        steps: vec![SequenceStep::Call {
            label: input.metadata.extension_name.clone(),
            eid: input.args.eid,
            fid: input.args.fid,
            args: vec![
                SequenceArg::Const {
                    value: input.args.arg0,
                },
                SequenceArg::Const {
                    value: input.args.arg1,
                },
                SequenceArg::Const {
                    value: input.args.arg2,
                },
                SequenceArg::Const {
                    value: input.args.arg3,
                },
                SequenceArg::Const {
                    value: input.args.arg4,
                },
                SequenceArg::Const {
                    value: input.args.arg5,
                },
            ],
            expect: None,
        }],
    })
}

pub fn sequence_program_from_semantic_input(
    input: &InputData,
    name: String,
    source: String,
    env: SequenceEnv,
) -> SequenceProgram {
    let mut program = SequenceProgram {
        metadata: SequenceMetadata {
            name,
            source,
            note: "schema-driven semantic call".to_string(),
        },
        env,
        memory: Vec::new(),
        steps: Vec::new(),
    };

    let args = semantic_sequence_args_from_input(input, &mut program.memory);
    program.steps.push(SequenceStep::Call {
        label: input.metadata.extension_name.clone(),
        eid: input.args.eid,
        fid: input.args.fid,
        args,
        expect: None,
    });
    validate_sequence_program(&program).expect("semantic sequence should validate");
    program
}

fn semantic_sequence_args_from_input(
    input: &InputData,
    memory: &mut Vec<SequenceMemoryObject>,
) -> Vec<SequenceArg> {
    let schema = input.schema();
    let mut args = Vec::with_capacity(6);
    let mut pending_split_object: Option<String> = None;

    for index in 0..6 {
        let kind = schema.argument_kind(index);
        let value = input.args.get(index);
        let arg = match kind {
            ArgumentKind::Address => {
                if value == 0 {
                    SequenceArg::Const { value }
                } else {
                    let object = ensure_semantic_memory(memory, index, kind, value);
                    SequenceArg::MemoryAddr { object }
                }
            }
            ArgumentKind::HartMaskAddress => {
                if value == 0 {
                    SequenceArg::Const { value }
                } else {
                    let object = ensure_semantic_memory(memory, index, kind, value);
                    SequenceArg::MemoryAddr { object }
                }
            }
            ArgumentKind::AddressLow => {
                if value == 0 {
                    pending_split_object = None;
                    SequenceArg::Const { value }
                } else {
                    let object = ensure_semantic_memory(memory, index, kind, value);
                    pending_split_object = Some(object.clone());
                    SequenceArg::MemoryAddrLow { object }
                }
            }
            ArgumentKind::AddressHigh => {
                if let Some(object) = pending_split_object.clone() {
                    SequenceArg::MemoryAddrHigh { object }
                } else {
                    SequenceArg::Const { value }
                }
            }
            ArgumentKind::Size => {
                if let Some(object) = semantic_memory_object_for_size(input, memory, index, &schema)
                {
                    SequenceArg::MemoryLen { object }
                } else {
                    SequenceArg::Const { value }
                }
            }
            ArgumentKind::Count
            | ArgumentKind::Flags
            | ArgumentKind::HartId
            | ArgumentKind::SuspendType
            | ArgumentKind::Opaque
            | ArgumentKind::Value => SequenceArg::Const { value },
        };
        args.push(arg);

        if !matches!(kind, ArgumentKind::AddressLow | ArgumentKind::AddressHigh) {
            pending_split_object = None;
        }
    }

    args
}

fn ensure_semantic_memory(
    memory: &mut Vec<SequenceMemoryObject>,
    index: usize,
    kind: ArgumentKind,
    guest_addr: u64,
) -> String {
    let id = format!("arg{index}_mem");
    if memory.iter().any(|object| object.id == id) {
        return id;
    }

    let bytes = semantic_memory_bytes(kind, index);
    let slot_offset = align_semantic_slot(
        memory
            .last()
            .map(|object| object.slot_offset + object.bytes.len() as u64)
            .unwrap_or(0x100),
    );
    memory.push(SequenceMemoryObject {
        id: id.clone(),
        slot_offset,
        guest_addr: Some(guest_addr),
        read: true,
        write: true,
        execute: false,
        bytes,
    });
    id
}

fn semantic_memory_object_for_size(
    input: &InputData,
    memory: &mut Vec<SequenceMemoryObject>,
    index: usize,
    schema: &crate::CallSchema,
) -> Option<String> {
    let next_index = index + 1;
    if next_index >= 6 {
        return None;
    }
    let next_kind = schema.argument_kind(next_index);
    if !matches!(
        next_kind,
        ArgumentKind::Address | ArgumentKind::AddressLow
    ) {
        return None;
    }
    let guest_addr = input.args.get(next_index);
    if guest_addr == 0 {
        return None;
    }
    Some(ensure_semantic_memory(
        memory, next_index, next_kind, guest_addr,
    ))
}

fn semantic_memory_bytes(kind: ArgumentKind, index: usize) -> Vec<u8> {
    match kind {
        _ => format!("arg{index}-semantic-buffer").into_bytes(),
    }
}

fn align_semantic_slot(value: u64) -> u64 {
    (value + 0x1f) & !0x1f
}

pub fn sequence_program_primary_exec_input(program: &SequenceProgram) -> Option<InputData> {
    sequence_program_to_exec(program)
        .ok()
        .and_then(|exec| exec_program_primary_input(&exec))
}
