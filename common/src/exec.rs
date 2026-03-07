use crate::{Args, InputData, Metadata, fix_input_args};

pub const EXEC_BUFFER_SIZE: usize = 4 << 10;
pub const EXEC_MAGIC: &[u8; 8] = b"SBIEXEC1";
pub const EXEC_NO_COPYOUT: u64 = u64::MAX;
pub const EXEC_MAX_ARGS: usize = 8;

const EXEC_INSTR_EOF: u64 = u64::MAX;
const EXEC_INSTR_COPYIN: u64 = u64::MAX - 1;
const EXEC_INSTR_COPYOUT: u64 = u64::MAX - 2;
const EXEC_INSTR_SET_PROPS: u64 = u64::MAX - 3;

const EXEC_ARG_CONST: u64 = 0;
const EXEC_ARG_ADDR32: u64 = 1;
const EXEC_ARG_ADDR64: u64 = 2;
const EXEC_ARG_RESULT: u64 = 3;
const EXEC_ARG_DATA: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCallKind {
    RawEcall,
    Fixed { eid: u64, fid: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecCallDesc {
    pub id: u64,
    pub name: &'static str,
    pub kind: ExecCallKind,
}

pub const EXEC_CALL_TABLE: [ExecCallDesc; 11] = [
    ExecCallDesc {
        id: 0,
        name: "raw_ecall",
        kind: ExecCallKind::RawEcall,
    },
    ExecCallDesc {
        id: 1,
        name: "timer_set_timer",
        kind: ExecCallKind::Fixed {
            eid: 0x5449_4d45,
            fid: 0,
        },
    },
    ExecCallDesc {
        id: 2,
        name: "ipi_send",
        kind: ExecCallKind::Fixed {
            eid: 0x0073_5049,
            fid: 0,
        },
    },
    ExecCallDesc {
        id: 3,
        name: "hsm_hart_start",
        kind: ExecCallKind::Fixed {
            eid: 0x4853_4d,
            fid: 0,
        },
    },
    ExecCallDesc {
        id: 4,
        name: "hsm_hart_stop",
        kind: ExecCallKind::Fixed {
            eid: 0x4853_4d,
            fid: 1,
        },
    },
    ExecCallDesc {
        id: 5,
        name: "hsm_hart_status",
        kind: ExecCallKind::Fixed {
            eid: 0x4853_4d,
            fid: 2,
        },
    },
    ExecCallDesc {
        id: 6,
        name: "hsm_hart_suspend",
        kind: ExecCallKind::Fixed {
            eid: 0x4853_4d,
            fid: 3,
        },
    },
    ExecCallDesc {
        id: 7,
        name: "reset_system_reset",
        kind: ExecCallKind::Fixed {
            eid: 0x5352_5354,
            fid: 0,
        },
    },
    ExecCallDesc {
        id: 8,
        name: "console_write",
        kind: ExecCallKind::Fixed {
            eid: 0x4442_434e,
            fid: 0,
        },
    },
    ExecCallDesc {
        id: 9,
        name: "pmu_get_event_info",
        kind: ExecCallKind::Fixed {
            eid: 0x504d_55,
            fid: 8,
        },
    },
    ExecCallDesc {
        id: 10,
        name: "rfence_remote_sfence_vma",
        kind: ExecCallKind::Fixed {
            eid: 0x5246_4e43,
            fid: 1,
        },
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecProgram {
    pub instructions: Vec<ExecInstr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecInstr {
    CopyIn {
        addr: u64,
        arg: ExecArg,
    },
    CopyOut {
        index: u64,
        addr: u64,
        size: u64,
    },
    SetProps {
        value: u64,
    },
    Call {
        call_id: u64,
        copyout_index: u64,
        args: Vec<ExecArg>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecArg {
    Const {
        size: u64,
        value: u64,
    },
    Addr32 {
        offset: u64,
    },
    Addr64 {
        offset: u64,
    },
    Result {
        size: u64,
        index: u64,
        op_div: u64,
        op_add: u64,
        default: u64,
    },
    Data(Vec<u8>),
}

impl ExecProgram {
    pub fn call_count(&self) -> u64 {
        self.instructions
            .iter()
            .filter(|instr| matches!(instr, ExecInstr::Call { .. }))
            .count() as u64
    }
}

pub fn exec_call_desc(call_id: u64) -> Option<&'static ExecCallDesc> {
    EXEC_CALL_TABLE.iter().find(|desc| desc.id == call_id)
}

pub fn exec_call_table() -> &'static [ExecCallDesc] {
    &EXEC_CALL_TABLE
}

pub fn validate_exec_call_table() -> Result<(), String> {
    for (index, desc) in EXEC_CALL_TABLE.iter().enumerate() {
        if desc.name.trim().is_empty() {
            return Err(format!("empty exec call name at index {index}"));
        }
        for other in EXEC_CALL_TABLE.iter().skip(index + 1) {
            if desc.id == other.id {
                return Err(format!("duplicate exec call id: {}", desc.id));
            }
            match (desc.kind, other.kind) {
                (
                    ExecCallKind::Fixed { eid, fid },
                    ExecCallKind::Fixed {
                        eid: other_eid,
                        fid: other_fid,
                    },
                ) if eid == other_eid && fid == other_fid => {
                    return Err(format!(
                        "duplicate fixed exec call mapping: eid=0x{eid:x} fid=0x{fid:x}"
                    ));
                }
                _ => {}
            }
        }

        if let ExecCallKind::Fixed { eid, fid } = desc.kind {
            if exec_call_id_for(eid, fid) != Some(desc.id) {
                return Err(format!("reverse lookup mismatch for call {}", desc.name));
            }
        }
    }
    Ok(())
}

pub fn format_exec_call_table() -> String {
    let mut lines = vec!["ID  NAME                     EID         FID        KIND".to_string()];
    for desc in exec_call_table() {
        let (eid, fid, kind) = match desc.kind {
            ExecCallKind::RawEcall => ("-".to_string(), "-".to_string(), "raw".to_string()),
            ExecCallKind::Fixed { eid, fid } => (
                format!("0x{eid:08x}"),
                format!("0x{fid:x}"),
                "fixed".to_string(),
            ),
        };
        lines.push(format!(
            "{:<3} {:<24} {:<11} {:<10} {}",
            desc.id, desc.name, eid, fid, kind
        ));
    }
    lines.join("\n")
}

pub fn exec_call_id_for(eid: u64, fid: u64) -> Option<u64> {
    EXEC_CALL_TABLE.iter().find_map(|desc| match desc.kind {
        ExecCallKind::Fixed {
            eid: desc_eid,
            fid: desc_fid,
        } if desc_eid == eid && desc_fid == fid => Some(desc.id),
        _ => None,
    })
}

pub fn exec_program_from_input(input: &InputData) -> ExecProgram {
    let call_id = exec_call_id_for(input.args.eid, input.args.fid).unwrap_or(0);
    let args = if call_id == 0 {
        vec![
            ExecArg::Const {
                size: 8,
                value: input.args.eid,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.fid,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg0,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg1,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg2,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg3,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg4,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg5,
            },
        ]
    } else {
        vec![
            ExecArg::Const {
                size: 8,
                value: input.args.arg0,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg1,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg2,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg3,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg4,
            },
            ExecArg::Const {
                size: 8,
                value: input.args.arg5,
            },
        ]
    };

    ExecProgram {
        instructions: vec![ExecInstr::Call {
            call_id,
            copyout_index: EXEC_NO_COPYOUT,
            args,
        }],
    }
}

pub fn normalize_exec_program(program: ExecProgram) -> ExecProgram {
    let instructions = program
        .instructions
        .into_iter()
        .map(|instr| match instr {
            ExecInstr::Call {
                call_id,
                copyout_index,
                args,
            } if args.iter().all(|arg| matches!(arg, ExecArg::Const { .. })) => {
                if let Some(mut input) = exec_call_to_input(call_id, &args) {
                    input = fix_input_args(input);
                    let normalized = exec_program_from_input(&input);
                    match normalized.instructions.into_iter().next() {
                        Some(ExecInstr::Call { call_id, args, .. }) => ExecInstr::Call {
                            call_id,
                            copyout_index,
                            args,
                        },
                        _ => ExecInstr::Call {
                            call_id,
                            copyout_index,
                            args,
                        },
                    }
                } else {
                    ExecInstr::Call {
                        call_id,
                        copyout_index,
                        args,
                    }
                }
            }
            other => other,
        })
        .collect();
    ExecProgram { instructions }
}

pub fn exec_program_to_bytes(program: &ExecProgram) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(EXEC_MAGIC);
    write_varint(program.call_count(), &mut buf);
    for instr in &program.instructions {
        match instr {
            ExecInstr::CopyIn { addr, arg } => {
                write_varint(EXEC_INSTR_COPYIN, &mut buf);
                write_varint(*addr, &mut buf);
                write_exec_arg(arg, &mut buf);
            }
            ExecInstr::CopyOut { index, addr, size } => {
                write_varint(EXEC_INSTR_COPYOUT, &mut buf);
                write_varint(*index, &mut buf);
                write_varint(*addr, &mut buf);
                write_varint(*size, &mut buf);
            }
            ExecInstr::SetProps { value } => {
                write_varint(EXEC_INSTR_SET_PROPS, &mut buf);
                write_varint(*value, &mut buf);
            }
            ExecInstr::Call {
                call_id,
                copyout_index,
                args,
            } => {
                write_varint(*call_id, &mut buf);
                write_varint(*copyout_index, &mut buf);
                write_varint(args.len() as u64, &mut buf);
                for arg in args {
                    write_exec_arg(arg, &mut buf);
                }
            }
        }
    }
    write_varint(EXEC_INSTR_EOF, &mut buf);
    buf
}

pub fn exec_program_from_bytes(bytes: &[u8]) -> Result<ExecProgram, String> {
    if !bytes.starts_with(EXEC_MAGIC) {
        return Err("missing syz-exec magic".to_string());
    }
    let mut pos = EXEC_MAGIC.len();
    let _call_count = read_varint(bytes, &mut pos)?;
    let mut instructions = Vec::new();

    while pos < bytes.len() {
        let opcode = read_varint(bytes, &mut pos)?;
        if opcode == EXEC_INSTR_EOF {
            break;
        }

        let instr = match opcode {
            EXEC_INSTR_COPYIN => {
                let addr = read_varint(bytes, &mut pos)?;
                let arg = read_exec_arg(bytes, &mut pos)?;
                ExecInstr::CopyIn { addr, arg }
            }
            EXEC_INSTR_COPYOUT => {
                let index = read_varint(bytes, &mut pos)?;
                let addr = read_varint(bytes, &mut pos)?;
                let size = read_varint(bytes, &mut pos)?;
                ExecInstr::CopyOut { index, addr, size }
            }
            EXEC_INSTR_SET_PROPS => {
                let value = read_varint(bytes, &mut pos)?;
                ExecInstr::SetProps { value }
            }
            call_id => {
                if exec_call_desc(call_id).is_none() {
                    return Err(format!("unknown exec call id: {call_id}"));
                }
                let copyout_index = read_varint(bytes, &mut pos)?;
                let nargs = read_varint(bytes, &mut pos)? as usize;
                if nargs > EXEC_MAX_ARGS {
                    return Err(format!("exec call has too many args: {nargs}"));
                }
                let mut args = Vec::with_capacity(nargs);
                for _ in 0..nargs {
                    args.push(read_exec_arg(bytes, &mut pos)?);
                }
                ExecInstr::Call {
                    call_id,
                    copyout_index,
                    args,
                }
            }
        };
        instructions.push(instr);
    }

    Ok(ExecProgram { instructions })
}

pub fn exec_program_primary_input(program: &ExecProgram) -> Option<InputData> {
    program.instructions.iter().find_map(|instr| match instr {
        ExecInstr::Call { call_id, args, .. } => exec_call_to_input(*call_id, args),
        _ => None,
    })
}

pub fn exec_program_describe(program: &ExecProgram) -> String {
    let mut lines = vec![format!("call_count = {}", program.call_count())];
    for (index, instr) in program.instructions.iter().enumerate() {
        match instr {
            ExecInstr::CopyIn { addr, arg } => {
                lines.push(format!("[{index}] copyin addr=0x{addr:x} arg={arg:?}"));
            }
            ExecInstr::CopyOut {
                index: slot,
                addr,
                size,
            } => {
                lines.push(format!(
                    "[{index}] copyout slot={slot} addr=0x{addr:x} size={size}"
                ));
            }
            ExecInstr::SetProps { value } => {
                lines.push(format!("[{index}] setprops value=0x{value:x}"));
            }
            ExecInstr::Call {
                call_id,
                copyout_index,
                args,
            } => {
                let desc = exec_call_desc(*call_id)
                    .map(|desc| desc.name)
                    .unwrap_or("unknown");
                lines.push(format!(
                    "[{index}] call id={call_id} name={desc} copyout=0x{copyout_index:x} nargs={}",
                    args.len()
                ));
            }
        }
    }
    lines.join("\n")
}

fn exec_call_to_input(call_id: u64, args: &[ExecArg]) -> Option<InputData> {
    let desc = exec_call_desc(call_id)?;
    let mut values = [0_u64; 8];
    match desc.kind {
        ExecCallKind::RawEcall => {
            if args.len() < 8 {
                return None;
            }
            for (index, arg) in args.iter().take(8).enumerate() {
                values[index] = materialize_exec_arg(arg);
            }
        }
        ExecCallKind::Fixed { eid, fid } => {
            values[0] = eid;
            values[1] = fid;
            for (index, arg) in args.iter().take(6).enumerate() {
                values[index + 2] = materialize_exec_arg(arg);
            }
        }
    }

    Some(InputData {
        metadata: Metadata::from_call(values[0], values[1], format!("exec-{}", desc.name)),
        args: Args {
            eid: values[0],
            fid: values[1],
            arg0: values[2],
            arg1: values[3],
            arg2: values[4],
            arg3: values[5],
            arg4: values[6],
            arg5: values[7],
        },
    })
}

fn materialize_exec_arg(arg: &ExecArg) -> u64 {
    match arg {
        ExecArg::Const { value, .. } => *value,
        ExecArg::Addr32 { offset } | ExecArg::Addr64 { offset } => *offset,
        ExecArg::Result { default, .. } => *default,
        ExecArg::Data(_) => 0,
    }
}

fn write_exec_arg(arg: &ExecArg, buf: &mut Vec<u8>) {
    match arg {
        ExecArg::Const { size, value } => {
            write_varint(EXEC_ARG_CONST, buf);
            write_varint(*size, buf);
            write_varint(*value, buf);
        }
        ExecArg::Addr32 { offset } => {
            write_varint(EXEC_ARG_ADDR32, buf);
            write_varint(*offset, buf);
        }
        ExecArg::Addr64 { offset } => {
            write_varint(EXEC_ARG_ADDR64, buf);
            write_varint(*offset, buf);
        }
        ExecArg::Result {
            size,
            index,
            op_div,
            op_add,
            default,
        } => {
            write_varint(EXEC_ARG_RESULT, buf);
            write_varint(*size, buf);
            write_varint(*index, buf);
            write_varint(*op_div, buf);
            write_varint(*op_add, buf);
            write_varint(*default, buf);
        }
        ExecArg::Data(data) => {
            write_varint(EXEC_ARG_DATA, buf);
            write_varint(data.len() as u64, buf);
            buf.extend_from_slice(data);
        }
    }
}

fn read_exec_arg(bytes: &[u8], pos: &mut usize) -> Result<ExecArg, String> {
    let arg_type = read_varint(bytes, pos)?;
    match arg_type {
        EXEC_ARG_CONST => {
            let size = read_varint(bytes, pos)?;
            let value = read_varint(bytes, pos)?;
            Ok(ExecArg::Const { size, value })
        }
        EXEC_ARG_ADDR32 => {
            let offset = read_varint(bytes, pos)?;
            Ok(ExecArg::Addr32 { offset })
        }
        EXEC_ARG_ADDR64 => {
            let offset = read_varint(bytes, pos)?;
            Ok(ExecArg::Addr64 { offset })
        }
        EXEC_ARG_RESULT => {
            let size = read_varint(bytes, pos)?;
            let index = read_varint(bytes, pos)?;
            let op_div = read_varint(bytes, pos)?;
            let op_add = read_varint(bytes, pos)?;
            let default = read_varint(bytes, pos)?;
            Ok(ExecArg::Result {
                size,
                index,
                op_div,
                op_add,
                default,
            })
        }
        EXEC_ARG_DATA => {
            let size = read_varint(bytes, pos)? as usize;
            if bytes.len().saturating_sub(*pos) < size {
                return Err("exec data arg overflow".to_string());
            }
            let data = bytes[*pos..*pos + size].to_vec();
            *pos += size;
            Ok(ExecArg::Data(data))
        }
        other => Err(format!("unknown exec arg type: {other}")),
    }
}

fn write_varint(value: u64, buf: &mut Vec<u8>) {
    let mut encoded = if (value as i64) < 0 {
        (!(value) << 1) | 1
    } else {
        value << 1
    };
    while encoded >= 0x80 {
        buf.push((encoded as u8) | 0x80);
        encoded >>= 7;
    }
    buf.push(encoded as u8);
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for _ in 0..10 {
        let Some(&byte) = bytes.get(*pos) else {
            return Err("unexpected end of exec input".to_string());
        };
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(if value & 1 == 1 {
                !(value >> 1)
            } else {
                value >> 1
            });
        }
        shift += 7;
    }
    Err("exec varint overflow".to_string())
}
