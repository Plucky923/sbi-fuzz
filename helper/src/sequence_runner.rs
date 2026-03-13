use common::{
    HostCall, HostHarnessInput, HostHarnessMode, HostHartState, HostMemoryRegion,
    HostPlatformFaultMode, HostPlatformFaultProfile, HostPrivilegeState, HostTargetKind,
    SequenceArg, SequenceFdtExpectation, SequenceMemoryObject, SequenceProgram, SequenceStep,
    sequence_memory_guest_addr, sequence_program_describe, sequence_program_from_bytes,
    sequence_program_from_exec, sequence_program_from_toml_input,
    sequence_program_semantic_signature, sequence_program_to_bytes,
};
use host_harness::{self, FdtSeedVariant, HostHarnessReport, HostHarnessResult};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct SequenceStepReport {
    pub index: usize,
    pub kind: String,
    pub label: String,
    pub classification: String,
    pub signature: String,
    pub expectation_ok: bool,
    pub interesting: bool,
    pub supported_by_target: Option<bool>,
    pub sbi_error: Option<i64>,
    pub value: Option<u64>,
    pub extension_found: Option<bool>,
    pub fdt_status: Option<i32>,
    pub fdt_hart_count: Option<u32>,
    pub state_signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceRunReport {
    pub impl_kind: HostTargetKind,
    pub input: String,
    pub name: String,
    pub classification: String,
    pub signature: String,
    pub interesting: bool,
    pub supported_by_target: bool,
    pub step_count: usize,
    pub state_signature: String,
    pub memory_signature: String,
    pub semantic_signature: String,
    pub steps: Vec<SequenceStepReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceMismatch {
    pub index: usize,
    pub label: String,
    pub kind: String,
    pub reason: String,
    pub opensbi_signature: String,
    pub rustsbi_signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceDiffReport {
    pub input: String,
    pub name: String,
    pub classification: String,
    pub signature: String,
    pub interesting: bool,
    pub compared_steps: usize,
    pub mismatches: Vec<SequenceMismatch>,
    pub opensbi: SequenceRunReport,
    pub rustsbi: SequenceRunReport,
}

#[derive(Debug, Clone)]
struct SequenceExecutionState {
    active_hart: u64,
    privilege: HostPrivilegeState,
    platform_fault: HostPlatformFaultProfile,
    hart_states: BTreeMap<u64, HostHartState>,
    call_results: Vec<u64>,
}

impl SequenceExecutionState {
    fn new(program: &SequenceProgram) -> Self {
        let mut hart_states = BTreeMap::new();
        for hart_id in 0..program.env.smp {
            hart_states.insert(u64::from(hart_id), HostHartState::Started);
        }
        Self {
            active_hart: 0,
            privilege: HostPrivilegeState::Supervisor,
            platform_fault: HostPlatformFaultProfile::none(),
            hart_states,
            call_results: Vec::new(),
        }
    }

    fn hart_state(&self, hart_id: u64) -> HostHartState {
        self.hart_states
            .get(&hart_id)
            .copied()
            .unwrap_or(HostHartState::Unknown)
    }

    fn state_signature(&self) -> String {
        let harts = self
            .hart_states
            .iter()
            .map(|(hart_id, state)| format!("{hart_id}:{state:?}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "active_hart={};privilege={:?};fault={:?};harts=[{}]",
            self.active_hart, self.privilege, self.platform_fault.mode, harts
        )
    }
}

pub fn generate_sequence_seeds(
    output: PathBuf,
    include_opensbi: bool,
    include_rustsbi: bool,
) -> Result<(), String> {
    fs::create_dir_all(&output).map_err(|err| err.to_string())?;
    let mut generated = 0_u64;

    if include_opensbi || include_rustsbi {
        for program in shared_sequences() {
            write_sequence_seed(&output, &program)?;
            generated += 1;
        }
    }
    if include_opensbi {
        for program in opensbi_sequences()? {
            write_sequence_seed(&output, &program)?;
            generated += 1;
        }
    }
    if include_rustsbi {
        for program in rustsbi_sequences()? {
            write_sequence_seed(&output, &program)?;
            generated += 1;
        }
    }

    println!(
        "Generated {} sequence seeds in {}",
        generated,
        output.display()
    );
    Ok(())
}

pub fn encode_sequence(input: PathBuf, output: Option<PathBuf>) -> Result<(), String> {
    let program = load_sequence_from_json(&input)?;
    let output_path = output.unwrap_or_else(|| {
        PathBuf::from(format!(
            "{}.seq",
            if program.metadata.name.trim().is_empty() {
                program.hash_string()
            } else {
                slugify(&program.metadata.name)
            }
        ))
    });
    fs::write(&output_path, sequence_program_to_bytes(&program)).map_err(|err| err.to_string())?;
    println!("Wrote {}", output_path.display());
    Ok(())
}

pub fn import_exec_as_sequence(input: PathBuf, output: Option<PathBuf>) -> Result<(), String> {
    let raw = fs::read(&input).map_err(|err| err.to_string())?;
    let program = if raw.starts_with(common::EXEC_MAGIC) {
        sequence_program_from_exec(&common::exec_program_from_bytes(&raw)?)?
    } else if input.extension().and_then(|ext| ext.to_str()) == Some("toml") {
        let text = String::from_utf8(raw).map_err(|err| err.to_string())?;
        let input = common::fix_input_args(common::input_from_toml(&text));
        sequence_program_from_toml_input(&input)
    } else {
        return Err(format!(
            "unsupported import source {}; expected .exec or .toml",
            input.display()
        ));
    };
    let output_path =
        output.unwrap_or_else(|| PathBuf::from(format!("{}.seq", program.hash_string())));
    fs::write(&output_path, sequence_program_to_bytes(&program)).map_err(|err| err.to_string())?;
    println!("Wrote {}", output_path.display());
    Ok(())
}

pub fn describe_sequence(input: PathBuf) -> Result<(), String> {
    let program = load_sequence_program(&input)?;
    println!("{}", sequence_program_describe(&program));
    Ok(())
}

pub fn run_sequence(
    input: PathBuf,
    impl_kind: HostTargetKind,
    json_out: Option<PathBuf>,
) -> Result<(), String> {
    let program = load_sequence_program(&input)?;
    let report = run_sequence_program(&program, impl_kind, input.display().to_string())?;
    emit_json(&report, json_out)
}

pub fn diff_sequence(input: PathBuf, json_out: Option<PathBuf>) -> Result<(), String> {
    let program = load_sequence_program(&input)?;
    let input_label = input.display().to_string();
    let opensbi = run_sequence_program(&program, HostTargetKind::OpenSbi, input_label.clone())?;
    let rustsbi = run_sequence_program(&program, HostTargetKind::RustSbi, input_label.clone())?;
    let report =
        diff_sequence_reports(input_label, program.metadata.name.clone(), opensbi, rustsbi);
    emit_json(&report, json_out)
}

pub fn run_sequence_program(
    program: &SequenceProgram,
    impl_kind: HostTargetKind,
    input_label: String,
) -> Result<SequenceRunReport, String> {
    let mut state = SequenceExecutionState::new(program);
    let memory_map = memory_map(program);
    let mut steps = Vec::new();

    for (index, step) in program.steps.iter().enumerate() {
        let report = match step {
            SequenceStep::SetTargetHart { hart_id } => {
                state.active_hart = *hart_id;
                state_only_step(index, "set_target_hart", format!("hart-{hart_id}"), &state)
            }
            SequenceStep::SetHartState {
                hart_id,
                state: hart_state,
            } => {
                state.hart_states.insert(*hart_id, *hart_state);
                state_only_step(
                    index,
                    "set_hart_state",
                    format!("hart-{hart_id}-{hart_state:?}"),
                    &state,
                )
            }
            SequenceStep::SetPrivilege { privilege } => {
                state.privilege = *privilege;
                state_only_step(index, "set_privilege", format!("{privilege:?}"), &state)
            }
            SequenceStep::SetPlatformFault { profile } => {
                state.platform_fault = *profile;
                state_only_step(
                    index,
                    "set_platform_fault",
                    format!("{:?}", profile.mode),
                    &state,
                )
            }
            SequenceStep::BusyWait { iterations } => {
                state_only_step(index, "busy_wait", format!("{iterations}"), &state)
            }
            SequenceStep::Call {
                label,
                eid,
                fid,
                args,
                expect,
            } => {
                let values = args
                    .iter()
                    .map(|arg| materialize_arg(arg, &memory_map, &state))
                    .collect::<Result<Vec<_>, _>>()?;
                let input = HostHarnessInput {
                    target_kind: impl_kind,
                    mode: if state.platform_fault.mode == HostPlatformFaultMode::None {
                        HostHarnessMode::Ecall
                    } else {
                        HostHarnessMode::PlatformFault
                    },
                    call: HostCall::new(
                        *eid,
                        *fid,
                        [
                            values[0], values[1], values[2], values[3], values[4], values[5],
                        ],
                    ),
                    hart_id: state.active_hart,
                    hart_state: state.hart_state(state.active_hart),
                    privilege: state.privilege,
                    memory_regions: memory_regions(program),
                    platform_fault: state.platform_fault,
                    fdt_blob: Vec::new(),
                    label: if label.trim().is_empty() {
                        format!("call-{index}")
                    } else {
                        label.clone()
                    },
                };
                let host_report = host_harness::run(&input)?;
                let report = call_step_report(index, label, &host_report, expect, &state);
                update_call_state(&mut state, *eid, *fid, &values, &host_report);
                steps.push(report.clone());
                continue;
            }
            SequenceStep::ParseFdt {
                label,
                object,
                expect,
            } => {
                let memory = memory_map
                    .get(object)
                    .ok_or_else(|| format!("unknown memory object {object}"))?;
                let input = HostHarnessInput {
                    target_kind: impl_kind,
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
                let host_report = host_harness::run(&input)?;
                let report = fdt_step_report(index, label, &host_report, expect, &state);
                steps.push(report.clone());
                continue;
            }
        };
        steps.push(report);
    }

    let interesting = steps.iter().any(|step| step.interesting);
    let supported_by_target = steps
        .iter()
        .filter_map(|step| step.supported_by_target)
        .all(|supported| supported);
    let classification = if steps
        .iter()
        .any(|step| step.classification == "expectation_failed")
    {
        "expectation_failed".to_string()
    } else if interesting {
        "interesting".to_string()
    } else {
        "ok".to_string()
    };
    let state_signature = state.state_signature();
    let memory_signature = build_memory_signature(program);

    Ok(SequenceRunReport {
        impl_kind,
        input: input_label,
        name: if program.metadata.name.trim().is_empty() {
            program.hash_string()
        } else {
            program.metadata.name.clone()
        },
        classification: classification.clone(),
        signature: format!(
            "{}|{}|{}",
            impl_name(impl_kind),
            classification,
            sequence_program_semantic_signature(program)
        ),
        interesting,
        supported_by_target,
        step_count: steps.len(),
        state_signature,
        memory_signature,
        semantic_signature: sequence_program_semantic_signature(program),
        steps,
    })
}

fn load_sequence_program(path: &PathBuf) -> Result<SequenceProgram, String> {
    let raw = fs::read(path).map_err(|err| err.to_string())?;
    if raw.starts_with(common::SEQUENCE_MAGIC) {
        return sequence_program_from_bytes(&raw);
    }
    let text = String::from_utf8(raw).map_err(|err| err.to_string())?;
    let program: SequenceProgram =
        serde_json::from_str(&text).map_err(|err| format!("parse sequence JSON: {err}"))?;
    common::validate_sequence_program(&program)?;
    Ok(program)
}

fn load_sequence_from_json(path: &PathBuf) -> Result<SequenceProgram, String> {
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let program: SequenceProgram =
        serde_json::from_str(&text).map_err(|err| format!("parse sequence JSON: {err}"))?;
    common::validate_sequence_program(&program)?;
    Ok(program)
}

fn emit_json<T: Serialize>(value: &T, json_out: Option<PathBuf>) -> Result<(), String> {
    let encoded = serde_json::to_string_pretty(value).map_err(|err| err.to_string())?;
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{encoded}\n")).map_err(|err| err.to_string())?;
    }
    println!("{encoded}");
    Ok(())
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

fn memory_map(program: &SequenceProgram) -> BTreeMap<String, &SequenceMemoryObject> {
    program
        .memory
        .iter()
        .map(|memory| (memory.id.clone(), memory))
        .collect()
}

fn memory_regions(program: &SequenceProgram) -> Vec<HostMemoryRegion> {
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

fn state_only_step(
    index: usize,
    kind: &str,
    label: String,
    state: &SequenceExecutionState,
) -> SequenceStepReport {
    SequenceStepReport {
        index,
        kind: kind.to_string(),
        label,
        classification: "ok".to_string(),
        signature: state.state_signature(),
        expectation_ok: true,
        interesting: false,
        supported_by_target: None,
        sbi_error: None,
        value: None,
        extension_found: None,
        fdt_status: None,
        fdt_hart_count: None,
        state_signature: state.state_signature(),
    }
}

fn call_step_report(
    index: usize,
    label: &str,
    host_report: &HostHarnessReport,
    expect: &Option<common::SequenceCallExpectation>,
    state: &SequenceExecutionState,
) -> SequenceStepReport {
    let (sbi_error, value, extension_found, mut classification, mut signature, supported) =
        match &host_report.result {
            HostHarnessResult::Ecall(report) => (
                Some(report.sbi_error),
                Some(report.value),
                Some(report.extension_found),
                host_report.classification.clone(),
                host_report.signature.clone(),
                Some(report.extension_found),
            ),
            HostHarnessResult::Fdt(_) => (
                None,
                None,
                None,
                "unexpected_result_kind".to_string(),
                host_report.signature.clone(),
                None,
            ),
        };

    let expectation_ok = expect.as_ref().map_or(true, |expect| {
        expect
            .sbi_error
            .map(|wanted| Some(wanted) == sbi_error)
            .unwrap_or(true)
            && expect
                .value
                .map(|wanted| Some(wanted) == value)
                .unwrap_or(true)
            && expect
                .extension_found
                .map(|wanted| Some(wanted) == extension_found)
                .unwrap_or(true)
            && expect
                .classification
                .as_ref()
                .map(|wanted| wanted == &classification)
                .unwrap_or(true)
    });
    if !expectation_ok {
        classification = "expectation_failed".to_string();
        signature = format!("{}|expectation_failed", signature);
    }

    SequenceStepReport {
        index,
        kind: "call".to_string(),
        label: if label.trim().is_empty() {
            format!("call-{index}")
        } else {
            label.to_string()
        },
        classification: classification.clone(),
        signature,
        expectation_ok,
        interesting: classification != "ok",
        supported_by_target: supported,
        sbi_error,
        value,
        extension_found,
        fdt_status: None,
        fdt_hart_count: None,
        state_signature: state.state_signature(),
    }
}

fn fdt_step_report(
    index: usize,
    label: &str,
    host_report: &HostHarnessReport,
    expect: &Option<SequenceFdtExpectation>,
    state: &SequenceExecutionState,
) -> SequenceStepReport {
    let (status, hart_count, mut classification, mut signature) = match &host_report.result {
        HostHarnessResult::Fdt(report) => (
            Some(report.status),
            Some(report.hart_count),
            host_report.classification.clone(),
            host_report.signature.clone(),
        ),
        HostHarnessResult::Ecall(_) => (
            None,
            None,
            "unexpected_result_kind".to_string(),
            host_report.signature.clone(),
        ),
    };
    let expectation_ok = expect.as_ref().map_or(true, |expect| {
        expect
            .status
            .map(|wanted| Some(wanted) == status)
            .unwrap_or(true)
            && expect
                .hart_count
                .map(|wanted| Some(wanted) == hart_count)
                .unwrap_or(true)
            && expect
                .classification
                .as_ref()
                .map(|wanted| wanted == &classification)
                .unwrap_or(true)
    });
    if !expectation_ok {
        classification = "expectation_failed".to_string();
        signature = format!("{}|expectation_failed", signature);
    }

    SequenceStepReport {
        index,
        kind: "parse_fdt".to_string(),
        label: if label.trim().is_empty() {
            format!("fdt-{index}")
        } else {
            label.to_string()
        },
        classification: classification.clone(),
        signature,
        expectation_ok,
        interesting: classification != "ok",
        supported_by_target: Some(classification != "fdt_error"),
        sbi_error: None,
        value: None,
        extension_found: None,
        fdt_status: status,
        fdt_hart_count: hart_count,
        state_signature: state.state_signature(),
    }
}

fn update_call_state(
    state: &mut SequenceExecutionState,
    eid: u64,
    fid: u64,
    args: &[u64],
    host_report: &HostHarnessReport,
) {
    let HostHarnessResult::Ecall(report) = &host_report.result else {
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
                    state
                        .hart_states
                        .insert(*target_hart, HostHartState::Started);
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

fn build_memory_signature(program: &SequenceProgram) -> String {
    program
        .memory
        .iter()
        .map(|memory| {
            format!(
                "{}@0x{:x}:{}{}{}:{}:{}",
                memory.id,
                sequence_memory_guest_addr(memory),
                if memory.read { "r" } else { "-" },
                if memory.write { "w" } else { "-" },
                if memory.execute { "x" } else { "-" },
                memory.bytes.len(),
                short_hash(&memory.bytes)
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn diff_sequence_reports(
    input: String,
    name: String,
    opensbi: SequenceRunReport,
    rustsbi: SequenceRunReport,
) -> SequenceDiffReport {
    let mut compared_steps = 0_usize;
    let mut mismatches = Vec::new();
    for (left, right) in opensbi.steps.iter().zip(rustsbi.steps.iter()) {
        if left.kind != right.kind {
            mismatches.push(SequenceMismatch {
                index: left.index,
                label: left.label.clone(),
                kind: "step_kind".to_string(),
                reason: format!("{} != {}", left.kind, right.kind),
                opensbi_signature: left.signature.clone(),
                rustsbi_signature: right.signature.clone(),
            });
            continue;
        }
        if left.kind == "call" || left.kind == "parse_fdt" {
            if left.supported_by_target != Some(true) || right.supported_by_target != Some(true) {
                if left.supported_by_target != right.supported_by_target {
                    mismatches.push(SequenceMismatch {
                        index: left.index,
                        label: left.label.clone(),
                        kind: "capability_mismatch".to_string(),
                        reason: format!(
                            "supported {:?} vs {:?}",
                            left.supported_by_target, right.supported_by_target
                        ),
                        opensbi_signature: left.signature.clone(),
                        rustsbi_signature: right.signature.clone(),
                    });
                }
                continue;
            }
            compared_steps += 1;
            let same = left.sbi_error == right.sbi_error
                && left.value == right.value
                && left.extension_found == right.extension_found
                && left.fdt_status == right.fdt_status
                && left.fdt_hart_count == right.fdt_hart_count;
            if !same {
                mismatches.push(SequenceMismatch {
                    index: left.index,
                    label: left.label.clone(),
                    kind: "divergence".to_string(),
                    reason: "observable results differ".to_string(),
                    opensbi_signature: left.signature.clone(),
                    rustsbi_signature: right.signature.clone(),
                });
            }
        }
    }

    let classification = if mismatches.is_empty() {
        "match".to_string()
    } else if mismatches
        .iter()
        .all(|item| item.kind == "capability_mismatch")
    {
        "capability_mismatch".to_string()
    } else {
        "divergence".to_string()
    };
    SequenceDiffReport {
        input,
        name,
        classification: classification.clone(),
        signature: format!(
            "{}|compared_steps={}|mismatches={}",
            classification,
            compared_steps,
            mismatches.len()
        ),
        interesting: classification != "match",
        compared_steps,
        mismatches,
        opensbi,
        rustsbi,
    }
}

fn write_sequence_seed(output: &PathBuf, program: &SequenceProgram) -> Result<(), String> {
    let name = if program.metadata.name.trim().is_empty() {
        program.hash_string()
    } else {
        slugify(&program.metadata.name)
    };
    let bin_path = output.join(format!("{name}.seq"));
    let json_path = output.join(format!("{name}.json"));
    fs::write(&bin_path, sequence_program_to_bytes(program)).map_err(|err| err.to_string())?;
    fs::write(
        &json_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(program).map_err(|err| err.to_string())?
        ),
    )
    .map_err(|err| err.to_string())?;
    Ok(())
}

fn shared_sequences() -> Vec<SequenceProgram> {
    vec![
        SequenceProgram {
            metadata: common::SequenceMetadata {
                name: "shared-base-hsm-status".to_string(),
                source: "generated".to_string(),
                note: "Probe HSM and query hart0 status across both implementations.".to_string(),
            },
            env: common::SequenceEnv::default(),
            memory: Vec::new(),
            steps: vec![
                SequenceStep::Call {
                    label: "base-get-spec-version".to_string(),
                    eid: 0x10,
                    fid: 0,
                    args: zero_args(),
                    expect: Some(common::SequenceCallExpectation {
                        sbi_error: Some(0),
                        value: None,
                        extension_found: Some(true),
                        classification: Some("ok".to_string()),
                    }),
                },
                SequenceStep::Call {
                    label: "base-probe-hsm".to_string(),
                    eid: 0x10,
                    fid: 3,
                    args: vec![
                        SequenceArg::Const { value: 0x4853_4d },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                    ],
                    expect: Some(common::SequenceCallExpectation {
                        sbi_error: Some(0),
                        value: None,
                        extension_found: Some(true),
                        classification: Some("ok".to_string()),
                    }),
                },
                SequenceStep::Call {
                    label: "hsm-hart-status".to_string(),
                    eid: 0x4853_4d,
                    fid: 2,
                    args: vec![
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                        SequenceArg::Const { value: 0 },
                    ],
                    expect: Some(common::SequenceCallExpectation {
                        sbi_error: Some(0),
                        value: Some(0),
                        extension_found: Some(true),
                        classification: Some("ok".to_string()),
                    }),
                },
            ],
        },
        SequenceProgram {
            metadata: common::SequenceMetadata {
                name: "shared-console-write-buffer".to_string(),
                source: "generated".to_string(),
                note: "Use an explicit shared buffer so address-sensitive extensions get memory-aware arguments.".to_string(),
            },
            env: common::SequenceEnv::default(),
            memory: vec![SequenceMemoryObject {
                id: "console_buf".to_string(),
                slot_offset: 0x40,
                guest_addr: Some(0x8000_2040),
                read: true,
                write: true,
                execute: false,
                bytes: b"ping".to_vec(),
            }],
            steps: vec![SequenceStep::Call {
                label: "console-write".to_string(),
                eid: 0x4442_434e,
                fid: 0,
                args: vec![
                    SequenceArg::MemoryLen {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::MemoryAddrLow {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::MemoryAddrHigh {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                ],
                expect: Some(common::SequenceCallExpectation {
                    sbi_error: Some(0),
                    value: None,
                    extension_found: Some(true),
                    classification: Some("ok".to_string()),
                }),
            }],
        },
    ]
}

fn opensbi_sequences() -> Result<Vec<SequenceProgram>, String> {
    Ok(vec![SequenceProgram {
        metadata: common::SequenceMetadata {
            name: "opensbi-minimal-fdt".to_string(),
            source: "generated".to_string(),
            note: "Parse a minimal OpenSBI device tree blob.".to_string(),
        },
        env: common::SequenceEnv {
            smp: 1,
            impl_hint: Some(HostTargetKind::OpenSbi),
            platform: "virt".to_string(),
        },
        memory: vec![SequenceMemoryObject {
            id: "fdt".to_string(),
            slot_offset: 0x100,
            guest_addr: None,
            read: true,
            write: false,
            execute: false,
            bytes: host_harness::seed_fdt_blob(HostTargetKind::OpenSbi, FdtSeedVariant::Minimal)?,
        }],
        steps: vec![SequenceStep::ParseFdt {
            label: "opensbi-fdt".to_string(),
            object: "fdt".to_string(),
            expect: Some(SequenceFdtExpectation {
                status: Some(0),
                hart_count: Some(1),
                classification: Some("ok".to_string()),
            }),
        }],
    }])
}

fn rustsbi_sequences() -> Result<Vec<SequenceProgram>, String> {
    Ok(vec![SequenceProgram {
        metadata: common::SequenceMetadata {
            name: "rustsbi-minimal-fdt".to_string(),
            source: "generated".to_string(),
            note: "Parse a minimal RustSBI device tree blob.".to_string(),
        },
        env: common::SequenceEnv {
            smp: 1,
            impl_hint: Some(HostTargetKind::RustSbi),
            platform: "virt".to_string(),
        },
        memory: vec![SequenceMemoryObject {
            id: "fdt".to_string(),
            slot_offset: 0x100,
            guest_addr: None,
            read: true,
            write: false,
            execute: false,
            bytes: host_harness::seed_fdt_blob(HostTargetKind::RustSbi, FdtSeedVariant::Minimal)?,
        }],
        steps: vec![SequenceStep::ParseFdt {
            label: "rustsbi-fdt".to_string(),
            object: "fdt".to_string(),
            expect: Some(SequenceFdtExpectation {
                status: Some(0),
                hart_count: Some(1),
                classification: Some("ok".to_string()),
            }),
        }],
    }])
}

fn zero_args() -> Vec<SequenceArg> {
    vec![
        SequenceArg::Const { value: 0 },
        SequenceArg::Const { value: 0 },
        SequenceArg::Const { value: 0 },
        SequenceArg::Const { value: 0 },
        SequenceArg::Const { value: 0 },
        SequenceArg::Const { value: 0 },
    ]
}

fn slugify(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn short_hash(bytes: &[u8]) -> String {
    let mut hash = 0x811c_9dc5_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

fn impl_name(kind: HostTargetKind) -> &'static str {
    match kind {
        HostTargetKind::OpenSbi => "opensbi",
        HostTargetKind::RustSbi => "rustsbi",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_sequence_runs_on_both_backends() {
        let program = shared_sequences()
            .into_iter()
            .next()
            .expect("shared sequence");
        let opensbi = run_sequence_program(&program, HostTargetKind::OpenSbi, "mem".to_string())
            .expect("run opensbi sequence");
        let rustsbi = run_sequence_program(&program, HostTargetKind::RustSbi, "mem".to_string())
            .expect("run rustsbi sequence");
        assert_eq!(opensbi.classification, "ok");
        assert_eq!(rustsbi.classification, "ok");
    }

    #[test]
    fn diff_report_detects_matches_for_shared_sequence() {
        let step = SequenceStepReport {
            index: 0,
            kind: "call".to_string(),
            label: "base-get-spec-version".to_string(),
            classification: "ok".to_string(),
            signature: "sig".to_string(),
            expectation_ok: true,
            interesting: false,
            supported_by_target: Some(true),
            sbi_error: Some(0),
            value: Some(2),
            extension_found: Some(true),
            fdt_status: None,
            fdt_hart_count: None,
            state_signature: "state".to_string(),
        };
        let opensbi = SequenceRunReport {
            impl_kind: HostTargetKind::OpenSbi,
            input: "seq".to_string(),
            name: "shared".to_string(),
            classification: "ok".to_string(),
            signature: "sig".to_string(),
            interesting: false,
            supported_by_target: true,
            step_count: 1,
            state_signature: "state".to_string(),
            memory_signature: "mem".to_string(),
            semantic_signature: "semantic".to_string(),
            steps: vec![step.clone()],
        };
        let rustsbi = SequenceRunReport {
            impl_kind: HostTargetKind::RustSbi,
            input: "seq".to_string(),
            name: "shared".to_string(),
            classification: "ok".to_string(),
            signature: "sig".to_string(),
            interesting: false,
            supported_by_target: true,
            step_count: 1,
            state_signature: "state".to_string(),
            memory_signature: "mem".to_string(),
            semantic_signature: "semantic".to_string(),
            steps: vec![step],
        };
        let diff = diff_sequence_reports("seq".to_string(), "shared".to_string(), opensbi, rustsbi);
        assert_eq!(diff.classification, "match");
    }
}
