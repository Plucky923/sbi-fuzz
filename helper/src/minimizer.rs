use common::{
    EXEC_MAGIC, EXEC_NO_COPYOUT, EXEC_PROP_BUSY_WAIT, EXEC_PROP_TARGET_HART, ExecArg, ExecCallKind,
    ExecInstr, ExecProgram, decode_exec_prop, exec_call_desc, exec_call_id_for,
    exec_program_from_bytes, exec_program_from_input, exec_program_to_bytes, fix_input_args,
    format_exec_prop, input_from_binary, input_from_toml, validate_exec_program,
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::Builder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MinimizeStats {
    pub tested_candidates: u64,
    pub accepted_candidates: u64,
    pub passes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinimizeProgramResult {
    pub program: ExecProgram,
    pub stats: MinimizeStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct MinimizeHangReport {
    pub status: String,
    pub input: String,
    pub output: String,
    pub timeout_ms: u64,
    pub attempts: u32,
    pub smp: u16,
    pub original_instruction_count: usize,
    pub minimized_instruction_count: usize,
    pub original_call_count: u64,
    pub minimized_call_count: u64,
    pub original_size: usize,
    pub minimized_size: usize,
    pub tested_candidates: u64,
    pub accepted_candidates: u64,
    pub passes: u64,
    pub semantic_signature: String,
    pub semantic_steps: Vec<String>,
    pub semantic_harts: Vec<u64>,
    pub semantic_calls: Vec<String>,
    pub original_semantic_signature: String,
    pub original_attempt_actuals: Vec<String>,
    pub final_attempt_actuals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecSemanticProfile {
    signature: String,
    steps: Vec<String>,
    harts: Vec<u64>,
    calls: Vec<String>,
}

pub fn minimize_hang(
    target: PathBuf,
    injector: PathBuf,
    input: PathBuf,
    output: PathBuf,
    smp: u16,
    timeout_ms: u64,
    attempts: u32,
    json_out: Option<PathBuf>,
) -> Result<(), String> {
    if timeout_ms == 0 {
        return Err("minimize-hang requires --timeout-ms > 0".to_string());
    }
    if attempts == 0 {
        return Err("minimize-hang requires --attempts > 0".to_string());
    }

    let helper = std::env::current_exe().map_err(|err| err.to_string())?;
    let original_program = load_exec_program(&input)?;
    let original_size = exec_program_to_bytes(&original_program).len();
    let original_attempt_actuals = replay_exit_kinds(
        &helper, &target, &injector, &input, smp, timeout_ms, attempts,
    )?;
    if !all_timeouts(&original_attempt_actuals) {
        return Err(format!(
            "input {} is not a stable hang within {} attempts: {:?}",
            input.display(),
            attempts,
            original_attempt_actuals
        ));
    }

    let mut stable_timeout = |program: &ExecProgram| -> bool {
        let Ok(temp) = Builder::new().suffix(".exec").tempfile() else {
            return false;
        };
        if fs::write(temp.path(), exec_program_to_bytes(program)).is_err() {
            return false;
        }
        replay_exit_kinds(
            &helper,
            &target,
            &injector,
            temp.path(),
            smp,
            timeout_ms,
            attempts,
        )
        .map(|actuals| all_timeouts(&actuals))
        .unwrap_or(false)
    };
    let minimized = minimize_exec_program(original_program.clone(), &mut stable_timeout);
    let original_profile = build_exec_semantic_profile(&original_program);
    let minimized_profile = build_exec_semantic_profile(&minimized.program);

    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let minimized_bytes = exec_program_to_bytes(&minimized.program);
    fs::write(&output, &minimized_bytes).map_err(|err| err.to_string())?;

    let final_attempt_actuals = replay_exit_kinds(
        &helper, &target, &injector, &output, smp, timeout_ms, attempts,
    )?;
    if !all_timeouts(&final_attempt_actuals) {
        return Err(format!(
            "minimized output {} is no longer a stable hang: {:?}",
            output.display(),
            final_attempt_actuals
        ));
    }

    let report = MinimizeHangReport {
        status: if minimized.program == original_program {
            "kept".to_string()
        } else {
            "minimized".to_string()
        },
        input: input.display().to_string(),
        output: output.display().to_string(),
        timeout_ms,
        attempts,
        smp,
        original_instruction_count: original_program.instructions.len(),
        minimized_instruction_count: minimized.program.instructions.len(),
        original_call_count: original_program.call_count(),
        minimized_call_count: minimized.program.call_count(),
        original_size,
        minimized_size: minimized_bytes.len(),
        tested_candidates: minimized.stats.tested_candidates,
        accepted_candidates: minimized.stats.accepted_candidates,
        passes: minimized.stats.passes,
        semantic_signature: minimized_profile.signature,
        semantic_steps: minimized_profile.steps,
        semantic_harts: minimized_profile.harts,
        semantic_calls: minimized_profile.calls,
        original_semantic_signature: original_profile.signature,
        original_attempt_actuals,
        final_attempt_actuals,
    };
    let encoded =
        serde_json::to_string_pretty(&report).map_err(|err| format!("serialize report: {err}"))?;
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{encoded}\n")).map_err(|err| err.to_string())?;
    }
    println!("{encoded}");
    Ok(())
}

fn load_exec_program(path: &Path) -> Result<ExecProgram, String> {
    if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
        let input = fs::read_to_string(path).map_err(|err| err.to_string())?;
        let data = fix_input_args(input_from_toml(&input));
        return Ok(exec_program_from_input(&data));
    }

    let bytes = fs::read(path).map_err(|err| err.to_string())?;
    if bytes.starts_with(EXEC_MAGIC) {
        return exec_program_from_bytes(&bytes);
    }

    let input = fix_input_args(input_from_binary(&bytes));
    Ok(exec_program_from_input(&input))
}

fn replay_exit_kinds(
    helper: &Path,
    target: &Path,
    injector: &Path,
    input: &Path,
    smp: u16,
    timeout_ms: u64,
    attempts: u32,
) -> Result<Vec<String>, String> {
    let mut actuals = Vec::with_capacity(attempts as usize);
    for _ in 0..attempts {
        actuals.push(run_helper(
            helper, target, injector, input, smp, timeout_ms,
        )?);
    }
    Ok(actuals)
}

fn run_helper(
    helper: &Path,
    target: &Path,
    injector: &Path,
    input: &Path,
    smp: u16,
    timeout_ms: u64,
) -> Result<String, String> {
    let output = Command::new(helper)
        .arg("run")
        .arg(target)
        .arg(injector)
        .arg(input)
        .arg("--smp")
        .arg(smp.to_string())
        .arg("--timeout-ms")
        .arg(timeout_ms.to_string())
        .output()
        .map_err(|err| format!("run helper for {} failed: {}", input.display(), err))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_exit_kind(&stdout)
        .or_else(|| parse_exit_kind(&stderr))
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "unable to parse exit kind for {} (status={}): stdout={:?} stderr={:?}",
                input.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            )
        })
}

fn parse_exit_kind(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        line.trim()
            .strip_prefix("Run finish. Exit kind: ")
            .map(str::trim)
    })
}

fn all_timeouts(actuals: &[String]) -> bool {
    actuals.iter().all(|actual| actual == "Timeout")
}

fn build_exec_semantic_profile(program: &ExecProgram) -> ExecSemanticProfile {
    let mut steps = Vec::new();
    let mut calls = Vec::new();
    let mut seen_harts = BTreeSet::new();
    let mut current_hart = 0_u64;
    let mut current_busy_wait = 0_u64;
    seen_harts.insert(current_hart);

    for instr in &program.instructions {
        match instr {
            ExecInstr::CopyIn { addr, arg } => {
                steps.push(format!("copyin@0x{addr:x}:{}", semantic_arg_brief(arg)));
            }
            ExecInstr::CopyOut { index, size, .. } => {
                steps.push(format!("copyout#{index}:{size}"));
            }
            ExecInstr::SetProps { value } => {
                let (kind, payload) = decode_exec_prop(*value);
                match kind {
                    EXEC_PROP_TARGET_HART => {
                        current_hart = payload;
                        seen_harts.insert(payload);
                        steps.push(format!("hart={payload}"));
                    }
                    EXEC_PROP_BUSY_WAIT => {
                        current_busy_wait = payload;
                        steps.push(format!("busy_wait={payload}"));
                    }
                    _ => steps.push(format!("prop:{}", format_exec_prop(*value))),
                }
            }
            ExecInstr::Call {
                call_id,
                copyout_index,
                args,
            } => {
                let mut call = format!("hart{current_hart}:{}", semantic_call_name(*call_id, args));
                if current_busy_wait > 0 {
                    call.push_str(&format!("@wait{current_busy_wait}"));
                }
                if *copyout_index != EXEC_NO_COPYOUT {
                    call.push_str(&format!("->r{copyout_index}"));
                }
                calls.push(call.clone());
                steps.push(call);
            }
        }
    }

    let signature = if steps.is_empty() {
        "empty".to_string()
    } else {
        steps.join("|")
    };
    ExecSemanticProfile {
        signature,
        steps,
        harts: seen_harts.into_iter().collect(),
        calls,
    }
}

fn semantic_arg_brief(arg: &ExecArg) -> String {
    match arg {
        ExecArg::Const { size, value } => format!("const{size}=0x{value:x}"),
        ExecArg::Addr32 { offset } => format!("addr32+0x{offset:x}"),
        ExecArg::Addr64 { offset } => format!("addr64+0x{offset:x}"),
        ExecArg::Result {
            index,
            op_div,
            op_add,
            default,
            ..
        } => {
            format!("result#{index}/{}+{}?0x{default:x}", op_div, op_add)
        }
        ExecArg::Data(data) => format!("data{}", data.len()),
    }
}

fn semantic_call_name(call_id: u64, args: &[ExecArg]) -> String {
    let Some(desc) = exec_call_desc(call_id) else {
        return format!("unknown_call({call_id})");
    };
    match desc.kind {
        ExecCallKind::Fixed { .. } => desc.name.to_string(),
        ExecCallKind::RawEcall => {
            let eid = semantic_arg_value(args.first());
            let fid = semantic_arg_value(args.get(1));
            if let Some(mapped_id) = exec_call_id_for(eid, fid).filter(|id| *id != 0) {
                if let Some(mapped_desc) = exec_call_desc(mapped_id) {
                    return format!("raw->{}", mapped_desc.name);
                }
            }
            if eid == 0x10 {
                return format!("raw->{}", base_call_name(fid));
            }
            format!("raw(0x{eid:x},0x{fid:x})")
        }
    }
}

fn base_call_name(fid: u64) -> &'static str {
    match fid {
        0 => "base_get_spec_version",
        1 => "base_get_impl_id",
        2 => "base_get_impl_version",
        3 => "base_probe_extension",
        4 => "base_get_mvendorid",
        5 => "base_get_marchid",
        6 => "base_get_mimpid",
        _ => "base_unknown",
    }
}

fn semantic_arg_value(arg: Option<&ExecArg>) -> u64 {
    match arg {
        Some(ExecArg::Const { value, .. }) => *value,
        Some(ExecArg::Addr32 { offset }) | Some(ExecArg::Addr64 { offset }) => *offset,
        Some(ExecArg::Result { default, .. }) => *default,
        Some(ExecArg::Data(_)) | None => 0,
    }
}

pub(crate) fn minimize_exec_program<F>(
    program: ExecProgram,
    predicate: &mut F,
) -> MinimizeProgramResult
where
    F: FnMut(&ExecProgram) -> bool,
{
    let mut current = program;
    let mut stats = MinimizeStats {
        tested_candidates: 0,
        accepted_candidates: 0,
        passes: 0,
    };

    if current.instructions.len() <= 1 {
        return MinimizeProgramResult {
            program: current,
            stats,
        };
    }

    let mut chunk_len = (current.instructions.len() / 2).max(1);
    while chunk_len >= 1 && current.instructions.len() > 1 {
        stats.passes += 1;
        let mut changed = false;
        let max_start = current.instructions.len().saturating_sub(chunk_len);
        for start in 0..=max_start {
            let Some(candidate) = remove_instruction_range(&current, start, chunk_len) else {
                continue;
            };
            stats.tested_candidates += 1;
            if predicate(&candidate) {
                current = candidate;
                stats.accepted_candidates += 1;
                changed = true;
                break;
            }
        }
        if changed {
            chunk_len = (current.instructions.len() / 2).max(1);
            continue;
        }
        if chunk_len == 1 {
            break;
        }
        chunk_len = (chunk_len / 2).max(1);
    }

    MinimizeProgramResult {
        program: current,
        stats,
    }
}

fn remove_instruction_range(
    program: &ExecProgram,
    start: usize,
    len: usize,
) -> Option<ExecProgram> {
    if len == 0 || start >= program.instructions.len() || start + len > program.instructions.len() {
        return None;
    }
    let mut instructions = Vec::with_capacity(program.instructions.len().saturating_sub(len));
    instructions.extend(program.instructions[..start].iter().cloned());
    instructions.extend(program.instructions[start + len..].iter().cloned());
    let candidate = ExecProgram { instructions };
    if candidate.call_count() == 0 {
        return None;
    }
    validate_exec_program(&candidate).ok()?;
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{EXEC_NO_COPYOUT, ExecArg, ExecInstr, exec_prop_busy_wait, exec_prop_target_hart};

    fn const_arg(value: u64) -> ExecArg {
        ExecArg::Const { size: 8, value }
    }

    fn raw_call(copyout_index: u64, tag: u64) -> ExecInstr {
        ExecInstr::Call {
            call_id: 0,
            copyout_index,
            args: vec![
                const_arg(tag),
                const_arg(0),
                const_arg(0),
                const_arg(0),
                const_arg(0),
                const_arg(0),
                const_arg(0),
                const_arg(0),
            ],
        }
    }

    #[test]
    fn parse_exit_kind_reads_helper_output() {
        let output = "noise\n\rRun finish. Exit kind: Timeout \n";
        assert_eq!(parse_exit_kind(output), Some("Timeout"));
        assert_eq!(parse_exit_kind("missing"), None);
    }

    #[test]
    fn minimize_exec_program_removes_irrelevant_instructions() {
        let program = ExecProgram {
            instructions: vec![
                ExecInstr::SetProps {
                    value: exec_prop_busy_wait(32),
                },
                raw_call(0, 0x1111),
                ExecInstr::SetProps {
                    value: exec_prop_target_hart(1),
                },
                raw_call(1, 0x2222),
                ExecInstr::CopyOut {
                    index: 1,
                    addr: 0x40,
                    size: 8,
                },
                raw_call(EXEC_NO_COPYOUT, 0x3333),
            ],
        };

        let mut predicate = |candidate: &ExecProgram| {
            candidate.instructions.iter().any(|instr| {
                matches!(
                    instr,
                    ExecInstr::SetProps { value }
                    if *value == exec_prop_target_hart(1)
                )
            }) && candidate.instructions.iter().any(|instr| {
                matches!(
                    instr,
                    ExecInstr::Call { copyout_index, args, .. }
                    if *copyout_index == 1 && matches!(args.first(), Some(ExecArg::Const { value: 0x2222, .. }))
                )
            })
        };

        let result = minimize_exec_program(program, &mut predicate);
        assert_eq!(result.program.instructions.len(), 2);
        assert_eq!(result.program.call_count(), 1);
        assert!(
            result
                .program
                .instructions
                .iter()
                .any(|instr| matches!(instr, ExecInstr::SetProps { .. }))
        );
        assert!(
            result
                .program
                .instructions
                .iter()
                .any(|instr| matches!(instr, ExecInstr::Call { .. }))
        );
        assert!(result.stats.tested_candidates > 0);
        assert!(result.stats.accepted_candidates > 0);
    }

    #[test]
    fn semantic_profile_tracks_harts_and_calls() {
        let program = ExecProgram {
            instructions: vec![
                ExecInstr::SetProps {
                    value: exec_prop_target_hart(2),
                },
                ExecInstr::SetProps {
                    value: exec_prop_busy_wait(512),
                },
                ExecInstr::Call {
                    call_id: 0,
                    copyout_index: EXEC_NO_COPYOUT,
                    args: vec![
                        const_arg(0x10),
                        const_arg(2),
                        const_arg(0),
                        const_arg(0),
                        const_arg(0),
                        const_arg(0),
                        const_arg(0),
                        const_arg(0),
                    ],
                },
            ],
        };

        let profile = build_exec_semantic_profile(&program);
        assert_eq!(profile.harts, vec![0, 2]);
        assert!(profile.signature.contains("hart=2"));
        assert!(profile.signature.contains("busy_wait=512"));
        assert!(
            profile
                .signature
                .contains("hart2:raw->base_get_impl_version@wait512")
        );
        assert_eq!(
            profile.calls,
            vec!["hart2:raw->base_get_impl_version@wait512"]
        );
    }
}
