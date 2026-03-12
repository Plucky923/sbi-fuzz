use crate::coverage::{
    OracleFailureSnapshot, SharedCoverageSnapshot, collect_oracle_failure_snapshot,
    collect_shared_coverage_snapshot, format_hex_u64, reset_oracle_failure, reset_shared_coverage,
    resolve_oracle_failure, resolve_shared_coverage, symbolize_coverage_pcs,
};
use common::*;
use libafl::executors::ExitKind;
use libafl::{
    corpus::InMemoryCorpus,
    observers::{CanTrack, HitcountsMapObserver, VariableMapObserver},
    state::StdState,
};
use libafl_bolts::{ownedref::OwnedMutSlice, tuples::tuple_list};
use libafl_qemu::{
    Emulator, QemuExitError, QemuExitReason, QemuShutdownCause, Regs, elf::EasyElf,
    modules::edges::StdEdgeCoverageModuleBuilder,
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};
use serde::Serialize;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{
    fs::{self},
    path::PathBuf,
    process,
};

#[derive(Debug, Clone)]
struct RunOutcome {
    exit_kind: ExitKind,
    coverage_snapshot: Option<SharedCoverageSnapshot>,
    oracle_snapshot: Option<OracleFailureSnapshot>,
    symbolized: Vec<String>,
    fallback_to_qemu_edges: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageArtifact {
    shared_buffer_addr: String,
    raw_count: usize,
    unique_count: usize,
    pcs: Vec<String>,
    symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageRunReport {
    target: String,
    injector: String,
    input: String,
    exit_kind: String,
    fallback_to_qemu_edges: bool,
    coverage_parse_error: Option<String>,
    coverage: Option<CoverageArtifact>,
    oracle_failure: Option<String>,
}

pub fn emit_timeout_coverage_report(
    target: &PathBuf,
    injector: &PathBuf,
    input: &PathBuf,
    json_out: Option<PathBuf>,
) {
    let report = CoverageRunReport {
        target: target.display().to_string(),
        injector: injector.display().to_string(),
        input: input.display().to_string(),
        exit_kind: exit_kind_name(&ExitKind::Timeout).to_string(),
        fallback_to_qemu_edges: true,
        coverage_parse_error: None,
        coverage: None,
        oracle_failure: None,
    };
    let json = serde_json::to_string_pretty(&report).expect("serialize timeout coverage report");
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{json}\n"))
            .expect(format!("write timeout coverage file: {:?}", &json_out).as_str());
    }
    println!("{json}");
}

/// Execute a single test case in the QEMU emulator.
pub fn run(target: PathBuf, injector: PathBuf, input: PathBuf, smp: u16) {
    let outcome = execute(&target, &injector, &input, smp, true, 8);
    if let Some(snapshot) = outcome.coverage_snapshot.as_ref() {
        print_coverage_summary(&target, snapshot, &outcome.symbolized);
    }

    println!(
        "Run finish. Exit kind: {}",
        exit_kind_name(&outcome.exit_kind)
    );
}

/// Execute one input and export shared-memory coverage artifacts.
pub fn collect_coverage(
    target: PathBuf,
    injector: PathBuf,
    input: PathBuf,
    smp: u16,
    raw_out: Option<PathBuf>,
    json_out: Option<PathBuf>,
    symbolize_limit: usize,
) {
    let outcome = execute(&target, &injector, &input, smp, false, symbolize_limit);

    if let Some(raw_out) = raw_out {
        if let Some(snapshot) = outcome.coverage_snapshot.as_ref() {
            fs::write(&raw_out, &snapshot.raw)
                .expect(format!("write raw coverage file: {:?}", &raw_out).as_str());
        }
    }

    let report = build_coverage_report(&target, &injector, &input, &outcome);
    let json = serde_json::to_string_pretty(&report).expect("serialize coverage report");
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{json}\n"))
            .expect(format!("write json coverage file: {:?}", &json_out).as_str());
    }
    println!("{json}");
}

const TEMP_INPUT_BINARY: &str = "/tmp/sbifuzz_input.bin";

pub fn debug(target: PathBuf, injector: PathBuf, input: PathBuf, smp: u16) {
    let input_binary = match load_wire_input(&input) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("Reject invalid input {}: {}", input.display(), err);
            return;
        }
    };
    fs::write(TEMP_INPUT_BINARY, &input_binary).expect("write input binary");

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(&injector, &mut elf_buffer).expect("load injector elf");
    let main_addr = elf
        .resolve_symbol("main", 0)
        .expect("symbol main not found");
    let input_addr = elf
        .resolve_symbol("FUZZ_INPUT", 0)
        .expect("symbol FUZZ_INPUT not found");
    let breakpoint = elf
        .resolve_symbol("BREAKPOINT", 0)
        .expect("symbol BREAKPOINT not found");

    let smp = smp.max(1).to_string();
    let args = vec![
        "qemu-system-riscv64",
        "-M",
        "virt",
        "-smp",
        &smp,
        "-m",
        "256M",
        "-bios",
        target.to_str().expect("target path"),
        "-kernel",
        injector.to_str().expect("injector path"),
        "-monitor",
        "null",
        "-serial",
        "stdio",
        "-nographic",
        "-snapshot",
        "-no-shutdown",
        "-S",
        "-s",
    ];
    let program = &args[0];
    let program_args = &args[1..];
    let mut cmd = Command::new(program);
    cmd.args(program_args);

    println!(
        r#"A QEMU will be started. You can run the following command to attach GDB:
gdb-multiarch -ex "target remote :1234" \
    -ex "restore {TEMP_INPUT_BINARY} binary 0x{:x}" -ex "b *0x{:x}" -ex "b *0x{:x}" # load input and set breakpoint"#,
        input_addr, main_addr, breakpoint
    );

    let err = cmd.exec();

    eprintln!("run failed: {}, command: {:?}", err, cmd);
    std::process::exit(1);
}

fn execute(
    target: &PathBuf,
    injector: &PathBuf,
    input: &PathBuf,
    smp: u16,
    serial_stdio: bool,
    symbolize_limit: usize,
) -> RunOutcome {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(injector, &mut elf_buffer).expect("load injector elf");

    let input_addr = elf
        .resolve_symbol("FUZZ_INPUT", 0)
        .expect("symbol FUZZ_INPUT not found");
    let main_addr = elf
        .resolve_symbol("main", 0)
        .expect("symbol main not found");
    let breakpoint = elf
        .resolve_symbol("BREAKPOINT", 0)
        .expect("symbol BREAKPOINT not found");
    let shared_coverage = resolve_shared_coverage(&elf);
    let oracle_failure = resolve_oracle_failure(&elf);

    let serial = if serial_stdio { "stdio" } else { "null" };
    let smp = smp.max(1).to_string();
    let qemu_config = vec![
        "fuzzer".to_string(),
        "-M".to_string(),
        "virt".to_string(),
        "-smp".to_string(),
        smp,
        "-m".to_string(),
        "256M".to_string(),
        "-bios".to_string(),
        target.to_str().expect("target path").to_string(),
        "-kernel".to_string(),
        injector.to_str().expect("injector path").to_string(),
        "-monitor".to_string(),
        "null".to_string(),
        "-serial".to_string(),
        serial.to_string(),
        "-nographic".to_string(),
        "-snapshot".to_string(),
        "-S".to_string(),
    ];

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    let emulator_modules = tuple_list!(
        StdEdgeCoverageModuleBuilder::default()
            .map_observer(edges_observer.as_mut())
            .build()
            .expect("build std edge coverage module")
    );

    let emulator: Emulator<
        libafl_qemu::command::NopCommand,
        libafl_qemu::command::NopCommandManager,
        libafl_qemu::NopEmulatorDriver,
        (
            libafl_qemu::modules::EdgeCoverageModule<
                libafl_qemu::modules::utils::filters::StdAddressFilter,
                libafl_qemu::modules::utils::filters::StdPageFilter,
                libafl_qemu::modules::edges::EdgeCoverageFullVariant,
                false,
                0,
            >,
            (),
        ),
        libafl::inputs::ValueInput<Vec<u8>>,
        StdState<
            InMemoryCorpus<libafl::inputs::ValueInput<Vec<u8>>>,
            libafl::inputs::ValueInput<Vec<u8>>,
            libafl_bolts::rands::RomuDuoJrRand,
            libafl::corpus::ondisk::OnDiskCorpus<libafl::inputs::ValueInput<Vec<u8>>>,
        >,
        libafl_qemu::NopSnapshotManager,
    > = Emulator::empty()
        .qemu_parameters(qemu_config)
        .modules(emulator_modules)
        .build()
        .expect("build emulator");
    let qemu = emulator.qemu();
    qemu.set_breakpoint(main_addr);
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(_)) => {}
            _ => panic!("Unexpected QEMU exit."),
        }
    }
    qemu.remove_breakpoint(main_addr);
    qemu.set_breakpoint(breakpoint);

    let input_binary = match load_wire_input(input) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("Reject invalid input {}: {}", input.display(), err);
            return RunOutcome {
                exit_kind: ExitKind::Ok,
                coverage_snapshot: None,
                oracle_snapshot: None,
                symbolized: Vec::new(),
                fallback_to_qemu_edges: true,
            };
        }
    };

    if let Some(shared_coverage) = shared_coverage {
        reset_shared_coverage(&emulator.qemu(), shared_coverage);
    }
    if let Some(oracle_failure) = oracle_failure {
        reset_oracle_failure(&emulator.qemu(), oracle_failure);
    }
    unsafe { emulator.write_phys_mem(input_addr, &input_binary) }
    let mut qemu_ret = match unsafe { emulator.qemu().run() } {
        Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
        Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
        Err(QemuExitError::UnexpectedExit) => ExitKind::Crash,
        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
            signal.handle();
            process::exit(0);
        }
        Ok(QemuExitReason::End(QemuShutdownCause::GuestPanic)) => ExitKind::Crash,
        Ok(QemuExitReason::End(QemuShutdownCause::GuestShutdown))
        | Ok(QemuExitReason::End(QemuShutdownCause::GuestReset))
        | Ok(QemuExitReason::End(QemuShutdownCause::SubsystemReset))
        | Ok(QemuExitReason::End(QemuShutdownCause::HostQmpSystemReset))
        | Ok(QemuExitReason::End(QemuShutdownCause::SnapshotLoad)) => ExitKind::Timeout,
        Ok(QemuExitReason::End(QemuShutdownCause::HostError))
        | Ok(QemuExitReason::End(QemuShutdownCause::HostQmpQuit))
        | Ok(QemuExitReason::End(QemuShutdownCause::HostUi))
        | Ok(QemuExitReason::End(QemuShutdownCause::None)) => ExitKind::Crash,
        e => panic!("Unexpected QEMU exit: {e:?}."),
    };

    let oracle_snapshot = oracle_failure
        .map(|oracle_failure| collect_oracle_failure_snapshot(&emulator.qemu(), oracle_failure));

    if qemu_ret == ExitKind::Ok {
        let cpu = emulator.qemu().cpu_from_index(0);
        let pc = cpu.read_reg(Regs::Pc).unwrap_or(0);
        if !(breakpoint..breakpoint + 5).contains(&pc) {
            if serial_stdio {
                println!(
                    "Unexpected PC: {:#x}, expected breakpoint at {:#x}",
                    pc, breakpoint
                );
            }
            qemu_ret = ExitKind::Crash;
        }
        let a0 = cpu.read_reg(Regs::A0).unwrap_or(1);
        if !is_standard_sbi_error_code(a0) {
            if serial_stdio {
                if let Some(snapshot) = oracle_snapshot.as_ref() {
                    if let Ok(Some(failure)) = snapshot.parsed.as_ref() {
                        println!(
                            "Oracle failure at 0x{:x}: {}",
                            snapshot.addr,
                            format_exec_oracle_failure(failure)
                        );
                    } else {
                        println!("Invalid return value: {:#x}, expected SBI error code", a0);
                    }
                } else {
                    println!("Invalid return value: {:#x}, expected SBI error code", a0);
                }
            }
            qemu_ret = ExitKind::Crash;
        }
    }

    let mut fallback_to_qemu_edges = true;
    let mut symbolized = Vec::new();
    let coverage_snapshot = shared_coverage.map(|shared_coverage| {
        let snapshot = collect_shared_coverage_snapshot(&emulator.qemu(), shared_coverage);
        if let Ok(coverage) = snapshot.parsed.as_ref() {
            if !coverage.is_empty() {
                fallback_to_qemu_edges = false;
                symbolized = symbolize_coverage_pcs(target, &coverage.pcs, symbolize_limit)
                    .unwrap_or_else(|_| Vec::new());
            }
        }
        snapshot
    });

    RunOutcome {
        exit_kind: qemu_ret,
        coverage_snapshot,
        oracle_snapshot,
        symbolized,
        fallback_to_qemu_edges,
    }
}

fn print_coverage_summary(
    target: &PathBuf,
    snapshot: &SharedCoverageSnapshot,
    symbolized: &[String],
) {
    match snapshot.parsed.as_ref() {
        Ok(coverage) if coverage.is_empty() => {
            println!(
                "Guest coverage buffer at 0x{:x} is empty; keeping QEMU edge signal as fallback",
                snapshot.addr
            );
        }
        Ok(coverage) => {
            println!(
                "Guest coverage buffer at 0x{:x}: raw_pcs={} unique_pcs={}",
                snapshot.addr,
                coverage.raw_count,
                coverage.unique_pcs().len()
            );
            if symbolized.is_empty() {
                if let Ok(lines) = symbolize_coverage_pcs(target, &coverage.pcs, 8) {
                    for line in lines {
                        println!("  {}", line);
                    }
                }
            } else {
                for line in symbolized {
                    println!("  {}", line);
                }
            }
        }
        Err(err) => {
            println!(
                "Failed to parse guest coverage buffer at 0x{:x}: {}",
                snapshot.addr, err
            );
        }
    }
}

fn build_coverage_report(
    target: &PathBuf,
    injector: &PathBuf,
    input: &PathBuf,
    outcome: &RunOutcome,
) -> CoverageRunReport {
    let coverage_parse_error = outcome
        .coverage_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.parsed.as_ref().err().cloned());
    let coverage = outcome.coverage_snapshot.as_ref().and_then(|snapshot| {
        snapshot
            .parsed
            .as_ref()
            .ok()
            .map(|coverage| CoverageArtifact {
                shared_buffer_addr: format_hex_u64(snapshot.addr),
                raw_count: coverage.raw_count,
                unique_count: coverage.unique_pcs().len(),
                pcs: coverage.pcs.iter().map(|pc| format_hex_u64(*pc)).collect(),
                symbols: outcome.symbolized.clone(),
            })
    });
    let oracle_failure = outcome.oracle_snapshot.as_ref().and_then(|snapshot| {
        snapshot
            .parsed
            .as_ref()
            .ok()
            .and_then(|failure| failure.as_ref().map(format_exec_oracle_failure))
    });

    CoverageRunReport {
        target: target.display().to_string(),
        injector: injector.display().to_string(),
        input: input.display().to_string(),
        exit_kind: exit_kind_name(&outcome.exit_kind).to_string(),
        fallback_to_qemu_edges: outcome.fallback_to_qemu_edges,
        coverage_parse_error,
        coverage,
        oracle_failure,
    }
}

fn exit_kind_name(kind: &ExitKind) -> String {
    format!("{kind:?}")
}

fn load_wire_input(input: &PathBuf) -> Result<Vec<u8>, String> {
    if input.extension().and_then(|ext| ext.to_str()) == Some("toml") {
        let toml_content = fs::read_to_string(input).map_err(|err| err.to_string())?;
        let input = fix_input_args(input_from_toml(&toml_content));
        let program = normalize_exec_program(exec_program_from_input(&input));
        return Ok(exec_program_to_bytes(&program));
    }

    let bytes = fs::read(input).map_err(|err| err.to_string())?;
    if bytes.starts_with(EXEC_MAGIC) {
        exec_program_from_bytes(&bytes)?;
    }
    Ok(bytes)
}
