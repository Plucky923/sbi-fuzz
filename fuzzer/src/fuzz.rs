use chrono::Local;
use common::*;
use core::time::Duration;
use csv::Writer;
use libafl::{
    Error, HasNamedMetadata,
    corpus::{Corpus, CorpusId, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::{EventConfig, launcher::Launcher, std_maybe_report_progress, std_report_progress},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{Generator, RandBytesGenerator},
    inputs::{HasTargetBytes, Input, ResizableMutator},
    monitors::{ClientStats, Monitor, UserStatsValue},
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    nonzero,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasExecutions, StdState},
};
use libafl_bolts::{
    AsSlice, ClientId,
    core_affinity::Cores,
    current_nanos, current_time, impl_serdeany,
    generic_hash_std,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    Emulator, QemuExitError, QemuExitReason, QemuShutdownCause, Regs,
    elf::EasyElf,
    executor::QemuExecutor,
    modules::{DrCovModule, edges::StdEdgeCoverageModuleBuilder, utils::filters::StdAddressFilter},
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use std::{
    cmp::max,
    collections::HashMap,
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::PathBuf,
    process::{self},
};

// Define the memory range for firmware
const FIRMWARE_ADDR_START: u64 = 0x8000_0000;
const FIRMWARE_ADDR_END: u64 = 0x8020_0000;

#[derive(Debug, Clone, Copy)]
struct SharedCoverageConfig {
    addr: u64,
    capacity: usize,
}

impl SharedCoverageConfig {
    fn byte_len(self) -> usize {
        sbi_coverage_buffer_bytes(self.capacity)
    }
}

fn resolve_shared_coverage(elf: &EasyElf) -> Option<SharedCoverageConfig> {
    elf.resolve_symbol(SBI_COVERAGE_BUFFER_SYMBOL, 0)
        .map(|addr| SharedCoverageConfig {
            addr,
            capacity: SBI_COVERAGE_PC_CAPACITY,
        })
}

fn reset_shared_coverage(qemu: &libafl_qemu::Qemu, coverage: SharedCoverageConfig) {
    let bytes = sbi_coverage_zero_buffer(coverage.capacity);
    unsafe { qemu.write_phys_mem(coverage.addr, &bytes) }
}

fn collect_shared_coverage(
    qemu: &libafl_qemu::Qemu,
    coverage: SharedCoverageConfig,
) -> Result<SbiCoverageBuffer, String> {
    let mut bytes = vec![0; coverage.byte_len()];
    unsafe { qemu.read_phys_mem(coverage.addr, &mut bytes) }
    parse_sbi_coverage_buffer(&bytes)
}

fn overwrite_edges_with_shared_coverage(pcs: &[u64]) {
    let edges =
        unsafe { std::slice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE) };
    edges.fill(0);
    let max_edges = fold_sbi_coverage_into_map(pcs, edges);
    unsafe {
        MAX_EDGES_FOUND = max_edges;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
struct FuzzInput(Vec<u8>);

impl FuzzInput {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Input for FuzzInput {
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<std::path::Path>,
    {
        atomic_write_file(&path.as_ref().to_path_buf(), self.0.clone())
            .map_err(|err| Error::os_error(err, "write fuzz input".to_string()))
    }

    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<std::path::Path>,
    {
        Ok(Self(fs::read(path)?))
    }

    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!("{:016x}", generic_hash_std(self))
    }
}

impl HasTargetBytes for FuzzInput {
    fn target_bytes(&self) -> libafl_bolts::ownedref::OwnedSlice<u8> {
        libafl_bolts::ownedref::OwnedSlice::from(self.0.as_slice())
    }
}

impl libafl_bolts::HasLen for FuzzInput {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl libafl::inputs::HasMutatorBytes for FuzzInput {
    fn mutator_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn mutator_bytes_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl ResizableMutator<u8> for FuzzInput {
    fn resize(&mut self, new_len: usize, value: u8) {
        self.0.resize(new_len, value);
    }

    fn extend<'a, I: IntoIterator<Item = &'a u8>>(&mut self, iter: I)
    where
        u8: 'a,
    {
        Extend::extend(&mut self.0, iter);
    }

    fn splice<R, I>(&mut self, range: R, replace_with: I) -> std::vec::Splice<'_, I::IntoIter>
    where
        R: std::ops::RangeBounds<usize>,
        I: IntoIterator<Item = u8>,
    {
        self.0.splice(range, replace_with)
    }

    fn drain<R>(&mut self, range: R) -> std::vec::Drain<'_, u8>
    where
        R: std::ops::RangeBounds<usize>,
    {
        self.0.drain(range)
    }
}

#[derive(Clone, Debug)]
struct FuzzInputGenerator(RandBytesGenerator);

impl FuzzInputGenerator {
    fn new(max_size: core::num::NonZeroUsize) -> Self {
        Self(RandBytesGenerator::new(max_size))
    }
}

impl<S> Generator<FuzzInput, S> for FuzzInputGenerator
where
    S: libafl::state::HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<FuzzInput, Error> {
        self.0.generate(state).map(|bytes| FuzzInput::new(bytes.into()))
    }
}

/// Main fuzzing function that sets up and runs the fuzzer
///
/// # Arguments
///
/// * `target` - Path to the target firmware
/// * `injector` - Path to the injector binary
/// * `seed_dir` - Directory containing seed inputs
/// * `objective_dir` - Directory to store objective findings
/// * `cores` - CPU cores to use for fuzzing
/// * `timeout` - Maximum execution time for each test case
/// * `dr_cov` - Optional path for Dr. Coverage output
/// * `check_skip_fn` - Function to determine if certain inputs should be skipped
pub fn fuzz(
    target: PathBuf,
    injector: PathBuf,
    seed_dir: Option<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
    cores: &str,
    timeout: Duration,
    smp: u16,
    dr_cov: Option<PathBuf>,
    monitor_csv: Option<PathBuf>,
    check_skip_fn: impl Fn(&InputData) -> bool,
) -> Result<(), Error> {
    // Parse arguments and create necessary directories
    if !objective_dir.exists() {
        fs::create_dir(&objective_dir).expect("create objective directory");
    }
    let objective_raw_dir = objective_dir.join(".raw");
    if !objective_raw_dir.exists() {
        fs::create_dir(&objective_raw_dir).expect("create raw objective directory");
    }
    let cores = Cores::from_cmdline(cores).expect("parse cores");
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(&injector, &mut elf_buffer).expect("load injector elf");

    // Resolve important symbols from the injector ELF file
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
    let smp = max(1, smp).to_string();

    // Define the client function that will be executed for each fuzzing instance
    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        // Configure QEMU parameters
        let qemu_config = vec![
            "fuzzer".to_string(),
            "-M".to_string(),
            "virt".to_string(),
            "-smp".to_string(),
            smp.clone(),
            "-m".to_string(),
            "256M".to_string(),
            "-bios".to_string(),
            target.clone().to_str().expect("target path").to_string(),
            "-kernel".to_string(),
            injector
                .clone()
                .to_str()
                .expect("injector path")
                .to_string(),
            "-monitor".to_string(),
            "null".to_string(),
            "-serial".to_string(),
            "null".to_string(),
            "-nographic".to_string(),
            "-snapshot".to_string(),
            "-S".to_string(),
        ];

        // Set up observers for coverage and timing
        let time_observer = TimeObserver::new("time");
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Configure Dr. Coverage if provided
        let mut dr_cov_path = PathBuf::from("");
        let mut dr_cov_addr = 0..0;
        let mut dr_cov_module_map: RangeMap<u64, (u16, String)> = RangeMap::new();
        if dr_cov.is_some() {
            dr_cov_path = dr_cov.clone().unwrap();
            dr_cov_addr = FIRMWARE_ADDR_START..FIRMWARE_ADDR_END;
            dr_cov_module_map.insert(
                FIRMWARE_ADDR_START..FIRMWARE_ADDR_END,
                (1, "sbi".to_string()),
            );
        }

        // Set up coverage modules
        let emulator_modules = tuple_list!(
            StdEdgeCoverageModuleBuilder::default()
                .address_filter(StdAddressFilter::allow_list(vec![
                    FIRMWARE_ADDR_START..FIRMWARE_ADDR_END
                ]))
                .map_observer(edges_observer.as_mut())
                .build()
                .expect("build std edge coverage module"),
            DrCovModule::builder()
                .filename(dr_cov_path)
                .module_mapping(dr_cov_module_map)
                .filter(StdAddressFilter::allow_list(vec![dr_cov_addr]))
                .full_trace(false)
                .build()
        );

        // Initialize the QEMU emulator and set breakpoints
        let emulator = Emulator::empty()
            .qemu_parameters(qemu_config)
            .modules(emulator_modules)
            .build()?;
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

        // Save initial CPU state for restoring between runs
        let saved_cpu_state = qemu.cpu_from_index(0).save_state();
        let snap = qemu.create_fast_snapshot(true);

        // Define the execution harness function
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           state: &mut StdState<_, _, _, _>,
                           input: &FuzzInput| {
            // Convert fuzzer input to fixed-size binary
            let target = input.target_bytes();
            let raw = target.as_slice();

            let exec_program = if raw.starts_with(EXEC_MAGIC) {
                match exec_program_from_bytes(raw) {
                    Ok(program) => Some(program),
                    Err(_) => return ExitKind::Ok,
                }
            } else {
                None
            };

            let mut input = if let Some(program) = exec_program.as_ref() {
                exec_program_primary_input(program).unwrap_or_else(|| InputData {
                    metadata: Metadata::from_call(0, 0, "exec-unknown".to_string()),
                    args: Args {
                        eid: 0,
                        fid: 0,
                        arg0: 0,
                        arg1: 0,
                        arg2: 0,
                        arg3: 0,
                        arg4: 0,
                        arg5: 0,
                    },
                })
            } else {
                let mut buf = vec![0; INPUT_SIZE];
                let copy_len = raw.len().min(INPUT_SIZE);
                buf[..copy_len].copy_from_slice(&raw[..copy_len]);
                fix_input_args(input_from_binary(&buf))
            };
            if check_skip_fn(&input) {
                // Skip execution if user-defined function says so
                return ExitKind::Ok;
            }
            let semantic_objective_key =
                objective_key_for_case(exec_program.as_ref(), &input, None);
            let st = state
                .named_metadata::<ObjectiveCountMetadata>("objective_id_count")
                .expect("get count");
            if let Some(objective_key) = semantic_objective_key.as_deref() {
                if st.get_objective_key_count(objective_key) >= 3 {
                    return ExitKind::Ok;
                }
            }
            if exec_program.is_some() {
                if st.get_eid_count(input.args.eid) >= 250 {
                    return ExitKind::Ok;
                }
            } else if st.get_eid_count(input.args.eid) >= 100
                || st.get_count(input.args.eid, input.args.fid) >= 10
            {
                // Limit number of crashes per extension ID / function ID to avoid excessive findings
                return ExitKind::Ok;
            }

            let hash = input.hash_string();
            let toml_path = objective_dir.join(format!(
                "{}-{:x}-{}.toml",
                input.metadata.extension_name, input.args.fid, hash
            ));
            if toml_path.exists() {
                // Skip execution if input has already been recorded
                return ExitKind::Ok;
            }

            // Write input to emulator memory and execute
            let wire_input = if exec_program.is_some() {
                raw.to_vec()
            } else {
                let program = normalize_exec_program(exec_program_from_input(&input));
                exec_program_to_bytes(&program)
            };
            if let Some(shared_coverage) = shared_coverage {
                reset_shared_coverage(&emulator.qemu(), shared_coverage);
            }
            *state.executions_mut() += 1;
            unsafe { emulator.write_phys_mem(input_addr, &wire_input) }
            let mut qemu_ret = match unsafe { emulator.qemu().run() } {
                Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
                Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
                Err(QemuExitError::UnexpectedExit) => ExitKind::Crash,
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                    // Handle external signals to stop fuzzing
                    signal.handle();
                    process::exit(0);
                }
                Ok(QemuExitReason::End(QemuShutdownCause::GuestPanic)) => ExitKind::Crash,
                Ok(QemuExitReason::End(QemuShutdownCause::GuestShutdown))
                | Ok(QemuExitReason::End(QemuShutdownCause::GuestReset))
                | Ok(QemuExitReason::End(QemuShutdownCause::SubsystemReset))
                | Ok(QemuExitReason::End(QemuShutdownCause::HostQmpSystemReset))
                | Ok(QemuExitReason::End(QemuShutdownCause::SnapshotLoad)) => ExitKind::Ok,
                Ok(QemuExitReason::End(QemuShutdownCause::HostError))
                | Ok(QemuExitReason::End(QemuShutdownCause::HostQmpQuit))
                | Ok(QemuExitReason::End(QemuShutdownCause::HostUi))
                | Ok(QemuExitReason::End(QemuShutdownCause::None)) => ExitKind::Crash,
                e => panic!("Unexpected QEMU exit: {e:?}."),
            };

            // Validate execution results
            if qemu_ret == ExitKind::Ok {
                // Verify we reached the expected breakpoint
                let cpu = emulator.qemu().cpu_from_index(0);
                let pc = cpu.read_reg(Regs::Pc).unwrap_or(0);
                if !(breakpoint..breakpoint + 5).contains(&pc) {
                    qemu_ret = ExitKind::Crash;
                }
                // Verify return value is a standard SBI error code
                let a0 = cpu.read_reg(Regs::A0).unwrap_or(1);
                if !is_standard_sbi_error_code(a0) {
                    qemu_ret = ExitKind::Crash;
                }
            }

            if let Some(shared_coverage) = shared_coverage {
                if let Ok(coverage) = collect_shared_coverage(&emulator.qemu(), shared_coverage) {
                    if !coverage.is_empty() {
                        overwrite_edges_with_shared_coverage(&coverage.pcs);
                    }
                }
            }

            // Special handling for SBI calls that may cause halts
            if qemu_ret == ExitKind::Timeout && is_halt_sbi_call(input.args.eid, input.args.fid) {
                qemu_ret = ExitKind::Ok
            }

            // Save interesting inputs that cause crashes or timeouts
            if qemu_ret != ExitKind::Ok {
                input.metadata.source = format!("fuzz-{}-{:?}", hash, qemu_ret);
                atomic_write_file(&toml_path, input_to_toml(&input).into_bytes())
                    .expect(format!("write toml file: {:?}", &toml_path).as_str());
                let raw_path = objective_raw_dir.join(format!("{}.exec", hash));
                atomic_write_file(&raw_path, wire_input.clone())
                    .expect(format!("write raw exec file: {:?}", &raw_path).as_str());
                state
                    .named_metadata_mut::<ObjectiveCountMetadata>("objective_id_count")
                    .expect("get count")
                    .add_count(
                        input.args.eid,
                        input.args.fid,
                        objective_key_for_case(exec_program.as_ref(), &input, Some(&qemu_ret))
                            .as_deref(),
                    );
            }

            // Restore emulator state for next run
            unsafe { emulator.restore_fast_snapshot(snap) }
            emulator
                .qemu()
                .cpu_from_index(0)
                .restore_state(&saved_cpu_state);

            qemu_ret
        };

        // Set up feedback mechanisms for the fuzzer
        let mut feedback = feedback_or!(
            TimeFeedback::new(&time_observer),
            MaxMapFeedback::new(&edges_observer)
        );
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // Initialize or use provided fuzzer state
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryOnDiskCorpus::new(objective_dir.join(".corpus"))
                    .expect("create on disk corpus"),
                OnDiskCorpus::new(&objective_raw_dir).expect("create on disk corpus"),
                &mut feedback,
                &mut objective,
            )
            .expect("create state")
        });

        // Initialize objective count metadata
        let mut objective_id_count = ObjectiveCountMetadata::new();
        let output_paths = fs::read_dir(&objective_dir).expect("read output dir");
        for path in output_paths {
            let path = path.expect("read path").path();
            if path.extension().unwrap_or_default() != "toml" {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            if content.trim().is_empty() {
                continue;
            }
            let Ok(input) = try_input_from_toml(&content) else {
                continue;
            };
            let hash = path
                .file_stem()
                .and_then(|value| value.to_str())
                .and_then(|value| value.rsplit('-').next())
                .unwrap_or_default();
            let raw_path = objective_raw_dir.join(format!("{hash}.exec"));
            let raw_exec = if raw_path.exists() {
                fs::read(&raw_path)
                    .ok()
                    .filter(|bytes| bytes.starts_with(EXEC_MAGIC))
                    .and_then(|bytes| exec_program_from_bytes(&bytes).ok())
            } else {
                None
            };
            let recorded_exit_kind = objective_exit_kind_from_source(&input.metadata.source);
            objective_id_count.add_count(
                input.args.eid,
                input.args.fid,
                objective_key_for_case(raw_exec.as_ref(), &input, recorded_exit_kind.as_ref())
                    .as_deref(),
            );
        }
        state.add_named_metadata("objective_id_count", objective_id_count);

        // Configure scheduler, fuzzer, and executor
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("create executor");

        // Configure execution behavior and load initial inputs
        executor.break_on_timeout();
        if state.must_load_initial_inputs() && seed_dir.is_none() {
            let mut generator = FuzzInputGenerator::new(nonzero!(256));
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 100)
                .unwrap_or_else(|_| {
                    println!("Failed to generate initial corpus");
                    process::exit(0);
                });
        }

        if state.corpus().count() == 0 {
            let bootstrap_paths = list_bootstrap_paths(&objective_raw_dir, seed_dir.as_ref(), 8);
            for (index, bootstrap_path) in bootstrap_paths.iter().enumerate() {
                let bytes = fs::read(bootstrap_path).expect("read bootstrap corpus input");
                let id = state
                    .corpus_mut()
                    .add(Testcase::new(FuzzInput::new(bytes)))?;
                if index == 0 {
                    *state.corpus_mut().current_mut() = Some(id);
                }
                println!("Bootstrapped corpus from {}", bootstrap_path.display());
            }
        }

        // Set up mutation strategy and start the fuzzing loop
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        let monitor_timeout = Duration::from_secs(1);
        let fuzz_result = loop {
            std_maybe_report_progress(&mut mgr, &mut state, monitor_timeout)?;
            match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
                Ok(_) => {}
                Err(Error::ShuttingDown) => {
                    let _ = std_report_progress(&mut mgr, &mut state);
                    break Ok(());
                }
                Err(err) => break Err(err),
            }
        };
        match fuzz_result {
            Ok(()) => Ok(()),
            Err(err) => Err(err),
        }?;
        Ok(())
    };

    // Set up shared memory, monitoring, and launch the fuzzer
    let shmem_provider = StdShMemProvider::new().expect("init shared memory");
    let monitor = MultiMonitorWithCSV::new(monitor_csv);
    let mut launcher = Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .run_client(&mut run_client)
        .cores(&cores)
        .monitor(monitor)
        .build();

    // Start the fuzzing campaign
    launcher.launch()
}

fn atomic_write_file(path: &PathBuf, bytes: Vec<u8>) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    let pid = process::id();
    for attempt in 0..16_u32 {
        let tmp_path = path.with_file_name(format!(
            ".{}.{}.{}.{}.tmp",
            file_name,
            pid,
            current_nanos(),
            attempt
        ));
        match fs::write(&tmp_path, &bytes) {
            Ok(()) => {
                fs::rename(tmp_path, path)?;
                return Ok(());
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        format!("failed to allocate unique tmp path for {}", path.display()),
    ))
}

fn list_bootstrap_paths(
    objective_raw_dir: &PathBuf,
    seed_dir: Option<&PathBuf>,
    limit: usize,
) -> Vec<PathBuf> {
    let from_dir = |dir: &PathBuf| -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(dir)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        paths.sort();
        if limit > 0 && paths.len() > limit {
            paths.truncate(limit);
        }
        paths
    };

    let objective_paths = from_dir(objective_raw_dir);
    if !objective_paths.is_empty() {
        return objective_paths;
    }
    seed_dir.map(from_dir).unwrap_or_default()
}

fn objective_key_for_case(
    exec_program: Option<&ExecProgram>,
    input: &InputData,
    exit_kind: Option<&ExitKind>,
) -> Option<String> {
    let exit_kind = exit_kind.map(|kind| format!("{kind:?}"))?;
    let body = match exec_program {
        Some(program) => exec_semantic_signature(program),
        None => format!("call:{:x}-{:x}", input.args.eid, input.args.fid),
    };
    Some(format!("{exit_kind}|{body}"))
}

fn objective_exit_kind_from_source(source: &str) -> Option<ExitKind> {
    match source.rsplit('-').next()? {
        "Crash" => Some(ExitKind::Crash),
        "Timeout" => Some(ExitKind::Timeout),
        "Ok" => Some(ExitKind::Ok),
        _ => None,
    }
}

fn exec_semantic_signature(program: &ExecProgram) -> String {
    let mut steps = Vec::new();
    let mut current_hart = 0_u64;
    let mut current_busy_wait = 0_u64;
    for instr in &program.instructions {
        match instr {
            ExecInstr::CopyIn { addr, .. } => steps.push(format!("copyin@0x{addr:x}")),
            ExecInstr::CopyOut { index, size, .. } => steps.push(format!("copyout#{index}:{size}")),
            ExecInstr::SetProps { value } => {
                let (kind, payload) = decode_exec_prop(*value);
                match kind {
                    EXEC_PROP_TARGET_HART => {
                        current_hart = payload;
                        steps.push(format!("hart={payload}"));
                    }
                    EXEC_PROP_BUSY_WAIT => {
                        current_busy_wait = payload;
                        steps.push(format!("wait={payload}"));
                    }
                    _ => steps.push(format!("prop=0x{value:x}")),
                }
            }
            ExecInstr::Call {
                call_id,
                copyout_index,
                args,
            } => {
                let mut call = format!(
                    "hart{current_hart}:{}",
                    exec_semantic_call_name(*call_id, args)
                );
                if current_busy_wait > 0 {
                    call.push_str(&format!("@w{current_busy_wait}"));
                }
                if *copyout_index != EXEC_NO_COPYOUT {
                    call.push_str(&format!("->r{copyout_index}"));
                }
                steps.push(call);
            }
        }
    }
    if steps.is_empty() {
        "empty".to_string()
    } else {
        steps.join("|")
    }
}

fn exec_semantic_call_name(call_id: u64, args: &[ExecArg]) -> String {
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

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone)]
pub struct MultiMonitorWithCSV {
    csv_path: Option<PathBuf>,
    start_time: Duration,
    last_display: Duration,
    last_client_id: ClientId,
    client_stats: Vec<ClientStats>,
}

impl MultiMonitorWithCSV {
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(csv_path: Option<PathBuf>) -> Self {
        if csv_path.is_some() {
            let csv_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(csv_path.clone().unwrap())
                .expect("open csv file");
            let mut writer = Writer::from_writer(csv_file);
            writer
                .write_record(&[
                    "ClientID",
                    "Time",
                    "Runtime",
                    "Clients",
                    "Corpus",
                    "Objective",
                    "Executions",
                    "Speed",
                    "Edges",
                ])
                .expect("write csv header");
            writer.flush().expect("flush csv");
        }
        Self {
            csv_path,
            start_time: current_time(),
            last_display: Duration::from_secs(0),
            last_client_id: ClientId(0),
            client_stats: vec![],
        }
    }

    /// Returns the number of edges found.
    fn count_edges_found(&self) -> usize {
        let mut count = 0;
        for i in 0..self.client_stats_count() {
            let client = self.client_stats_for(libafl_bolts::ClientId((i + 1) as _));
            client
                .user_monitor
                .get("edges")
                .map(|val| match val.value() {
                    UserStatsValue::Ratio(_, val) => count = max(count, *val as _),
                    _ => {}
                });
        }
        count
    }
}

impl Monitor for MultiMonitorWithCSV {
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    fn aggregate(&mut self, _: &str) {}

    /// Display the current status of the fuzzer
    fn display(&mut self, _: &str, client_id: ClientId) {
        let ct = current_time();
        if (ct - self.last_display < Duration::from_millis(100))
            && (client_id == self.last_client_id)
        {
            return;
        }
        self.last_display = ct;
        self.last_client_id = client_id;

        let now = Local::now();
        let formatted_time = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let runtime = format_duration_hmsf(&(ct - self.start_time));
        let clients = self.client_stats_count();
        let cropus = self.corpus_size();
        let objectives = self.objective_size();
        let executions = self.total_execs();
        let speed = self.execs_per_sec_pretty();
        let edges = self.count_edges_found();
        println!(
            "[{}] [FUZZER] Runtime: {} | Clients: {} | Corpus: {} | Objective: {} | Executions: {} | Speed: {} exec/sec | Edges: {}",
            formatted_time, runtime, clients, cropus, objectives, executions, speed, edges
        );

        if self.csv_path.is_some() {
            let csv_file = OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(self.csv_path.clone().unwrap())
                .expect("open csv file");
            let mut writer = Writer::from_writer(csv_file);
            writer
                .write_record(&[
                    "GLOBAL",
                    &formatted_time,
                    &runtime,
                    &clients.to_string(),
                    &cropus.to_string(),
                    &objectives.to_string(),
                    &executions.to_string(),
                    &format!("{:.2}", self.execs_per_sec()),
                    &edges.to_string(),
                ])
                .expect("write csv global data");
            let client = &mut self.client_stats_mut()[client_id.0 as usize];
            let edges = client
                .user_monitor
                .get("edges")
                .map(|val| match val.value() {
                    UserStatsValue::Ratio(_, val) => val.to_string(),
                    _ => "".to_string(),
                })
                .unwrap_or_default();
            writer
                .write_record(&[
                    &client_id.0.to_string(),
                    &formatted_time,
                    &format_duration_hmsf(&(ct - client.start_time)),
                    "",
                    &client.corpus_size.to_string(),
                    &client.objective_size.to_string(),
                    &client.executions.to_string(),
                    &format!("{:.2}", client.execs_per_sec(ct)),
                    &edges,
                ])
                .expect("write csv client data");
            writer.flush().expect("flush csv");
        }
    }
}

/// Formats a Duration into a human-readable string in the format "HH:MM:SS.mmm"
///
/// # Arguments
///
/// * `duration` - The Duration to format
///
/// # Returns
///
/// A string representation of the duration in hours, minutes, seconds, and milliseconds
fn format_duration_hmsf(duration: &Duration) -> String {
    // Convert total duration to milliseconds
    let total_ms = duration.as_millis();

    // Calculate hours component
    let hours = total_ms / (1000 * 60 * 60);

    // Calculate minutes component (modulo 60 to get only the minutes part)
    let minutes = (total_ms / (1000 * 60)) % 60;

    // Calculate seconds component (modulo 60 to get only the seconds part)
    let seconds = (total_ms / 1000) % 60;

    // Calculate milliseconds component
    let milliseconds = total_ms % 1000;

    // Format the components into a string with zero-padding
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        hours, minutes, seconds, milliseconds
    )
}

/// A structure to track and store counts of different SBI call objectives
/// Stores counts indexed by EID (extension ID) and EID-FID (extension ID - function ID) pairs
#[derive(Debug, Serialize, Deserialize)]
struct ObjectiveCountMetadata {
    // HashMap storing counts for each EID and EID-FID combination
    count: HashMap<String, u64>,
}

impl ObjectiveCountMetadata {
    /// Creates a new empty ObjectiveCountMetadata instance
    fn new() -> Self {
        Self {
            count: HashMap::new(),
        }
    }

    /// Increments the count for a specific EID and EID-FID combination
    ///
    /// # Arguments
    ///
    /// * `eid` - Extension ID
    /// * `fid` - Function ID
    fn add_count(&mut self, eid: u64, fid: u64, objective_key: Option<&str>) {
        // Increment count for the EID
        *self.count.entry(format!("{:x}", eid)).or_insert(0) += 1;

        // Increment count for the EID-FID combination
        *self
            .count
            .entry(format!("{:x}-{:x}", eid, fid))
            .or_insert(0) += 1;
        if let Some(objective_key) = objective_key {
            *self
                .count
                .entry(format!("objective:{objective_key}"))
                .or_insert(0) += 1;
        }
    }

    /// Gets the count for a specific EID-FID combination
    ///
    /// # Arguments
    ///
    /// * `eid` - Extension ID
    /// * `fid` - Function ID
    ///
    /// # Returns
    ///
    /// The count for the specified EID-FID combination, or 0 if not found
    fn get_count(&self, eid: u64, fid: u64) -> u64 {
        *self
            .count
            .get(&format!("{:x}-{:x}", eid, fid))
            .unwrap_or(&0)
    }

    /// Gets the count for a specific EID across all function IDs
    ///
    /// # Arguments
    ///
    /// * `eid` - Extension ID
    ///
    /// # Returns
    ///
    /// The total count for the specified EID, or 0 if not found
    fn get_eid_count(&self, eid: u64) -> u64 {
        *self.count.get(&format!("{:x}", eid)).unwrap_or(&0)
    }

    fn get_objective_key_count(&self, objective_key: &str) -> u64 {
        *self
            .count
            .get(&format!("objective:{objective_key}"))
            .unwrap_or(&0)
    }
}

// Implement serialization/deserialization for the ObjectiveCountMetadata struct
impl_serdeany!(ObjectiveCountMetadata);

#[cfg(test)]
mod tests {
    use super::*;

    fn const_arg(value: u64) -> ExecArg {
        ExecArg::Const { size: 8, value }
    }

    #[test]
    fn exec_semantic_signature_distinguishes_harts_and_calls() {
        let hart1 = ExecProgram {
            instructions: vec![
                ExecInstr::SetProps {
                    value: exec_prop_target_hart(1),
                },
                ExecInstr::Call {
                    call_id: 0,
                    copyout_index: 3,
                    args: vec![
                        const_arg(0x10),
                        const_arg(1),
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
        let hart2 = ExecProgram {
            instructions: vec![
                ExecInstr::SetProps {
                    value: exec_prop_target_hart(2),
                },
                ExecInstr::Call {
                    call_id: 0,
                    copyout_index: 3,
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

        let lhs = exec_semantic_signature(&hart1);
        let rhs = exec_semantic_signature(&hart2);
        assert_ne!(lhs, rhs);
        assert!(lhs.contains("hart1:raw->base_get_impl_id->r3"));
        assert!(rhs.contains("hart2:raw->base_get_impl_version->r3"));
    }

    #[test]
    fn objective_count_metadata_tracks_semantic_keys() {
        let mut metadata = ObjectiveCountMetadata::new();
        metadata.add_count(0x10, 1, Some("Timeout|hart1:raw->base_get_impl_id"));
        metadata.add_count(0x10, 1, Some("Timeout|hart1:raw->base_get_impl_id"));
        metadata.add_count(0x10, 2, Some("Timeout|hart2:raw->base_get_impl_version"));

        assert_eq!(metadata.get_count(0x10, 1), 2);
        assert_eq!(metadata.get_eid_count(0x10), 3);
        assert_eq!(
            metadata.get_objective_key_count("Timeout|hart1:raw->base_get_impl_id"),
            2
        );
        assert_eq!(
            metadata.get_objective_key_count("Timeout|hart2:raw->base_get_impl_version"),
            1
        );
    }
}
