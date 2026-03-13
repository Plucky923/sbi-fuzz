use clap::{Args, Parser, Subcommand, ValueEnum};
use common::*;
use host_harness::{FdtSeedVariant, seed_fdt_blob};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

// Import modules that implement different functionalities
mod coverage;
mod instrumenter;
mod minimizer;
mod runner;
mod scenario_generator;
mod seed_generator;
mod sequence_runner;

/// Main CLI structure that defines the top-level command interface
#[derive(Parser)]
#[clap(name = "helper")]
#[clap(about = "A helper for fuzzing sbi firmware")]
struct Cli {
    /// Subcommand to execute
    #[clap(subcommand)]
    command: Commands,
}

/// Enum defining all available subcommands for the helper tool
#[derive(Subcommand)]
enum Commands {
    /// Generate seeds from RISC-V SBI documentation
    GenerateSeed(GenerateSeed),
    /// Generate host-side layered harness seeds
    GenerateHostSeeds(GenerateHostSeeds),
    /// Generate RustSBI-oriented multi-call exec seeds
    GenerateRustsbiScenarios(GenerateRustsbiScenarios),
    /// Generate sequence seeds for OpenSBI, RustSBI, or both
    GenerateSequenceSeeds(GenerateSequenceSeeds),
    /// Print the current exec call registry
    ListCalls,
    /// Encode a TOML input into syzkaller-style exec bytes
    EncodeExecInput(ParseBinaryInput),
    /// Encode a sequence JSON file into a `.seq` binary
    EncodeSequence(SequenceInput),
    /// Print a human-readable description of a `.seq` sequence
    DescribeSequence(ParseBinaryInput),
    /// Print shared-memory coverage buffer information from the injector ELF
    CoverageInfo(CoverageInfo),
    /// Execute one input and export shared-memory coverage artifacts
    CollectCoverage(CollectCoverage),
    /// Internal worker subcommand used by `collect-coverage --timeout-ms`
    #[clap(hide = true)]
    CollectCoverageOnce(CollectCoverage),
    /// Import Linux-style sbi_ecall samples into TOML corpus seeds
    ImportLinuxCorpus(ImportLinuxCorpus),
    /// Minimize a stable-hang `.exec` into a shorter reproducer
    MinimizeHang(MinimizeHang),
    /// Import an `.exec` or `.toml` input into sequence format
    ImportExecAsSequence(SequenceInput),
    /// Run the SBI firmware using the given input
    Run(RunArgs),
    /// Internal worker subcommand used by `run --timeout-ms`
    #[clap(hide = true)]
    RunOnce(RunArgs),
    /// Run the SBI firmware with GDB support using the given input
    Debug(RunArgs),
    /// Run one host-side layered harness input
    RunHostHarness(RunHostHarness),
    /// Run one sequence input against a host-harness backend
    RunSequence(RunSequence),
    /// Run one sequence input against both host-harness backends and diff the result
    DiffSequence(DiffSequence),
    /// Instrument SBI firmware source code with KASAN (support OpenSBI)
    InstrumentKasan(InstrumentKasan),
    /// Parse the input from a binary file
    ParseBinaryInput(ParseBinaryInput),
}

/// Arguments for seed generation command
#[derive(Args)]
struct GenerateSeed {
    /// Output directory for generated seeds
    output: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HostSeedMode {
    Ecall,
    PlatformFault,
    Fdt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HostTargetCli {
    Opensbi,
    Rustsbi,
}

#[derive(Args)]
struct GenerateHostSeeds {
    /// Target backend to generate seeds for
    #[arg(long, value_enum)]
    target_kind: HostTargetCli,

    /// Harness seed mode to generate
    #[arg(long, value_enum)]
    mode: HostSeedMode,

    /// Output directory for generated `.host` seeds
    output: PathBuf,
}

/// Arguments for RustSBI scenario generation
#[derive(Args)]
struct GenerateRustsbiScenarios {
    /// Output directory for generated `.exec` seeds
    output: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SequenceImplCli {
    Opensbi,
    Rustsbi,
    Both,
}

#[derive(Args)]
struct GenerateSequenceSeeds {
    /// Generate seeds for a specific implementation or for both
    #[arg(long, value_enum, default_value = "both")]
    target_kind: SequenceImplCli,

    /// Output directory for generated `.seq` seeds
    output: PathBuf,
}

/// Arguments for Linux corpus import
#[derive(Args)]
struct ImportLinuxCorpus {
    /// Path to the Linux-like C source file
    source: PathBuf,

    /// Output directory for generated seed files
    output: PathBuf,
}

/// Arguments for coverage buffer inspection
#[derive(Args)]
struct CoverageInfo {
    /// Path to the injector ELF
    injector: PathBuf,
}

#[derive(Args)]
struct SequenceInput {
    /// Input file
    input: PathBuf,

    /// Optional output path
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for both Run and Debug commands
#[derive(Args)]
struct RunArgs {
    /// Specify the target program (binary format, e.g. "fw_dynamic.bin")
    target: PathBuf,

    /// Specify the injector program (elf format)
    injector: PathBuf,

    /// Specify the input file.
    input: PathBuf,

    /// Number of emulated harts passed to QEMU `-smp`
    #[arg(long, default_value_t = 1)]
    smp: u16,

    /// Optional wall-clock timeout for `helper run`
    #[arg(long)]
    timeout_ms: Option<u64>,
}

#[derive(Args)]
struct RunHostHarness {
    /// Host harness input file (`.host` or JSON)
    input: PathBuf,

    /// Optional JSON summary output path
    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Args)]
struct RunSequence {
    /// Sequence input file (`.seq` or JSON)
    input: PathBuf,

    /// Backend implementation to execute
    #[arg(long, value_enum)]
    target_kind: Option<HostTargetCli>,

    /// Optional JSON summary output path
    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Args)]
struct DiffSequence {
    /// Sequence input file (`.seq` or JSON)
    input: PathBuf,

    /// Optional JSON summary output path
    #[arg(long)]
    json_out: Option<PathBuf>,
}

/// Arguments for stable-hang minimization
#[derive(Args)]
struct MinimizeHang {
    /// Specify the target program (binary format, e.g. "fw_dynamic.bin")
    target: PathBuf,

    /// Specify the injector program (elf format)
    injector: PathBuf,

    /// Specify the input file.
    input: PathBuf,

    /// Output path for the minimized `.exec`
    output: PathBuf,

    /// Number of emulated harts passed to QEMU `-smp`
    #[arg(long, default_value_t = 1)]
    smp: u16,

    /// Wall-clock timeout per replay attempt
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,

    /// Number of replay attempts required to keep a candidate
    #[arg(long, default_value_t = 2)]
    attempts: u32,

    /// Optional JSON summary output path
    #[arg(long)]
    json_out: Option<PathBuf>,
}

/// Arguments for shared coverage collection
#[derive(Args)]
struct CollectCoverage {
    /// Specify the target program (binary format, e.g. "fw_dynamic.bin")
    target: PathBuf,

    /// Specify the injector program (elf format)
    injector: PathBuf,

    /// Specify the input file
    input: PathBuf,

    /// Number of emulated harts passed to QEMU `-smp`
    #[arg(long, default_value_t = 1)]
    smp: u16,

    /// Optional raw shared-memory coverage dump output path
    #[arg(long)]
    raw_out: Option<PathBuf>,

    /// Optional JSON summary output path
    #[arg(long)]
    json_out: Option<PathBuf>,

    /// Number of symbolized PCs to include in JSON/stdout
    #[arg(long, default_value_t = 8)]
    symbolize_limit: usize,

    /// Optional wall-clock timeout for `helper collect-coverage`
    #[arg(long)]
    timeout_ms: Option<u64>,
}

/// Arguments for KASAN instrumentation command
#[derive(Args)]
struct InstrumentKasan {
    /// Path to the source code to instrument
    path: PathBuf,
}

/// Arguments for parsing binary input command
#[derive(Args)]
struct ParseBinaryInput {
    /// Path to the binary input file to parse
    input: PathBuf,
}

/// Main function that parses CLI arguments and dispatches to the appropriate handler
fn main() {
    // Parse command line arguments
    let args = Cli::parse();

    // Execute the appropriate subcommand
    match args.command {
        Commands::GenerateSeed(g) => {
            // Generate seed inputs based on SBI documentation
            seed_generator::generate(g.output);
        }
        Commands::GenerateHostSeeds(args) => {
            generate_host_seeds(args.target_kind, args.mode, args.output);
        }
        Commands::GenerateRustsbiScenarios(args) => {
            scenario_generator::generate_rustsbi_scenarios(args.output);
        }
        Commands::GenerateSequenceSeeds(args) => {
            let (include_opensbi, include_rustsbi) = match args.target_kind {
                SequenceImplCli::Opensbi => (true, false),
                SequenceImplCli::Rustsbi => (false, true),
                SequenceImplCli::Both => (true, true),
            };
            if let Err(err) = sequence_runner::generate_sequence_seeds(
                args.output,
                include_opensbi,
                include_rustsbi,
            ) {
                eprintln!("generate-sequence-seeds failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::ListCalls => {
            list_calls();
        }
        Commands::EncodeExecInput(args) => {
            encode_exec_input(args.input);
        }
        Commands::EncodeSequence(args) => {
            if let Err(err) = sequence_runner::encode_sequence(args.input, args.output) {
                eprintln!("encode-sequence failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::DescribeSequence(args) => {
            if let Err(err) = sequence_runner::describe_sequence(args.input) {
                eprintln!("describe-sequence failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::CoverageInfo(args) => {
            coverage::print_shared_coverage_info(args.injector);
        }
        Commands::CollectCoverage(args) => {
            collect_coverage_with_optional_timeout(args);
        }
        Commands::CollectCoverageOnce(args) => {
            runner::collect_coverage(
                args.target,
                args.injector,
                args.input,
                args.smp,
                args.raw_out,
                args.json_out,
                args.symbolize_limit,
            );
        }
        Commands::ImportLinuxCorpus(args) => {
            import_linux_corpus(args.source, args.output);
        }
        Commands::MinimizeHang(args) => {
            if let Err(err) = minimizer::minimize_hang(
                args.target,
                args.injector,
                args.input,
                args.output,
                args.smp,
                args.timeout_ms,
                args.attempts,
                args.json_out,
            ) {
                eprintln!("minimize-hang failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::ImportExecAsSequence(args) => {
            if let Err(err) = sequence_runner::import_exec_as_sequence(args.input, args.output) {
                eprintln!("import-exec-as-sequence failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::Run(args) => {
            run_with_optional_timeout(args);
        }
        Commands::RunOnce(args) => {
            runner::run(args.target, args.injector, args.input, args.smp);
        }
        Commands::Debug(args) => {
            // Run the target firmware with GDB debugging support
            runner::debug(args.target, args.injector, args.input, args.smp);
        }
        Commands::RunHostHarness(args) => {
            run_host_harness(args.input, args.json_out);
        }
        Commands::RunSequence(args) => {
            let target_kind = match args.target_kind {
                Some(HostTargetCli::Opensbi) => HostTargetKind::OpenSbi,
                Some(HostTargetCli::Rustsbi) => HostTargetKind::RustSbi,
                None => load_sequence_target_hint(&args.input).unwrap_or(HostTargetKind::OpenSbi),
            };
            if let Err(err) = sequence_runner::run_sequence(args.input, target_kind, args.json_out)
            {
                eprintln!("run-sequence failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::DiffSequence(args) => {
            if let Err(err) = sequence_runner::diff_sequence(args.input, args.json_out) {
                eprintln!("diff-sequence failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::InstrumentKasan(args) => {
            // Instrument the target source code with KASAN
            instrumenter::instrument_kasan(args.path);
        }
        Commands::ParseBinaryInput(args) => {
            // Parse and convert binary input to a more readable format
            parse_binary_input(args.input);
        }
    }
}

fn run_with_optional_timeout(args: RunArgs) {
    let Some(timeout_ms) = args.timeout_ms.filter(|value| *value > 0) else {
        runner::run(args.target, args.injector, args.input, args.smp);
        return;
    };

    let current_exe = std::env::current_exe().expect("resolve current helper executable");
    let mut child = Command::new(current_exe)
        .arg("run-once")
        .arg(&args.target)
        .arg(&args.injector)
        .arg(&args.input)
        .arg("--smp")
        .arg(args.smp.to_string())
        .spawn()
        .expect("spawn timeout-bounded helper child");

    let deadline = Duration::from_millis(timeout_ms);
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll timeout-bounded helper child") {
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
            return;
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            println!("Run finish. Exit kind: Timeout");
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn collect_coverage_with_optional_timeout(args: CollectCoverage) {
    let Some(timeout_ms) = args.timeout_ms.filter(|value| *value > 0) else {
        runner::collect_coverage(
            args.target,
            args.injector,
            args.input,
            args.smp,
            args.raw_out,
            args.json_out,
            args.symbolize_limit,
        );
        return;
    };

    let current_exe = std::env::current_exe().expect("resolve current helper executable");
    let mut child = Command::new(current_exe);
    child
        .arg("collect-coverage-once")
        .arg(&args.target)
        .arg(&args.injector)
        .arg(&args.input)
        .arg("--smp")
        .arg(args.smp.to_string())
        .arg("--symbolize-limit")
        .arg(args.symbolize_limit.to_string());

    if let Some(raw_out) = args.raw_out.as_ref() {
        child.arg("--raw-out").arg(raw_out);
    }
    if let Some(json_out) = args.json_out.as_ref() {
        child.arg("--json-out").arg(json_out);
    }

    let mut child = child
        .spawn()
        .expect("spawn timeout-bounded helper coverage child");

    let deadline = Duration::from_millis(timeout_ms);
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("poll timeout-bounded helper coverage child")
        {
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
            return;
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(raw_out) = args.raw_out.as_ref() {
                let _ = fs::remove_file(raw_out);
            }
            runner::emit_timeout_coverage_report(
                &args.target,
                &args.injector,
                &args.input,
                args.json_out,
            );
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Parse a binary input file and convert it to TOML format
///
/// This function reads a binary input file, converts it to an internal representation,
/// adds metadata including a hash for identification, and writes it to a TOML file
/// with a name based on the extension name, function ID, and hash.
///
/// # Arguments
///
/// * `input` - Path to the binary input file to parse
fn parse_binary_input(input: PathBuf) {
    // Read the binary input file
    let binary = fs::read(&input).expect("read input file");

    if let Ok(program) = sequence_program_from_bytes(&binary) {
        let hash = program.hash_string();
        let description_path = PathBuf::from(".").join(format!("sequence-program-{hash}.txt"));
        let json_path = PathBuf::from(".").join(format!("sequence-program-{hash}.json"));
        fs::write(&description_path, sequence_program_describe(&program))
            .expect(format!("write description file: {:?}", &description_path).as_str());
        fs::write(
            &json_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&program).expect("serialize sequence json")
            ),
        )
        .expect(format!("write sequence json: {:?}", &json_path).as_str());
        println!("Wrote {:?} and {:?}", description_path, json_path);
        return;
    }

    if let Ok(program) = exec_program_from_bytes(&binary) {
        let hash = format!("{:08x}", fxhash(&binary));
        let description_path = PathBuf::from(".").join(format!("exec-program-{hash}.txt"));
        fs::write(&description_path, exec_program_describe(&program))
            .expect(format!("write description file: {:?}", &description_path).as_str());
        if let Some(mut data) = exec_program_primary_input(&program) {
            data.metadata.source = format!("exec-binary-{}-{}", input.display(), hash);
            let toml_path = PathBuf::from(".").join(format!(
                "{}-{:x}-{}.toml",
                data.metadata.extension_name, data.args.fid, hash
            ));
            fs::write(&toml_path, input_to_toml(&data))
                .expect(format!("write toml file: {:?}", &toml_path).as_str());
            println!("Wrote {:?} and {:?}", description_path, toml_path);
        } else {
            println!("Wrote {:?}", description_path);
        }
        return;
    }

    // Convert binary to structured input data
    let mut data = input_from_binary(&binary);

    // Generate a hash string for the input
    let hash = data.hash_string();

    // Set the source metadata to identify where this input came from
    data.metadata.source = format!("binary-{}-{}", input.display(), hash);

    // Create a TOML filename based on the input properties
    let toml_path = PathBuf::from(".").join(format!(
        "{}-{:x}-{}.toml",
        data.metadata.extension_name, data.args.fid, hash
    ));

    // Write the structured data to a TOML file
    fs::write(&toml_path, input_to_toml(&data))
        .expect(format!("write toml file: {:?}", &toml_path).as_str());

    // Inform the user where the output was written
    println!("Wrote to {:?}", toml_path);
}

fn encode_exec_input(input: PathBuf) {
    let toml_content = fs::read_to_string(&input).expect("read input file");
    let input = fix_input_args(input_from_toml(&toml_content));
    let program = normalize_exec_program(exec_program_from_input(&input));
    let binary = exec_program_to_bytes(&program);
    let output_path = PathBuf::from(".").join(format!("{}.exec", input.hash_string()));
    fs::write(&output_path, binary).expect(format!("write exec file: {:?}", &output_path).as_str());
    println!("Wrote {:?}", output_path);
}

fn load_sequence_target_hint(path: &PathBuf) -> Option<HostTargetKind> {
    let raw = fs::read(path).ok()?;
    if raw.starts_with(SEQUENCE_MAGIC) {
        return sequence_program_from_bytes(&raw).ok()?.env.impl_hint;
    }
    let text = String::from_utf8(raw).ok()?;
    serde_json::from_str::<SequenceProgram>(&text)
        .ok()?
        .env
        .impl_hint
}

fn fxhash(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn list_calls() {
    validate_exec_call_table().expect("validate exec call table");
    println!("{}", format_exec_call_table());
}

fn import_linux_corpus(source: PathBuf, output: PathBuf) {
    let status = Command::new("python3")
        .arg("scripts/import-linux-sbi-corpus.py")
        .arg(&source)
        .arg(&output)
        .status()
        .expect("run Linux corpus import script");
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn generate_host_seeds(target_kind: HostTargetCli, mode: HostSeedMode, output: PathBuf) {
    fs::create_dir_all(&output).expect("create host harness seed output directory");
    let target_kind = match target_kind {
        HostTargetCli::Opensbi => HostTargetKind::OpenSbi,
        HostTargetCli::Rustsbi => HostTargetKind::RustSbi,
    };
    let seeds = match (target_kind, mode) {
        (HostTargetKind::OpenSbi, HostSeedMode::Ecall) => host_opensbi_ecall_seeds(),
        (HostTargetKind::OpenSbi, HostSeedMode::PlatformFault) => {
            host_opensbi_platform_fault_seeds()
        }
        (HostTargetKind::OpenSbi, HostSeedMode::Fdt) => host_opensbi_fdt_seeds(),
        (HostTargetKind::RustSbi, HostSeedMode::Ecall) => host_rustsbi_ecall_seeds(),
        (HostTargetKind::RustSbi, HostSeedMode::PlatformFault) => {
            host_rustsbi_platform_fault_seeds()
        }
        (HostTargetKind::RustSbi, HostSeedMode::Fdt) => host_rustsbi_fdt_seeds(),
    };
    let seed_count = seeds.len();

    for (name, input) in seeds {
        let bin_path = output.join(format!("{name}.host"));
        let json_path = output.join(format!("{name}.json"));
        fs::write(&bin_path, host_harness_input_to_bytes(&input))
            .expect(format!("write host seed binary: {:?}", &bin_path).as_str());
        fs::write(
            &json_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&input).expect("serialize host seed json")
            ),
        )
        .expect(format!("write host seed json: {:?}", &json_path).as_str());
    }

    println!(
        "Generated {} host-harness seeds in {}",
        seed_count,
        output.display()
    );
}

fn run_host_harness(input_path: PathBuf, json_out: Option<PathBuf>) {
    let input = load_host_harness_input(&input_path);
    let report = host_harness::run(&input).expect("run host harness input");
    let json = serde_json::to_string_pretty(&report).expect("serialize host harness report");
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{json}\n"))
            .expect(format!("write host harness json: {:?}", &json_out).as_str());
    }
    println!("{json}");
}

fn load_host_harness_input(path: &PathBuf) -> HostHarnessInput {
    let raw = fs::read(path).expect("read host harness input");
    if let Ok(input) = host_harness_input_from_bytes(&raw) {
        return input;
    }
    let json = String::from_utf8(raw).expect("host harness JSON should be UTF-8");
    serde_json::from_str(&json).expect("parse host harness JSON input")
}

fn host_opensbi_ecall_seeds() -> Vec<(String, HostHarnessInput)> {
    vec![
        (
            "base-get-spec-version".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x10, 0, [0; 6]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "base-get-spec-version".to_string(),
            },
        ),
        (
            "base-probe-hsm".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x10, 3, [0x4853_4d, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "base-probe-hsm".to_string(),
            },
        ),
        (
            "hsm-hart-status".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x4853_4d, 2, [0, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "hsm-hart-status".to_string(),
            },
        ),
        (
            "timer-set-timer".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x5449_4d45, 0, [0x1234_5678, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "timer-set-timer".to_string(),
            },
        ),
        (
            "console-write".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x4442_434e, 0, [12, 0x8000_1000, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: vec![HostMemoryRegion {
                    guest_addr: 0x8000_1000,
                    read: true,
                    write: true,
                    execute: false,
                    bytes: b"hello host!\n".to_vec(),
                }],
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "console-write".to_string(),
            },
        ),
        (
            "unknown-extension".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0xdead_beef, 0x55, [1, 2, 3, 4, 5, 6]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "unknown-extension".to_string(),
            },
        ),
    ]
}

fn host_opensbi_platform_fault_seeds() -> Vec<(String, HostHarnessInput)> {
    vec![
        (
            "ipi-raw-error".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x735049, 0, [1, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::raw_error(7),
                fdt_blob: Vec::new(),
                label: "ipi-raw-error".to_string(),
            },
        ),
        (
            "rfence-denied".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x5246_4e43, 1, [1, 0, 0, 0x1000, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::sbi_error(SbiError::Denied),
                fdt_blob: Vec::new(),
                label: "rfence-denied".to_string(),
            },
        ),
        (
            "console-duplicate".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x4442_434e, 0, [4, 0x8000_2000, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: vec![HostMemoryRegion {
                    guest_addr: 0x8000_2000,
                    read: true,
                    write: true,
                    execute: false,
                    bytes: b"ping".to_vec(),
                }],
                platform_fault: HostPlatformFaultProfile {
                    mode: HostPlatformFaultMode::None,
                    error: 0,
                    value: 0,
                    duplicate_side_effects: true,
                },
                fdt_blob: Vec::new(),
                label: "console-duplicate".to_string(),
            },
        ),
        (
            "hsm-start-timeout".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::OpenSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x4853_4d, 0, [1, 0x8020_0000, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Stopped,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::sbi_error(SbiError::Timeout),
                fdt_blob: Vec::new(),
                label: "hsm-start-timeout".to_string(),
            },
        ),
    ]
}

fn host_opensbi_fdt_seeds() -> Vec<(String, HostHarnessInput)> {
    vec![
        host_fdt_seed(
            HostTargetKind::OpenSbi,
            "fdt-minimal",
            FdtSeedVariant::Minimal,
        ),
        host_fdt_seed(
            HostTargetKind::OpenSbi,
            "fdt-missing-cpus",
            FdtSeedVariant::MissingCpus,
        ),
        host_fdt_seed(
            HostTargetKind::OpenSbi,
            "fdt-bad-coldboot-phandle",
            FdtSeedVariant::BadColdbootPhandle,
        ),
        host_fdt_seed(
            HostTargetKind::OpenSbi,
            "fdt-bad-heap-size",
            FdtSeedVariant::BadHeapSize,
        ),
    ]
}

fn host_rustsbi_ecall_seeds() -> Vec<(String, HostHarnessInput)> {
    vec![
        (
            "base-get-spec-version".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x10, 0, [0; 6]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "base-get-spec-version".to_string(),
            },
        ),
        (
            "base-probe-ipi".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x10, 3, [0x7350_49, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "base-probe-ipi".to_string(),
            },
        ),
        (
            "hsm-hart-status".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x4853_4d, 2, [0, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "hsm-hart-status".to_string(),
            },
        ),
        (
            "timer-set-timer".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x5449_4d45, 0, [0x1234_5678, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "timer-set-timer".to_string(),
            },
        ),
        (
            "console-write".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0x4442_434e, 0, [12, 0x8000_1000, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: vec![HostMemoryRegion {
                    guest_addr: 0x8000_1000,
                    read: true,
                    write: true,
                    execute: false,
                    bytes: b"hello host!\n".to_vec(),
                }],
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "console-write".to_string(),
            },
        ),
        (
            "unknown-extension".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::Ecall,
                call: HostCall::new(0xdead_beef, 0x55, [1, 2, 3, 4, 5, 6]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::none(),
                fdt_blob: Vec::new(),
                label: "unknown-extension".to_string(),
            },
        ),
    ]
}

fn host_rustsbi_platform_fault_seeds() -> Vec<(String, HostHarnessInput)> {
    vec![
        (
            "ipi-raw-error".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x7350_49, 0, [1, 0, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::raw_error(7),
                fdt_blob: Vec::new(),
                label: "ipi-raw-error".to_string(),
            },
        ),
        (
            "rfence-denied".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x5246_4e43, 1, [1, 0, 0, 0x1000, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::sbi_error(SbiError::Denied),
                fdt_blob: Vec::new(),
                label: "rfence-denied".to_string(),
            },
        ),
        (
            "console-duplicate".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x4442_434e, 0, [4, 0x8000_2000, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Started,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: vec![HostMemoryRegion {
                    guest_addr: 0x8000_2000,
                    read: true,
                    write: true,
                    execute: false,
                    bytes: b"ping".to_vec(),
                }],
                platform_fault: HostPlatformFaultProfile {
                    mode: HostPlatformFaultMode::None,
                    error: 0,
                    value: 0,
                    duplicate_side_effects: true,
                },
                fdt_blob: Vec::new(),
                label: "console-duplicate".to_string(),
            },
        ),
        (
            "hsm-start-timeout".to_string(),
            HostHarnessInput {
                target_kind: HostTargetKind::RustSbi,
                mode: HostHarnessMode::PlatformFault,
                call: HostCall::new(0x4853_4d, 0, [1, 0x8020_0000, 0, 0, 0, 0]),
                hart_id: 0,
                hart_state: HostHartState::Stopped,
                privilege: HostPrivilegeState::Supervisor,
                memory_regions: Vec::new(),
                platform_fault: HostPlatformFaultProfile::sbi_error(SbiError::Timeout),
                fdt_blob: Vec::new(),
                label: "hsm-start-timeout".to_string(),
            },
        ),
    ]
}

fn host_rustsbi_fdt_seeds() -> Vec<(String, HostHarnessInput)> {
    vec![
        host_fdt_seed(
            HostTargetKind::RustSbi,
            "fdt-minimal",
            FdtSeedVariant::Minimal,
        ),
        host_fdt_seed(
            HostTargetKind::RustSbi,
            "fdt-missing-cpus",
            FdtSeedVariant::MissingCpus,
        ),
        host_fdt_seed(
            HostTargetKind::RustSbi,
            "fdt-bad-stdout-path",
            FdtSeedVariant::BadStdoutPath,
        ),
        host_fdt_seed(
            HostTargetKind::RustSbi,
            "fdt-bad-console-compatible",
            FdtSeedVariant::BadConsoleCompatible,
        ),
    ]
}

fn host_fdt_seed(
    target_kind: HostTargetKind,
    name: &str,
    variant: FdtSeedVariant,
) -> (String, HostHarnessInput) {
    (
        name.to_string(),
        HostHarnessInput {
            target_kind,
            mode: HostHarnessMode::Fdt,
            call: HostCall::new(0, 0, [0; 6]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: seed_fdt_blob(target_kind, variant).expect("build host FDT seed"),
            label: name.to_string(),
        },
    )
}
