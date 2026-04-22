use clap::{Args, Parser, Subcommand, ValueEnum};
use common::*;
use host_harness::{FdtSeedVariant, seed_fdt_blob};
use std::{fs, path::PathBuf, process::Command};

#[cfg(feature = "qemu")]
use std::{
    thread,
    time::{Duration, Instant},
};

// Import modules that implement different functionalities
#[cfg(feature = "qemu")]
#[cfg(feature = "qemu")]
mod baseline;
#[cfg(feature = "qemu")]
mod coverage;
mod instrumenter;
#[cfg(feature = "qemu")]
mod minimizer;
#[cfg(feature = "qemu")]
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
    /// Export the host-side libFuzzer corpus layout under one root directory
    ExportFuzzCorpus(ExportFuzzCorpus),
    /// Print the current exec call registry
    ListCalls,
    /// Encode a TOML input into syzkaller-style exec bytes
    EncodeExecInput(ParseBinaryInput),
    /// Encode a sequence JSON file into a `.seq` binary
    EncodeSequence(SequenceInput),
    /// Print a human-readable description of a `.seq` sequence
    DescribeSequence(ParseBinaryInput),
    /// Print shared-memory coverage buffer information from the injector ELF
    #[cfg(feature = "qemu")]
    CoverageInfo(CoverageInfo),
    /// Execute one input and export shared-memory coverage artifacts
    #[cfg(feature = "qemu")]
    CollectCoverage(CollectCoverage),
    /// Internal worker subcommand used by `collect-coverage --timeout-ms`
    #[clap(hide = true)]
    #[cfg(feature = "qemu")]
    CollectCoverageOnce(CollectCoverage),
    /// Import Linux-style sbi_ecall samples into TOML corpus seeds
    ImportLinuxCorpus(ImportLinuxCorpus),
    /// Minimize a stable-hang `.exec` into a shorter reproducer
    #[cfg(feature = "qemu")]
    MinimizeHang(MinimizeHang),
    /// Import an `.exec` or `.toml` input into sequence format
    ImportExecAsSequence(SequenceInput),
    /// Run the SBI firmware using the given input
    #[cfg(feature = "qemu")]
    Run(RunArgs),
    /// Internal worker subcommand used by `run --timeout-ms`
    #[clap(hide = true)]
    #[cfg(feature = "qemu")]
    RunOnce(RunArgs),
    /// Run the SBI firmware with GDB support using the given input
    #[cfg(feature = "qemu")]
    Debug(RunArgs),
    /// Run one host-side layered harness input
    RunHostHarness(RunHostHarness),
    /// Replay one host-side input against both backends and emit filtered diffs
    DiffHostHarness(RunHostHarness),
    /// Convert one host-harness crash/input into an `.exec` program when possible
    ConvertHostCrashToExec(ConvertHostCrashToExec),
    /// Run one sequence input against a host-harness backend
    RunSequence(RunSequence),
    /// Run one sequence input against both host-harness backends and diff the result
    DiffSequence(DiffSequence),
    /// Minimize a host-side sequence that triggers a spec or memory violation
    MinimizeSpecViolation(MinimizeSpecViolation),
    /// Internal helper to keep selected exec instructions for analysis
    #[clap(hide = true)]
    SliceExec(SliceExec),
    /// Internal helper to patch one exec call/setprops value for analysis
    #[clap(hide = true)]
    PatchExecValue(PatchExecValue),
    /// Instrument SBI firmware source code with KASAN (support OpenSBI)
    InstrumentKasan(InstrumentKasan),
    /// Parse the input from a binary file
    ParseBinaryInput(ParseBinaryInput),
    /// Collect coverage baseline across input directories and emit baseline.json
    #[cfg(feature = "qemu")]
    CoverageBaseline(baseline::CoverageBaseline),
}

/// Arguments for seed generation command
#[derive(Args)]
struct GenerateSeed {
    /// Output directory for generated seeds
    output: String,

    /// Optional TOML lock file describing the seed source repository and commit
    #[arg(long)]
    lock_file: Option<PathBuf>,

    /// Override the seed source repository URL or local git path
    #[arg(long)]
    repo_url: Option<String>,

    /// Override the git commit checked out before extracting the SBI docs
    #[arg(long)]
    commit: Option<String>,
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

#[derive(Args)]
struct ExportFuzzCorpus {
    /// Output root for the host-side fuzz corpus tree
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
#[cfg(feature = "qemu")]
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
#[cfg(feature = "qemu")]
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
struct ConvertHostCrashToExec {
    /// Host harness input file (`.host`, JSON, or raw fuzz crash)
    input: PathBuf,

    /// Output `.exec` file
    output: PathBuf,
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

#[derive(Args)]
struct MinimizeSpecViolation {
    /// Sequence input file (`.seq` or JSON)
    input: PathBuf,

    /// Backend implementation to execute
    #[arg(long, value_enum)]
    target_kind: HostTargetCli,

    /// Output path for the minimized sequence (`.seq` or JSON)
    output: PathBuf,

    /// Optional JSON summary output path
    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Args)]
struct SliceExec {
    /// Input `.exec` program
    input: PathBuf,

    /// Output `.exec` program
    output: PathBuf,

    /// Comma-separated instruction indexes to keep, e.g. `0,1,4`
    #[arg(long)]
    keep: String,
}

#[derive(Args)]
struct PatchExecValue {
    /// Input `.exec` program
    input: PathBuf,

    /// Output `.exec` program
    output: PathBuf,

    /// Instruction index to patch
    #[arg(long)]
    instr: usize,

    /// Argument index for call instructions, or `0` for setprops value
    #[arg(long)]
    arg: usize,

    /// Replacement value, decimal or `0x` hexadecimal
    #[arg(long)]
    value: String,
}

/// Arguments for stable-hang minimization
#[cfg(feature = "qemu")]
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
#[cfg(feature = "qemu")]
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
            if let Err(err) = seed_generator::generate(g.output, g.lock_file, g.repo_url, g.commit)
            {
                eprintln!("generate-seed failed: {err}");
                std::process::exit(1);
            }
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
        Commands::ExportFuzzCorpus(args) => {
            if let Err(err) = export_fuzz_corpus(args.output) {
                eprintln!("export-fuzz-corpus failed: {err}");
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
        #[cfg(feature = "qemu")]
        Commands::CoverageInfo(args) => {
            coverage::print_shared_coverage_info(args.injector);
        }
        #[cfg(feature = "qemu")]
        Commands::CollectCoverage(args) => {
            collect_coverage_with_optional_timeout(args);
        }
        #[cfg(feature = "qemu")]
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
        #[cfg(feature = "qemu")]
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
        #[cfg(feature = "qemu")]
        Commands::Run(args) => {
            run_with_optional_timeout(args);
        }
        #[cfg(feature = "qemu")]
        Commands::RunOnce(args) => {
            runner::run(args.target, args.injector, args.input, args.smp);
        }
        #[cfg(feature = "qemu")]
        Commands::Debug(args) => {
            // Run the target firmware with GDB debugging support
            runner::debug(args.target, args.injector, args.input, args.smp);
        }
        Commands::RunHostHarness(args) => {
            run_host_harness(args.input, args.json_out);
        }
        Commands::DiffHostHarness(args) => {
            diff_host_harness(args.input, args.json_out);
        }
        Commands::ConvertHostCrashToExec(args) => {
            if let Err(err) = convert_host_crash_to_exec(args.input, args.output) {
                eprintln!("convert-host-crash-to-exec failed: {err}");
                std::process::exit(1);
            }
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
        Commands::MinimizeSpecViolation(args) => {
            let target_kind = match args.target_kind {
                HostTargetCli::Opensbi => HostTargetKind::OpenSbi,
                HostTargetCli::Rustsbi => HostTargetKind::RustSbi,
            };
            if let Err(err) = sequence_runner::minimize_spec_violation(
                args.input,
                target_kind,
                args.output,
                args.json_out,
            ) {
                eprintln!("minimize-spec-violation failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::SliceExec(args) => {
            if let Err(err) = slice_exec(args.input, args.output, args.keep) {
                eprintln!("slice-exec failed: {err}");
                std::process::exit(1);
            }
        }
        Commands::PatchExecValue(args) => {
            if let Err(err) = patch_exec_value(args.input, args.output, args.instr, args.arg, args.value) {
                eprintln!("patch-exec-value failed: {err}");
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
        #[cfg(feature = "qemu")]
        Commands::CoverageBaseline(args) => {
            baseline::collect_coverage_baseline(args);
        }
    }
}

#[cfg(feature = "qemu")]
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

#[cfg(feature = "qemu")]
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
    let input = match try_input_from_toml(&toml_content) {
        Ok(data) => fix_input_args(data),
        Err(err) => {
            eprintln!("encode-exec-input: failed to parse TOML: {err}");
            std::process::exit(1);
        }
    };
    let program = normalize_exec_program(exec_program_from_input(&input));
    let binary = exec_program_to_bytes(&program);
    let output_path = PathBuf::from(".").join(format!("{}.exec", input.hash_string()));
    fs::write(&output_path, binary).expect(format!("write exec file: {:?}", &output_path).as_str());
    println!("Wrote {:?}", output_path);
}

fn slice_exec(input: PathBuf, output: PathBuf, keep: String) -> Result<(), String> {
    let raw = fs::read(&input).map_err(|err| err.to_string())?;
    let program = exec_program_from_bytes(&raw)?;
    let keep_indexes = keep
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<usize>()
                .map_err(|err| format!("invalid instruction index `{part}`: {err}"))
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if keep_indexes.is_empty() {
        return Err("slice-exec requires at least one instruction index".to_string());
    }

    let instructions = program
        .instructions
        .into_iter()
        .enumerate()
        .filter_map(|(index, instr)| keep_indexes.contains(&index).then_some(instr))
        .collect::<Vec<_>>();
    if instructions.is_empty() {
        return Err("slice-exec produced an empty program".to_string());
    }
    let sliced = ExecProgram { instructions };
    validate_exec_program(&sliced)?;
    fs::write(&output, exec_program_to_bytes(&sliced)).map_err(|err| err.to_string())?;
    println!("Wrote {}", output.display());
    Ok(())
}

fn patch_exec_value(
    input: PathBuf,
    output: PathBuf,
    instr: usize,
    arg: usize,
    value: String,
) -> Result<(), String> {
    let raw = fs::read(&input).map_err(|err| err.to_string())?;
    let mut program = exec_program_from_bytes(&raw)?;
    let parsed = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|err| format!("invalid hex value `{value}`: {err}"))?
    } else {
        value
            .parse::<u64>()
            .map_err(|err| format!("invalid value `{value}`: {err}"))?
    };

    let instr_ref = program
        .instructions
        .get_mut(instr)
        .ok_or_else(|| format!("instruction index {instr} out of range"))?;
    match instr_ref {
        ExecInstr::Call { args, .. } => {
            let arg_ref = args
                .get_mut(arg)
                .ok_or_else(|| format!("arg index {arg} out of range for call[{instr}]"))?;
            match arg_ref {
                ExecArg::Const { value, .. } => *value = parsed,
                other => {
                    return Err(format!(
                        "call[{instr}] arg[{arg}] is not a const arg: {other:?}"
                    ))
                }
            }
        }
        ExecInstr::SetProps { value } => {
            if arg != 0 {
                return Err("setprops only supports --arg 0".to_string());
            }
            *value = parsed;
        }
        other => {
            return Err(format!(
                "instruction[{instr}] is not patchable by patch-exec-value: {other:?}"
            ))
        }
    }

    validate_exec_program(&program)?;
    fs::write(&output, exec_program_to_bytes(&program)).map_err(|err| err.to_string())?;
    println!("Wrote {}", output.display());
    Ok(())
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
    if let Some(dir) = active_call_schema_registry_dir() {
        println!(
            "Schema registry: {} ({} entries across {} files)",
            dir.display(),
            active_call_schema_registry_entry_count(),
            active_call_schema_registry_source_count()
        );
    } else {
        println!("Schema registry: built-in defaults");
    }
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

fn export_fuzz_corpus(output: PathBuf) -> Result<(), String> {
    let opensbi_ecall = output.join("fuzz_ecall_opensbi");
    let rustsbi_ecall = output.join("fuzz_ecall_rustsbi");
    let sequence_both = output.join("fuzz_sequence_both");
    let diff_ecall = output.join("fuzz_diff_ecall");
    let diff_sequence = output.join("fuzz_diff_sequence");
    let smoke = output.join("fuzz_harness_smoke");

    generate_host_seeds(HostTargetCli::Opensbi, HostSeedMode::Ecall, opensbi_ecall.clone());
    generate_host_seeds(HostTargetCli::Rustsbi, HostSeedMode::Ecall, rustsbi_ecall.clone());
    sequence_runner::generate_sequence_seeds(sequence_both.clone(), true, true)?;

    fs::create_dir_all(&diff_ecall).map_err(|err| err.to_string())?;
    fs::create_dir_all(&diff_sequence).map_err(|err| err.to_string())?;
    fs::create_dir_all(&smoke).map_err(|err| err.to_string())?;

    copy_dir_files(&opensbi_ecall, &diff_ecall, "host")?;
    copy_dir_files(&rustsbi_ecall, &diff_ecall, "host")?;
    copy_dir_files(&sequence_both, &diff_sequence, "seq")?;
    fs::write(smoke.join("smoke_crash"), b"SBI_FUZZ_SMOKE_CRASH").map_err(|err| err.to_string())?;
    println!("Exported host fuzz corpus to {}", output.display());
    Ok(())
}

fn copy_dir_files(source: &PathBuf, target: &PathBuf, extension: &str) -> Result<(), String> {
    for entry in fs::read_dir(source).map_err(|err| err.to_string())? {
        let entry = entry.map_err(|err| err.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(extension) {
            continue;
        }
        let file_name = path
            .file_name()
            .ok_or_else(|| format!("missing file name for {}", path.display()))?;
        fs::copy(&path, target.join(file_name)).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn run_host_harness(input_path: PathBuf, json_out: Option<PathBuf>) {
    let input = load_host_harness_input(&input_path);
    let mem_oracle = MemoryOracle::snapshot_before(&input.memory_regions);
    let report = host_harness::run(&input).expect("run host harness input");
    let analysis = HostHarnessAnalysis {
        input: input.clone(),
        spec_violations: check_host_report(&input, &report).violations,
        memory_violations: mem_oracle.check_after(&input, &report),
        report,
    };
    let json = serde_json::to_string_pretty(&analysis).expect("serialize host harness report");
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{json}\n"))
            .expect(format!("write host harness json: {:?}", &json_out).as_str());
    }
    println!("{json}");
}

fn diff_host_harness(input_path: PathBuf, json_out: Option<PathBuf>) {
    let mut input = load_host_harness_input(&input_path);
    input.mode = HostHarnessMode::Ecall;
    input.platform_fault = HostPlatformFaultProfile::none();
    input.fdt_blob.clear();

    let mut opensbi_input = input.clone();
    opensbi_input.target_kind = HostTargetKind::OpenSbi;
    let mut rustsbi_input = input.clone();
    rustsbi_input.target_kind = HostTargetKind::RustSbi;

    let opensbi = host_harness::run(&opensbi_input).expect("run opensbi host diff input");
    let rustsbi = host_harness::run(&rustsbi_input).expect("run rustsbi host diff input");
    let diffs = diff_host_reports(&opensbi_input, &opensbi, &rustsbi, &DiffPolicy::default());
    let analysis = HostHarnessDiffAnalysis {
        input,
        opensbi,
        rustsbi,
        diffs,
    };
    let json = serde_json::to_string_pretty(&analysis).expect("serialize host harness diff");
    if let Some(json_out) = json_out {
        fs::write(&json_out, format!("{json}\n"))
            .expect(format!("write host harness diff json: {:?}", &json_out).as_str());
    }
    println!("{json}");
}

#[derive(serde::Serialize)]
struct HostHarnessAnalysis {
    input: HostHarnessInput,
    report: host_harness::HostHarnessReport,
    spec_violations: Vec<SpecViolation>,
    memory_violations: Vec<MemoryViolation>,
}

#[derive(serde::Serialize)]
struct HostHarnessDiffAnalysis {
    input: HostHarnessInput,
    opensbi: host_harness::HostHarnessReport,
    rustsbi: host_harness::HostHarnessReport,
    diffs: Vec<DiffResult>,
}

fn load_host_harness_input(path: &PathBuf) -> HostHarnessInput {
    let raw = fs::read(path).expect("read host harness input");
    if let Ok(input) = host_harness_input_from_bytes(&raw) {
        return input;
    }
    if let Ok(json) = String::from_utf8(raw.clone()) {
        if let Ok(input) = serde_json::from_str(&json) {
            return input;
        }
    }
    HostHarnessInput::from_fuzz_bytes(&raw)
}

fn convert_host_crash_to_exec(input_path: PathBuf, output: PathBuf) -> Result<(), String> {
    let input = load_host_harness_input(&input_path);
    if input.mode == HostHarnessMode::Fdt {
        return Err("FDT host inputs cannot be lowered into .exec".to_string());
    }
    if input.platform_fault.mode != HostPlatformFaultMode::None {
        return Err(
            "platform fault host inputs are host-specific and cannot be lowered into .exec"
                .to_string(),
        );
    }

    let program = host_input_to_sequence_program(&input)?;
    let exec = common::sequence_program_to_exec(&program)?;
    fs::write(&output, common::exec_program_to_bytes(&exec)).map_err(|err| err.to_string())?;
    println!("Wrote {}", output.display());
    Ok(())
}

fn host_input_to_sequence_program(input: &HostHarnessInput) -> Result<SequenceProgram, String> {
    let mut memory = Vec::new();
    let mut matched_objects = [None, None, None, None, None, None];
    for (index, region) in input.memory_regions.iter().enumerate() {
        let id = format!("mem{index}");
        for (arg_index, arg) in input.call.args.iter().enumerate() {
            if *arg == region.guest_addr || *arg == region.bytes.len() as u64 {
                matched_objects[arg_index] = Some(id.clone());
            }
        }
        memory.push(SequenceMemoryObject {
            id,
            slot_offset: (index as u64) * 0x100,
            guest_addr: Some(region.guest_addr),
            read: region.read,
            write: region.write,
            execute: region.execute,
            bytes: region.bytes.clone(),
        });
    }

    let schema = get_call_schema(input.call.extid, input.call.fid);
    let args = (0..6)
        .map(|index| {
            let value = input.call.args[index];
            let object = matched_objects[index].clone();
            match schema.argument_kind(index) {
                ArgumentKind::Address => object
                    .map(|object| SequenceArg::MemoryAddr { object })
                    .unwrap_or(SequenceArg::Const { value }),
                ArgumentKind::HartMaskAddress => object
                    .map(|object| SequenceArg::MemoryAddr { object })
                    .unwrap_or(SequenceArg::Const { value }),
                ArgumentKind::AddressLow => object
                    .map(|object| SequenceArg::MemoryAddrLow { object })
                    .unwrap_or(SequenceArg::Const { value }),
                ArgumentKind::AddressHigh => {
                    if value == 0 {
                        matched_objects[index.saturating_sub(1)]
                            .clone()
                            .map(|object| SequenceArg::MemoryAddrHigh { object })
                            .unwrap_or(SequenceArg::Const { value })
                    } else {
                        SequenceArg::Const { value }
                    }
                }
                ArgumentKind::Size | ArgumentKind::Count => object
                    .map(|object| SequenceArg::MemoryLen { object })
                    .unwrap_or(SequenceArg::Const { value }),
                _ => SequenceArg::Const { value },
            }
        })
        .collect::<Vec<_>>();

    let mut steps = Vec::new();
    if input.hart_id != 0 {
        steps.push(SequenceStep::SetTargetHart {
            hart_id: input.hart_id,
        });
    }
    if input.hart_state != HostHartState::Started {
        steps.push(SequenceStep::SetHartState {
            hart_id: input.hart_id,
            state: input.hart_state,
        });
    }
    if input.privilege != HostPrivilegeState::Supervisor {
        steps.push(SequenceStep::SetPrivilege {
            privilege: input.privilege,
        });
    }
    let default_label = if input.label.trim().is_empty() {
        format!("host-{:x}-{:x}", input.call.extid, input.call.fid)
    } else {
        input.label.clone()
    };
    steps.push(SequenceStep::Call {
        label: default_label.clone(),
        eid: input.call.extid,
        fid: input.call.fid,
        args,
        expect: None,
    });

    let program = SequenceProgram {
        metadata: SequenceMetadata {
            name: default_label,
            source: format!("host-crash:{}", input.hash_string()),
            note: String::new(),
        },
        env: SequenceEnv {
            smp: (input.hart_id as u16).saturating_add(1).max(1),
            impl_hint: Some(input.target_kind),
            platform: "host-converted".to_string(),
        },
        memory,
        steps,
    };
    common::validate_sequence_program(&program)?;
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_input_to_sequence_program_maps_hart_mask_address_to_memory() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x7350_49, 0, [0x8000_3000, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: vec![HostMemoryRegion {
                guest_addr: 0x8000_3000,
                read: true,
                write: false,
                execute: false,
                bytes: vec![0x1],
            }],
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: String::new(),
        };

        let program = host_input_to_sequence_program(&input).expect("convert host input");
        assert_eq!(program.metadata.name, "host-735049-0");
        assert_eq!(program.env.platform, "host-converted");

        match &program.steps[0] {
            SequenceStep::Call { args, label, .. } => {
                assert_eq!(label, "host-735049-0");
                assert!(matches!(args[0], SequenceArg::MemoryAddr { .. }));
            }
            other => panic!("unexpected step: {other:?}"),
        }
    }
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
