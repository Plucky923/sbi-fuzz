use clap::{Args, Parser, Subcommand};
use common::*;
use std::{fs, path::PathBuf, process::Command};

// Import modules that implement different functionalities
mod instrumenter;
mod runner;
mod seed_generator;

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
    /// Print the current exec call registry
    ListCalls,
    /// Encode a TOML input into syzkaller-style exec bytes
    EncodeExecInput(ParseBinaryInput),
    /// Import Linux-style sbi_ecall samples into TOML corpus seeds
    ImportLinuxCorpus(ImportLinuxCorpus),
    /// Run the SBI firmware using the given input
    Run(RunArgs),
    /// Run the SBI firmware with GDB support using the given input
    Debug(RunArgs),
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

/// Arguments for Linux corpus import
#[derive(Args)]
struct ImportLinuxCorpus {
    /// Path to the Linux-like C source file
    source: PathBuf,

    /// Output directory for generated seed files
    output: PathBuf,
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
        Commands::ListCalls => {
            list_calls();
        }
        Commands::EncodeExecInput(args) => {
            encode_exec_input(args.input);
        }
        Commands::ImportLinuxCorpus(args) => {
            import_linux_corpus(args.source, args.output);
        }
        Commands::Run(args) => {
            // Run the target firmware with the specified input
            runner::run(args.target, args.injector, args.input);
        }
        Commands::Debug(args) => {
            // Run the target firmware with GDB debugging support
            runner::debug(args.target, args.injector, args.input);
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
