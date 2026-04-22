use common::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::runner::{collect_coverage_report, collect_coverage_report_with_timeout};

/// Arguments for the coverage baseline command
#[derive(clap::Args)]
pub struct CoverageBaseline {
    /// Target firmware binary (e.g. fw_dynamic.bin)
    target: PathBuf,
    /// Injector ELF
    injector: PathBuf,
    /// Input directories to scan for seeds/inputs
    input_dirs: Vec<PathBuf>,
    /// Output path for baseline.json
    #[arg(short, long, default_value = "baseline.json")]
    output: PathBuf,
    /// Number of emulated harts passed to QEMU `-smp`
    #[arg(long, default_value_t = 1)]
    smp: u16,
    /// Number of symbolized PCs to include in reports
    #[arg(long, default_value_t = 8)]
    symbolize_limit: usize,
    /// Optional wall-clock timeout per input (ms)
    #[arg(long)]
    timeout_ms: Option<u64>,
}

/// Per-extension/function baseline statistics
#[derive(Default, serde::Serialize)]
struct BaselineEntry {
    unique_pcs: usize,
    total_pcs: usize,
    semantic_signature_count: usize,
    timeout_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcs_sample: Option<Vec<String>>,
}

/// Top-level baseline report
#[derive(serde::Serialize)]
struct BaselineReport {
    schema_version: String,
    target: String,
    injector: String,
    entries: HashMap<String, BaselineEntry>,
}

/// Recognized seed file extensions
const SEED_EXTENSIONS: &[&str] = &["toml", "exec", "seq", "bin", "raw"];

/// Check if a file path has a recognized seed extension
fn is_seed_file(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if SEED_EXTENSIONS.contains(&ext) => true,
        None => true, // no extension is treated as raw binary
        _ => false,
    }
}

/// Extract (eid, fid) pairs and semantic signature from an input file
fn extract_input_profile(path: &Path) -> Result<(Vec<(u64, u64)>, String), String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

    let ext = path.extension().and_then(|e| e.to_str());

    match ext {
        Some("toml") => {
            let content = String::from_utf8(bytes.clone())
                .map_err(|e| format!("utf8 {}: {}", path.display(), e))?;
            let input = fix_input_args(
                try_input_from_toml(&content)
                    .map_err(|e| format!("toml {}: {}", path.display(), e))?
            );
            let eid = input.args.eid;
            let fid = input.args.fid;
            let signature = format!("toml:{eid:08x}:{fid:x}:{}", content_hash_short(&bytes));
            Ok((vec![(eid, fid)], signature))
        }
        Some("seq") => {
            let program = sequence_program_from_bytes(&bytes)
                .map_err(|e| format!("seq {}: {}", path.display(), e))?;
            let mut pairs = Vec::new();
            for step in &program.steps {
                if let SequenceStep::Call { eid, fid, .. } = step {
                    pairs.push((*eid, *fid));
                }
            }
            let signature = sequence_program_semantic_signature(&program);
            Ok((pairs, signature))
        }
        Some("exec") => {
            let program = exec_program_from_bytes(&bytes)
                .map_err(|e| format!("exec {}: {}", path.display(), e))?;
            let mut pairs = Vec::new();
            for instr in &program.instructions {
                if let ExecInstr::Call { call_id, args, .. } = instr {
                    pairs.push(exec_call_eid_fid(*call_id, args)
                        .ok_or_else(|| format!("exec {}: cannot resolve call_id={}", path.display(), call_id))?);
                }
            }
            let signature = format!("exec:{}", content_hash_short(&bytes));
            Ok((pairs, signature))
        }
        None | Some("bin") | Some("raw") => {
            if bytes.len() >= 16 {
                let input = input_from_binary(&bytes);
                let eid = input.args.eid;
                let fid = input.args.fid;
                let signature = format!("raw:{eid:08x}:{fid:x}:{}", content_hash_short(&bytes));
                Ok((vec![(eid, fid)], signature))
            } else {
                Err(format!("raw binary too short (need >= 16 bytes): {}", path.display()))
            }
        }
        Some(other) => {
            Err(format!("unsupported extension '.{}' for seed file: {}", other, path.display()))
        }
    }
}

/// Map an exec call_id to (eid, fid).
/// For raw_ecall (call_id == 0), requires the first two args to be Const.
fn exec_call_eid_fid(call_id: u64, args: &[ExecArg]) -> Option<(u64, u64)> {
    let desc = EXEC_CALL_TABLE.iter().find(|d| d.id == call_id)?;
    match desc.kind {
        ExecCallKind::Fixed { eid, fid } => Some((eid, fid)),
        ExecCallKind::RawEcall => {
            if args.len() < 2 {
                return None;
            }
            let eid = arg_as_const_u64(&args[0])?;
            let fid = arg_as_const_u64(&args[1])?;
            Some((eid, fid))
        }
    }
}

/// Extract a u64 value from an ExecArg only if it is Const.
fn arg_as_const_u64(arg: &ExecArg) -> Option<u64> {
    match arg {
        ExecArg::Const { value, .. } => Some(*value),
        _ => None,
    }
}

/// Short content hash for signature deduplication
fn content_hash_short(bytes: &[u8]) -> String {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(bytes);
    format!("{:016x}", hasher.finish())
}

/// Collect coverage baseline across input directories
pub fn collect_coverage_baseline(args: CoverageBaseline) {
    // Validate target and injector exist
    if !args.target.exists() {
        eprintln!("coverage-baseline: target firmware does not exist: {}", args.target.display());
        std::process::exit(1);
    }
    if !args.injector.exists() {
        eprintln!("coverage-baseline: injector ELF does not exist: {}", args.injector.display());
        std::process::exit(1);
    }

    // Validate input directories exist
    for dir in &args.input_dirs {
        if !dir.exists() {
            eprintln!("coverage-baseline: input directory does not exist: {}", dir.display());
            std::process::exit(1);
        }
        if !dir.is_dir() {
            eprintln!("coverage-baseline: input path is not a directory: {}", dir.display());
            std::process::exit(1);
        }
    }

    // Gather all input files (filter to known seed extensions)
    let mut input_files = Vec::new();
    for dir in &args.input_dirs {
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() && is_seed_file(entry.path()) {
                input_files.push(entry.path().to_path_buf());
            }
        }
    }

    if input_files.is_empty() {
        eprintln!("coverage-baseline: no input files found in provided directories");
        std::process::exit(1);
    }

    println!("coverage-baseline: found {} input files", input_files.len());

    // Aggregated state per eid/fid
    #[derive(Default)]
    struct Agg {
        unique_pcs: HashSet<String>,
        total_pcs: usize,
        semantic_signatures: HashSet<String>,
        timeout_count: usize,
        pcs_sample: Vec<String>,
    }
    let mut agg: HashMap<String, Agg> = HashMap::new();

    let mut processed = 0usize;

    for input_path in &input_files {
        let profile = match extract_input_profile(input_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("coverage-baseline: failed to process {}: {}", input_path.display(), e);
                std::process::exit(1);
            }
        };

        let (eid_fid_pairs, signature) = profile;
        if eid_fid_pairs.is_empty() {
            eprintln!("coverage-baseline: no eid/fid pairs found in {}", input_path.display());
            std::process::exit(1);
        }

        // Run coverage collection (with optional per-input timeout)
        let report = match args.timeout_ms {
            Some(ms) if ms > 0 => collect_coverage_report_with_timeout(
                args.target.clone(),
                args.injector.clone(),
                input_path.clone(),
                args.smp,
                args.symbolize_limit,
                ms,
            ),
            _ => collect_coverage_report(
                args.target.clone(),
                args.injector.clone(),
                input_path.clone(),
                args.smp,
                args.symbolize_limit,
            ),
        };

        let is_timeout = report.exit_kind == "Timeout";

        // Hard-fail on coverage parse errors or fallback coverage
        if let Some(ref err) = report.coverage_parse_error {
            eprintln!("coverage-baseline: coverage parse error for {}: {}", input_path.display(), err);
            std::process::exit(1);
        }
        if report.fallback_to_qemu_edges {
            eprintln!("coverage-baseline: fallback QEMU edges for {} (shared buffer unavailable)", input_path.display());
            std::process::exit(1);
        }
        if report.coverage.is_none() && !is_timeout {
            eprintln!("coverage-baseline: no coverage data for {} (exit_kind={})", input_path.display(), report.exit_kind);
            std::process::exit(1);
        }

        // Collect PCs from report
        let mut report_pcs: Vec<String> = Vec::new();
        if let Some(cov) = report.coverage {
            report_pcs = cov.pcs;
        }

        // Aggregate per eid/fid
        for (eid, fid) in &eid_fid_pairs {
            let key = format!("0x{eid:08x}/0x{fid:x}");
            let entry = agg.entry(key).or_default();

            for pc in &report_pcs {
                if entry.unique_pcs.insert(pc.clone()) && entry.pcs_sample.len() < args.symbolize_limit {
                    entry.pcs_sample.push(pc.clone());
                }
                entry.total_pcs += 1;
            }
            entry.semantic_signatures.insert(signature.clone());
            if is_timeout {
                entry.timeout_count += 1;
            }
        }

        processed += 1;
        if processed % 10 == 0 {
            println!("coverage-baseline: processed {}/{} files", processed, input_files.len());
        }
    }

    // Build report
    let mut entries: HashMap<String, BaselineEntry> = HashMap::new();
    for (key, a) in agg {
        entries.insert(
            key,
            BaselineEntry {
                unique_pcs: a.unique_pcs.len(),
                total_pcs: a.total_pcs,
                semantic_signature_count: a.semantic_signatures.len(),
                timeout_count: a.timeout_count,
                pcs_sample: if a.pcs_sample.is_empty() { None } else { Some(a.pcs_sample) },
            },
        );
    }

    let report = BaselineReport {
        schema_version: "1.0.0".to_string(),
        target: args.target.display().to_string(),
        injector: args.injector.display().to_string(),
        entries,
    };

    let json = serde_json::to_string_pretty(&report).expect("serialize baseline report");
    fs::write(&args.output, format!("{json}\n"))
        .expect(format!("write baseline file: {:?}", &args.output).as_str());

    println!(
        "coverage-baseline: wrote {} entries to {} (processed {})",
        report.entries.len(),
        args.output.display(),
        processed
    );
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_toml_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let toml = r#"
[metadata]
source = "test"
extension_name = "Base"

[args]
eid = 0x10
fid = 0
arg0 = 1
arg1 = 2
arg2 = 3
arg3 = 4
arg4 = 5
arg5 = 6
"#;
        fs::write(&path, toml).unwrap();

        let (pairs, sig) = extract_input_profile(&path).unwrap();
        assert_eq!(pairs, vec![(0x10, 0)]);
        assert!(sig.starts_with("toml:00000010:0:"));
    }

    #[test]
    fn test_extract_malformed_toml_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        fs::write(&path, b"not valid toml [[[").unwrap();

        let result = extract_input_profile(&path);
        assert!(result.is_err(), "expected failure for malformed toml");
    }

    #[test]
    fn test_extract_seq_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.seq");
        let program = SequenceProgram {
            steps: vec![
                SequenceStep::SetTargetHart { hart_id: 0 },
                SequenceStep::Call {
                    label: "test".to_string(),
                    eid: 0x4853_4d,
                    fid: 0,
                    args: vec![],
                    expect: None,
                },
            ],
        };
        fs::write(&path, sequence_program_to_bytes(&program)).unwrap();

        let (pairs, sig) = extract_input_profile(&path).unwrap();
        assert_eq!(pairs, vec![(0x4853_4d, 0)]);
        assert!(sig.contains("hart:0"));
        assert!(sig.contains("call:48534d:0:"));
    }

    #[test]
    fn test_extract_fixed_exec_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.exec");
        let input = InputData {
            metadata: Metadata::from_call(0x4853_4d, 0, "test".to_string()),
            args: Args {
                eid: 0x4853_4d,
                fid: 0,
                arg0: 1,
                arg1: 2,
                arg2: 3,
                arg3: 4,
                arg4: 5,
                arg5: 6,
            },
        };
        let program = exec_program_from_input(&input);
        fs::write(&path, exec_program_to_bytes(&program)).unwrap();

        let (pairs, sig) = extract_input_profile(&path).unwrap();
        assert_eq!(pairs, vec![(0x4853_4d, 0)]);
        assert!(sig.starts_with("exec:"));
    }

    #[test]
    fn test_extract_raw_ecall_exec_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.exec");
        let input = InputData {
            metadata: Metadata::from_call(0x1234, 0x56, "test".to_string()),
            args: Args {
                eid: 0x1234,
                fid: 0x56,
                arg0: 1,
                arg1: 2,
                arg2: 3,
                arg3: 4,
                arg4: 5,
                arg5: 6,
            },
        };
        let program = exec_program_from_input(&input);
        fs::write(&path, exec_program_to_bytes(&program)).unwrap();

        let (pairs, sig) = extract_input_profile(&path).unwrap();
        assert_eq!(pairs, vec![(0x1234, 0x56)]);
        assert!(sig.starts_with("exec:"));
    }

    #[test]
    fn test_extract_invalid_input_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.xyz");
        fs::write(&path, b"not-a-valid-input").unwrap();

        let result = extract_input_profile(&path);
        assert!(result.is_err(), "expected failure for invalid input");
    }

    #[test]
    fn test_extract_malformed_exec_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.exec");
        fs::write(&path, b"SBIBAD01garbage").unwrap();

        let result = extract_input_profile(&path);
        assert!(result.is_err(), "expected failure for malformed .exec");
    }
}
