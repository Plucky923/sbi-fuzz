use common::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::runner::{collect_coverage_report, CoverageRunReport};

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
    #[serde(flatten)]
    entries: HashMap<String, BaselineEntry>,
}

/// Extract (eid, fid) pairs and semantic signature from an input file
fn extract_input_profile(path: &Path) -> Result<(Vec<(u64, u64)>, String), String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

    let ext = path.extension().and_then(|e| e.to_str());

    match ext {
        Some("toml") => {
            let content = String::from_utf8(bytes.clone())
                .map_err(|e| format!("utf8 {}: {}", path.display(), e))?;
            let input = fix_input_args(input_from_toml(&content));
            let eid = input.args.eid;
            let fid = input.args.fid;
            let signature = format!("toml:{eid:08x}:{fid:x}:{}", sha256_short(&bytes));
            Ok((vec![(eid, fid)], signature))
        }
        Some("seq") | Some("json") => {
            let program = if ext == Some("json") {
                let content = String::from_utf8(bytes.clone())
                    .map_err(|e| format!("utf8 {}: {}", path.display(), e))?;
                serde_json::from_str::<SequenceProgram>(&content)
                    .map_err(|e| format!("json {}: {}", path.display(), e))?
            } else {
                sequence_program_from_bytes(&bytes)
                    .map_err(|e| format!("seq {}: {}", path.display(), e))?
            };
            let mut pairs = Vec::new();
            for step in &program.steps {
                if let SequenceStep::Call { eid, fid, .. } = step {
                    pairs.push((*eid, *fid));
                }
            }
            let signature = sequence_program_semantic_signature(&program);
            Ok((pairs, signature))
        }
        _ => {
            // Try exec binary first, then raw binary input
            if let Ok(program) = exec_program_from_bytes(&bytes) {
                let mut pairs = Vec::new();
                for instr in &program.instructions {
                    if let ExecInstr::Call { call_id, .. } = instr {
                        if let Some((eid, fid)) = exec_call_eid_fid(*call_id) {
                            pairs.push((eid, fid));
                        }
                    }
                }
                let signature = format!("exec:{}", sha256_short(&bytes));
                Ok((pairs, signature))
            } else if bytes.len() >= 16 {
                let input = input_from_binary(&bytes);
                let eid = input.args.eid;
                let fid = input.args.fid;
                let signature = format!("raw:{eid:08x}:{fid:x}:{}", sha256_short(&bytes));
                Ok((vec![(eid, fid)], signature))
            } else {
                Err(format!("unrecognized input format: {}", path.display()))
            }
        }
    }
}

/// Map an exec call_id to (eid, fid) if it is a fixed call
fn exec_call_eid_fid(call_id: u64) -> Option<(u64, u64)> {
    for desc in EXEC_CALL_TABLE.iter() {
        if desc.id == call_id {
            if let ExecCallKind::Fixed { eid, fid } = desc.kind {
                return Some((eid, fid));
            }
        }
    }
    None
}

/// Short SHA-256 hex digest of bytes
fn sha256_short(bytes: &[u8]) -> String {
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

    // Gather all input files
    let mut input_files = Vec::new();
    for dir in &args.input_dirs {
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
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
    let mut failed = 0usize;

    for input_path in &input_files {
        let profile = match extract_input_profile(input_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("coverage-baseline: skip {}: {}", input_path.display(), e);
                failed += 1;
                continue;
            }
        };

        let (eid_fid_pairs, signature) = profile;
        if eid_fid_pairs.is_empty() {
            eprintln!("coverage-baseline: skip {}: no eid/fid pairs found", input_path.display());
            failed += 1;
            continue;
        }

        // Run coverage collection
        let report = collect_coverage_report(
            args.target.clone(),
            args.injector.clone(),
            input_path.clone(),
            args.smp,
            args.symbolize_limit,
        );

        let is_timeout = report.exit_kind == "Timeout";

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
        "coverage-baseline: wrote {} to {} (processed {}, failed {})",
        report.entries.len(),
        args.output.display(),
        processed,
        failed
    );
}
