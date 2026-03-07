use common::*;
use std::fs::{self, File, create_dir_all};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;
use walkdir::WalkDir;

// Clone a git repository to a temporary directory and return the path to it
fn clone_repository(url: &str) -> PathBuf {
    let temp_dir = tempdir().expect("create temp directory");
    let temp_path = temp_dir.into_path();
    println!(
        "Cloning repository to temp directory: {} source: {}",
        temp_path.display(),
        url
    );

    let mut last_error = String::new();
    for attempt in 1..=3 {
        let output = Command::new("git")
            .args(["-c", "http.version=HTTP/1.1", "clone", "--depth=1", url])
            .arg(&temp_path)
            .output()
            .expect("execute git clone command");

        if output.status.success() {
            return temp_path;
        }

        last_error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if attempt < 3 {
            println!(
                "Clone attempt {attempt} failed, retrying in 1s: {}",
                last_error
            );
            sleep(Duration::from_secs(1));
            let _ = fs::remove_dir_all(&temp_path);
            fs::create_dir_all(&temp_path).expect("recreate temp clone directory");
        }
    }

    panic!("Failed to clone repository after retries: {}", last_error);
}

// Parse an AsciiDoc file to extract SBI function information
// Returns a vector of tuples containing (function_name, fid, eid)
fn extract_sbi_function_listing(file_path: &Path) -> Vec<(String, String, String)> {
    let mut content = String::new();
    let mut file = File::open(file_path).expect("open file");
    file.read_to_string(&mut content).expect("read file");
    let mut functions = Vec::new();
    let mut in_function_section = false;
    let mut in_table = false;
    let mut skip_header = true;

    for line in content.lines() {
        if line.contains("=== Function Listing") {
            in_function_section = true;
            continue;
        }
        if !in_function_section {
            continue;
        }

        if line.contains("|===") {
            if !in_table {
                in_table = true;
                continue;
            } else {
                break;
            }
        }

        if in_table {
            if skip_header {
                skip_header = false;
                continue;
            }

            let parts: Vec<&str> = line
                .split('|')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();

            if parts.len() >= 4 {
                let function_name = parts[0].to_string();
                let fid = parts[2].to_string();
                let eid = parts[3].to_string();

                if !function_name.is_empty() && !fid.is_empty() && !eid.is_empty() {
                    functions.push((function_name, fid, eid));
                }
            }
        }
    }
    functions
}

// URL of the RISC-V SBI documentation repository
const SBI_DOC_REPO: &str = "https://github.com/riscv-non-isa/riscv-sbi-doc.git";

// Generate seed files for SBI fuzzing based on the official RISC-V SBI documentation
pub fn generate(output: String) {
    let output_dir = PathBuf::from(output);
    create_dir_all(&output_dir).expect("create output directory");

    let repo_dir = clone_repository(SBI_DOC_REPO);
    let src_dir = repo_dir.join("src");
    let mut count = 0;

    for entry in WalkDir::new(&src_dir) {
        let entry = entry.expect("read directory entry");
        let path = entry.path();

        if path.extension().unwrap_or_default() != "adoc" {
            continue;
        }

        let extension_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let functions = extract_sbi_function_listing(path);

        for (func_name, fid, eid) in functions {
            let clean_func_name = if let Some(stripped) = func_name.strip_prefix("sbi_") {
                stripped
            } else {
                &func_name
            };
            let eid = parse_u64(&eid).expect("parse eid");
            let fid = parse_u64(&fid).expect("parse fid");

            let data = fix_input_args(InputData {
                metadata: Metadata::from_call(
                    eid,
                    fid,
                    format!("sbifuzz-generate-{}-{}", extension_name, clean_func_name),
                ),
                args: Args {
                    eid,
                    fid,
                    arg0: 0,
                    arg1: 0,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                    arg5: 0,
                },
            });

            let toml_path = output_dir.join(format!("{}-{}.toml", extension_name, clean_func_name));
            fs::write(&toml_path, input_to_toml(&data))
                .expect(format!("write toml file: {:?}", &toml_path).as_str());
            count += 1;
        }
    }
    println!("Generated {} seed files", count);
}
