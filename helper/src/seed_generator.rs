use common::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, create_dir_all};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;
use walkdir::WalkDir;

// URL of the RISC-V SBI documentation repository
const SBI_DOC_REPO: &str = "https://github.com/riscv-non-isa/riscv-sbi-doc.git";

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeedSourceConfig {
    repo_url: String,
    commit: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SeedSourceLock {
    #[serde(default)]
    repo_url: Option<String>,
    #[serde(default)]
    commit: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeedGenerationManifest {
    repo_url: String,
    requested_commit: Option<String>,
    resolved_commit: Option<String>,
    output_dir: String,
    generated_count: usize,
}

fn default_lock_file() -> Option<PathBuf> {
    let path = PathBuf::from("config/locks/riscv-sbi-doc.lock");
    path.exists().then_some(path)
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|item| {
        let trimmed = item.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn load_seed_source_config(
    lock_file: Option<&Path>,
    repo_url_override: Option<String>,
    commit_override: Option<String>,
) -> Result<SeedSourceConfig, String> {
    let mut config = SeedSourceConfig {
        repo_url: SBI_DOC_REPO.to_string(),
        commit: None,
    };

    if let Some(lock_path) = lock_file {
        let raw = fs::read_to_string(lock_path)
            .map_err(|err| format!("read lock file {}: {err}", lock_path.display()))?;
        let lock: SeedSourceLock = toml::from_str(&raw)
            .map_err(|err| format!("parse lock file {}: {err}", lock_path.display()))?;
        if let Some(repo_url) = normalize_optional_string(lock.repo_url) {
            config.repo_url = repo_url;
        }
        config.commit = normalize_optional_string(lock.commit);
    }

    if let Some(repo_url) = normalize_optional_string(repo_url_override) {
        config.repo_url = repo_url;
    }
    if let Some(commit) = normalize_optional_string(commit_override) {
        config.commit = Some(commit);
    }

    Ok(config)
}

// Clone a git repository to a temporary directory and return the path to it
fn clone_repository(config: &SeedSourceConfig) -> PathBuf {
    let temp_dir = tempdir().expect("create temp directory");
    let temp_path = temp_dir.into_path();
    println!(
        "Cloning repository to temp directory: {} source: {}{}",
        temp_path.display(),
        config.repo_url,
        config
            .commit
            .as_ref()
            .map(|commit| format!(" commit: {commit}"))
            .unwrap_or_default()
    );

    let mut last_error = String::new();
    for attempt in 1..=3 {
        let mut command = Command::new("git");
        command.arg("-c").arg("http.version=HTTP/1.1").arg("clone");
        if config.commit.is_none() {
            command.arg("--depth=1");
        }
        command.arg(&config.repo_url).arg(&temp_path);
        let output = command.output().expect("execute git clone command");

        if output.status.success() {
            if let Some(commit) = &config.commit {
                let checkout = Command::new("git")
                    .arg("-C")
                    .arg(&temp_path)
                    .args(["checkout", "--detach", commit])
                    .output()
                    .expect("execute git checkout command");
                if checkout.status.success() {
                    return temp_path;
                }
                last_error = String::from_utf8_lossy(&checkout.stderr).trim().to_string();
            } else {
                return temp_path;
            }
        }

        if last_error.is_empty() {
            last_error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        }
        if attempt < 3 {
            println!(
                "Clone attempt {attempt} failed, retrying in 1s: {}",
                last_error
            );
            sleep(Duration::from_secs(1));
            let _ = fs::remove_dir_all(&temp_path);
            fs::create_dir_all(&temp_path).expect("recreate temp clone directory");
            last_error.clear();
        }
    }

    panic!("Failed to clone repository after retries: {}", last_error);
}

fn resolve_repository_head(repo_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if head.is_empty() { None } else { Some(head) }
}

fn source_suffix_for_commit(commit: Option<&str>) -> String {
    commit
        .map(|value| format!("@{}", value.chars().take(12).collect::<String>()))
        .unwrap_or_default()
}

fn write_seed_manifest(
    output_dir: &Path,
    config: &SeedSourceConfig,
    resolved_commit: Option<&str>,
    count: usize,
) -> Result<(), String> {
    let manifest = SeedGenerationManifest {
        repo_url: config.repo_url.clone(),
        requested_commit: config.commit.clone(),
        resolved_commit: resolved_commit.map(str::to_string),
        output_dir: output_dir.display().to_string(),
        generated_count: count,
    };
    let payload = serde_json::to_string_pretty(&manifest)
        .map_err(|err| format!("serialize manifest: {err}"))?;
    fs::write(output_dir.join("seed-source.json"), format!("{payload}\n"))
        .map_err(|err| format!("write seed-source.json: {err}"))
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

// Generate seed files for SBI fuzzing based on the official RISC-V SBI documentation
pub fn generate(
    output: String,
    lock_file: Option<PathBuf>,
    repo_url: Option<String>,
    commit: Option<String>,
) -> Result<(), String> {
    let output_dir = PathBuf::from(output);
    create_dir_all(&output_dir).map_err(|err| format!("create output directory: {err}"))?;

    let lock_file = lock_file.or_else(default_lock_file);
    let config = load_seed_source_config(lock_file.as_deref(), repo_url, commit)?;
    let repo_dir = clone_repository(&config);
    let resolved_commit = resolve_repository_head(&repo_dir);
    let src_dir = repo_dir.join("src");
    let mut count = 0_usize;

    for entry in WalkDir::new(&src_dir) {
        let entry = entry.map_err(|err| format!("read directory entry: {err}"))?;
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
            let source_prefix = format!(
                "sbifuzz-generate-{}-{}{}",
                extension_name,
                clean_func_name,
                source_suffix_for_commit(resolved_commit.as_deref())
            );
            let file_prefix = format!("{}-{}", extension_name, clean_func_name);
            for variant in generate_seed_variants(eid, fid, &source_prefix) {
                let file_name = if variant.file_suffix.is_empty() {
                    format!("{file_prefix}.toml")
                } else {
                    format!("{file_prefix}-{}.toml", variant.file_suffix)
                };
                let toml_path = output_dir.join(file_name);
                fs::write(&toml_path, input_to_toml(&variant.input))
                    .map_err(|err| format!("write toml file {}: {err}", toml_path.display()))?;
                count += 1;
            }
        }
    }
    write_seed_manifest(&output_dir, &config, resolved_commit.as_deref(), count)?;
    println!("Generated {} seed files", count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_seed_source_config_uses_lock_file_defaults() {
        let temp_dir = tempdir().expect("create tempdir");
        let lock_path = temp_dir.path().join("source.lock");
        fs::write(
            &lock_path,
            "repo_url = \"https://example.com/docs.git\"\ncommit = \"abc123\"\n",
        )
        .expect("write lock file");

        let config =
            load_seed_source_config(Some(&lock_path), None, None).expect("load seed config");
        assert_eq!(
            config,
            SeedSourceConfig {
                repo_url: "https://example.com/docs.git".to_string(),
                commit: Some("abc123".to_string()),
            }
        );
    }

    #[test]
    fn load_seed_source_config_cli_overrides_lock_file() {
        let temp_dir = tempdir().expect("create tempdir");
        let lock_path = temp_dir.path().join("source.lock");
        fs::write(
            &lock_path,
            "repo_url = \"https://example.com/docs.git\"\ncommit = \"abc123\"\n",
        )
        .expect("write lock file");

        let config = load_seed_source_config(
            Some(&lock_path),
            Some("https://override.local/docs.git".to_string()),
            Some("deadbeef".to_string()),
        )
        .expect("load seed config");
        assert_eq!(
            config,
            SeedSourceConfig {
                repo_url: "https://override.local/docs.git".to_string(),
                commit: Some("deadbeef".to_string()),
            }
        );
    }
}
