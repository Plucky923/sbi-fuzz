use crate::{CallSchema, builtin_call_schema};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSchemaRegistry {
    entries: Vec<CallSchemaEntry>,
    sources: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallSchemaEntry {
    eid: u64,
    fid: Option<u64>,
    schema: CallSchema,
    source: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct CallSchemaRegistryFile {
    #[serde(default)]
    calls: Vec<RawCallSchemaEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct RawCallSchemaEntry {
    eid: u64,
    #[serde(default)]
    fid: Option<u64>,
    #[serde(flatten)]
    schema: CallSchema,
}

#[derive(Debug)]
struct DefaultSchemaRegistryState {
    dir: Option<PathBuf>,
    registry: Option<CallSchemaRegistry>,
}

static DEFAULT_SCHEMA_REGISTRY: OnceLock<DefaultSchemaRegistryState> = OnceLock::new();

impl CallSchemaRegistry {
    pub fn schema_for_call(&self, eid: u64, fid: u64) -> Option<CallSchema> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.eid == eid && entry.fid == Some(fid))
            .or_else(|| {
                self.entries
                    .iter()
                    .rev()
                    .find(|entry| entry.eid == eid && entry.fid.is_none())
            })
            .map(|entry| entry.schema)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn source_paths(&self) -> &[PathBuf] {
        &self.sources
    }
}

pub fn resolve_call_schema(
    registry: Option<&CallSchemaRegistry>,
    eid: u64,
    fid: u64,
) -> CallSchema {
    registry
        .and_then(|loaded| loaded.schema_for_call(eid, fid))
        .unwrap_or_else(|| builtin_call_schema(eid, fid))
}

pub fn load_call_schema_registry_from_dir(dir: &Path) -> Result<CallSchemaRegistry, String> {
    if !dir.is_dir() {
        return Err(format!(
            "schema registry directory does not exist: {}",
            dir.display()
        ));
    }

    let mut files = fs::read_dir(dir)
        .map_err(|err| format!("read schema registry directory {}: {err}", dir.display()))?
        .map(|entry| entry.map(|item| item.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read schema registry entries {}: {err}", dir.display()))?;
    files.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("toml"));
    files.sort();

    let mut entries = Vec::new();
    let mut sources = Vec::new();
    for path in files {
        let raw = fs::read_to_string(&path)
            .map_err(|err| format!("read schema file {}: {err}", path.display()))?;
        let parsed: CallSchemaRegistryFile = toml::from_str(&raw)
            .map_err(|err| format!("parse schema file {}: {err}", path.display()))?;
        if parsed.calls.is_empty() {
            continue;
        }
        sources.push(path.clone());
        entries.extend(parsed.calls.into_iter().map(|entry| CallSchemaEntry {
            eid: entry.eid,
            fid: entry.fid,
            schema: entry.schema,
            source: path.clone(),
        }));
    }

    Ok(CallSchemaRegistry { entries, sources })
}

fn discover_schema_registry_dir() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("SBIFUZZ_SCHEMA_DIR") {
        let explicit = explicit.trim();
        if !explicit.is_empty() {
            let path = PathBuf::from(explicit);
            if path.is_dir() {
                return Some(path);
            }
        }
    }

    if let Ok(current) = env::current_dir() {
        for ancestor in current.ancestors() {
            let candidate = ancestor.join("config").join("schemas");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }

    let manifest_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("config")
        .join("schemas");
    manifest_candidate.is_dir().then_some(manifest_candidate)
}

fn default_schema_registry_state() -> &'static DefaultSchemaRegistryState {
    DEFAULT_SCHEMA_REGISTRY.get_or_init(|| {
        let Some(dir) = discover_schema_registry_dir() else {
            return DefaultSchemaRegistryState {
                dir: None,
                registry: None,
            };
        };

        match load_call_schema_registry_from_dir(&dir) {
            Ok(registry) => DefaultSchemaRegistryState {
                dir: Some(dir),
                registry: Some(registry),
            },
            Err(err) => {
                eprintln!(
                    "Warning: failed to load schema registry from {}: {err}",
                    dir.display()
                );
                DefaultSchemaRegistryState {
                    dir: None,
                    registry: None,
                }
            }
        }
    })
}

pub fn default_call_schema_registry() -> Option<&'static CallSchemaRegistry> {
    default_schema_registry_state().registry.as_ref()
}

pub fn active_call_schema_registry_dir() -> Option<&'static PathBuf> {
    default_schema_registry_state().dir.as_ref()
}

pub fn active_call_schema_registry_entry_count() -> usize {
    default_call_schema_registry()
        .map(CallSchemaRegistry::entry_count)
        .unwrap_or(0)
}

pub fn active_call_schema_registry_source_count() -> usize {
    default_call_schema_registry()
        .map(|registry| registry.source_paths().len())
        .unwrap_or(0)
}
