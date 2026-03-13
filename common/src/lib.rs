use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::num::ParseIntError;
use std::path::Path;

mod coverage;
mod exec;
mod host;
mod sequence;

pub use coverage::*;
pub use exec::*;
pub use host::*;
pub use sequence::*;

/// Represents the complete input data structure for SBI calls
/// Contains both metadata and arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputData {
    pub metadata: Metadata,
    pub args: Args,
}

/// Metadata information about the SBI call
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    pub extension_name: String, // Name of the SBI extension
    pub source: String,         // Source of the input (e.g., generated, manual)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<CallSchema>,
}

impl Metadata {
    pub fn from_call(eid: u64, fid: u64, source: String) -> Self {
        Self {
            extension_name: get_extension_name(eid),
            source,
            schema: Some(get_call_schema(eid, fid)),
        }
    }
}

/// Semantic role of an SBI argument.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentKind {
    #[default]
    Value,
    Address,
    AddressLow,
    AddressHigh,
    Size,
    Count,
    Flags,
    HartId,
    HartMaskAddress,
    SuspendType,
    Opaque,
}

/// Semantic schema for the six SBI arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSchema {
    #[serde(default)]
    pub arg0: ArgumentKind,
    #[serde(default)]
    pub arg1: ArgumentKind,
    #[serde(default)]
    pub arg2: ArgumentKind,
    #[serde(default)]
    pub arg3: ArgumentKind,
    #[serde(default)]
    pub arg4: ArgumentKind,
    #[serde(default)]
    pub arg5: ArgumentKind,
}

impl CallSchema {
    pub const fn new(
        arg0: ArgumentKind,
        arg1: ArgumentKind,
        arg2: ArgumentKind,
        arg3: ArgumentKind,
        arg4: ArgumentKind,
        arg5: ArgumentKind,
    ) -> Self {
        Self {
            arg0,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
        }
    }

    pub fn argument_kind(&self, index: usize) -> ArgumentKind {
        match index {
            0 => self.arg0,
            1 => self.arg1,
            2 => self.arg2,
            3 => self.arg3,
            4 => self.arg4,
            5 => self.arg5,
            _ => panic!("invalid argument index: {index}"),
        }
    }
}

/// Arguments for an SBI call
/// All fields are serialized/deserialized as hexadecimal strings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Args {
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub eid: u64, // Extension ID
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub fid: u64, // Function ID
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg0: u64, // First argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg1: u64, // Second argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg2: u64, // Third argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg3: u64, // Fourth argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg4: u64, // Fifth argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg5: u64, // Sixth argument
}

impl Args {
    pub fn get(&self, index: usize) -> u64 {
        match index {
            0 => self.arg0,
            1 => self.arg1,
            2 => self.arg2,
            3 => self.arg3,
            4 => self.arg4,
            5 => self.arg5,
            _ => panic!("invalid argument index: {index}"),
        }
    }

    pub fn set(&mut self, index: usize, value: u64) {
        match index {
            0 => self.arg0 = value,
            1 => self.arg1 = value,
            2 => self.arg2 = value,
            3 => self.arg3 = value,
            4 => self.arg4 = value,
            5 => self.arg5 = value,
            _ => panic!("invalid argument index: {index}"),
        }
    }
}

impl InputData {
    /// Generate a short hash string for the input data
    /// Used for uniquely identifying inputs
    pub fn hash_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input_to_binary(self));
        let result = hasher.finalize();
        result
            .iter()
            .take(4)
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
    }

    pub fn refresh_metadata(&mut self) {
        self.metadata.extension_name = get_extension_name(self.args.eid);
        self.metadata.schema = Some(get_call_schema(self.args.eid, self.args.fid));
    }

    pub fn schema(&self) -> CallSchema {
        self.metadata
            .schema
            .unwrap_or_else(|| get_call_schema(self.args.eid, self.args.fid))
    }
}

/// Custom serializer to convert u64 values to hexadecimal strings
fn serialize_to_hex<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{:X}", value);
    serializer.serialize_str(&hex_string)
}

/// Custom deserializer to convert hexadecimal strings to u64 values
fn deserialize_from_hex<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(deserializer)?;
    let cleaned_str = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str.as_str());
    u64::from_str_radix(cleaned_str, 16)
        .map_err(|e: ParseIntError| serde::de::Error::custom(format!("fail to parse int: {}", e)))
}

/// Parse TOML content into InputData structure
/// Handles conversion of hex literals in TOML to proper format
pub fn input_from_toml(toml_content: &str) -> InputData {
    try_input_from_toml(toml_content).expect("parse toml")
}

pub fn try_input_from_toml(toml_content: &str) -> Result<InputData, String> {
    let re = regex::Regex::new(r#"(=\s*)(0x[0-9A-Fa-f]+)"#).expect("compile regex");
    let toml_content = re.replace_all(&toml_content, r#"$1"$2""#).to_string();
    let mut input: InputData = toml::from_str(&toml_content).map_err(|err| err.to_string())?;
    input.refresh_metadata();
    Ok(input)
}

/// Size of binary input representation in bytes
pub const INPUT_SIZE: usize = 64;

/// Convert binary content to InputData structure
pub fn input_from_binary(binary_content: &[u8]) -> InputData {
    let mut binary_content = binary_content.to_vec();
    binary_content.resize(INPUT_SIZE, 0);

    let args = Args {
        eid: u64::from_le_bytes(binary_content[0..8].try_into().unwrap()),
        fid: u64::from_le_bytes(binary_content[8..16].try_into().unwrap()),
        arg0: u64::from_le_bytes(binary_content[16..24].try_into().unwrap()),
        arg1: u64::from_le_bytes(binary_content[24..32].try_into().unwrap()),
        arg2: u64::from_le_bytes(binary_content[32..40].try_into().unwrap()),
        arg3: u64::from_le_bytes(binary_content[40..48].try_into().unwrap()),
        arg4: u64::from_le_bytes(binary_content[48..56].try_into().unwrap()),
        arg5: u64::from_le_bytes(binary_content[56..64].try_into().unwrap()),
    };

    let mut input = InputData {
        metadata: Metadata::default(),
        args,
    };
    input.refresh_metadata();
    input
}

/// Convert InputData to TOML format
pub fn input_to_toml(input: &InputData) -> String {
    let toml_content = toml::to_string_pretty(&input).expect("serialize toml");
    let re = regex::Regex::new(r#""(0x[0-9A-Fa-f]+)""#).expect("compile regex");
    re.replace_all(&toml_content, "$1").to_string()
}

/// Convert InputData to binary format
pub fn input_to_binary(input: &InputData) -> Vec<u8> {
    let mut binary_content = Vec::new();
    binary_content.extend_from_slice(&input.args.eid.to_le_bytes());
    binary_content.extend_from_slice(&input.args.fid.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg0.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg1.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg2.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg3.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg4.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg5.to_le_bytes());
    binary_content
}

/// Check if an SBI call would cause the system to halt
pub fn is_halt_sbi_call(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x8);
    res = res || (eid == 0x53525354 && fid == 0);
    res = res || (eid == 0x48534D && fid == 0x1);
    res = res || (eid == 0x48534D && fid == 0x3);
    res
}

/// Get the extension name based on the extension ID (eid)
pub fn get_extension_name(eid: u64) -> String {
    match eid {
        0x0..=0xF_u64 => "legacy-".to_string() + eid.to_string().as_str(),
        0x10 => "base".to_string(),
        0x54494D45 => "timer".to_string(),
        0x735049 => "ipi".to_string(),
        0x52464E43 => "fence".to_string(),
        0x48534D => "hsm".to_string(),
        0x53525354 => "reset".to_string(),
        0x504D55 => "pmu".to_string(),
        0x4442434E => "console".to_string(),
        0x53555350 => "suspend".to_string(),
        0x43505043 => "cppc".to_string(),
        0x4E41434C => "nacl".to_string(),
        0x535441 => "sta".to_string(),
        0x535345 => "sse".to_string(),
        0x46574654 => "fwft".to_string(),
        0x44425452 => "dbtr".to_string(),
        0x4D505859 => "mpxy".to_string(),
        _ => "unknown".to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArtifactMode {
    Generic,
    RustSbiPrototyperDynamic,
    RustSbiPrototyperJump,
    RustSbiPrototyperPayload,
    RustSbiPrototyperOpaque,
}

pub fn detect_target_artifact_mode(path: &Path) -> TargetArtifactMode {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return TargetArtifactMode::Generic;
    };

    if !file_name.starts_with("rustsbi-prototyper") {
        return TargetArtifactMode::Generic;
    }
    if file_name.contains("-dynamic.")
        || file_name.ends_with("-dynamic.bin")
        || file_name.ends_with("-dynamic.elf")
    {
        return TargetArtifactMode::RustSbiPrototyperDynamic;
    }
    if file_name.contains("-jump.")
        || file_name.ends_with("-jump.bin")
        || file_name.ends_with("-jump.elf")
    {
        return TargetArtifactMode::RustSbiPrototyperJump;
    }
    if file_name.contains("-payload-") || file_name.contains("-payload.") {
        return TargetArtifactMode::RustSbiPrototyperPayload;
    }
    TargetArtifactMode::RustSbiPrototyperOpaque
}

pub fn validate_target_supports_external_kernel_payload(path: &Path) -> Result<(), String> {
    match detect_target_artifact_mode(path) {
        TargetArtifactMode::Generic | TargetArtifactMode::RustSbiPrototyperDynamic => Ok(()),
        TargetArtifactMode::RustSbiPrototyperJump => Err(format!(
            "target artifact '{}' is RustSBI jump mode and does not support external injector payloads; use rustsbi-prototyper-dynamic.bin instead",
            path.display()
        )),
        TargetArtifactMode::RustSbiPrototyperPayload => Err(format!(
            "target artifact '{}' embeds its own payload and does not support external injector payloads; use rustsbi-prototyper-dynamic.bin instead",
            path.display()
        )),
        TargetArtifactMode::RustSbiPrototyperOpaque => Err(format!(
            "target artifact '{}' is an ambiguous RustSBI prototyper build; use rustsbi-prototyper-dynamic.bin for fuzz/replay/injector workflows",
            path.display()
        )),
    }
}

// Target memory range modeled by the current harness.
const START_ADDRESS: u64 = 0x8000_0000;
const END_ADDRESS: u64 = 0x8fff_ffff;
const PAGE_SIZE: u64 = 0x1000;
const MAX_CONSOLE_WRITE_BYTES: u64 = 0x100;
const MAX_REMOTE_FENCE_SIZE: u64 = 0x20_000;
const MAX_SSE_ATTR_COUNT: u64 = 0x40;
const MAX_PMU_ENTRY_COUNT: u64 = 0x40;

/// Return the argument schema for a known SBI call.
pub fn get_call_schema(eid: u64, fid: u64) -> CallSchema {
    match (eid, fid) {
        (0x4, _) => CallSchema::new(
            ArgumentKind::HartMaskAddress,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x5, _) => CallSchema::new(
            ArgumentKind::HartMaskAddress,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x6, _) | (0x7, _) => CallSchema::new(
            ArgumentKind::HartMaskAddress,
            ArgumentKind::Address,
            ArgumentKind::Size,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x4442434E, 0) => CallSchema::new(
            ArgumentKind::Size,
            ArgumentKind::AddressLow,
            ArgumentKind::AddressHigh,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x535345, 0) | (0x535345, 1) => CallSchema::new(
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Count,
            ArgumentKind::AddressLow,
            ArgumentKind::AddressHigh,
            ArgumentKind::Value,
        ),
        (0x504D55, 0x8) => CallSchema::new(
            ArgumentKind::AddressLow,
            ArgumentKind::AddressHigh,
            ArgumentKind::Count,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x48534D, 0x0) => CallSchema::new(
            ArgumentKind::HartId,
            ArgumentKind::Address,
            ArgumentKind::Opaque,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x48534D, 0x2) => CallSchema::new(
            ArgumentKind::HartId,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        (0x48534D, 0x3) => CallSchema::new(
            ArgumentKind::SuspendType,
            ArgumentKind::Address,
            ArgumentKind::Opaque,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ),
        _ => CallSchema::default(),
    }
}

/// Normalize arguments according to their semantics so random byte mutations
/// are projected into more interesting SBI values.
pub fn fix_input_args(mut data: InputData) -> InputData {
    data.refresh_metadata();
    let schema = data.schema();

    for index in 0..6 {
        let value = data.args.get(index);
        let normalized = match schema.argument_kind(index) {
            ArgumentKind::Value | ArgumentKind::Opaque => value,
            ArgumentKind::Address | ArgumentKind::HartMaskAddress => normalize_address(value),
            ArgumentKind::AddressLow => normalize_address_low(value),
            ArgumentKind::AddressHigh => 0,
            ArgumentKind::Size => normalize_size(value),
            ArgumentKind::Count => normalize_count(value),
            ArgumentKind::Flags => normalize_flags(value),
            ArgumentKind::HartId => normalize_hart_id(value),
            ArgumentKind::SuspendType => normalize_suspend_type(value),
        };
        data.args.set(index, normalized);
    }

    apply_call_specific_constraints(&mut data);
    data
}

fn apply_call_specific_constraints(data: &mut InputData) {
    let eid = data.args.eid;
    let fid = data.args.fid;

    if is_remote_fence(eid, fid) {
        data.args.arg2 = data.args.arg2.min(MAX_REMOTE_FENCE_SIZE);
    }

    if is_sse_read_write(eid, fid) {
        data.args.arg2 = data.args.arg2.min(MAX_SSE_ATTR_COUNT);
        data.args.arg4 = 0;
    }

    if is_console_write(eid, fid) {
        data.args.arg0 = data.args.arg0.min(MAX_CONSOLE_WRITE_BYTES);
        data.args.arg2 = 0;
    }

    if is_get_pmu_event_info(eid, fid) {
        data.args.arg1 = 0;
        data.args.arg2 = data.args.arg2.min(MAX_PMU_ENTRY_COUNT);
    }
}

fn normalize_address(value: u64) -> u64 {
    let offset = value & (PAGE_SIZE - 1);
    let span = END_ADDRESS - START_ADDRESS;
    let in_range = START_ADDRESS + (value % (span + 1));
    let middle = START_ADDRESS + (span / 2);
    let candidates = [
        START_ADDRESS,
        START_ADDRESS.saturating_add(1),
        align_down(START_ADDRESS.saturating_add(offset), PAGE_SIZE),
        START_ADDRESS.saturating_add(offset),
        in_range,
        align_down(in_range, PAGE_SIZE),
        middle,
        middle.saturating_add(1),
        END_ADDRESS.saturating_sub(offset),
        END_ADDRESS,
        0,
        1,
        START_ADDRESS.saturating_sub(offset.saturating_add(1)),
        END_ADDRESS.saturating_add(offset.saturating_add(1)),
        u64::MAX.saturating_sub(offset),
    ];
    choose_interesting(value, &candidates)
}

fn normalize_address_low(value: u64) -> u64 {
    if value <= u64::from(u32::MAX) {
        return value;
    }
    normalize_address(value) & u64::from(u32::MAX)
}

fn normalize_size(value: u64) -> u64 {
    let candidates = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 0];
    choose_interesting(value, &candidates)
}

fn normalize_count(value: u64) -> u64 {
    let candidates = [1, 2, 4, 8, 16, 32, 64, 128, 0];
    choose_interesting(value, &candidates)
}

fn normalize_flags(value: u64) -> u64 {
    let candidates = [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 63, 127, 255];
    choose_interesting(value, &candidates)
}

fn normalize_hart_id(value: u64) -> u64 {
    let candidates = [0, 1, 2, 3, 4, 7, u64::MAX];
    choose_interesting(value, &candidates)
}

fn normalize_suspend_type(value: u64) -> u64 {
    let candidates = [0, 1, 2, 3, 4, 0x8000_0000, u64::MAX];
    choose_interesting(value, &candidates)
}

fn choose_interesting(value: u64, candidates: &[u64]) -> u64 {
    if candidates.contains(&value) {
        return value;
    }
    candidates[value as usize % candidates.len()]
}

fn align_down(value: u64, alignment: u64) -> u64 {
    debug_assert!(alignment.is_power_of_two());
    value & !(alignment - 1)
}

/// Check if the call is a remote fence operation
fn is_remote_fence(eid: u64, _: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x6);
    res = res || (eid == 0x7);
    res
}

/// Check if the call is an SSE read or write operation
fn is_sse_read_write(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x535345 && fid == 0x0);
    res = res || (eid == 0x535345 && fid == 0x1);
    res
}

/// Check if the call is a console write operation
fn is_console_write(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x4442434E && fid == 0);
    res
}

/// Check if the call is a PMU event info operation
fn is_get_pmu_event_info(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x504D55 && fid == 0x8);
    res
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SbiError {
    Success,
    Failed,
    NotSupported,
    InvalidParam,
    Denied,
    InvalidAddress,
    AlreadyAvailable,
    AlreadyStarted,
    AlreadyStopped,
    NoShmem,
    InvalidState,
    BadRange,
    Timeout,
    Io,
}

impl SbiError {
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            -1 => Some(Self::Failed),
            -2 => Some(Self::NotSupported),
            -3 => Some(Self::InvalidParam),
            -4 => Some(Self::Denied),
            -5 => Some(Self::InvalidAddress),
            -6 => Some(Self::AlreadyAvailable),
            -7 => Some(Self::AlreadyStarted),
            -8 => Some(Self::AlreadyStopped),
            -9 => Some(Self::NoShmem),
            -10 => Some(Self::InvalidState),
            -11 => Some(Self::BadRange),
            -12 => Some(Self::Timeout),
            -13 => Some(Self::Io),
            _ => None,
        }
    }

    pub fn code(self) -> i64 {
        match self {
            Self::Success => 0,
            Self::Failed => -1,
            Self::NotSupported => -2,
            Self::InvalidParam => -3,
            Self::Denied => -4,
            Self::InvalidAddress => -5,
            Self::AlreadyAvailable => -6,
            Self::AlreadyStarted => -7,
            Self::AlreadyStopped => -8,
            Self::NoShmem => -9,
            Self::InvalidState => -10,
            Self::BadRange => -11,
            Self::Timeout => -12,
            Self::Io => -13,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::NotSupported => "not_supported",
            Self::InvalidParam => "invalid_param",
            Self::Denied => "denied",
            Self::InvalidAddress => "invalid_address",
            Self::AlreadyAvailable => "already_available",
            Self::AlreadyStarted => "already_started",
            Self::AlreadyStopped => "already_stopped",
            Self::NoShmem => "no_shmem",
            Self::InvalidState => "invalid_state",
            Self::BadRange => "bad_range",
            Self::Timeout => "timeout",
            Self::Io => "io",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SbiRet {
    pub error: i64,
    pub value: u64,
}

impl SbiRet {
    pub fn from_regs(a0: u64, a1: u64) -> Self {
        Self {
            error: a0 as i64,
            value: a1,
        }
    }

    pub fn error_kind(self) -> Option<SbiError> {
        SbiError::from_code(self.error)
    }

    pub fn is_valid(self) -> bool {
        self.error_kind().is_some()
    }

    pub fn is_ok(self) -> bool {
        self.error == 0
    }
}

pub fn is_standard_sbi_error_code(raw_a0: u64) -> bool {
    SbiError::from_code(raw_a0 as i64).is_some()
}

/// Parse a string as a u64, supporting both decimal and hexadecimal (0x prefix) formats
pub fn parse_u64(s: &str) -> Result<u64, String> {
    let res = if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| format!("invalid hexadecimal eid: {}", s))?
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid decimal eid: {}", s))?
    };
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_mode_detection_distinguishes_rustsbi_variants() {
        assert_eq!(
            detect_target_artifact_mode(Path::new("rustsbi-prototyper-dynamic.bin")),
            TargetArtifactMode::RustSbiPrototyperDynamic
        );
        assert_eq!(
            detect_target_artifact_mode(Path::new("rustsbi-prototyper-jump.bin")),
            TargetArtifactMode::RustSbiPrototyperJump
        );
        assert_eq!(
            detect_target_artifact_mode(Path::new("rustsbi-prototyper-payload-test.bin")),
            TargetArtifactMode::RustSbiPrototyperPayload
        );
        assert_eq!(
            detect_target_artifact_mode(Path::new("rustsbi-prototyper.bin")),
            TargetArtifactMode::RustSbiPrototyperOpaque
        );
        assert_eq!(
            detect_target_artifact_mode(Path::new("fw_dynamic.bin")),
            TargetArtifactMode::Generic
        );
    }

    #[test]
    fn external_kernel_validation_rejects_wrong_rustsbi_artifacts() {
        assert!(
            validate_target_supports_external_kernel_payload(Path::new(
                "rustsbi-prototyper-dynamic.bin"
            ))
            .is_ok()
        );
        assert!(
            validate_target_supports_external_kernel_payload(Path::new("fw_dynamic.bin")).is_ok()
        );
        assert!(
            validate_target_supports_external_kernel_payload(Path::new("rustsbi-prototyper.bin"))
                .is_err()
        );
        assert!(
            validate_target_supports_external_kernel_payload(Path::new(
                "rustsbi-prototyper-jump.bin"
            ))
            .is_err()
        );
    }
}
