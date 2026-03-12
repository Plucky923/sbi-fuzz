use crate::SbiError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HOST_HARNESS_MAGIC: &[u8; 8] = b"SBIHOST1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTargetKind {
    #[default]
    OpenSbi,
    RustSbi,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHarnessMode {
    #[default]
    Ecall,
    PlatformFault,
    Fdt,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHartState {
    Unknown,
    #[default]
    Started,
    Stopped,
    Suspended,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPrivilegeState {
    User,
    #[default]
    Supervisor,
    Machine,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatformFaultMode {
    #[default]
    None,
    ReturnSbiError,
    ReturnRawError,
    OverrideValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMemoryRegion {
    pub guest_addr: u64,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub execute: bool,
    #[serde(default)]
    pub bytes: Vec<u8>,
}

impl HostMemoryRegion {
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCall {
    pub extid: u64,
    pub fid: u64,
    pub args: [u64; 6],
}

impl HostCall {
    pub const fn new(extid: u64, fid: u64, args: [u64; 6]) -> Self {
        Self { extid, fid, args }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPlatformFaultProfile {
    #[serde(default)]
    pub mode: HostPlatformFaultMode,
    #[serde(default)]
    pub error: i64,
    #[serde(default)]
    pub value: u64,
    #[serde(default)]
    pub duplicate_side_effects: bool,
}

impl Default for HostPlatformFaultProfile {
    fn default() -> Self {
        Self {
            mode: HostPlatformFaultMode::None,
            error: 0,
            value: 0,
            duplicate_side_effects: false,
        }
    }
}

impl HostPlatformFaultProfile {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn sbi_error(error: SbiError) -> Self {
        Self {
            mode: HostPlatformFaultMode::ReturnSbiError,
            error: error.code(),
            value: 0,
            duplicate_side_effects: false,
        }
    }

    pub fn raw_error(error: i64) -> Self {
        Self {
            mode: HostPlatformFaultMode::ReturnRawError,
            error,
            value: 0,
            duplicate_side_effects: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHarnessInput {
    #[serde(default)]
    pub target_kind: HostTargetKind,
    #[serde(default)]
    pub mode: HostHarnessMode,
    pub call: HostCall,
    #[serde(default)]
    pub hart_id: u64,
    #[serde(default)]
    pub hart_state: HostHartState,
    #[serde(default)]
    pub privilege: HostPrivilegeState,
    #[serde(default)]
    pub memory_regions: Vec<HostMemoryRegion>,
    #[serde(default)]
    pub platform_fault: HostPlatformFaultProfile,
    #[serde(default)]
    pub fdt_blob: Vec<u8>,
    #[serde(default)]
    pub label: String,
}

impl HostHarnessInput {
    pub fn hash_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(host_harness_input_to_bytes(self));
        let result = hasher.finalize();
        result
            .iter()
            .take(4)
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
    }
}

pub fn host_harness_input_to_bytes(input: &HostHarnessInput) -> Vec<u8> {
    let payload = serde_json::to_vec(input).expect("serialize host harness input");
    let mut bytes = Vec::with_capacity(HOST_HARNESS_MAGIC.len() + 4 + payload.len());
    bytes.extend_from_slice(HOST_HARNESS_MAGIC);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

pub fn host_harness_input_from_bytes(bytes: &[u8]) -> Result<HostHarnessInput, String> {
    if bytes.len() < HOST_HARNESS_MAGIC.len() + 4 {
        return Err("host harness input too short".to_string());
    }
    if &bytes[..HOST_HARNESS_MAGIC.len()] != HOST_HARNESS_MAGIC {
        return Err("invalid host harness magic".to_string());
    }
    let body_len_offset = HOST_HARNESS_MAGIC.len();
    let body_len = u32::from_le_bytes(
        bytes[body_len_offset..body_len_offset + 4]
            .try_into()
            .expect("host harness header length slice"),
    ) as usize;
    let body = &bytes[body_len_offset + 4..];
    if body.len() != body_len {
        return Err(format!(
            "host harness payload length mismatch: header={body_len}, actual={}",
            body.len()
        ));
    }

    serde_json::from_slice(body).map_err(|err| format!("parse host harness payload: {err}"))
}
