use crate::SbiError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HOST_HARNESS_MAGIC: &[u8; 8] = b"SBIHOST1";
pub const HOST_HARNESS_FUZZ_MAX_REGIONS: usize = 4;
pub const HOST_HARNESS_FUZZ_MAX_REGION_BYTES: usize = 256;
pub const HOST_HARNESS_FUZZ_MAX_HARTS: u8 = 64;
const HOST_HARNESS_FUZZ_DEFAULT_GUEST_BASE: u64 = 0x8000_0000;

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

    pub fn is_active(&self) -> bool {
        self.mode != HostPlatformFaultMode::None || self.duplicate_side_effects
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

#[derive(Debug, Clone, Serialize)]
pub struct HostHarnessReport {
    pub target_kind: HostTargetKind,
    pub backend: String,
    pub mode: HostHarnessMode,
    pub classification: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_memory_regions: Vec<HostMemoryRegion>,
    #[serde(flatten)]
    pub result: HostHarnessResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostHarnessResult {
    Ecall(HostEcallReport),
    Fdt(HostFdtReport),
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEcallReport {
    pub extid: u64,
    pub fid: u64,
    pub sbi_error: i64,
    pub sbi_error_name: Option<String>,
    pub value: u64,
    pub next_mepc: Option<u64>,
    pub extension_found: bool,
    pub side_effects: u32,
    pub console_bytes: u32,
    pub timer_value: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostFdtReport {
    pub status: i32,
    pub model: String,
    pub hart_count: u32,
    pub chosen_present: bool,
    pub config_present: bool,
    pub failure: Option<String>,
    pub details: HostFdtDetails,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum HostFdtDetails {
    OpenSbi {
        coldboot_hart_count: u32,
        heap_size: u32,
    },
    RustSbi {
        stdout_path_present: bool,
        console_present: bool,
        ipi_present: bool,
        reset_present: bool,
        memory_start: u64,
        memory_end: u64,
    },
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

    pub fn from_fuzz_bytes(bytes: &[u8]) -> Self {
        let mut cursor = FuzzCursor::new(bytes);
        let target_selector = cursor.read_u8();
        let mode_selector = cursor.read_u8();
        let raw_extid = cursor.read_u64();
        let raw_fid = cursor.read_u64();
        let mut raw_args = [0_u64; 6];
        for arg in &mut raw_args {
            *arg = cursor.read_u64();
        }
        let hart_selector = cursor.read_u8();
        let hart_state_selector = cursor.read_u8();
        let privilege_selector = cursor.read_u8();
        let fault_mode_selector = cursor.read_u8();
        let fault_error = cursor.read_i64();
        let fault_value = cursor.read_u64();
        let duplicate_side_effects = cursor.read_u8() % 2 == 1;
        let region_count = usize::from(cursor.read_u8()).min(HOST_HARNESS_FUZZ_MAX_REGIONS);

        let target_kind = match target_selector & 1 {
            0 => HostTargetKind::OpenSbi,
            _ => HostTargetKind::RustSbi,
        };
        let mode = match mode_selector % 3 {
            0 => HostHarnessMode::Ecall,
            1 => HostHarnessMode::PlatformFault,
            _ => HostHarnessMode::Fdt,
        };
        let extid = fuzz_extid(raw_extid, target_selector, mode);
        let fid = fuzz_fid(extid, raw_fid);
        let hart_id = u64::from(hart_selector % HOST_HARNESS_FUZZ_MAX_HARTS);
        let hart_state = match hart_state_selector % 4 {
            0 => HostHartState::Unknown,
            1 => HostHartState::Started,
            2 => HostHartState::Stopped,
            _ => HostHartState::Suspended,
        };
        let privilege = match privilege_selector % 3 {
            0 => HostPrivilegeState::User,
            1 => HostPrivilegeState::Supervisor,
            _ => HostPrivilegeState::Machine,
        };
        let platform_fault = HostPlatformFaultProfile {
            mode: match fault_mode_selector % 4 {
                0 => HostPlatformFaultMode::None,
                1 => HostPlatformFaultMode::ReturnSbiError,
                2 => HostPlatformFaultMode::ReturnRawError,
                _ => HostPlatformFaultMode::OverrideValue,
            },
            error: fault_error,
            value: fault_value,
            duplicate_side_effects,
        };

        let mut memory_regions = Vec::with_capacity(region_count);
        for region_index in 0..region_count {
            let raw_guest_addr = cursor.read_u64();
            let perm = cursor.read_u8();
            let mut len = usize::from(cursor.read_u16()).min(HOST_HARNESS_FUZZ_MAX_REGION_BYTES);
            if len == 0 && region_index == 0 {
                len = 16;
            }
            let mut region_bytes = cursor.take_vec(len);
            while region_bytes.len() < len {
                let fill = bytes
                    .get(region_bytes.len() % bytes.len().max(1))
                    .copied()
                    .unwrap_or(region_index as u8)
                    .wrapping_add(region_bytes.len() as u8);
                region_bytes.push(fill);
            }
            memory_regions.push(HostMemoryRegion {
                guest_addr: fuzz_region_guest_addr(raw_guest_addr, region_index, &raw_args),
                read: perm == 0 || perm & 0b001 != 0,
                write: perm == 0 || perm & 0b010 != 0,
                execute: perm & 0b100 != 0,
                bytes: region_bytes,
            });
        }

        let call_args = fuzz_call_args(extid, fid, raw_args, &memory_regions, bytes);
        let fdt_blob = match mode {
            HostHarnessMode::Fdt => {
                let blob = cursor.remaining_vec();
                if blob.is_empty() {
                    vec![0xd0, 0x0d, 0xfe, 0xed]
                } else {
                    blob.into_iter().take(4096).collect()
                }
            }
            _ => Vec::new(),
        };

        Self {
            target_kind,
            mode,
            call: HostCall::new(extid, fid, call_args),
            hart_id,
            hart_state,
            privilege,
            memory_regions,
            platform_fault,
            fdt_blob,
            label: format!("fuzz-{}-{}", bytes.len(), extid),
        }
    }

    pub fn to_fuzz_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(match self.target_kind {
            HostTargetKind::OpenSbi => 0,
            HostTargetKind::RustSbi => 1,
        });
        bytes.push(match self.mode {
            HostHarnessMode::Ecall => 0,
            HostHarnessMode::PlatformFault => 1,
            HostHarnessMode::Fdt => 2,
        });
        bytes.extend_from_slice(&self.call.extid.to_le_bytes());
        bytes.extend_from_slice(&self.call.fid.to_le_bytes());
        for arg in self.call.args {
            bytes.extend_from_slice(&arg.to_le_bytes());
        }
        bytes.push(self.hart_id as u8);
        bytes.push(match self.hart_state {
            HostHartState::Unknown => 0,
            HostHartState::Started => 1,
            HostHartState::Stopped => 2,
            HostHartState::Suspended => 3,
        });
        bytes.push(match self.privilege {
            HostPrivilegeState::User => 0,
            HostPrivilegeState::Supervisor => 1,
            HostPrivilegeState::Machine => 2,
        });
        bytes.push(match self.platform_fault.mode {
            HostPlatformFaultMode::None => 0,
            HostPlatformFaultMode::ReturnSbiError => 1,
            HostPlatformFaultMode::ReturnRawError => 2,
            HostPlatformFaultMode::OverrideValue => 3,
        });
        bytes.extend_from_slice(&self.platform_fault.error.to_le_bytes());
        bytes.extend_from_slice(&self.platform_fault.value.to_le_bytes());
        bytes.push(u8::from(self.platform_fault.duplicate_side_effects));
        bytes.push(self.memory_regions.len().min(HOST_HARNESS_FUZZ_MAX_REGIONS) as u8);
        for region in self
            .memory_regions
            .iter()
            .take(HOST_HARNESS_FUZZ_MAX_REGIONS)
        {
            bytes.extend_from_slice(&region.guest_addr.to_le_bytes());
            let perm = u8::from(region.read)
                | (u8::from(region.write) << 1)
                | (u8::from(region.execute) << 2);
            bytes.push(perm);
            let len = region.bytes.len().min(HOST_HARNESS_FUZZ_MAX_REGION_BYTES) as u16;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(&region.bytes[..usize::from(len)]);
        }
        if self.mode == HostHarnessMode::Fdt {
            bytes.extend_from_slice(&self.fdt_blob[..self.fdt_blob.len().min(4096)]);
        }
        bytes
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

struct FuzzCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> FuzzCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn read_u16(&mut self) -> u16 {
        let mut raw = [0_u8; 2];
        let chunk = self.take_slice(2);
        raw[..chunk.len()].copy_from_slice(chunk);
        u16::from_le_bytes(raw)
    }

    fn read_u64(&mut self) -> u64 {
        let mut raw = [0_u8; 8];
        let chunk = self.take_slice(8);
        raw[..chunk.len()].copy_from_slice(chunk);
        u64::from_le_bytes(raw)
    }

    fn read_i64(&mut self) -> i64 {
        let mut raw = [0_u8; 8];
        let chunk = self.take_slice(8);
        raw[..chunk.len()].copy_from_slice(chunk);
        i64::from_le_bytes(raw)
    }

    fn take_vec(&mut self, len: usize) -> Vec<u8> {
        self.take_slice(len).to_vec()
    }

    fn remaining_vec(&mut self) -> Vec<u8> {
        self.take_slice(self.bytes.len().saturating_sub(self.offset))
            .to_vec()
    }

    fn take_slice(&mut self, len: usize) -> &'a [u8] {
        let start = self.offset.min(self.bytes.len());
        let end = start.saturating_add(len).min(self.bytes.len());
        self.offset = end;
        &self.bytes[start..end]
    }
}

fn fuzz_extid(raw_extid: u64, selector: u8, mode: HostHarnessMode) -> u64 {
    const KNOWN_EXTENSIONS: [u64; 8] = [
        0x10,
        0x5449_4d45,
        0x735049,
        0x5246_4e43,
        0x4853_4d,
        0x4442_434e,
        0x5352_5354,
        0x504d55,
    ];

    if mode == HostHarnessMode::Fdt {
        return 0;
    }
    if raw_extid == 0 {
        return KNOWN_EXTENSIONS[usize::from(selector) % KNOWN_EXTENSIONS.len()];
    }
    if raw_extid < KNOWN_EXTENSIONS.len() as u64 {
        return KNOWN_EXTENSIONS[raw_extid as usize];
    }
    raw_extid
}

fn fuzz_fid(extid: u64, raw_fid: u64) -> u64 {
    if raw_fid != 0 {
        return raw_fid & 0xf;
    }
    match extid {
        0x10 => 0,
        0x4853_4d => 2,
        0x4442_434e => 0,
        0x5246_4e43 => 1,
        0x504d55 => 8,
        _ => 0,
    }
}

fn fuzz_region_guest_addr(raw_guest_addr: u64, region_index: usize, raw_args: &[u64; 6]) -> u64 {
    let anchor = raw_args
        .iter()
        .copied()
        .find(|value| *value >= HOST_HARNESS_FUZZ_DEFAULT_GUEST_BASE);
    let base = anchor.unwrap_or(
        HOST_HARNESS_FUZZ_DEFAULT_GUEST_BASE + (region_index as u64 * 0x1000),
    );

    match raw_guest_addr {
        0 => base,
        value if value < 0x1000 => base.saturating_add(value * 8),
        value => value,
    }
}

fn fuzz_call_args(
    extid: u64,
    fid: u64,
    mut args: [u64; 6],
    memory_regions: &[HostMemoryRegion],
    raw_bytes: &[u8],
) -> [u64; 6] {
    if let Some(region) = memory_regions.first() {
        if extid == 0x4442_434e && matches!(fid, 0 | 1) {
            if args[0] == 0 {
                args[0] = region.bytes.len() as u64;
            }
            if args[1] == 0 {
                args[1] = region.guest_addr;
            }
            args[2] = 0;
        }
        if extid == 0x504d55 && fid == 8 {
            if args[0] == 0 {
                args[0] = region.guest_addr;
            }
            args[1] = 0;
        }
    }

    match (extid, fid) {
        (0x10, 3) if args[0] == 0 => {
            args[0] = fuzz_extid(raw_bytes.first().copied().unwrap_or(5) as u64, 5, HostHarnessMode::Ecall);
        }
        (0x4853_4d, 0) => {
            if args[0] == 0 {
                args[0] = 1;
            }
            if args[1] == 0 {
                args[1] = 0x8020_0000;
            }
        }
        (0x5246_4e43, 1 | 2) if args[3] == 0 => {
            args[3] = 0x1000;
        }
        _ => {}
    }

    args
}
