mod opensbi;
mod rustsbi;

use common::{HostHarnessInput, HostHarnessMode, HostTargetKind};
use serde::Serialize;

pub const FDT_SEED_BUFFER_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtSeedVariant {
    Minimal,
    MissingCpus,
    BadColdbootPhandle,
    BadHeapSize,
    BadStdoutPath,
    BadConsoleCompatible,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostHarnessReport {
    pub target_kind: HostTargetKind,
    pub backend: String,
    pub mode: HostHarnessMode,
    pub classification: String,
    pub signature: String,
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

pub fn run(input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
    match input.target_kind {
        HostTargetKind::OpenSbi => opensbi::run(input),
        HostTargetKind::RustSbi => rustsbi::run(input),
    }
}

pub fn seed_fdt_blob(
    target_kind: HostTargetKind,
    variant: FdtSeedVariant,
) -> Result<Vec<u8>, String> {
    match target_kind {
        HostTargetKind::OpenSbi => opensbi::seed_fdt_blob(variant),
        HostTargetKind::RustSbi => rustsbi::seed_fdt_blob(variant),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        HostCall, HostHartState, HostMemoryRegion, HostPlatformFaultMode, HostPlatformFaultProfile,
        HostPrivilegeState, SbiError,
    };

    #[test]
    fn opensbi_base_get_spec_version_runs() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x10, 0, [0; 6]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "opensbi-base".to_string(),
        };

        let report = run(&input).expect("run opensbi base ecall");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, 0);
                assert!(report.value > 0);
                assert!(report.extension_found);
                assert_eq!(report.next_mepc, Some(0x1004));
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[test]
    fn opensbi_platform_fault_raw_error_is_sanitized() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::PlatformFault,
            call: HostCall::new(0x735049, 0, [1, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::raw_error(7),
            fdt_blob: Vec::new(),
            label: "opensbi-ipi-raw-error".to_string(),
        };

        let report = run(&input).expect("run opensbi platform fault");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, SbiError::Failed.code());
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[test]
    fn rustsbi_base_get_spec_version_runs() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x10, 0, [0; 6]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "rustsbi-base".to_string(),
        };

        let report = run(&input).expect("run rustsbi base ecall");
        assert_eq!(report.target_kind, HostTargetKind::RustSbi);
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, 0);
                assert!(report.value > 0);
                assert!(report.extension_found);
                assert_eq!(report.next_mepc, None);
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[test]
    fn rustsbi_platform_fault_raw_error_is_preserved() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::PlatformFault,
            call: HostCall::new(0x735049, 0, [1, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::raw_error(7),
            fdt_blob: Vec::new(),
            label: "rustsbi-ipi-raw-error".to_string(),
        };

        let report = run(&input).expect("run rustsbi platform fault");
        assert_eq!(report.classification, "non_standard_error");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, 7);
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[test]
    fn rustsbi_console_duplicate_side_effects_are_visible() {
        let input = HostHarnessInput {
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
            label: "rustsbi-console-dup".to_string(),
        };

        let report = run(&input).expect("run rustsbi console write");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, 0);
                assert_eq!(report.console_bytes, 8);
                assert!(report.side_effects >= 2);
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[test]
    fn opensbi_minimal_fdt_seed_parses() {
        let blob =
            seed_fdt_blob(HostTargetKind::OpenSbi, FdtSeedVariant::Minimal).expect("build DTB");
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::Fdt,
            call: HostCall::new(0, 0, [0; 6]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: blob,
            label: "opensbi-fdt".to_string(),
        };

        let report = run(&input).expect("run opensbi fdt");
        match report.result {
            HostHarnessResult::Fdt(report) => {
                assert_eq!(report.status, 0);
                assert!(report.config_present);
                assert_eq!(report.hart_count, 1);
            }
            HostHarnessResult::Ecall(_) => panic!("expected fdt report"),
        }
    }

    #[test]
    fn rustsbi_bad_stdout_path_is_partial_config() {
        let blob = seed_fdt_blob(HostTargetKind::RustSbi, FdtSeedVariant::BadStdoutPath)
            .expect("build RustSBI DTB");
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Fdt,
            call: HostCall::new(0, 0, [0; 6]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: blob,
            label: "rustsbi-fdt".to_string(),
        };

        let report = run(&input).expect("run rustsbi fdt");
        assert_eq!(report.classification, "partial_config");
        match report.result {
            HostHarnessResult::Fdt(report) => match report.details {
                HostFdtDetails::RustSbi {
                    stdout_path_present,
                    console_present,
                    ..
                } => {
                    assert_eq!(report.hart_count, 1);
                    assert!(!stdout_path_present);
                    assert!(!console_present);
                }
                HostFdtDetails::OpenSbi { .. } => panic!("expected rustsbi details"),
            },
            HostHarnessResult::Ecall(_) => panic!("expected fdt report"),
        }
    }

    #[test]
    fn rustsbi_minimal_fdt_seed_parses() {
        let blob = seed_fdt_blob(HostTargetKind::RustSbi, FdtSeedVariant::Minimal)
            .expect("build RustSBI minimal DTB");
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Fdt,
            call: HostCall::new(0, 0, [0; 6]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: blob,
            label: "rustsbi-fdt-minimal".to_string(),
        };

        let report = run(&input).expect("run rustsbi minimal fdt");
        assert_eq!(report.classification, "ok");
        match report.result {
            HostHarnessResult::Fdt(report) => match report.details {
                HostFdtDetails::RustSbi {
                    stdout_path_present,
                    console_present,
                    ..
                } => {
                    assert_eq!(report.hart_count, 1);
                    assert!(stdout_path_present);
                    assert!(console_present);
                }
                HostFdtDetails::OpenSbi { .. } => panic!("expected rustsbi details"),
            },
            HostHarnessResult::Ecall(_) => panic!("expected fdt report"),
        }
    }
}
