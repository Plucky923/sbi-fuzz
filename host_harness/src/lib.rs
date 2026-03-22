#[cfg(feature = "host-opensbi")]
mod opensbi;
#[cfg(not(feature = "host-opensbi"))]
mod opensbi {
    use crate::FdtSeedVariant;
    use common::{HostHarnessInput, HostHarnessReport};

    pub(crate) fn run(_input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
        Err(crate::backend_disabled("OpenSBI", "host-opensbi"))
    }

    pub(crate) fn seed_fdt_blob(_variant: FdtSeedVariant) -> Result<Vec<u8>, String> {
        Err(crate::backend_disabled("OpenSBI", "host-opensbi"))
    }
}

#[cfg(feature = "host-rustsbi")]
mod rustsbi;
#[cfg(not(feature = "host-rustsbi"))]
mod rustsbi {
    use crate::FdtSeedVariant;
    use common::{HostHarnessInput, HostHarnessReport};

    pub(crate) fn run(_input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
        Err(crate::backend_disabled("RustSBI", "host-rustsbi"))
    }

    pub(crate) fn seed_fdt_blob(_variant: FdtSeedVariant) -> Result<Vec<u8>, String> {
        Err(crate::backend_disabled("RustSBI", "host-rustsbi"))
    }
}

pub use common::{
    HostEcallReport, HostFdtDetails, HostFdtReport, HostHarnessReport, HostHarnessResult,
};
use common::{HostHarnessInput, HostTargetKind};

pub const FDT_SEED_BUFFER_CAPACITY: usize = 4096;

#[cfg(any(not(feature = "host-opensbi"), not(feature = "host-rustsbi")))]
fn backend_disabled(name: &str, feature: &str) -> String {
    format!("{name} host backend not built; enable the `{feature}` feature")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtSeedVariant {
    Minimal,
    MissingCpus,
    BadColdbootPhandle,
    BadHeapSize,
    BadStdoutPath,
    BadConsoleCompatible,
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
        HostCall, HostHarnessMode, HostHartState, HostMemoryRegion, HostPlatformFaultMode,
        HostPlatformFaultProfile, HostPrivilegeState, SbiError,
    };

    #[cfg(feature = "host-opensbi")]
    const OPEN_FDT_OOB_REPRO_BLOB: &[u8] = &[
        208, 13, 254, 237, 0, 0, 3, 7, 0, 0, 0, 56, 0, 0, 2, 184, 0, 0, 0, 40, 0, 0, 0, 17, 0, 0,
        0, 16, 0, 0, 0, 0, 0, 0, 0, 79, 0, 0, 2, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 18, 0, 0, 0, 33, 114, 105, 115, 99, 118, 45,
        118, 105, 114, 116, 105, 111, 44, 113, 101, 109, 117, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 18, 0,
        0, 0, 27, 114, 117, 115, 116, 115, 98, 105, 44, 113, 101, 109, 117, 45, 118, 105, 114, 116,
        0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 15, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0,
        0, 0, 0, 0, 2, 0, 0, 0, 1, 99, 104, 111, 115, 101, 110, 0, 0, 0, 0, 0, 3, 0, 0, 0, 21, 0,
        0, 0, 67, 47, 115, 111, 99, 47, 115, 101, 114, 105, 97, 108, 64, 49, 48, 48, 48, 48, 48,
        48, 48, 0, 0, 0, 15, 0, 0, 0, 2, 0, 0, 0, 1, 115, 111, 99, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0,
        0, 60, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 15, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
    ];

    #[cfg(feature = "host-opensbi")]
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

    #[cfg(feature = "host-opensbi")]
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

    #[cfg(feature = "host-rustsbi")]
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

    #[cfg(feature = "host-rustsbi")]
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

    #[cfg(feature = "host-rustsbi")]
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

    #[cfg(feature = "host-rustsbi")]
    #[test]
    fn rustsbi_console_read_updates_post_memory_snapshot() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x4442_434e, 1, [4, 0x8000_3000, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: vec![HostMemoryRegion {
                guest_addr: 0x8000_3000,
                read: true,
                write: true,
                execute: false,
                bytes: vec![0; 4],
            }],
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "rustsbi-console-read".to_string(),
        };

        let report = run(&input).expect("run rustsbi console read");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, 0);
                assert_eq!(
                    input.memory_regions[0].bytes,
                    vec![0, 0, 0, 0],
                    "input snapshot should remain immutable"
                );
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
        assert_eq!(report.post_memory_regions[0].bytes, b"RRRR");
    }

    #[cfg(feature = "host-opensbi")]
    #[test]
    fn opensbi_hsm_suspend_rejects_invalid_suspend_type() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x4853_4d, 3, [0x1234, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Unknown,
            privilege: HostPrivilegeState::Machine,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "opensbi-hsm-suspend-invalid-type".to_string(),
        };

        let report = run(&input).expect("run opensbi hsm suspend");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, SbiError::InvalidParam.code());
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[cfg(feature = "host-opensbi")]
    #[test]
    fn opensbi_pmu_counter_get_info_rejects_out_of_range_counter() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x504D55, 1, [8, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Machine,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "opensbi-pmu-counter-invalid".to_string(),
        };

        let report = run(&input).expect("run opensbi pmu get_info");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, SbiError::InvalidParam.code());
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[cfg(feature = "host-opensbi")]
    #[test]
    fn opensbi_hsm_status_rejects_invalid_hart() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x4853_4d, 2, [255, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "opensbi-hsm-status-invalid-hart".to_string(),
        };

        let report = run(&input).expect("run opensbi hsm status");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, SbiError::InvalidParam.code());
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[cfg(feature = "host-opensbi")]
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

    #[cfg(feature = "host-opensbi")]
    #[test]
    fn opensbi_truncated_fdt_is_reported_as_error() {
        let mut blob =
            seed_fdt_blob(HostTargetKind::OpenSbi, FdtSeedVariant::Minimal).expect("build DTB");
        blob.truncate(blob.len().saturating_sub(16));
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
            label: "opensbi-fdt-truncated".to_string(),
        };

        let report = run(&input).expect("run opensbi truncated fdt");
        assert_eq!(report.classification, "fdt_error");
        match report.result {
            HostHarnessResult::Fdt(report) => {
                assert_ne!(report.status, 0);
                assert!(report.failure.is_some());
            }
            HostHarnessResult::Ecall(_) => panic!("expected fdt report"),
        }
    }

    #[cfg(feature = "host-opensbi")]
    #[test]
    fn opensbi_known_fdt_oob_reproducer_is_now_reported_as_fdt_error() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::OpenSbi,
            mode: HostHarnessMode::Fdt,
            call: HostCall::new(0, 0, [0; 6]),
            hart_id: 1,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: OPEN_FDT_OOB_REPRO_BLOB.to_vec(),
            label: "opensbi-fdt-oob-repro".to_string(),
        };

        let report = run(&input).expect("run opensbi oob repro fdt");
        assert_eq!(report.classification, "fdt_error");
        match report.result {
            HostHarnessResult::Fdt(report) => {
                assert_ne!(report.status, 0);
                assert!(report.failure.is_some());
            }
            HostHarnessResult::Ecall(_) => panic!("expected fdt report"),
        }
    }

    #[cfg(feature = "host-rustsbi")]
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

    #[cfg(feature = "host-rustsbi")]
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

    #[cfg(feature = "host-rustsbi")]
    #[test]
    fn rustsbi_hsm_start_rejects_invalid_hart() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x4853_4d, 0, [255, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Unknown,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "rustsbi-hsm-start-invalid-hart".to_string(),
        };

        let report = run(&input).expect("run rustsbi hsm start");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, SbiError::InvalidParam.code());
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }

    #[cfg(feature = "host-rustsbi")]
    #[test]
    fn rustsbi_hsm_status_rejects_invalid_hart() {
        let input = HostHarnessInput {
            target_kind: HostTargetKind::RustSbi,
            mode: HostHarnessMode::Ecall,
            call: HostCall::new(0x4853_4d, 2, [255, 0, 0, 0, 0, 0]),
            hart_id: 0,
            hart_state: HostHartState::Started,
            privilege: HostPrivilegeState::Supervisor,
            memory_regions: Vec::new(),
            platform_fault: HostPlatformFaultProfile::none(),
            fdt_blob: Vec::new(),
            label: "rustsbi-hsm-status-invalid-hart".to_string(),
        };

        let report = run(&input).expect("run rustsbi hsm status");
        match report.result {
            HostHarnessResult::Ecall(report) => {
                assert_eq!(report.sbi_error, SbiError::InvalidParam.code());
            }
            HostHarnessResult::Fdt(_) => panic!("expected ecall report"),
        }
    }
}
