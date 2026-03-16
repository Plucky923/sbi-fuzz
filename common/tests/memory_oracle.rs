use common::{
    HostCall, HostEcallReport, HostHarnessInput, HostHarnessMode, HostHarnessReport,
    HostHarnessResult, HostHartState, HostMemoryRegion, HostPlatformFaultProfile,
    HostPrivilegeState, HostTargetKind, MemoryOracle, MemoryViolation, SbiError,
};

fn sample_input(fid: u64) -> HostHarnessInput {
    HostHarnessInput {
        target_kind: HostTargetKind::RustSbi,
        mode: HostHarnessMode::Ecall,
        call: HostCall::new(0x4442_434e, fid, [4, 0x8000_1000, 0, 0, 0, 0]),
        hart_id: 0,
        hart_state: HostHartState::Started,
        privilege: HostPrivilegeState::Supervisor,
        memory_regions: vec![
            HostMemoryRegion {
                guest_addr: 0x8000_1000,
                read: true,
                write: true,
                execute: false,
                bytes: b"ping".to_vec(),
            },
            HostMemoryRegion {
                guest_addr: 0x8000_2000,
                read: true,
                write: false,
                execute: false,
                bytes: b"pong".to_vec(),
            },
        ],
        platform_fault: HostPlatformFaultProfile::none(),
        fdt_blob: Vec::new(),
        label: "memory".to_string(),
    }
}

fn sample_report(post_memory_regions: Vec<HostMemoryRegion>) -> HostHarnessReport {
    HostHarnessReport {
        target_kind: HostTargetKind::RustSbi,
        backend: "test".to_string(),
        mode: HostHarnessMode::Ecall,
        classification: "ok".to_string(),
        signature: "test".to_string(),
        post_memory_regions,
        result: HostHarnessResult::Ecall(HostEcallReport {
            extid: 0x4442_434e,
            fid: 1,
            sbi_error: SbiError::Success.code(),
            sbi_error_name: Some("success".to_string()),
            value: 4,
            next_mepc: None,
            extension_found: true,
            side_effects: 1,
            console_bytes: 4,
            timer_value: 0,
        }),
    }
}

#[test]
fn read_only_region_modification_is_detected() {
    let input = sample_input(1);
    let oracle = MemoryOracle::snapshot_before(&input.memory_regions);
    let mut post = input.memory_regions.clone();
    post[1].bytes[0] = b'X';
    let violations = oracle.check_after(&input, &sample_report(post));
    assert_eq!(
        violations,
        vec![MemoryViolation::ReadOnlyRegionModified { region_index: 1 }]
    );
}

#[test]
fn dbcn_read_allows_target_buffer_mutation() {
    let input = sample_input(1);
    let oracle = MemoryOracle::snapshot_before(&input.memory_regions);
    let mut post = input.memory_regions.clone();
    post[0].bytes[..4].copy_from_slice(b"RRRR");
    let violations = oracle.check_after(&input, &sample_report(post));
    assert!(violations.is_empty());
}
