use common::{
    HostCall, HostEcallReport, HostHarnessInput, HostHarnessMode, HostHartState,
    HostMemoryRegion, HostPlatformFaultProfile, HostPrivilegeState, HostTargetKind, SbiError,
    SpecViolation, check_ecall_result,
};

fn sample_input(extid: u64, fid: u64, args: [u64; 6]) -> HostHarnessInput {
    HostHarnessInput {
        target_kind: HostTargetKind::RustSbi,
        mode: HostHarnessMode::Ecall,
        call: HostCall::new(extid, fid, args),
        hart_id: 0,
        hart_state: HostHartState::Started,
        privilege: HostPrivilegeState::Supervisor,
        memory_regions: Vec::new(),
        platform_fault: HostPlatformFaultProfile::none(),
        fdt_blob: Vec::new(),
        label: "oracle".to_string(),
    }
}

fn sample_report(extid: u64, fid: u64, sbi_error: i64, value: u64) -> HostEcallReport {
    HostEcallReport {
        extid,
        fid,
        sbi_error,
        sbi_error_name: SbiError::from_code(sbi_error).map(|error| error.name().to_string()),
        value,
        next_mepc: None,
        extension_found: sbi_error != SbiError::NotSupported.code(),
        side_effects: 0,
        console_bytes: 0,
        timer_value: 0,
    }
}

#[test]
fn unsupported_extension_requires_not_supported() {
    let input = sample_input(0xdead_beef, 0, [0; 6]);
    let report = sample_report(0xdead_beef, 0, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::UnsupportedExtensionWrongError { .. }]
    ));
}

#[test]
fn base_probe_extension_requires_non_zero_value_for_known_extension() {
    let input = sample_input(0x10, 3, [0x4853_4d, 0, 0, 0, 0, 0]);
    let report = sample_report(0x10, 3, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongValue { .. }]
    ));
}

#[test]
fn base_spec_version_must_be_at_least_two() {
    let input = sample_input(0x10, 0, [0; 6]);
    let report = sample_report(0x10, 0, SbiError::Success.code(), 1);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::BaseSpecVersionTooLow { got: 1 }]
    ));
}

#[test]
fn base_unknown_fid_is_rejected() {
    let input = sample_input(0x10, 9, [0; 6]);
    let report = sample_report(0x10, 9, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            ..
        }] if *expected == SbiError::NotSupported.code() && *got == SbiError::Success.code()
    ));
}

#[test]
fn legacy_extension_is_not_treated_as_unknown() {
    let input = sample_input(0x1, 0, [0; 6]);
    let report = sample_report(0x1, 0, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(violations.is_empty());
}

#[test]
fn dbcn_invalid_address_is_rejected() {
    let input = sample_input(0x4442_434e, 0, [4, 0x9000_0000, 0, 0, 0, 0]);
    let report = sample_report(0x4442_434e, 0, SbiError::Success.code(), 4);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::InvalidAddressNotRejected { .. }, ..]
    ));
}

#[test]
fn dbcn_partial_overflow_is_detected() {
    let mut input = sample_input(0x4442_434e, 0, [4, 0x8000_1000, 0, 0, 0, 0]);
    input.memory_regions = vec![HostMemoryRegion {
        guest_addr: 0x8000_1000,
        read: true,
        write: true,
        execute: false,
        bytes: b"ping".to_vec(),
    }];
    let report = sample_report(0x4442_434e, 0, SbiError::Success.code(), 8);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::PartialIoInconsistent {
            reported: 8,
            actual: 4
        }, ..]
    ));
}

#[test]
fn dbcn_write_byte_must_not_report_extra_value() {
    let input = sample_input(0x4442_434e, 2, [0, 0, 0, 0, 0, 0]);
    let report = sample_report(0x4442_434e, 2, SbiError::Success.code(), 1);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::PartialIoInconsistent {
            reported: 1,
            actual: 0
        }]
    ));
}

#[test]
fn hsm_invalid_hart_status_is_rejected() {
    let input = sample_input(0x4853_4d, 2, [64, 0, 0, 0, 0, 0]);
    let report = sample_report(0x4853_4d, 2, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            ..
        }] if *expected == SbiError::InvalidParam.code() && *got == SbiError::Success.code()
    ));
}

#[test]
fn hsm_start_on_started_hart_requires_already_available() {
    let mut input = sample_input(0x4853_4d, 0, [1, 0, 0, 0, 0, 0]);
    input.hart_state = HostHartState::Started;
    let report = sample_report(0x4853_4d, 0, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            ..
        }] if *expected == SbiError::AlreadyAvailable.code() && *got == SbiError::Success.code()
    ));
}

#[test]
fn hsm_stop_on_stopped_hart_is_illegal_transition() {
    let mut input = sample_input(0x4853_4d, 1, [0; 6]);
    input.hart_state = HostHartState::Stopped;
    let report = sample_report(0x4853_4d, 1, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::HsmIllegalTransition { .. }]
    ));
}

#[test]
fn hsm_suspend_invalid_type_is_rejected_even_from_started_state() {
    let mut input = sample_input(0x4853_4d, 3, [0x2, 0, 0, 0, 0, 0]);
    input.hart_state = HostHartState::Started;
    let report = sample_report(0x4853_4d, 3, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            context
        }] if *expected == SbiError::InvalidParam.code()
            && *got == SbiError::Success.code()
            && context.contains("hart_suspend")
    ));
}

#[test]
fn active_platform_fault_profile_skips_spec_checks() {
    let mut input = sample_input(0x4442_434e, 0, [4, 0x8000_1000, 0, 0, 0, 0]);
    input.mode = HostHarnessMode::PlatformFault;
    input.platform_fault = HostPlatformFaultProfile {
        duplicate_side_effects: true,
        ..HostPlatformFaultProfile::none()
    };
    input.memory_regions = vec![HostMemoryRegion {
        guest_addr: 0x8000_1000,
        read: true,
        write: true,
        execute: false,
        bytes: b"ping".to_vec(),
    }];
    let report = sample_report(0x4442_434e, 0, SbiError::Success.code(), 8);
    let violations = check_ecall_result(&input, &report);
    assert!(violations.is_empty());
}

#[test]
fn ipi_invalid_hart_mask_member_is_rejected() {
    let input = sample_input(0x7350_49, 0, [0b0001_0000, 60, 0, 0, 0, 0]);
    let report = sample_report(0x7350_49, 0, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::HartMaskInvalidNotRejected { hart_id: 64 }]
    ));
}

#[test]
fn ipi_empty_mask_is_accepted() {
    let input = sample_input(0x7350_49, 0, [0, u64::MAX - 1, 0, 0, 0, 0]);
    let report = sample_report(0x7350_49, 0, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(violations.is_empty());
}

#[test]
fn rfence_invalid_hart_mask_member_is_rejected() {
    let input = sample_input(0x5246_4e43, 1, [1, 64, 0x8000_1000, 0x1000, 0, 0]);
    let report = sample_report(0x5246_4e43, 1, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::HartMaskInvalidNotRejected { hart_id: 64 }]
    ));
}

#[test]
fn rfence_all_harts_base_minus_one_is_accepted() {
    let input = sample_input(0x5246_4e43, 1, [0, u64::MAX, 0x8000_1000, 0x1000, 0, 0]);
    let report = sample_report(
        0x5246_4e43,
        1,
        SbiError::InvalidParam.code(),
        0,
    );
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            ..
        }] if *expected == SbiError::Success.code() && *got == SbiError::InvalidParam.code()
    ));
}

#[test]
fn pmu_num_counters_requires_success() {
    let input = sample_input(0x504d_55, 0, [0; 6]);
    let report = sample_report(0x504d_55, 0, SbiError::Failed.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            ..
        }] if *expected == SbiError::Success.code() && *got == SbiError::Failed.code()
    ));
}

#[test]
fn pmu_counter_index_out_of_range_is_rejected() {
    let input = sample_input(0x504d_55, 1, [8, 0, 0, 0, 0, 0]);
    let report = sample_report(0x504d_55, 1, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::WrongErrorCode {
            expected,
            got,
            ..
        }] if *expected == SbiError::InvalidParam.code() && *got == SbiError::Success.code()
    ));
}

#[test]
fn pmu_snapshot_invalid_address_is_rejected() {
    let input = sample_input(0x504d_55, 7, [0x8000_3000, 0, 0, 0, 0, 0]);
    let report = sample_report(0x504d_55, 7, SbiError::Success.code(), 0);
    let violations = check_ecall_result(&input, &report);
    assert!(matches!(
        violations.as_slice(),
        [SpecViolation::InvalidAddressNotRejected { .. }]
    ));
}
