use common::{
    DiffPolicy, DiffSeverity, HostCall, HostEcallReport, HostHarnessInput, HostHarnessMode,
    HostHarnessReport, HostHarnessResult, HostHartState, HostPlatformFaultProfile,
    HostPrivilegeState, HostTargetKind, SbiError, diff_host_reports,
};

fn sample_input(extid: u64, fid: u64) -> HostHarnessInput {
    HostHarnessInput {
        target_kind: HostTargetKind::OpenSbi,
        mode: HostHarnessMode::Ecall,
        call: HostCall::new(extid, fid, [0; 6]),
        hart_id: 0,
        hart_state: HostHartState::Started,
        privilege: HostPrivilegeState::Supervisor,
        memory_regions: Vec::new(),
        platform_fault: HostPlatformFaultProfile::none(),
        fdt_blob: Vec::new(),
        label: "diff".to_string(),
    }
}

fn sample_report(
    target_kind: HostTargetKind,
    extid: u64,
    fid: u64,
    sbi_error: i64,
    value: u64,
) -> HostHarnessReport {
    HostHarnessReport {
        target_kind,
        backend: format!("{target_kind:?}"),
        mode: HostHarnessMode::Ecall,
        classification: "ok".to_string(),
        signature: "sig".to_string(),
        post_memory_regions: Vec::new(),
        result: HostHarnessResult::Ecall(HostEcallReport {
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
        }),
    }
}

#[test]
fn diff_policy_ignores_base_probe_value_diff() {
    let input = sample_input(0x10, 1);
    let opensbi = sample_report(HostTargetKind::OpenSbi, 0x10, 1, 0, 1);
    let rustsbi = sample_report(HostTargetKind::RustSbi, 0x10, 1, 0, 0);
    let diffs = diff_host_reports(&input, &opensbi, &rustsbi, &DiffPolicy::default());
    assert!(diffs.is_empty());
}

#[test]
fn diff_policy_reports_error_code_divergence() {
    let input = sample_input(0x4442_434e, 0);
    let opensbi = sample_report(HostTargetKind::OpenSbi, 0x4442_434e, 0, 0, 4);
    let rustsbi = sample_report(
        HostTargetKind::RustSbi,
        0x4442_434e,
        0,
        SbiError::InvalidParam.code(),
        0,
    );
    let diffs = diff_host_reports(&input, &opensbi, &rustsbi, &DiffPolicy::default());
    assert!(diffs.iter().any(|diff| diff.field == "sbi_error"));
}

#[test]
fn diff_policy_uses_spec_violation_severity_when_one_side_is_wrong() {
    let input = sample_input(0xdead_beef, 0);
    let opensbi = sample_report(HostTargetKind::OpenSbi, 0xdead_beef, 0, 0, 0);
    let rustsbi = sample_report(
        HostTargetKind::RustSbi,
        0xdead_beef,
        0,
        SbiError::NotSupported.code(),
        0,
    );
    let diffs = diff_host_reports(&input, &opensbi, &rustsbi, &DiffPolicy::default());
    assert!(diffs.iter().any(|diff| diff.severity == DiffSeverity::SpecViolation));
}

#[test]
fn diff_policy_does_not_hide_known_extension_not_supported_divergence() {
    let input = sample_input(0x4442_434e, 0);
    let opensbi = sample_report(HostTargetKind::OpenSbi, 0x4442_434e, 0, 0, 4);
    let rustsbi = sample_report(
        HostTargetKind::RustSbi,
        0x4442_434e,
        0,
        SbiError::NotSupported.code(),
        0,
    );
    let diffs = diff_host_reports(&input, &opensbi, &rustsbi, &DiffPolicy::default());
    assert!(diffs.iter().any(|diff| diff.field == "sbi_error"));
}

#[test]
fn diff_policy_still_ignores_unknown_extension_not_supported_noise() {
    let input = sample_input(0xdead_beef, 0);
    let opensbi = sample_report(
        HostTargetKind::OpenSbi,
        0xdead_beef,
        0,
        SbiError::NotSupported.code(),
        0,
    );
    let rustsbi = sample_report(
        HostTargetKind::RustSbi,
        0xdead_beef,
        0,
        SbiError::NotSupported.code(),
        0,
    );
    let diffs = diff_host_reports(&input, &opensbi, &rustsbi, &DiffPolicy::default());
    assert!(diffs.is_empty());
}
