use crate::{
    HostHarnessInput, HostHarnessReport, HostHarnessResult, SbiError, check_host_report,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownDiff {
    pub eid: Option<u64>,
    pub fid: Option<u64>,
    pub field: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffPolicy {
    pub ignore_impl_defined_value: bool,
    pub ignore_unsupported_extension_diff: bool,
    #[serde(default)]
    pub error_code_only_eids: HashSet<u64>,
    #[serde(default)]
    pub known_diffs: Vec<KnownDiff>,
}

impl Default for DiffPolicy {
    fn default() -> Self {
        let mut error_code_only_eids = HashSet::new();
        error_code_only_eids.insert(0x10);
        Self {
            ignore_impl_defined_value: true,
            ignore_unsupported_extension_diff: true,
            error_code_only_eids,
            known_diffs: vec![KnownDiff {
                eid: None,
                fid: None,
                field: "next_mepc".to_string(),
                reason: "OpenSBI host shim reports next_mepc while RustSBI host path does not".to_string(),
            }],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffSeverity {
    SpecViolation,
    ImplementationDefined,
    KnownAccepted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffResult {
    pub field: String,
    pub opensbi: String,
    pub rustsbi: String,
    pub severity: DiffSeverity,
    #[serde(default)]
    pub context: String,
}

pub fn diff_host_reports(
    input: &HostHarnessInput,
    opensbi: &HostHarnessReport,
    rustsbi: &HostHarnessReport,
    policy: &DiffPolicy,
) -> Vec<DiffResult> {
    let opensbi_verdict = check_host_report(input, opensbi);
    let mut rustsbi_input = input.clone();
    rustsbi_input.target_kind = crate::HostTargetKind::RustSbi;
    let rustsbi_verdict = check_host_report(&rustsbi_input, rustsbi);

    let opensbi_has_spec_violation = !opensbi_verdict.violations.is_empty();
    let rustsbi_has_spec_violation = !rustsbi_verdict.violations.is_empty();
    let mut diffs = Vec::new();

    if opensbi_has_spec_violation ^ rustsbi_has_spec_violation {
        diffs.push(DiffResult {
            field: "oracle".to_string(),
            opensbi: format!("{:?}", opensbi_verdict.violations),
            rustsbi: format!("{:?}", rustsbi_verdict.violations),
            severity: DiffSeverity::SpecViolation,
            context: format!(
                "eid=0x{:x} fid=0x{:x}",
                input.call.extid, input.call.fid
            ),
        });
    }

    match (&opensbi.result, &rustsbi.result) {
        (HostHarnessResult::Ecall(opensbi_ecall), HostHarnessResult::Ecall(rustsbi_ecall)) => {
            push_ecall_diff(
                &mut diffs,
                policy,
                input,
                "sbi_error",
                opensbi_ecall.sbi_error.to_string(),
                rustsbi_ecall.sbi_error.to_string(),
                false,
                opensbi_has_spec_violation || rustsbi_has_spec_violation,
            );
            push_ecall_diff(
                &mut diffs,
                policy,
                input,
                "extension_found",
                opensbi_ecall.extension_found.to_string(),
                rustsbi_ecall.extension_found.to_string(),
                false,
                opensbi_has_spec_violation || rustsbi_has_spec_violation,
            );
            push_ecall_diff(
                &mut diffs,
                policy,
                input,
                "value",
                opensbi_ecall.value.to_string(),
                rustsbi_ecall.value.to_string(),
                true,
                opensbi_has_spec_violation || rustsbi_has_spec_violation,
            );
            push_ecall_diff(
                &mut diffs,
                policy,
                input,
                "console_bytes",
                opensbi_ecall.console_bytes.to_string(),
                rustsbi_ecall.console_bytes.to_string(),
                false,
                opensbi_has_spec_violation || rustsbi_has_spec_violation,
            );
            push_ecall_diff(
                &mut diffs,
                policy,
                input,
                "timer_value",
                opensbi_ecall.timer_value.to_string(),
                rustsbi_ecall.timer_value.to_string(),
                false,
                opensbi_has_spec_violation || rustsbi_has_spec_violation,
            );
            if !field_is_known(policy, input.call.extid, input.call.fid, "next_mepc")
                && opensbi_ecall.next_mepc != rustsbi_ecall.next_mepc
            {
                diffs.push(DiffResult {
                    field: "next_mepc".to_string(),
                    opensbi: format!("{:?}", opensbi_ecall.next_mepc),
                    rustsbi: format!("{:?}", rustsbi_ecall.next_mepc),
                    severity: DiffSeverity::KnownAccepted,
                    context: "known host shim divergence".to_string(),
                });
            }
        }
        (HostHarnessResult::Fdt(opensbi_fdt), HostHarnessResult::Fdt(rustsbi_fdt)) => {
            if opensbi_fdt.status != rustsbi_fdt.status {
                diffs.push(DiffResult {
                    field: "fdt_status".to_string(),
                    opensbi: opensbi_fdt.status.to_string(),
                    rustsbi: rustsbi_fdt.status.to_string(),
                    severity: DiffSeverity::ImplementationDefined,
                    context: "host-side FDT parsing semantics diverged".to_string(),
                });
            }
            if opensbi_fdt.hart_count != rustsbi_fdt.hart_count {
                diffs.push(DiffResult {
                    field: "fdt_hart_count".to_string(),
                    opensbi: opensbi_fdt.hart_count.to_string(),
                    rustsbi: rustsbi_fdt.hart_count.to_string(),
                    severity: DiffSeverity::ImplementationDefined,
                    context: "host-side FDT parsing semantics diverged".to_string(),
                });
            }
        }
        _ => diffs.push(DiffResult {
            field: "result_kind".to_string(),
            opensbi: format!("{:?}", opensbi.result),
            rustsbi: format!("{:?}", rustsbi.result),
            severity: DiffSeverity::SpecViolation,
            context: "different result kinds".to_string(),
        }),
    }

    diffs
        .into_iter()
        .filter(|diff| diff.severity != DiffSeverity::KnownAccepted)
        .collect()
}

fn push_ecall_diff(
    diffs: &mut Vec<DiffResult>,
    policy: &DiffPolicy,
    input: &HostHarnessInput,
    field: &str,
    opensbi: String,
    rustsbi: String,
    value_field: bool,
    has_spec_violation: bool,
) {
    if opensbi == rustsbi {
        return;
    }
    if field_is_known(policy, input.call.extid, input.call.fid, field) {
        return;
    }
    if policy.ignore_unsupported_extension_diff
        && ((field == "sbi_error"
            && (opensbi == SbiError::NotSupported.code().to_string()
                || rustsbi == SbiError::NotSupported.code().to_string()))
            || (field == "extension_found" && (opensbi == "false" || rustsbi == "false")))
    {
        return;
    }
    if value_field && should_ignore_value_diff(policy, input) {
        return;
    }
    if input.call.extid == 0x4853_4d
        && input.call.fid == 3
        && input.hart_state != crate::HostHartState::Started
        && field == "sbi_error"
    {
        return;
    }
    let severity = if has_spec_violation {
        DiffSeverity::SpecViolation
    } else {
        DiffSeverity::ImplementationDefined
    };
    diffs.push(DiffResult {
        field: field.to_string(),
        opensbi,
        rustsbi,
        severity,
        context: format!("eid=0x{:x} fid=0x{:x}", input.call.extid, input.call.fid),
    });
}

fn should_ignore_value_diff(policy: &DiffPolicy, input: &HostHarnessInput) -> bool {
    if policy.error_code_only_eids.contains(&input.call.extid) {
        return true;
    }
    policy.ignore_impl_defined_value
        && matches!(
            (input.call.extid, input.call.fid),
            (0x10, 1 | 2 | 3) | (0x504d55, _)
        )
}

fn field_is_known(policy: &DiffPolicy, eid: u64, fid: u64, field: &str) -> bool {
    policy.known_diffs.iter().any(|known| {
        known.field == field
            && known.eid.map(|value| value == eid).unwrap_or(true)
            && known.fid.map(|value| value == fid).unwrap_or(true)
    })
}
