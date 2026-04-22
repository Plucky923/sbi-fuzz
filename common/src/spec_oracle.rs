use crate::{
    HostEcallReport, HostHarnessInput, HostHarnessMode, HostHarnessReport, HostHarnessResult,
    HostHartState, SbiError,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecOracleVerdict {
    pub passed: bool,
    pub violations: Vec<SpecViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SpecViolation {
    UnsupportedExtensionWrongError { eid: u64, got: i64 },
    InvalidAddressNotRejected { eid: u64, fid: u64, addr: u64, len: u64 },
    HsmIllegalTransition {
        from: HostHartState,
        to: HostHartState,
        op: &'static str,
    },
    PartialIoInconsistent { reported: u64, actual: u64 },
    WrongErrorCode {
        expected: i64,
        got: i64,
        context: String,
    },
    WrongValue {
        expected: String,
        got: u64,
        context: String,
    },
    HartMaskInvalidNotRejected { hart_id: u64 },
    BaseSpecVersionTooLow { got: u64 },
}

pub fn check_host_report(input: &HostHarnessInput, report: &HostHarnessReport) -> SpecOracleVerdict {
    let violations = match &report.result {
        HostHarnessResult::Ecall(ecall) => check_ecall_result(input, ecall),
        HostHarnessResult::Fdt(_) => Vec::new(),
    };
    SpecOracleVerdict {
        passed: violations.is_empty(),
        violations,
    }
}

pub fn check_ecall_result(input: &HostHarnessInput, report: &HostEcallReport) -> Vec<SpecViolation> {
    if input.mode == HostHarnessMode::PlatformFault || input.platform_fault.is_active() {
        return Vec::new();
    }

    let mut violations = Vec::new();
    if !is_known_extension(input.call.extid)
        && report.sbi_error != SbiError::NotSupported.code()
    {
        violations.push(SpecViolation::UnsupportedExtensionWrongError {
            eid: input.call.extid,
            got: report.sbi_error,
        });
    }

    match input.call.extid {
        0x10 => check_base_rules(input, report, &mut violations),
        0x4442_434e => check_dbcn_rules(input, report, &mut violations),
        0x4853_4d => check_hsm_rules(input, report, &mut violations),
        0x7350_49 | 0x5246_4e43 => check_hart_mask_rules(input, report, &mut violations),
        0x504d_55 => check_pmu_rules(input, report, &mut violations),
        0x5449_4d45 => check_timer_rules(input, report, &mut violations),
        0x5352_5354 => check_reset_rules(input, report, &mut violations),
        0x535441 => check_sta_rules(input, report, &mut violations),
        0x4e41434c => check_nacl_rules(input, report, &mut violations),
        _ => {}
    }

    violations
}

fn check_base_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if input.call.fid > 6 {
        if report.sbi_error != SbiError::NotSupported.code() {
            violations.push(SpecViolation::WrongErrorCode {
                expected: SbiError::NotSupported.code(),
                got: report.sbi_error,
                context: format!("base fid {} should be rejected", input.call.fid),
            });
        }
        return;
    }

    if report.sbi_error != SbiError::Success.code() {
        violations.push(SpecViolation::WrongErrorCode {
            expected: SbiError::Success.code(),
            got: report.sbi_error,
            context: format!("base fid {} should succeed", input.call.fid),
        });
    }

    if input.call.fid == 0 && report.value < 2 {
        violations.push(SpecViolation::BaseSpecVersionTooLow { got: report.value });
    }

    if input.call.fid == 3
        && is_non_legacy_known_extension(input.call.args[0])
        && report.value == 0
    {
        violations.push(SpecViolation::WrongValue {
            expected: "non-zero".to_string(),
            got: report.value,
            context: format!(
                "probe_extension should report support for eid 0x{:x}",
                input.call.args[0]
            ),
        });
    }
}

fn check_dbcn_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    match input.call.fid {
        0 | 1 => {
            let num_bytes = input.call.args[0];
            let addr = input.call.args[1];
            let hi = input.call.args[2];
            let need_read = input.call.fid == 0;
            let need_write = input.call.fid == 1;
            let valid = hi == 0
                && region_covers(
                    &input.memory_regions,
                    addr,
                    num_bytes,
                    need_read,
                    need_write,
                );
            if !valid && report.sbi_error == SbiError::Success.code() {
                violations.push(SpecViolation::InvalidAddressNotRejected {
                    eid: input.call.extid,
                    fid: input.call.fid,
                    addr,
                    len: num_bytes,
                });
            } else if !valid && report.sbi_error != SbiError::InvalidParam.code() {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::InvalidParam.code(),
                    got: report.sbi_error,
                    context: format!(
                        "dbcn fid {} should reject invalid address range",
                        input.call.fid
                    ),
                });
            }
            if report.sbi_error == SbiError::Success.code() && report.value > num_bytes {
                violations.push(SpecViolation::PartialIoInconsistent {
                    reported: report.value,
                    actual: num_bytes,
                });
            }
        }
        2 => {
            if report.sbi_error == SbiError::Success.code() && report.value != 0 {
                violations.push(SpecViolation::PartialIoInconsistent {
                    reported: report.value,
                    actual: 0,
                });
            }
        }
        _ => {}
    }
}

fn check_hsm_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if input.call.fid == 0 && input.call.args[0] >= MAX_TRACKED_HARTS {
        if report.sbi_error != SbiError::InvalidParam.code() {
            violations.push(SpecViolation::WrongErrorCode {
                expected: SbiError::InvalidParam.code(),
                got: report.sbi_error,
                context: format!(
                    "hart_start should reject invalid hart {}",
                    input.call.args[0]
                ),
            });
        }
    }

    if input.call.fid == 3 {
        let suspend_type = input.call.args[0];
        let suspend_type_invalid = suspend_type & !0x8000_0000 != 0;
        if suspend_type_invalid && report.sbi_error != SbiError::InvalidParam.code() {
            violations.push(SpecViolation::WrongErrorCode {
                expected: SbiError::InvalidParam.code(),
                got: report.sbi_error,
                context: "hart_suspend with invalid suspend_type".to_string(),
            });
        }
    }

    match input.call.fid {
        0 if input.hart_state == HostHartState::Started => {
            if !matches!(
                report.sbi_error,
                value if value == SbiError::AlreadyAvailable.code()
                    || value == SbiError::AlreadyStarted.code()
            ) {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::AlreadyAvailable.code(),
                    got: report.sbi_error,
                    context: "hart_start on started hart".to_string(),
                });
            }
        }
        1 if input.hart_state == HostHartState::Stopped => {
            if report.sbi_error != SbiError::AlreadyStopped.code() {
                violations.push(SpecViolation::HsmIllegalTransition {
                    from: HostHartState::Stopped,
                    to: HostHartState::Stopped,
                    op: "hart_stop",
                });
            }
        }
        2 if input.call.args[0] >= MAX_TRACKED_HARTS => {
            if report.sbi_error != SbiError::InvalidParam.code() {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::InvalidParam.code(),
                    got: report.sbi_error,
                    context: format!(
                        "hart_get_status should reject invalid hart {}",
                        input.call.args[0]
                    ),
                });
            }
        }
        _ => {}
    }
}

fn check_hart_mask_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if report.sbi_error == SbiError::NotSupported.code() {
        return;
    }

    let hart_mask_base = input.call.args[1];
    if hart_mask_base == u64::MAX {
        if report.sbi_error == SbiError::InvalidParam.code() {
            violations.push(SpecViolation::WrongErrorCode {
                expected: SbiError::Success.code(),
                got: report.sbi_error,
                context: "hart_mask_base=-1 should mean all harts".to_string(),
            });
        }
        return;
    }

    if let Some(invalid_hart_id) = first_invalid_hart_mask_member(input.call.args[0], hart_mask_base)
    {
        if report.sbi_error == SbiError::Success.code() {
            violations.push(SpecViolation::HartMaskInvalidNotRejected {
                hart_id: invalid_hart_id,
            });
        } else if report.sbi_error != SbiError::InvalidParam.code() {
            violations.push(SpecViolation::WrongErrorCode {
                expected: SbiError::InvalidParam.code(),
                got: report.sbi_error,
                context: format!(
                    "hart mask should reject invalid hart {}",
                    invalid_hart_id
                ),
            });
        }
    }
}

fn check_pmu_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if report.sbi_error == SbiError::NotSupported.code() {
        return;
    }

    match input.call.fid {
        0 => {
            if report.sbi_error != SbiError::Success.code() {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::Success.code(),
                    got: report.sbi_error,
                    context: "pmu num_counters should succeed".to_string(),
                });
            }
        }
        1 | 5 | 6 => {
            let counter_idx = input.call.args[0];
            if counter_idx >= PMU_COUNTER_COUNT_HINT
                && report.sbi_error != SbiError::InvalidParam.code()
            {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::InvalidParam.code(),
                    got: report.sbi_error,
                    context: format!("pmu counter index {} should be rejected", counter_idx),
                });
            }
        }
        7 => {
            let addr = join_split_address(input.call.args[0], input.call.args[1]);
            let len = 8;
            let invalid_addr = addr != 0 && !region_covers(&input.memory_regions, addr, len, true, false);
            if invalid_addr {
                if report.sbi_error == SbiError::Success.code() {
                    violations.push(SpecViolation::InvalidAddressNotRejected {
                        eid: input.call.extid,
                        fid: input.call.fid,
                        addr,
                        len,
                    });
                } else if report.sbi_error != SbiError::InvalidParam.code() {
                    violations.push(SpecViolation::WrongErrorCode {
                        expected: SbiError::InvalidParam.code(),
                        got: report.sbi_error,
                        context: format!(
                            "pmu snapshot_set_shmem should reject invalid address 0x{:x}",
                            addr
                        ),
                    });
                }
            }
        }
        _ => {}
    }
}

fn check_timer_rules(
    _input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if report.sbi_error == SbiError::NotSupported.code() {
        return;
    }
    // Timer set_timer (fid 0) should always succeed for any timer value
    if report.sbi_error != SbiError::Success.code() {
        violations.push(SpecViolation::WrongErrorCode {
            expected: SbiError::Success.code(),
            got: report.sbi_error,
            context: "timer set_timer should succeed".to_string(),
        });
    }
}

fn check_reset_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if report.sbi_error == SbiError::NotSupported.code() {
        return;
    }
    match input.call.fid {
        0 => {
            let reset_type = input.call.args[0];
            let valid_type = matches!(reset_type, 0 | 1 | 2);
            let reset_reason = input.call.args[1];
            let valid_reason = matches!(reset_reason, 0 | 1);
            if !valid_type || !valid_reason {
                if report.sbi_error == SbiError::Success.code() {
                    violations.push(SpecViolation::WrongErrorCode {
                        expected: SbiError::InvalidParam.code(),
                        got: report.sbi_error,
                        context: "system_reset should reject invalid type/reason".to_string(),
                    });
                } else if report.sbi_error != SbiError::InvalidParam.code() {
                    violations.push(SpecViolation::WrongErrorCode {
                        expected: SbiError::InvalidParam.code(),
                        got: report.sbi_error,
                        context: "system_reset wrong error for invalid params".to_string(),
                    });
                }
            }
        }
        _ => {}
    }
}

fn check_sta_rules(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if report.sbi_error == SbiError::NotSupported.code() {
        return;
    }
    match input.call.fid {
        0 => {
            // set_shmem: address validation similar to PMU snapshot_set_shmem
            let addr = join_split_address(input.call.args[0], input.call.args[1]);
            let len = 8; // typical shmem size for STA
            let invalid_addr = addr != 0 && !region_covers(&input.memory_regions, addr, len, true, false);
            if invalid_addr {
                if report.sbi_error == SbiError::Success.code() {
                    violations.push(SpecViolation::InvalidAddressNotRejected {
                        eid: input.call.extid,
                        fid: input.call.fid,
                        addr,
                        len,
                    });
                } else if report.sbi_error != SbiError::InvalidParam.code() {
                    violations.push(SpecViolation::WrongErrorCode {
                        expected: SbiError::InvalidParam.code(),
                        got: report.sbi_error,
                        context: format!(
                            "sta set_shmem should reject invalid address 0x{:x}",
                            addr
                        ),
                    });
                }
            }
        }
        1 => {
            // get_susp_size should succeed
            if report.sbi_error != SbiError::Success.code() {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::Success.code(),
                    got: report.sbi_error,
                    context: "sta get_susp_size should succeed".to_string(),
                });
            }
        }
        2 => {
            // system_suspend: validate suspend_type (same pattern as HSM)
            let suspend_type = input.call.args[0];
            let suspend_type_invalid = suspend_type & !0x8000_0000 != 0;
            if suspend_type_invalid && report.sbi_error != SbiError::InvalidParam.code() {
                violations.push(SpecViolation::WrongErrorCode {
                    expected: SbiError::InvalidParam.code(),
                    got: report.sbi_error,
                    context: "sta system_suspend with invalid suspend_type".to_string(),
                });
            }
        }
        _ => {}
    }
}

fn check_nacl_rules(
    _input: &HostHarnessInput,
    report: &HostEcallReport,
    violations: &mut Vec<SpecViolation>,
) {
    if report.sbi_error == SbiError::NotSupported.code() {
        return;
    }
    // NACL probe_feature (fid 0) should succeed; sync operations should succeed
    if report.sbi_error != SbiError::Success.code() {
        violations.push(SpecViolation::WrongErrorCode {
            expected: SbiError::Success.code(),
            got: report.sbi_error,
            context: "nacl operation should succeed".to_string(),
        });
    }
}

fn is_known_extension(extid: u64) -> bool {
    matches!(
        extid,
        0x0..=0xF
            | 0x10
            | 0x5449_4d45
            | 0x735049
            | 0x5246_4e43
            | 0x4853_4d
            | 0x4442_434e
            | 0x5352_5354
            | 0x504d55
            | 0x4e41434c
            | 0x535441
            | 0x535345
            | 0x46574654
            | 0x44425452
            | 0x4d505859
    )
}

fn is_non_legacy_known_extension(extid: u64) -> bool {
    is_known_extension(extid) && !matches!(extid, 0x0..=0xF)
}

const MAX_TRACKED_HARTS: u64 = 64;
const PMU_COUNTER_COUNT_HINT: u64 = 4;

fn join_split_address(low: u64, high: u64) -> u64 {
    ((high & u64::from(u32::MAX)) << 32) | (low & u64::from(u32::MAX))
}

fn first_invalid_hart_mask_member(hart_mask: u64, hart_mask_base: u64) -> Option<u64> {
    if hart_mask == 0 {
        return None;
    }

    if hart_mask_base >= MAX_TRACKED_HARTS {
        return Some(hart_mask_base);
    }

    for bit in 0..u64::BITS {
        if (hart_mask >> bit) & 1 == 0 {
            continue;
        }
        let hart_id = hart_mask_base.saturating_add(u64::from(bit));
        if hart_id >= MAX_TRACKED_HARTS {
            return Some(hart_id);
        }
    }

    None
}

fn region_covers(
    regions: &[crate::HostMemoryRegion],
    addr: u64,
    len: u64,
    need_read: bool,
    need_write: bool,
) -> bool {
    let Some(end) = addr.checked_add(len) else {
        return false;
    };

    regions.iter().any(|region| {
        let Some(region_end) = region.guest_addr.checked_add(region.bytes.len() as u64) else {
            return false;
        };
        addr >= region.guest_addr
            && end <= region_end
            && (!need_read || region.read)
            && (!need_write || region.write)
    })
}
