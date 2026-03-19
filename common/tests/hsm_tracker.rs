use common::{
    HsmHartState, HsmOp, HsmStateTracker, HostEcallReport, HostHarnessMode, HostHarnessReport,
    HostHarnessResult, HostTargetKind, SbiError, SequenceArg, SequenceStep,
};

fn success_report() -> HostHarnessReport {
    HostHarnessReport {
        target_kind: HostTargetKind::OpenSbi,
        backend: "test".to_string(),
        mode: HostHarnessMode::Ecall,
        classification: "ok".to_string(),
        signature: "ok".to_string(),
        post_memory_regions: Vec::new(),
        result: HostHarnessResult::Ecall(HostEcallReport {
            extid: 0x4853_4d,
            fid: 0,
            sbi_error: SbiError::Success.code(),
            sbi_error_name: Some("success".to_string()),
            value: 0,
            next_mepc: None,
            extension_found: true,
            side_effects: 0,
            console_bytes: 0,
            timer_value: 0,
        }),
    }
}

#[test]
fn expected_outcomes_follow_basic_state_rules() {
    let tracker = HsmStateTracker::new(2);
    assert_eq!(
        tracker.expected_outcomes(HsmOp::HartStart, 0),
        vec![SbiError::AlreadyAvailable.code(), SbiError::AlreadyStarted.code()]
    );
    assert_eq!(
        tracker.expected_outcomes(HsmOp::HartSuspend, 1),
        vec![SbiError::InvalidState.code()]
    );
}

#[test]
fn update_marks_started_hart() {
    let mut tracker = HsmStateTracker::new(2);
    let step = SequenceStep::Call {
        label: "start".to_string(),
        eid: 0x4853_4d,
        fid: 0,
        args: vec![
            SequenceArg::Const { value: 1 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
        ],
        expect: None,
    };
    tracker.update(&step, &success_report());
    assert_eq!(tracker.hart_state(1), Some(HsmHartState::Started));
}

#[test]
fn explicit_hart_state_step_updates_tracker() {
    let mut tracker = HsmStateTracker::new(2);
    let step = SequenceStep::SetHartState {
        hart_id: 1,
        state: common::HostHartState::Suspended,
    };
    tracker.update(&step, &success_report());
    assert_eq!(tracker.hart_state(1), Some(HsmHartState::Suspended));
}

#[test]
fn pending_states_report_invalid_follow_up_operations() {
    let tracker = HsmStateTracker::with_states(vec![
        HsmHartState::Started,
        HsmHartState::StartPending,
    ]);
    assert_eq!(
        tracker.expected_outcomes(HsmOp::HartSuspend, 1),
        vec![SbiError::InvalidState.code()]
    );
}

#[test]
fn set_target_hart_redirects_successful_stop_updates() {
    let mut tracker = HsmStateTracker::with_states(vec![
        HsmHartState::Started,
        HsmHartState::Started,
    ]);
    tracker.update(&SequenceStep::SetTargetHart { hart_id: 1 }, &success_report());
    let step = SequenceStep::Call {
        label: "stop".to_string(),
        eid: 0x4853_4d,
        fid: 1,
        args: vec![
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
        ],
        expect: None,
    };
    tracker.update(&step, &success_report());
    assert_eq!(tracker.hart_state(0), Some(HsmHartState::Started));
    assert_eq!(tracker.hart_state(1), Some(HsmHartState::Stopped));
}

#[test]
fn set_target_hart_redirects_successful_suspend_updates() {
    let mut tracker = HsmStateTracker::with_states(vec![
        HsmHartState::Started,
        HsmHartState::Started,
    ]);
    tracker.update(&SequenceStep::SetTargetHart { hart_id: 1 }, &success_report());
    let step = SequenceStep::Call {
        label: "suspend".to_string(),
        eid: 0x4853_4d,
        fid: 3,
        args: vec![
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
        ],
        expect: None,
    };
    tracker.update(&step, &success_report());
    assert_eq!(tracker.hart_state(0), Some(HsmHartState::Started));
    assert_eq!(tracker.hart_state(1), Some(HsmHartState::Suspended));
}

#[test]
fn failed_hsm_calls_do_not_mutate_tracker_state() {
    let mut tracker = HsmStateTracker::with_states(vec![
        HsmHartState::Started,
        HsmHartState::Started,
    ]);
    tracker.select_hart(1);
    let step = SequenceStep::Call {
        label: "stop".to_string(),
        eid: 0x4853_4d,
        fid: 1,
        args: vec![
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
        ],
        expect: None,
    };
    let failed = HostHarnessReport {
        target_kind: HostTargetKind::OpenSbi,
        backend: "test".to_string(),
        mode: HostHarnessMode::Ecall,
        classification: "sbi_error:failed".to_string(),
        signature: "failed".to_string(),
        post_memory_regions: Vec::new(),
        result: HostHarnessResult::Ecall(HostEcallReport {
            extid: 0x4853_4d,
            fid: 1,
            sbi_error: SbiError::Failed.code(),
            sbi_error_name: Some("failed".to_string()),
            value: 0,
            next_mepc: None,
            extension_found: true,
            side_effects: 0,
            console_bytes: 0,
            timer_value: 0,
        }),
    };
    tracker.update(&step, &failed);
    assert_eq!(tracker.hart_state(0), Some(HsmHartState::Started));
    assert_eq!(tracker.hart_state(1), Some(HsmHartState::Started));
}
