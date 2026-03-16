use crate::{HostHarnessReport, HostHarnessResult, HostHartState, SequenceStep, SbiError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmHartState {
    Started,
    Stopped,
    StartPending,
    StopPending,
    Suspended,
    SuspendPending,
    ResumePending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmOp {
    HartStart,
    HartStop,
    HartSuspend,
    HartGetStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HsmViolation {
    UnknownHart { hart_id: u64 },
    IllegalStopTarget { hart_id: u64 },
    IllegalTransition {
        hart_id: u64,
        from: HsmHartState,
        to: HsmHartState,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmStateTracker {
    hart_states: Vec<HsmHartState>,
}

impl HsmStateTracker {
    pub fn new(smp: u16) -> Self {
        let smp = smp.max(1);
        let mut hart_states = vec![HsmHartState::Stopped; smp as usize];
        hart_states[0] = HsmHartState::Started;
        Self { hart_states }
    }

    pub fn with_states(hart_states: Vec<HsmHartState>) -> Self {
        Self { hart_states }
    }

    pub fn hart_state(&self, hart_id: u64) -> Option<HsmHartState> {
        self.hart_states.get(hart_id as usize).copied()
    }

    pub fn update(&mut self, step: &SequenceStep, report: &HostHarnessReport) {
        if let SequenceStep::SetHartState { hart_id, state } = step {
            self.apply_explicit_state(*hart_id, *state);
            return;
        }
        let HostHarnessResult::Ecall(ecall) = &report.result else {
            return;
        };
        if ecall.sbi_error != SbiError::Success.code() {
            return;
        }
        if let SequenceStep::Call { eid, fid, args, .. } = step {
            if *eid != 0x4853_4d {
                return;
            }
            match *fid {
                0 => {
                    let Some(target_hart) = constant_arg(args.first()) else {
                        return;
                    };
                    if let Some(state) = self.hart_states.get_mut(target_hart as usize) {
                        *state = HsmHartState::Started;
                    }
                }
                1 => {
                    if let Some(state) = self.hart_states.get_mut(0) {
                        *state = HsmHartState::Stopped;
                    }
                }
                3 => {
                    if let Some(state) = self.hart_states.get_mut(0) {
                        *state = HsmHartState::Suspended;
                    }
                }
                _ => {}
            }
        }
    }

    pub fn check_invariants(&self) -> Vec<HsmViolation> {
        let mut violations = Vec::new();
        if self.hart_states.is_empty() {
            violations.push(HsmViolation::UnknownHart { hart_id: 0 });
        }
        for (hart_id, state) in self.hart_states.iter().enumerate() {
            match state {
                HsmHartState::StartPending | HsmHartState::StopPending | HsmHartState::SuspendPending => {}
                HsmHartState::ResumePending if hart_id == 0 => violations.push(
                    HsmViolation::IllegalTransition {
                        hart_id: hart_id as u64,
                        from: HsmHartState::Stopped,
                        to: HsmHartState::ResumePending,
                    },
                ),
                _ => {}
            }
        }
        violations
    }

    pub fn expected_outcomes(&self, op: HsmOp, target_hart: u64) -> Vec<i64> {
        let Some(state) = self.hart_state(target_hart) else {
            return vec![SbiError::InvalidParam.code()];
        };
        match op {
            HsmOp::HartStart => match state {
                HsmHartState::Started => vec![
                    SbiError::AlreadyAvailable.code(),
                    SbiError::AlreadyStarted.code(),
                ],
                HsmHartState::StartPending | HsmHartState::ResumePending => vec![
                    SbiError::AlreadyAvailable.code(),
                    SbiError::AlreadyStarted.code(),
                ],
                HsmHartState::Stopped | HsmHartState::Suspended | HsmHartState::StopPending => {
                    vec![SbiError::Success.code()]
                }
                HsmHartState::SuspendPending => vec![SbiError::InvalidState.code()],
            },
            HsmOp::HartStop => match state {
                HsmHartState::Stopped => vec![SbiError::AlreadyStopped.code()],
                HsmHartState::StopPending => vec![SbiError::AlreadyStopped.code()],
                HsmHartState::Started | HsmHartState::Suspended => vec![SbiError::Success.code()],
                HsmHartState::StartPending
                | HsmHartState::SuspendPending
                | HsmHartState::ResumePending => vec![SbiError::InvalidState.code()],
            },
            HsmOp::HartSuspend => match state {
                HsmHartState::Started => vec![SbiError::Success.code()],
                HsmHartState::Stopped
                | HsmHartState::Suspended
                | HsmHartState::StartPending
                | HsmHartState::StopPending
                | HsmHartState::SuspendPending
                | HsmHartState::ResumePending => vec![SbiError::InvalidState.code()],
            },
            HsmOp::HartGetStatus => vec![SbiError::Success.code()],
        }
    }

    fn apply_explicit_state(&mut self, hart_id: u64, state: HostHartState) {
        let Some(slot) = self.hart_states.get_mut(hart_id as usize) else {
            return;
        };
        *slot = match state {
            HostHartState::Unknown => HsmHartState::Stopped,
            HostHartState::Started => HsmHartState::Started,
            HostHartState::Stopped => HsmHartState::Stopped,
            HostHartState::Suspended => HsmHartState::Suspended,
        };
    }
}

fn constant_arg(arg: Option<&crate::SequenceArg>) -> Option<u64> {
    match arg {
        Some(crate::SequenceArg::Const { value }) => Some(*value),
        _ => None,
    }
}
