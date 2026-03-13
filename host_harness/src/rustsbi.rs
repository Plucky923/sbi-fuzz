use crate::{
    FDT_SEED_BUFFER_CAPACITY, FdtSeedVariant, HostEcallReport, HostFdtDetails, HostFdtReport,
    HostHarnessReport, HostHarnessResult,
};
use common::{
    HostHarnessInput, HostHarnessMode, HostHartState, HostMemoryRegion, HostPlatformFaultMode,
    HostPlatformFaultProfile, HostTargetKind, SbiError,
};
use rustsbi::{
    _StandardExtensionProbe, _rustsbi_base_env_info, _rustsbi_console, _rustsbi_console_probe,
    _rustsbi_fence, _rustsbi_fence_probe, _rustsbi_hsm, _rustsbi_hsm_probe, _rustsbi_ipi,
    _rustsbi_ipi_probe, _rustsbi_reset, _rustsbi_reset_probe, _rustsbi_timer, _rustsbi_timer_probe,
    Console, EnvInfo, Fence, HartMask, Hsm, Ipi, Physical, Reset, RustSBI, SbiRet, Timer,
};
use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::rc::Rc;

#[repr(C)]
struct NativeRustsbiFdtResponse {
    status: c_int,
    hart_count: u32,
    chosen_present: u32,
    stdout_path_present: u32,
    console_present: u32,
    ipi_present: u32,
    reset_present: u32,
    memory_start: u64,
    memory_end: u64,
    model: [c_char; 64],
    failure: [c_char; 96],
}

impl Default for NativeRustsbiFdtResponse {
    fn default() -> Self {
        Self {
            status: 0,
            hart_count: 0,
            chosen_present: 0,
            stdout_path_present: 0,
            console_present: 0,
            ipi_present: 0,
            reset_present: 0,
            memory_start: 0,
            memory_end: 0,
            model: [0; 64],
            failure: [0; 96],
        }
    }
}

unsafe extern "C" {
    fn sbifuzz_host_parse_rustsbi_fdt(
        blob: *const u8,
        blob_len: usize,
        resp: *mut NativeRustsbiFdtResponse,
    ) -> c_int;
    fn sbifuzz_host_build_rustsbi_seed_fdt(variant: u32, out: *mut u8, out_cap: usize) -> usize;
}

#[derive(Clone)]
struct SharedState(Rc<RefCell<BackendState>>);

#[derive(Clone)]
struct MockEnvInfo;

struct MockConsole {
    state: SharedState,
}

struct MockTimer {
    state: SharedState,
}

struct MockIpi {
    state: SharedState,
}

struct MockHsm {
    state: SharedState,
}

struct MockReset {
    state: SharedState,
}

struct MockFence {
    state: SharedState,
}

struct RustSbiAdapter {
    env: MockEnvInfo,
    console: MockConsole,
    timer: MockTimer,
    ipi: MockIpi,
    hsm: MockHsm,
    reset: MockReset,
    fence: MockFence,
}

#[derive(Clone)]
struct BackendState {
    memory_regions: Vec<HostMemoryRegion>,
    platform_fault: HostPlatformFaultProfile,
    hart_state: HostHartState,
    side_effects: u32,
    console_bytes: u32,
    timer_value: u64,
}

impl BackendState {
    fn from_input(input: &HostHarnessInput) -> Self {
        Self {
            memory_regions: input.memory_regions.clone(),
            platform_fault: input.platform_fault,
            hart_state: input.hart_state,
            side_effects: 0,
            console_bytes: 0,
            timer_value: 0,
        }
    }

    fn duplicate_multiplier(&self) -> u32 {
        if self.platform_fault.duplicate_side_effects {
            2
        } else {
            1
        }
    }

    fn record_side_effect(&mut self, base: u32) {
        self.side_effects += base.saturating_mul(self.duplicate_multiplier());
    }

    fn success_or_fault(&mut self, default_value: usize, record_side_effects: bool) -> SbiRet {
        match self.platform_fault.mode {
            HostPlatformFaultMode::ReturnSbiError | HostPlatformFaultMode::ReturnRawError => {
                SbiRet {
                    error: self.platform_fault.error as usize,
                    value: self.platform_fault.value as usize,
                }
            }
            HostPlatformFaultMode::OverrideValue => {
                if record_side_effects {
                    self.record_side_effect(1);
                }
                SbiRet::success(self.platform_fault.value as usize)
            }
            HostPlatformFaultMode::None => {
                if record_side_effects {
                    self.record_side_effect(1);
                }
                SbiRet::success(default_value)
            }
        }
    }

    fn resolve_phys_addr(num_bytes: usize, lo: usize, hi: usize) -> Result<(u64, usize), SbiRet> {
        if hi != 0 {
            return Err(SbiRet::invalid_param());
        }
        Ok((lo as u64, num_bytes))
    }

    fn find_region_index(
        &self,
        addr: u64,
        len: usize,
        need_read: bool,
        need_write: bool,
    ) -> Option<(usize, usize)> {
        let len_u64 = len as u64;
        let end = addr.checked_add(len_u64)?;
        for (index, region) in self.memory_regions.iter().enumerate() {
            let region_end = region.guest_addr.checked_add(region.bytes.len() as u64)?;
            if addr < region.guest_addr || region_end < end {
                continue;
            }
            if need_read && !region.read {
                continue;
            }
            if need_write && !region.write {
                continue;
            }
            let offset = (addr - region.guest_addr) as usize;
            return Some((index, offset));
        }
        None
    }
}

impl SharedState {
    fn snapshot(&self) -> BackendState {
        self.0.borrow().clone()
    }
}

impl RustSbiAdapter {
    fn from_input(input: &HostHarnessInput) -> Self {
        let shared = SharedState(Rc::new(RefCell::new(BackendState::from_input(input))));
        Self {
            env: MockEnvInfo,
            console: MockConsole {
                state: shared.clone(),
            },
            timer: MockTimer {
                state: shared.clone(),
            },
            ipi: MockIpi {
                state: shared.clone(),
            },
            hsm: MockHsm {
                state: shared.clone(),
            },
            reset: MockReset {
                state: shared.clone(),
            },
            fence: MockFence { state: shared },
        }
    }

    fn state(&self) -> SharedState {
        self.console.state.clone()
    }

    fn probe_extension(&self, extension: usize) -> usize {
        match extension {
            rustsbi::spec::base::EID_BASE => {
                rustsbi::spec::base::UNAVAILABLE_EXTENSION.wrapping_add(1)
            }
            rustsbi::spec::time::EID_TIME => _rustsbi_timer_probe(&self.timer),
            rustsbi::spec::spi::EID_SPI => _rustsbi_ipi_probe(&self.ipi),
            rustsbi::spec::hsm::EID_HSM => _rustsbi_hsm_probe(&self.hsm),
            rustsbi::spec::srst::EID_SRST => _rustsbi_reset_probe(&self.reset),
            rustsbi::spec::dbcn::EID_DBCN => _rustsbi_console_probe(&self.console),
            rustsbi::spec::rfnc::EID_RFNC => _rustsbi_fence_probe(&self.fence),
            _ => rustsbi::spec::base::UNAVAILABLE_EXTENSION,
        }
    }
}

impl EnvInfo for MockEnvInfo {
    fn mvendorid(&self) -> usize {
        0x1234
    }

    fn marchid(&self) -> usize {
        0x5678
    }

    fn mimpid(&self) -> usize {
        0x9abc
    }
}

impl Console for MockConsole {
    fn write(&self, bytes: Physical<&[u8]>) -> SbiRet {
        let (addr, len) = match BackendState::resolve_phys_addr(
            bytes.num_bytes(),
            bytes.phys_addr_lo(),
            bytes.phys_addr_hi(),
        ) {
            Ok(value) => value,
            Err(err) => return err,
        };
        let mut state = self.state.0.borrow_mut();
        if state.find_region_index(addr, len, true, false).is_none() {
            return SbiRet::invalid_param();
        }
        let multiplier = state.duplicate_multiplier() as usize;
        state.console_bytes = state
            .console_bytes
            .saturating_add((len as u32).saturating_mul(multiplier as u32));
        state.success_or_fault(len.saturating_mul(multiplier), true)
    }

    fn read(&self, bytes: Physical<&mut [u8]>) -> SbiRet {
        let (addr, len) = match BackendState::resolve_phys_addr(
            bytes.num_bytes(),
            bytes.phys_addr_lo(),
            bytes.phys_addr_hi(),
        ) {
            Ok(value) => value,
            Err(err) => return err,
        };
        let mut state = self.state.0.borrow_mut();
        let Some((index, offset)) = state.find_region_index(addr, len, false, true) else {
            return SbiRet::invalid_param();
        };
        if !matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            let end = offset + len;
            state.memory_regions[index].bytes[offset..end].fill(b'R');
        }
        let multiplier = state.duplicate_multiplier() as usize;
        state.console_bytes = state
            .console_bytes
            .saturating_add((len as u32).saturating_mul(multiplier as u32));
        state.success_or_fault(len.saturating_mul(multiplier), true)
    }

    fn write_byte(&self, _byte: u8) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        state.console_bytes = state
            .console_bytes
            .saturating_add(state.duplicate_multiplier());
        state.success_or_fault(0, true)
    }
}

impl Timer for MockTimer {
    fn set_timer(&self, stime_value: u64) {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return;
        }
        state.timer_value = stime_value;
        state.record_side_effect(1);
    }
}

impl Ipi for MockIpi {
    fn send_ipi(&self, _hart_mask: HartMask) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        state.success_or_fault(0, true)
    }
}

impl Hsm for MockHsm {
    fn hart_start(&self, _hartid: usize, _start_addr: usize, _opaque: usize) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return state.success_or_fault(0, false);
        }
        if state.hart_state == HostHartState::Started {
            return SbiRet::already_started();
        }
        state.success_or_fault(0, true)
    }

    fn hart_stop(&self) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return state.success_or_fault(0, false);
        }
        if state.hart_state == HostHartState::Stopped {
            return SbiRet::already_stopped();
        }
        state.success_or_fault(0, true)
    }

    fn hart_get_status(&self, _hartid: usize) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return state.success_or_fault(0, false);
        }
        let value = match state.hart_state {
            HostHartState::Unknown | HostHartState::Started => 0,
            HostHartState::Stopped => 1,
            HostHartState::Suspended => 4,
        };
        state.success_or_fault(value, false)
    }

    fn hart_suspend(&self, _suspend_type: u32, _resume_addr: usize, _opaque: usize) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return state.success_or_fault(0, false);
        }
        if state.hart_state != HostHartState::Started {
            return SbiRet {
                error: SbiError::InvalidState.code() as usize,
                value: 0,
            };
        }
        state.success_or_fault(0, true)
    }
}

impl Reset for MockReset {
    fn system_reset(&self, reset_type: u32, reset_reason: u32) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return state.success_or_fault(0, false);
        }
        let reset_type_valid = matches!(reset_type, 0..=2);
        let reset_reason_valid = matches!(reset_reason, 0..=1);
        if !reset_type_valid || !reset_reason_valid {
            return SbiRet::invalid_param();
        }
        state.success_or_fault(0, true)
    }
}

impl Fence for MockFence {
    fn remote_fence_i(&self, _hart_mask: HartMask) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        state.success_or_fault(0, true)
    }

    fn remote_sfence_vma(&self, _hart_mask: HartMask, start_addr: usize, size: usize) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if start_addr.checked_add(size).is_none() {
            return SbiRet::invalid_address();
        }
        state.success_or_fault(0, true)
    }

    fn remote_sfence_vma_asid(
        &self,
        _hart_mask: HartMask,
        start_addr: usize,
        size: usize,
        _asid: usize,
    ) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if start_addr.checked_add(size).is_none() {
            return SbiRet::invalid_address();
        }
        state.success_or_fault(0, true)
    }
}

impl RustSBI for RustSbiAdapter {
    fn handle_ecall(&self, extension: usize, function: usize, param: [usize; 6]) -> SbiRet {
        let raw = match extension {
            rustsbi::spec::base::EID_BASE => {
                let probe = _StandardExtensionProbe {
                    base: rustsbi::spec::base::UNAVAILABLE_EXTENSION.wrapping_add(1),
                    fence: _rustsbi_fence_probe(&self.fence),
                    timer: _rustsbi_timer_probe(&self.timer),
                    ipi: _rustsbi_ipi_probe(&self.ipi),
                    hsm: _rustsbi_hsm_probe(&self.hsm),
                    reset: _rustsbi_reset_probe(&self.reset),
                    pmu: rustsbi::spec::base::UNAVAILABLE_EXTENSION,
                    console: _rustsbi_console_probe(&self.console),
                    susp: rustsbi::spec::base::UNAVAILABLE_EXTENSION,
                    cppc: rustsbi::spec::base::UNAVAILABLE_EXTENSION,
                    nacl: rustsbi::spec::base::UNAVAILABLE_EXTENSION,
                    sta: rustsbi::spec::base::UNAVAILABLE_EXTENSION,
                };
                _rustsbi_base_env_info(param, function, &self.env, probe)
            }
            rustsbi::spec::time::EID_TIME => _rustsbi_timer(&self.timer, param, function),
            rustsbi::spec::spi::EID_SPI => _rustsbi_ipi(&self.ipi, param, function),
            rustsbi::spec::hsm::EID_HSM => _rustsbi_hsm(&self.hsm, param, function),
            rustsbi::spec::srst::EID_SRST => _rustsbi_reset(&self.reset, param, function),
            rustsbi::spec::dbcn::EID_DBCN => _rustsbi_console(&self.console, param, function),
            rustsbi::spec::rfnc::EID_RFNC => _rustsbi_fence(&self.fence, param, function),
            _ => SbiRet::not_supported(),
        };

        if extension == rustsbi::spec::time::EID_TIME {
            let shared = self.state();
            let mut state = shared.0.borrow_mut();
            if matches!(
                state.platform_fault.mode,
                HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
            ) {
                return state.success_or_fault(raw.value, false);
            }
            if state.platform_fault.mode == HostPlatformFaultMode::OverrideValue {
                return SbiRet::success(state.platform_fault.value as usize);
            }
        }

        raw
    }
}

pub(crate) fn seed_fdt_blob(variant: FdtSeedVariant) -> Result<Vec<u8>, String> {
    let raw_variant = match variant {
        FdtSeedVariant::Minimal => 0,
        FdtSeedVariant::MissingCpus => 1,
        FdtSeedVariant::BadStdoutPath => 2,
        FdtSeedVariant::BadConsoleCompatible => 3,
        FdtSeedVariant::BadColdbootPhandle | FdtSeedVariant::BadHeapSize => {
            return Err(format!(
                "unsupported RustSBI FDT seed variant: {:?}",
                variant
            ));
        }
    };
    let mut buf = vec![0_u8; FDT_SEED_BUFFER_CAPACITY];
    let written =
        unsafe { sbifuzz_host_build_rustsbi_seed_fdt(raw_variant, buf.as_mut_ptr(), buf.len()) };
    if written == 0 {
        return Err(format!(
            "failed to build RustSBI FDT seed for variant {:?}",
            variant
        ));
    }
    buf.truncate(written);
    Ok(buf)
}

pub(crate) fn run(input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
    match input.mode {
        HostHarnessMode::Ecall | HostHarnessMode::PlatformFault => run_ecall(input),
        HostHarnessMode::Fdt => run_fdt(input),
    }
}

fn run_ecall(input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
    let adapter = RustSbiAdapter::from_input(input);
    let ret = adapter.handle_ecall(
        input.call.extid as usize,
        input.call.fid as usize,
        input.call.args.map(|arg| arg as usize),
    );
    let state = adapter.state().snapshot();
    let sbi_error = ret.error as i64;
    let sbi_error_name = SbiError::from_code(sbi_error).map(|err| err.name().to_string());
    let classification = if let Some(kind) = SbiError::from_code(sbi_error) {
        if kind == SbiError::Success {
            "ok".to_string()
        } else {
            format!("sbi_error:{}", kind.name())
        }
    } else {
        "non_standard_error".to_string()
    };
    let extension_found = adapter.probe_extension(input.call.extid as usize)
        != rustsbi::spec::base::UNAVAILABLE_EXTENSION;
    let signature = format!(
        "rustsbi/{:?}/ext=0x{:x}/fid=0x{:x}/err={}/found={}/sidefx={}",
        input.mode,
        input.call.extid,
        input.call.fid,
        sbi_error,
        extension_found,
        state.side_effects
    );

    Ok(HostHarnessReport {
        target_kind: HostTargetKind::RustSbi,
        backend: "rustsbi-rust".to_string(),
        mode: input.mode,
        classification,
        signature,
        result: HostHarnessResult::Ecall(HostEcallReport {
            extid: input.call.extid,
            fid: input.call.fid,
            sbi_error,
            sbi_error_name,
            value: ret.value as u64,
            next_mepc: None,
            extension_found,
            side_effects: state.side_effects,
            console_bytes: state.console_bytes,
            timer_value: state.timer_value,
        }),
    })
}

fn run_fdt(input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
    let mut response = NativeRustsbiFdtResponse::default();
    let rc = unsafe {
        sbifuzz_host_parse_rustsbi_fdt(input.fdt_blob.as_ptr(), input.fdt_blob.len(), &mut response)
    };
    if rc != 0 {
        return Err(format!("RustSBI host FDT adapter failed with status {rc}"));
    }

    let stdout_path_present = response.stdout_path_present != 0;
    let console_present = response.console_present != 0;
    let ipi_present = response.ipi_present != 0;
    let reset_present = response.reset_present != 0;
    let classification = if response.status != 0 {
        "fdt_error".to_string()
    } else if !stdout_path_present || !console_present || !ipi_present || !reset_present {
        "partial_config".to_string()
    } else {
        "ok".to_string()
    };
    let signature = format!(
        "rustsbi/fdt/status={}/harts={}/stdout={}/console={}/ipi={}/reset={}",
        response.status,
        response.hart_count,
        response.stdout_path_present,
        response.console_present,
        response.ipi_present,
        response.reset_present
    );
    let failure = c_buf_to_string(&response.failure);

    Ok(HostHarnessReport {
        target_kind: HostTargetKind::RustSbi,
        backend: "rustsbi-fdt".to_string(),
        mode: HostHarnessMode::Fdt,
        classification,
        signature,
        result: HostHarnessResult::Fdt(HostFdtReport {
            status: response.status,
            model: c_buf_to_string(&response.model),
            hart_count: response.hart_count,
            chosen_present: response.chosen_present != 0,
            config_present: stdout_path_present,
            failure: if failure.is_empty() {
                None
            } else {
                Some(failure)
            },
            details: HostFdtDetails::RustSbi {
                stdout_path_present,
                console_present,
                ipi_present,
                reset_present,
                memory_start: response.memory_start,
                memory_end: response.memory_end,
            },
        }),
    })
}

fn c_buf_to_string(buf: &[c_char]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}
