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
use std::collections::HashMap;
use std::rc::Rc;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_VERSION: u32 = 17;
const FDT_LAST_COMP_VERSION: u32 = 16;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const FDT_HEADER_BYTES: usize = 40;
const FDT_RESERVATION_BYTES: usize = 16;
const FDT_STATUS_BAD_VALUE: i32 = -1;
const FDT_STATUS_TRUNCATED: i32 = -2;
const FDT_STATUS_BAD_MAGIC: i32 = -3;
const FDT_STATUS_BAD_LAYOUT: i32 = -4;
const FDT_STATUS_NOT_FOUND: i32 = -5;
const RUSTSBI_CONSOLE_COMPATS: [&str; 4] = [
    "ns16550a",
    "snps,dw-apb-uart",
    "xlnx,xps-uartlite-1.00.a",
    "bflb,bl808-uart",
];

#[derive(Debug, Default)]
struct RustsbiFdtAnalysis {
    status: i32,
    hart_count: u32,
    chosen_present: bool,
    stdout_path_present: bool,
    console_present: bool,
    ipi_present: bool,
    reset_present: bool,
    memory_start: u64,
    memory_end: u64,
    model: String,
    failure: Option<String>,
}

#[derive(Debug)]
struct ParsedDtb {
    nodes: Vec<ParsedNode>,
}

#[derive(Debug)]
struct ParsedNode {
    name: String,
    path: String,
    props: HashMap<String, Vec<u8>>,
}

#[derive(Debug)]
struct DtbHeader {
    totalsize: usize,
    off_dt_struct: usize,
    off_dt_strings: usize,
    size_dt_struct: usize,
    size_dt_strings: usize,
}

struct DtbBuilder {
    strings: Vec<u8>,
    string_offsets: HashMap<&'static str, u32>,
    structure: Vec<u8>,
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
    hart_id: u64,
    hart_state: HostHartState,
    modeled_harts: u64,
    side_effects: u32,
    console_bytes: u32,
    timer_value: u64,
}

impl BackendState {
    fn from_input(input: &HostHarnessInput) -> Self {
        Self {
            memory_regions: input.memory_regions.clone(),
            platform_fault: input.platform_fault,
            hart_id: input.hart_id,
            hart_state: input.hart_state,
            modeled_harts: 64,
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

    fn hart_get_status(&self, hartid: usize) -> SbiRet {
        let mut state = self.state.0.borrow_mut();
        if matches!(
            state.platform_fault.mode,
            HostPlatformFaultMode::ReturnRawError | HostPlatformFaultMode::ReturnSbiError
        ) {
            return state.success_or_fault(0, false);
        }
        if hartid as u64 >= state.modeled_harts {
            return SbiRet::invalid_param();
        }
        let target_state = if hartid as u64 == state.hart_id {
            state.hart_state
        } else {
            HostHartState::Stopped
        };
        let value = match target_state {
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
    build_rustsbi_seed_fdt(variant)
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
        post_memory_regions: state.memory_regions.clone(),
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
    let response = analyze_rustsbi_fdt(&input.fdt_blob);
    let classification = if response.status != 0 {
        "fdt_error".to_string()
    } else if !response.stdout_path_present
        || !response.console_present
        || !response.ipi_present
        || !response.reset_present
    {
        "partial_config".to_string()
    } else {
        "ok".to_string()
    };
    let signature = format!(
        "rustsbi/fdt/status={}/harts={}/stdout={}/console={}/ipi={}/reset={}",
        response.status,
        response.hart_count,
        u8::from(response.stdout_path_present),
        u8::from(response.console_present),
        u8::from(response.ipi_present),
        u8::from(response.reset_present)
    );

    Ok(HostHarnessReport {
        target_kind: HostTargetKind::RustSbi,
        backend: "rustsbi-fdt".to_string(),
        mode: HostHarnessMode::Fdt,
        classification,
        signature,
        post_memory_regions: Vec::new(),
        result: HostHarnessResult::Fdt(HostFdtReport {
            status: response.status,
            model: response.model,
            hart_count: response.hart_count,
            chosen_present: response.chosen_present,
            config_present: response.stdout_path_present,
            failure: response.failure,
            details: HostFdtDetails::RustSbi {
                stdout_path_present: response.stdout_path_present,
                console_present: response.console_present,
                ipi_present: response.ipi_present,
                reset_present: response.reset_present,
                memory_start: response.memory_start,
                memory_end: response.memory_end,
            },
        }),
    })
}

fn build_rustsbi_seed_fdt(variant: FdtSeedVariant) -> Result<Vec<u8>, String> {
    let mut builder = DtbBuilder::new();
    builder.begin_node("");
    builder.prop_u32("#address-cells", 2);
    builder.prop_u32("#size-cells", 2);
    builder.prop_str("model", "rustsbi,qemu-virt");
    builder.prop_str("compatible", "riscv-virtio,qemu");

    if variant != FdtSeedVariant::MissingCpus {
        builder.begin_node("cpus");
        builder.prop_u32("#address-cells", 1);
        builder.prop_u32("#size-cells", 0);
        builder.begin_node("cpu@0");
        builder.prop_str("device_type", "cpu");
        builder.prop_str("compatible", "riscv");
        builder.prop_u32("reg", 0);
        builder.end_node();
        builder.end_node();
    }

    builder.begin_node("memory@80000000");
    builder.prop_str("device_type", "memory");
    builder.prop_u32s("reg", &[0, 0x8000_0000, 0, 0x1000_0000]);
    builder.end_node();

    builder.begin_node("soc");
    builder.prop_u32("#address-cells", 2);
    builder.prop_u32("#size-cells", 2);
    builder.prop_empty("ranges");

    builder.begin_node("serial@10000000");
    if variant == FdtSeedVariant::BadConsoleCompatible {
        builder.prop_str("compatible", "vendor,bad-uart");
    } else {
        builder.prop_str("compatible", "ns16550a");
    }
    builder.prop_u32s("reg", &[0, 0x1000_0000, 0, 0x100]);
    builder.end_node();

    builder.begin_node("clint@2000000");
    builder.prop_str("compatible", "riscv,clint0");
    builder.prop_u32s("reg", &[0, 0x0200_0000, 0, 0x1_0000]);
    builder.end_node();

    builder.begin_node("test@100000");
    builder.prop_str("compatible", "sifive,test0");
    builder.prop_u32s("reg", &[0, 0x0010_0000, 0, 0x1000]);
    builder.end_node();

    builder.end_node();

    builder.begin_node("chosen");
    if variant == FdtSeedVariant::BadStdoutPath {
        builder.prop_str("stdout-path", "/soc/missing@deadbeef");
    } else {
        builder.prop_str("stdout-path", "/soc/serial@10000000");
    }
    builder.end_node();
    builder.end_node();

    let blob = builder.finish();
    if blob.len() > FDT_SEED_BUFFER_CAPACITY {
        return Err(format!(
            "RustSBI FDT seed exceeded buffer capacity: {} > {}",
            blob.len(),
            FDT_SEED_BUFFER_CAPACITY
        ));
    }
    Ok(blob)
}

fn analyze_rustsbi_fdt(blob: &[u8]) -> RustsbiFdtAnalysis {
    let parsed = match parse_dtb(blob) {
        Ok(parsed) => parsed,
        Err((status, failure)) => {
            return RustsbiFdtAnalysis {
                status,
                failure: Some(failure),
                ..RustsbiFdtAnalysis::default()
            };
        }
    };

    let Some(root) = parsed.node("/") else {
        return RustsbiFdtAnalysis {
            status: FDT_STATUS_BAD_LAYOUT,
            failure: Some("missing root node".to_string()),
            ..RustsbiFdtAnalysis::default()
        };
    };

    let Some(_cpus) = parsed.node("/cpus") else {
        return RustsbiFdtAnalysis {
            status: FDT_STATUS_NOT_FOUND,
            failure: Some("missing /cpus node".to_string()),
            model: prop_cstr(root, "model").unwrap_or_default(),
            ..RustsbiFdtAnalysis::default()
        };
    };

    let (memory_start, memory_end) = match parse_memory_window(&parsed, root) {
        Ok(window) => window,
        Err((status, _failure)) if status == FDT_STATUS_NOT_FOUND => (0, 0),
        Err((status, failure)) => {
            return RustsbiFdtAnalysis {
                status,
                failure: Some(failure),
                model: prop_cstr(root, "model").unwrap_or_default(),
                ..RustsbiFdtAnalysis::default()
            };
        }
    };

    let hart_count = parsed
        .nodes
        .iter()
        .filter(|node| parent_path(&node.path) == "/cpus" && node.name.starts_with("cpu"))
        .filter(|node| prop_cstr(node, "status").as_deref() != Some("disabled"))
        .count() as u32;
    let chosen = parsed.node("/chosen");
    let stdout_path_present = chosen
        .and_then(|node| prop_cstr(node, "stdout-path"))
        .and_then(|value| normalize_stdout_path(&value))
        .and_then(|path| parsed.node(&path))
        .is_some();
    let console_present = chosen
        .and_then(|node| prop_cstr(node, "stdout-path"))
        .and_then(|value| normalize_stdout_path(&value))
        .and_then(|path| parsed.node(&path))
        .is_some_and(is_console_node);
    let ipi_present = parsed.nodes.iter().any(|node| {
        compatible_contains(node, "riscv,clint0") || compatible_contains(node, "thead,c900-clint")
    });
    let reset_present = parsed
        .nodes
        .iter()
        .any(|node| compatible_contains(node, "sifive,test0"));

    RustsbiFdtAnalysis {
        status: 0,
        hart_count,
        chosen_present: chosen.is_some(),
        stdout_path_present,
        console_present,
        ipi_present,
        reset_present,
        memory_start,
        memory_end,
        model: prop_cstr(root, "model").unwrap_or_default(),
        failure: None,
    }
}

type DtbResult<T> = Result<T, (i32, String)>;

impl ParsedDtb {
    fn node(&self, path: &str) -> Option<&ParsedNode> {
        self.nodes.iter().find(|node| node.path == path)
    }
}

impl DtbBuilder {
    fn new() -> Self {
        Self {
            strings: Vec::new(),
            string_offsets: HashMap::new(),
            structure: Vec::new(),
        }
    }

    fn begin_node(&mut self, name: &str) {
        self.push_u32(FDT_BEGIN_NODE);
        self.structure.extend_from_slice(name.as_bytes());
        self.structure.push(0);
        self.pad_structure();
    }

    fn end_node(&mut self) {
        self.push_u32(FDT_END_NODE);
    }

    fn prop_u32(&mut self, name: &'static str, value: u32) {
        self.prop_bytes(name, &value.to_be_bytes());
    }

    fn prop_u32s(&mut self, name: &'static str, values: &[u32]) {
        let mut bytes = Vec::with_capacity(values.len() * 4);
        for value in values {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        self.prop_bytes(name, &bytes);
    }

    fn prop_str(&mut self, name: &'static str, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.prop_bytes(name, &bytes);
    }

    fn prop_empty(&mut self, name: &'static str) {
        self.prop_bytes(name, &[]);
    }

    fn prop_bytes(&mut self, name: &'static str, value: &[u8]) {
        let name_offset = self.string_offset(name);
        self.push_u32(FDT_PROP);
        self.push_u32(value.len() as u32);
        self.push_u32(name_offset);
        self.structure.extend_from_slice(value);
        self.pad_structure();
    }

    fn finish(mut self) -> Vec<u8> {
        self.push_u32(FDT_END);
        let off_dt_struct = FDT_HEADER_BYTES + FDT_RESERVATION_BYTES;
        let off_dt_strings = off_dt_struct + self.structure.len();
        let totalsize = off_dt_strings + self.strings.len();
        let mut out = Vec::with_capacity(totalsize);
        out.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        out.extend_from_slice(&(totalsize as u32).to_be_bytes());
        out.extend_from_slice(&(off_dt_struct as u32).to_be_bytes());
        out.extend_from_slice(&(off_dt_strings as u32).to_be_bytes());
        out.extend_from_slice(&(FDT_HEADER_BYTES as u32).to_be_bytes());
        out.extend_from_slice(&FDT_VERSION.to_be_bytes());
        out.extend_from_slice(&FDT_LAST_COMP_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        out.extend_from_slice(&(self.strings.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.structure.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0_u8; FDT_RESERVATION_BYTES]);
        out.extend_from_slice(&self.structure);
        out.extend_from_slice(&self.strings);
        out
    }

    fn push_u32(&mut self, value: u32) {
        self.structure.extend_from_slice(&value.to_be_bytes());
    }

    fn pad_structure(&mut self) {
        while self.structure.len() % 4 != 0 {
            self.structure.push(0);
        }
    }

    fn string_offset(&mut self, name: &'static str) -> u32 {
        if let Some(offset) = self.string_offsets.get(name) {
            return *offset;
        }
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.string_offsets.insert(name, offset);
        offset
    }
}

fn parse_dtb(blob: &[u8]) -> DtbResult<ParsedDtb> {
    let header = parse_dtb_header(blob)?;
    let struct_end = header
        .off_dt_struct
        .checked_add(header.size_dt_struct)
        .ok_or((
            FDT_STATUS_BAD_LAYOUT,
            "structure block overflow".to_string(),
        ))?;
    let strings_end = header
        .off_dt_strings
        .checked_add(header.size_dt_strings)
        .ok_or((FDT_STATUS_BAD_LAYOUT, "strings block overflow".to_string()))?;
    let blob_end = header.totalsize.min(blob.len());
    if struct_end > blob_end || strings_end > blob_end {
        return Err((
            FDT_STATUS_TRUNCATED,
            "FDT blocks extend past blob boundary".to_string(),
        ));
    }
    parse_dtb_structure(
        &blob[header.off_dt_struct..struct_end],
        &blob[header.off_dt_strings..strings_end],
    )
}

fn parse_dtb_header(blob: &[u8]) -> DtbResult<DtbHeader> {
    if blob.len() < FDT_HEADER_BYTES {
        return Err((FDT_STATUS_TRUNCATED, "blob too short".to_string()));
    }
    let magic = read_be_u32(blob, 0)?;
    if magic != FDT_MAGIC {
        return Err((FDT_STATUS_BAD_MAGIC, "bad FDT magic".to_string()));
    }
    let totalsize = read_be_u32(blob, 4)? as usize;
    if totalsize > blob.len() {
        return Err((
            FDT_STATUS_TRUNCATED,
            format!("blob shorter than totalsize: {totalsize} > {}", blob.len()),
        ));
    }
    let off_dt_struct = read_be_u32(blob, 8)? as usize;
    let off_dt_strings = read_be_u32(blob, 12)? as usize;
    let size_dt_strings = read_be_u32(blob, 32)? as usize;
    let size_dt_struct = read_be_u32(blob, 36)? as usize;
    if off_dt_struct >= totalsize || off_dt_strings >= totalsize {
        return Err((FDT_STATUS_BAD_LAYOUT, "invalid FDT offsets".to_string()));
    }
    Ok(DtbHeader {
        totalsize,
        off_dt_struct,
        off_dt_strings,
        size_dt_struct,
        size_dt_strings,
    })
}

fn parse_dtb_structure(structure: &[u8], strings: &[u8]) -> DtbResult<ParsedDtb> {
    let mut offset = 0;
    let mut stack = Vec::<usize>::new();
    let mut nodes = Vec::<ParsedNode>::new();

    while offset < structure.len() {
        let token = read_be_u32(structure, offset)?;
        offset += 4;
        match token {
            FDT_BEGIN_NODE => {
                let name_end = structure[offset..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or((FDT_STATUS_TRUNCATED, "unterminated node name".to_string()))?;
                let name =
                    String::from_utf8_lossy(&structure[offset..offset + name_end]).into_owned();
                offset += name_end + 1;
                offset = align4(offset);
                if offset > structure.len() {
                    return Err((
                        FDT_STATUS_TRUNCATED,
                        "node padding exceeds blob".to_string(),
                    ));
                }
                let path = if stack.is_empty() {
                    "/".to_string()
                } else {
                    let parent = &nodes[*stack.last().expect("parent node")].path;
                    if parent == "/" {
                        format!("/{}", name)
                    } else {
                        format!("{parent}/{}", name)
                    }
                };
                nodes.push(ParsedNode {
                    name,
                    path,
                    props: HashMap::new(),
                });
                stack.push(nodes.len() - 1);
            }
            FDT_END_NODE => {
                if stack.pop().is_none() {
                    return Err((FDT_STATUS_BAD_LAYOUT, "unexpected end node".to_string()));
                }
            }
            FDT_PROP => {
                if offset + 8 > structure.len() {
                    return Err((
                        FDT_STATUS_TRUNCATED,
                        "truncated property header".to_string(),
                    ));
                }
                let prop_len = read_be_u32(structure, offset)? as usize;
                let name_off = read_be_u32(structure, offset + 4)? as usize;
                offset += 8;
                let prop_end = offset.checked_add(prop_len).ok_or((
                    FDT_STATUS_BAD_LAYOUT,
                    "property length overflow".to_string(),
                ))?;
                if prop_end > structure.len() {
                    return Err((FDT_STATUS_TRUNCATED, "truncated property value".to_string()));
                }
                let prop_name = read_cstr(strings, name_off)
                    .map_err(|message| (FDT_STATUS_BAD_LAYOUT, message))?;
                let Some(current) = stack.last().copied() else {
                    return Err((FDT_STATUS_BAD_LAYOUT, "property outside node".to_string()));
                };
                nodes[current]
                    .props
                    .insert(prop_name, structure[offset..prop_end].to_vec());
                offset = align4(prop_end);
                if offset > structure.len() {
                    return Err((
                        FDT_STATUS_TRUNCATED,
                        "property padding exceeds blob".to_string(),
                    ));
                }
            }
            FDT_NOP => {}
            FDT_END => {
                if !stack.is_empty() {
                    return Err((FDT_STATUS_BAD_LAYOUT, "unterminated node stack".to_string()));
                }
                return Ok(ParsedDtb { nodes });
            }
            other => {
                return Err((FDT_STATUS_BAD_LAYOUT, format!("unknown FDT token {other}")));
            }
        }
    }

    Err((FDT_STATUS_TRUNCATED, "missing FDT_END token".to_string()))
}

fn parse_memory_window(parsed: &ParsedDtb, root: &ParsedNode) -> DtbResult<(u64, u64)> {
    let addr_cells = prop_u32(root, "#address-cells").unwrap_or(2) as usize;
    let size_cells = prop_u32(root, "#size-cells").unwrap_or(2) as usize;
    let Some(node) = parsed
        .nodes
        .iter()
        .find(|node| parent_path(&node.path) == "/" && node.name.starts_with("memory"))
    else {
        return Err((FDT_STATUS_NOT_FOUND, "missing memory node".to_string()));
    };
    let reg = node
        .props
        .get("reg")
        .ok_or((FDT_STATUS_BAD_VALUE, "memory node missing reg".to_string()))?;
    if reg.len() < (addr_cells + size_cells) * 4 {
        return Err((FDT_STATUS_BAD_VALUE, "memory reg is truncated".to_string()));
    }
    let address = cells_to_u64(reg, addr_cells)?;
    let size = cells_to_u64(&reg[addr_cells * 4..], size_cells)?;
    Ok((address, address.saturating_add(size)))
}

fn compatible_contains(node: &ParsedNode, needle: &str) -> bool {
    prop_string_list(node, "compatible")
        .iter()
        .any(|value| value == needle)
}

fn is_console_node(node: &ParsedNode) -> bool {
    RUSTSBI_CONSOLE_COMPATS
        .iter()
        .any(|needle| compatible_contains(node, needle))
}

fn normalize_stdout_path(value: &str) -> Option<String> {
    let path = value.split(':').next().unwrap_or_default().trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn prop_cstr(node: &ParsedNode, name: &str) -> Option<String> {
    node.props.get(name).map(|value| {
        let len = value
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(value.len());
        String::from_utf8_lossy(&value[..len]).into_owned()
    })
}

fn prop_string_list(node: &ParsedNode, name: &str) -> Vec<String> {
    let Some(value) = node.props.get(name) else {
        return Vec::new();
    };
    value
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect()
}

fn prop_u32(node: &ParsedNode, name: &str) -> Option<u32> {
    let value = node.props.get(name)?;
    if value.len() != 4 {
        return None;
    }
    Some(u32::from_be_bytes(
        value[..4].try_into().expect("u32 property"),
    ))
}

fn cells_to_u64(bytes: &[u8], cells: usize) -> DtbResult<u64> {
    if !(1..=2).contains(&cells) {
        return Err((
            FDT_STATUS_BAD_VALUE,
            format!("unsupported cell count: {cells}"),
        ));
    }
    if bytes.len() < cells * 4 {
        return Err((FDT_STATUS_BAD_VALUE, "cell array is truncated".to_string()));
    }
    let mut value = 0_u64;
    for chunk in bytes[..cells * 4].chunks_exact(4) {
        value = (value << 32) | u64::from(u32::from_be_bytes(chunk.try_into().expect("cell")));
    }
    Ok(value)
}

fn read_be_u32(bytes: &[u8], offset: usize) -> DtbResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or((FDT_STATUS_BAD_LAYOUT, "offset overflow".to_string()))?;
    let chunk = bytes
        .get(offset..end)
        .ok_or((FDT_STATUS_TRUNCATED, "unexpected end of blob".to_string()))?;
    Ok(u32::from_be_bytes(chunk.try_into().expect("u32 slice")))
}

fn read_cstr(bytes: &[u8], offset: usize) -> Result<String, String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| "string offset out of range".to_string())?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "unterminated string in strings block".to_string())?;
    Ok(String::from_utf8_lossy(&tail[..len]).into_owned())
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn parent_path(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    path.rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
}
