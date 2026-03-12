use crate::{
    FDT_SEED_BUFFER_CAPACITY, FdtSeedVariant, HostEcallReport, HostFdtDetails, HostFdtReport,
    HostHarnessReport, HostHarnessResult,
};
use common::{
    HostHarnessInput, HostHarnessMode, HostHartState, HostMemoryRegion, HostPlatformFaultMode,
    HostPrivilegeState, HostTargetKind, SbiError,
};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

#[repr(C)]
struct NativeMemoryRegion {
    guest_addr: u64,
    data_ptr: *const u8,
    data_len: usize,
    read: u8,
    write: u8,
    execute: u8,
}

#[repr(C)]
struct NativePlatformFaultProfile {
    mode: u32,
    error: i64,
    value: u64,
    duplicate_side_effects: u8,
}

#[repr(C)]
struct NativeHostRequest {
    extid: u64,
    fid: u64,
    args: [u64; 6],
    hart_id: u64,
    hart_state: u32,
    privilege: u32,
    regions_ptr: *const NativeMemoryRegion,
    regions_len: usize,
    fault: NativePlatformFaultProfile,
}

#[repr(C)]
#[derive(Default)]
struct NativeHostResponse {
    dispatch_status: c_int,
    sbi_error: i64,
    value: u64,
    next_mepc: u64,
    extension_found: u32,
    side_effects: u32,
    console_bytes: u32,
    timer_value: u64,
}

#[repr(C)]
struct NativeFdtResponse {
    status: c_int,
    hart_count: u32,
    chosen_present: u32,
    opensbi_config_present: u32,
    coldboot_hart_count: u32,
    heap_size: u32,
    model: [c_char; 64],
    failure: [c_char; 96],
}

impl Default for NativeFdtResponse {
    fn default() -> Self {
        Self {
            status: 0,
            hart_count: 0,
            chosen_present: 0,
            opensbi_config_present: 0,
            coldboot_hart_count: 0,
            heap_size: 0,
            model: [0; 64],
            failure: [0; 96],
        }
    }
}

unsafe extern "C" {
    fn sbifuzz_host_ecall_run(
        req: *const NativeHostRequest,
        resp: *mut NativeHostResponse,
    ) -> c_int;
    fn sbifuzz_host_parse_fdt(
        blob: *const u8,
        blob_len: usize,
        resp: *mut NativeFdtResponse,
    ) -> c_int;
    fn sbifuzz_host_build_seed_fdt(variant: u32, out: *mut u8, out_cap: usize) -> usize;
}

pub(crate) fn seed_fdt_blob(variant: FdtSeedVariant) -> Result<Vec<u8>, String> {
    let raw_variant = match variant {
        FdtSeedVariant::Minimal => 0,
        FdtSeedVariant::MissingCpus => 1,
        FdtSeedVariant::BadColdbootPhandle => 2,
        FdtSeedVariant::BadHeapSize => 3,
        FdtSeedVariant::BadStdoutPath | FdtSeedVariant::BadConsoleCompatible => {
            return Err(format!(
                "unsupported OpenSBI FDT seed variant: {:?}",
                variant
            ));
        }
    };
    let mut buf = vec![0_u8; FDT_SEED_BUFFER_CAPACITY];
    let written = unsafe { sbifuzz_host_build_seed_fdt(raw_variant, buf.as_mut_ptr(), buf.len()) };
    if written == 0 {
        return Err(format!(
            "failed to build OpenSBI FDT seed for variant {:?}",
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
    let native_regions: Vec<NativeMemoryRegion> =
        input.memory_regions.iter().map(region_to_native).collect();
    let request = NativeHostRequest {
        extid: input.call.extid,
        fid: input.call.fid,
        args: input.call.args,
        hart_id: input.hart_id,
        hart_state: hart_state_to_raw(input.hart_state),
        privilege: privilege_to_raw(input.privilege),
        regions_ptr: native_regions.as_ptr(),
        regions_len: native_regions.len(),
        fault: NativePlatformFaultProfile {
            mode: fault_mode_to_raw(input.platform_fault.mode),
            error: input.platform_fault.error,
            value: input.platform_fault.value,
            duplicate_side_effects: u8::from(input.platform_fault.duplicate_side_effects),
        },
    };
    let mut response = NativeHostResponse::default();
    let rc = unsafe { sbifuzz_host_ecall_run(&request, &mut response) };
    if rc != 0 {
        return Err(format!(
            "OpenSBI host ecall adapter failed with status {rc}"
        ));
    }

    let sbi_error_name = SbiError::from_code(response.sbi_error).map(|err| err.name().to_string());
    let classification = classify_ecall(response.dispatch_status, response.sbi_error);
    let signature = format!(
        "opensbi/{:?}/ext=0x{:x}/fid=0x{:x}/err={}/found={}/sidefx={}",
        input.mode,
        input.call.extid,
        input.call.fid,
        response.sbi_error,
        response.extension_found,
        response.side_effects
    );

    Ok(HostHarnessReport {
        target_kind: HostTargetKind::OpenSbi,
        backend: "opensbi-ffi".to_string(),
        mode: input.mode,
        classification,
        signature,
        result: HostHarnessResult::Ecall(HostEcallReport {
            extid: input.call.extid,
            fid: input.call.fid,
            sbi_error: response.sbi_error,
            sbi_error_name,
            value: response.value,
            next_mepc: Some(response.next_mepc),
            extension_found: response.extension_found != 0,
            side_effects: response.side_effects,
            console_bytes: response.console_bytes,
            timer_value: response.timer_value,
        }),
    })
}

fn run_fdt(input: &HostHarnessInput) -> Result<HostHarnessReport, String> {
    let mut response = NativeFdtResponse::default();
    let rc = unsafe {
        sbifuzz_host_parse_fdt(input.fdt_blob.as_ptr(), input.fdt_blob.len(), &mut response)
    };
    if rc != 0 {
        return Err(format!("OpenSBI host FDT adapter failed with status {rc}"));
    }

    let config_present = response.opensbi_config_present != 0;
    let classification = if response.status != 0 {
        "fdt_error".to_string()
    } else if !config_present {
        "partial_config".to_string()
    } else {
        "ok".to_string()
    };
    let signature = format!(
        "opensbi/fdt/status={}/harts={}/config={}",
        response.status, response.hart_count, response.opensbi_config_present
    );
    let failure = c_buf_to_string(&response.failure);

    Ok(HostHarnessReport {
        target_kind: HostTargetKind::OpenSbi,
        backend: "opensbi-ffi".to_string(),
        mode: HostHarnessMode::Fdt,
        classification,
        signature,
        result: HostHarnessResult::Fdt(HostFdtReport {
            status: response.status,
            model: c_buf_to_string(&response.model),
            hart_count: response.hart_count,
            chosen_present: response.chosen_present != 0,
            config_present,
            failure: if failure.is_empty() {
                None
            } else {
                Some(failure)
            },
            details: HostFdtDetails::OpenSbi {
                coldboot_hart_count: response.coldboot_hart_count,
                heap_size: response.heap_size,
            },
        }),
    })
}

fn classify_ecall(dispatch_status: c_int, sbi_error: i64) -> String {
    if dispatch_status != 0 {
        return "dispatch_error".to_string();
    }
    if let Some(kind) = SbiError::from_code(sbi_error) {
        if kind == SbiError::Success {
            "ok".to_string()
        } else {
            format!("sbi_error:{}", kind.name())
        }
    } else {
        "non_standard_error".to_string()
    }
}

fn region_to_native(region: &HostMemoryRegion) -> NativeMemoryRegion {
    NativeMemoryRegion {
        guest_addr: region.guest_addr,
        data_ptr: region.bytes.as_ptr(),
        data_len: region.bytes.len(),
        read: u8::from(region.read),
        write: u8::from(region.write),
        execute: u8::from(region.execute),
    }
}

fn hart_state_to_raw(state: HostHartState) -> u32 {
    match state {
        HostHartState::Unknown => 0,
        HostHartState::Started => 1,
        HostHartState::Stopped => 2,
        HostHartState::Suspended => 3,
    }
}

fn privilege_to_raw(state: HostPrivilegeState) -> u32 {
    match state {
        HostPrivilegeState::User => 0,
        HostPrivilegeState::Supervisor => 1,
        HostPrivilegeState::Machine => 2,
    }
}

fn fault_mode_to_raw(mode: HostPlatformFaultMode) -> u32 {
    match mode {
        HostPlatformFaultMode::None => 0,
        HostPlatformFaultMode::ReturnSbiError => 1,
        HostPlatformFaultMode::ReturnRawError => 2,
        HostPlatformFaultMode::OverrideValue => 3,
    }
}

fn c_buf_to_string(buf: &[c_char]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}
