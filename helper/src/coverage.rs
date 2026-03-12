use common::*;
use libafl_qemu::{Qemu, elf::EasyElf};
use std::path::{Path, PathBuf};

const OPENSBI_FIRMWARE_LOAD_ADDR: u64 = 0x8000_0000;

#[derive(Debug, Clone, Copy)]
pub struct SharedCoverageConfig {
    pub addr: u64,
    pub capacity: usize,
}

impl SharedCoverageConfig {
    pub fn byte_len(self) -> usize {
        sbi_coverage_buffer_bytes(self.capacity)
    }
}

#[derive(Debug, Clone)]
pub struct SharedCoverageSnapshot {
    pub addr: u64,
    pub raw: Vec<u8>,
    pub parsed: Result<SbiCoverageBuffer, String>,
}

#[derive(Debug, Clone, Copy)]
pub struct OracleFailureConfig {
    pub addr: u64,
}

#[derive(Debug, Clone)]
pub struct OracleFailureSnapshot {
    pub addr: u64,
    pub parsed: Result<Option<ExecOracleFailure>, String>,
}

pub fn resolve_shared_coverage(elf: &EasyElf) -> Option<SharedCoverageConfig> {
    elf.resolve_symbol(SBI_COVERAGE_BUFFER_SYMBOL, 0)
        .map(|addr| SharedCoverageConfig {
            addr,
            capacity: SBI_COVERAGE_PC_CAPACITY,
        })
}

pub fn reset_shared_coverage(qemu: &Qemu, coverage: SharedCoverageConfig) {
    let bytes = sbi_coverage_zero_buffer(coverage.capacity);
    unsafe { qemu.write_phys_mem(coverage.addr, &bytes) }
}

pub fn collect_shared_coverage_snapshot(
    qemu: &Qemu,
    coverage: SharedCoverageConfig,
) -> SharedCoverageSnapshot {
    let mut raw = vec![0; coverage.byte_len()];
    unsafe { qemu.read_phys_mem(coverage.addr, &mut raw) }
    let parsed = parse_sbi_coverage_buffer(&raw);
    SharedCoverageSnapshot {
        addr: coverage.addr,
        raw,
        parsed,
    }
}

pub fn print_shared_coverage_info(injector: PathBuf) {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(&injector, &mut elf_buffer).expect("load injector elf");
    match resolve_shared_coverage(&elf) {
        Some(coverage) => {
            println!(
                "symbol={} addr=0x{:x} expected_addr=0x{:x} capacity={} words={} bytes={} format='word0=count, word1..=pcs'",
                SBI_COVERAGE_BUFFER_SYMBOL,
                coverage.addr,
                SBI_COVERAGE_BUFFER_ADDR,
                coverage.capacity,
                sbi_coverage_buffer_words(coverage.capacity),
                coverage.byte_len()
            );
        }
        None => {
            println!(
                "symbol={} expected_addr=0x{:x} not found in {}",
                SBI_COVERAGE_BUFFER_SYMBOL,
                SBI_COVERAGE_BUFFER_ADDR,
                injector.display()
            );
        }
    }
}

pub fn resolve_oracle_failure(elf: &EasyElf) -> Option<OracleFailureConfig> {
    elf.resolve_symbol(SBI_ORACLE_BUFFER_SYMBOL, 0)
        .map(|addr| OracleFailureConfig { addr })
}

pub fn reset_oracle_failure(qemu: &Qemu, oracle: OracleFailureConfig) {
    let bytes = sbi_oracle_zero_buffer();
    unsafe { qemu.write_phys_mem(oracle.addr, &bytes) }
}

pub fn collect_oracle_failure_snapshot(
    qemu: &Qemu,
    oracle: OracleFailureConfig,
) -> OracleFailureSnapshot {
    let mut raw = vec![0; sbi_oracle_buffer_bytes()];
    unsafe { qemu.read_phys_mem(oracle.addr, &mut raw) }
    let parsed = parse_exec_oracle_buffer(&raw);
    OracleFailureSnapshot {
        addr: oracle.addr,
        parsed,
    }
}

pub fn symbolize_coverage_pcs(
    target: &Path,
    pcs: &[u64],
    limit: usize,
) -> Result<Vec<String>, String> {
    let elf_path = resolve_symbolization_target(target)
        .ok_or_else(|| format!("no sibling ELF found for {}", target.display()))?;

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(&elf_path, &mut elf_buffer).map_err(|err| {
        format!(
            "load coverage symbolization ELF {}: {err}",
            elf_path.display()
        )
    })?;
    let goblin = elf.goblin();
    let load_bias = if elf.is_pic() {
        OPENSBI_FIRMWARE_LOAD_ADDR
    } else {
        0
    };

    let mut symbols = goblin
        .syms
        .iter()
        .filter_map(|sym| {
            let name = goblin.strtab.get_at(sym.st_name)?;
            if sym.st_value == 0 || name.is_empty() || !sym.is_function() {
                return None;
            }
            Some((sym.st_value as u64 + load_bias, name.to_string()))
        })
        .collect::<Vec<_>>();
    symbols.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0).then(lhs.1.cmp(&rhs.1)));
    symbols.dedup();

    let mut unique_pcs = pcs.to_vec();
    unique_pcs.sort_unstable();
    unique_pcs.dedup();

    Ok(unique_pcs
        .into_iter()
        .take(limit)
        .map(|pc| symbolize_pc(pc, &symbols))
        .collect())
}

pub fn format_hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn resolve_symbolization_target(target: &Path) -> Option<PathBuf> {
    if target.extension().and_then(|ext| ext.to_str()) == Some("elf") {
        return Some(target.to_path_buf());
    }

    if target.extension().and_then(|ext| ext.to_str()) == Some("bin") {
        let elf = target.with_extension("elf");
        if elf.is_file() {
            return Some(elf);
        }
    }

    None
}

fn symbolize_pc(pc: u64, symbols: &[(u64, String)]) -> String {
    let index = symbols.partition_point(|(addr, _)| *addr <= pc);
    if index == 0 {
        return format!("0x{pc:x} => <unknown>");
    }

    let (addr, name) = &symbols[index - 1];
    format!("0x{pc:x} => {name}+0x{:x}", pc.saturating_sub(*addr))
}
