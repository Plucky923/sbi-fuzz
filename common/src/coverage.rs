use std::{convert::TryInto, mem::size_of};

pub const SBI_COVERAGE_BUFFER_SYMBOL: &str = "SBI_COVERAGE_BUFFER";
pub const SBI_COVERAGE_BUFFER_ADDR: u64 = 0x809f_c000;
pub const SBI_COVERAGE_PC_CAPACITY: usize = 1024;
pub const SBI_COVERAGE_WORD_BYTES: usize = size_of::<u64>();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbiCoverageBuffer {
    pub raw_count: usize,
    pub pcs: Vec<u64>,
}

impl SbiCoverageBuffer {
    pub fn is_empty(&self) -> bool {
        self.pcs.is_empty()
    }

    pub fn unique_pcs(&self) -> Vec<u64> {
        let mut pcs = self.pcs.clone();
        pcs.sort_unstable();
        pcs.dedup();
        pcs
    }
}

pub fn sbi_coverage_buffer_words(capacity: usize) -> usize {
    capacity.saturating_add(1)
}

pub fn sbi_coverage_buffer_bytes(capacity: usize) -> usize {
    sbi_coverage_buffer_words(capacity).saturating_mul(SBI_COVERAGE_WORD_BYTES)
}

pub fn sbi_coverage_zero_buffer(capacity: usize) -> Vec<u8> {
    vec![0; sbi_coverage_buffer_bytes(capacity)]
}

pub fn encode_sbi_coverage_buffer(pcs: &[u64], capacity: usize) -> Result<Vec<u8>, String> {
    if pcs.len() > capacity {
        return Err(format!(
            "coverage entry count {} exceeds capacity {}",
            pcs.len(),
            capacity
        ));
    }

    let mut buf = sbi_coverage_zero_buffer(capacity);
    buf[..SBI_COVERAGE_WORD_BYTES].copy_from_slice(&(pcs.len() as u64).to_le_bytes());
    for (index, pc) in pcs.iter().enumerate() {
        let start = SBI_COVERAGE_WORD_BYTES * (index + 1);
        let end = start + SBI_COVERAGE_WORD_BYTES;
        buf[start..end].copy_from_slice(&pc.to_le_bytes());
    }
    Ok(buf)
}

pub fn parse_sbi_coverage_buffer(bytes: &[u8]) -> Result<SbiCoverageBuffer, String> {
    if bytes.len() < SBI_COVERAGE_WORD_BYTES {
        return Err("coverage buffer too small".to_string());
    }
    if bytes.len() % SBI_COVERAGE_WORD_BYTES != 0 {
        return Err(format!(
            "coverage buffer size {} is not aligned to {}-byte words",
            bytes.len(),
            SBI_COVERAGE_WORD_BYTES
        ));
    }

    let mut words = Vec::with_capacity(bytes.len() / SBI_COVERAGE_WORD_BYTES);
    for chunk in bytes.chunks_exact(SBI_COVERAGE_WORD_BYTES) {
        words.push(u64::from_le_bytes(
            chunk
                .try_into()
                .expect("coverage buffer chunks must match word size"),
        ));
    }
    parse_sbi_coverage_words(&words)
}

pub fn parse_sbi_coverage_words(words: &[u64]) -> Result<SbiCoverageBuffer, String> {
    if words.is_empty() {
        return Err("coverage buffer has no header word".to_string());
    }

    let capacity = words.len() - 1;
    let raw_count = usize::try_from(words[0])
        .map_err(|_| format!("coverage count {} does not fit in host usize", words[0]))?;
    if raw_count > capacity {
        return Err(format!(
            "coverage count {} exceeds capacity {}",
            raw_count, capacity
        ));
    }

    Ok(SbiCoverageBuffer {
        raw_count,
        pcs: words[1..=raw_count].to_vec(),
    })
}

pub fn sbi_coverage_pc_bucket(pc: u64, map_len: usize) -> usize {
    if map_len == 0 {
        return 0;
    }

    let mut hash = pc;
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    (hash as usize) % map_len
}

pub fn fold_sbi_coverage_into_map(pcs: &[u64], map: &mut [u8]) -> usize {
    if map.is_empty() {
        return 0;
    }

    let mut max_index = 0;
    for &pc in pcs {
        let bucket = sbi_coverage_pc_bucket(pc, map.len());
        map[bucket] = map[bucket].saturating_add(1);
        max_index = max_index.max(bucket + 1);
    }
    max_index
}
