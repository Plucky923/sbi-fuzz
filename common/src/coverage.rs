use std::{convert::TryInto, mem::size_of};

pub const SBI_COVERAGE_BUFFER_SYMBOL: &str = "SBI_COVERAGE_BUFFER";
pub const SBI_COVERAGE_BUFFER_ADDR: u64 = 0x809f_c000;
pub const SBI_COVERAGE_PC_CAPACITY: usize = 8192;
pub const SBI_COVERAGE_WORD_BYTES: usize = size_of::<u64>();

/// A single coverage entry recording both the hart that executed and the PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEntry {
    pub hart_id: u64,
    pub pc: u64,
}

/// Decoded view of the shared SBI coverage buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbiCoverageBuffer {
    pub raw_count: usize,
    pub entries: Vec<CoverageEntry>,
}

impl SbiCoverageBuffer {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn pcs(&self) -> Vec<u64> {
        self.entries.iter().map(|e| e.pc).collect()
    }

    pub fn unique_pcs(&self) -> Vec<u64> {
        let mut pcs: Vec<u64> = self.entries.iter().map(|e| e.pc).collect();
        pcs.sort_unstable();
        pcs.dedup();
        pcs
    }

    pub fn unique_harts(&self) -> Vec<u64> {
        let mut harts: Vec<u64> = self.entries.iter().map(|e| e.hart_id).collect();
        harts.sort_unstable();
        harts.dedup();
        harts
    }

    /// Return consecutive (prev_pc, pc) pairs restricted to the same hart.
    pub fn edge_pairs(&self) -> Vec<(u64, u64)> {
        let mut pairs = Vec::new();
        for window in self.entries.windows(2) {
            if window[0].hart_id == window[1].hart_id {
                pairs.push((window[0].pc, window[1].pc));
            }
        }
        pairs
    }
}

pub fn sbi_coverage_buffer_words(capacity: usize) -> usize {
    // word0 = count, then 2 words per (hart_id, pc) entry
    capacity.saturating_mul(2).saturating_add(1)
}

pub fn sbi_coverage_buffer_bytes(capacity: usize) -> usize {
    sbi_coverage_buffer_words(capacity).saturating_mul(SBI_COVERAGE_WORD_BYTES)
}

pub fn sbi_coverage_zero_buffer(capacity: usize) -> Vec<u8> {
    vec![0; sbi_coverage_buffer_bytes(capacity)]
}

pub fn encode_sbi_coverage_buffer(
    entries: &[CoverageEntry],
    capacity: usize,
) -> Result<Vec<u8>, String> {
    if entries.len() > capacity {
        return Err(format!(
            "coverage entry count {} exceeds capacity {}",
            entries.len(),
            capacity
        ));
    }

    let mut buf = sbi_coverage_zero_buffer(capacity);
    buf[..SBI_COVERAGE_WORD_BYTES].copy_from_slice(&(entries.len() as u64).to_le_bytes());
    for (index, entry) in entries.iter().enumerate() {
        let hart_start = SBI_COVERAGE_WORD_BYTES * (2 * index + 1);
        let pc_start = hart_start + SBI_COVERAGE_WORD_BYTES;
        buf[hart_start..pc_start].copy_from_slice(&entry.hart_id.to_le_bytes());
        buf[pc_start..pc_start + SBI_COVERAGE_WORD_BYTES].copy_from_slice(&entry.pc.to_le_bytes());
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

    // capacity = number of (hart_id, pc) entries that fit
    let capacity = words.len().saturating_sub(1) / 2;
    let raw_count = usize::try_from(words[0])
        .map_err(|_| format!("coverage count {} does not fit in host usize", words[0]))?;
    if raw_count > capacity {
        return Err(format!(
            "coverage count {} exceeds capacity {}",
            raw_count, capacity
        ));
    }

    let mut entries = Vec::with_capacity(raw_count);
    for i in 0..raw_count {
        let hart_id = words[2 * i + 1];
        let pc = words[2 * i + 2];
        entries.push(CoverageEntry { hart_id, pc });
    }

    Ok(SbiCoverageBuffer {
        raw_count,
        entries,
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

/// Fold point coverage (individual PCs) into a byte map.
pub fn fold_sbi_coverage_into_map(entries: &[CoverageEntry], map: &mut [u8]) -> usize {
    if map.is_empty() {
        return 0;
    }

    let mut max_index = 0;
    for entry in entries {
        let bucket = sbi_coverage_pc_bucket(entry.pc, map.len());
        map[bucket] = map[bucket].saturating_add(1);
        max_index = max_index.max(bucket + 1);
    }
    max_index
}

/// Fold edge coverage (consecutive same-hart PC pairs) into a byte map.
pub fn fold_sbi_coverage_into_edge_map(entries: &[CoverageEntry], map: &mut [u8]) -> usize {
    if map.is_empty() || entries.len() < 2 {
        return 0;
    }

    let mut max_index = 0;
    for window in entries.windows(2) {
        if window[0].hart_id != window[1].hart_id {
            continue;
        }
        let combined = window[0].pc ^ window[1].pc.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let bucket = sbi_coverage_pc_bucket(combined, map.len());
        map[bucket] = map[bucket].saturating_add(1);
        max_index = max_index.max(bucket + 1);
    }
    max_index
}
