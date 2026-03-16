use crate::{HostHarnessInput, HostHarnessReport, HostHarnessResult, HostMemoryRegion};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegionSnapshot {
    guest_addr: u64,
    read: bool,
    write: bool,
    execute: bool,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryOracle {
    pre_snapshot: Vec<RegionSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MemoryViolation {
    ReadOnlyRegionModified { region_index: usize },
    UnrelatedRegionModified { region_index: usize },
    WriteExceedsBounds {
        region_index: usize,
        written: usize,
        capacity: usize,
    },
}

impl MemoryOracle {
    pub fn snapshot_before(regions: &[HostMemoryRegion]) -> Self {
        Self {
            pre_snapshot: regions
                .iter()
                .map(|region| RegionSnapshot {
                    guest_addr: region.guest_addr,
                    read: region.read,
                    write: region.write,
                    execute: region.execute,
                    bytes: region.bytes.clone(),
                })
                .collect(),
        }
    }

    pub fn check_after(
        &self,
        input: &HostHarnessInput,
        report: &HostHarnessReport,
    ) -> Vec<MemoryViolation> {
        let HostHarnessResult::Ecall(_) = report.result else {
            return Vec::new();
        };

        let allowed_writes = allowed_write_regions(input);
        let mut violations = Vec::new();
        for (index, before) in self.pre_snapshot.iter().enumerate() {
            let Some(after) = report.post_memory_regions.get(index) else {
                continue;
            };
            if after.bytes.len() > before.bytes.len() {
                violations.push(MemoryViolation::WriteExceedsBounds {
                    region_index: index,
                    written: after.bytes.len(),
                    capacity: before.bytes.len(),
                });
                continue;
            }
            if before.bytes == after.bytes {
                continue;
            }
            if !before.write {
                violations.push(MemoryViolation::ReadOnlyRegionModified {
                    region_index: index,
                });
                continue;
            }
            if !allowed_writes.contains(&index) {
                violations.push(MemoryViolation::UnrelatedRegionModified {
                    region_index: index,
                });
            }
        }
        violations
    }
}

fn allowed_write_regions(input: &HostHarnessInput) -> Vec<usize> {
    match (input.call.extid, input.call.fid) {
        (0x4442_434e, 1) => {
            let addr = input.call.args[1];
            let len = input.call.args[0];
            input
                .memory_regions
                .iter()
                .enumerate()
                .filter_map(|(index, region)| {
                    let end = addr.checked_add(len)?;
                    let region_end = region.guest_addr.checked_add(region.bytes.len() as u64)?;
                    (addr >= region.guest_addr && end <= region_end).then_some(index)
                })
                .collect()
        }
        _ => Vec::new(),
    }
}
