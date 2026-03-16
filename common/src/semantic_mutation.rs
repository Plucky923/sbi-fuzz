/// Semantic mutation strategies for SBI fuzzing
///
/// This module provides vulnerability-oriented mutation strategies that understand
/// the semantic meaning of SBI call arguments (addresses, sizes, flags, etc.)
/// rather than treating all bytes equally.
use crate::{ArgumentKind, InputData};
use rand::Rng;

/// Address pool for vulnerability-oriented address mutations
#[derive(Debug, Clone, Copy)]
pub enum AddressValue {
    /// Null pointer (0x0)
    Null,
    /// Unaligned addresses (not 8-byte aligned)
    Unaligned(u64),
    /// Page boundary addresses
    PageBoundary(u64),
    /// Cross-page addresses (spans two pages)
    CrossPage(u64),
    /// Sensitive M-mode regions (firmware code/data)
    SensitiveRegion(u64),
    /// Shared memory region
    SharedMemory(u64),
    /// Unmapped/hole region
    Unmapped(u64),
    /// Maximum address value
    MaxAddress,
}

impl AddressValue {
    /// Convert to u64 value
    pub fn to_u64(self) -> u64 {
        match self {
            AddressValue::Null => 0,
            AddressValue::Unaligned(base) => base | 0x1, // Force unaligned
            AddressValue::PageBoundary(page) => page * 0x1000,
            AddressValue::CrossPage(page) => (page * 0x1000) - 4,
            AddressValue::SensitiveRegion(addr) => addr,
            AddressValue::SharedMemory(addr) => addr,
            AddressValue::Unmapped(addr) => addr,
            AddressValue::MaxAddress => u64::MAX,
        }
    }

    /// Generate a random address value from the pool
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..10) {
            0 => AddressValue::Null,
            1 => AddressValue::Unaligned(rng.gen_range(0x80000000..0x90000000)),
            2 => AddressValue::PageBoundary(rng.gen_range(0x80000..0x90000)),
            3 => AddressValue::CrossPage(rng.gen_range(0x80000..0x90000)),
            4 => AddressValue::SensitiveRegion(0x80000000 + rng.gen_range(0..0x100000)),
            5 => AddressValue::SharedMemory(0x80200000 + rng.gen_range(0..0x100000)),
            6 => AddressValue::Unmapped(0xFFFFFFFF00000000 + rng.r#gen::<u32>() as u64),
            7 => AddressValue::MaxAddress,
            _ => AddressValue::Unaligned(rng.r#gen::<u64>()),
        }
    }
}

/// Size/count boundary values for vulnerability testing
#[derive(Debug, Clone, Copy)]
pub enum SizeValue {
    Zero,
    One,
    Seven,
    Eight,
    Fifteen,
    Sixteen,
    PageSizeMinus1,
    PageSize,
    PageSizePlus1,
    MaxU32,
    MaxU64,
}

impl SizeValue {
    pub fn to_u64(self) -> u64 {
        match self {
            SizeValue::Zero => 0,
            SizeValue::One => 1,
            SizeValue::Seven => 7,
            SizeValue::Eight => 8,
            SizeValue::Fifteen => 15,
            SizeValue::Sixteen => 16,
            SizeValue::PageSizeMinus1 => 0xFFF,
            SizeValue::PageSize => 0x1000,
            SizeValue::PageSizePlus1 => 0x1001,
            SizeValue::MaxU32 => u32::MAX as u64,
            SizeValue::MaxU64 => u64::MAX,
        }
    }

    pub fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..11) {
            0 => SizeValue::Zero,
            1 => SizeValue::One,
            2 => SizeValue::Seven,
            3 => SizeValue::Eight,
            4 => SizeValue::Fifteen,
            5 => SizeValue::Sixteen,
            6 => SizeValue::PageSizeMinus1,
            7 => SizeValue::PageSize,
            8 => SizeValue::PageSizePlus1,
            9 => SizeValue::MaxU32,
            _ => SizeValue::MaxU64,
        }
    }
}

/// Flags mutation strategies
#[derive(Debug, Clone, Copy)]
pub enum FlagsValue {
    /// All bits zero
    AllZero,
    /// All bits one
    AllOne,
    /// Single bit set
    SingleBit(u8),
    /// Reserved bits set
    ReservedBits,
    /// Mutually exclusive bits
    MutuallyExclusive,
}

impl FlagsValue {
    pub fn to_u64<R: Rng>(self, rng: &mut R) -> u64 {
        match self {
            FlagsValue::AllZero => 0,
            FlagsValue::AllOne => u64::MAX,
            FlagsValue::SingleBit(bit) => 1u64 << (bit % 64),
            FlagsValue::ReservedBits => {
                // Set high bits that are typically reserved
                0xFFFFFFFF00000000 | rng.r#gen::<u32>() as u64
            }
            FlagsValue::MutuallyExclusive => {
                // Set multiple bits that might be mutually exclusive
                (1u64 << rng.gen_range(0..8)) | (1u64 << rng.gen_range(8..16))
            }
        }
    }

    pub fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..5) {
            0 => FlagsValue::AllZero,
            1 => FlagsValue::AllOne,
            2 => FlagsValue::SingleBit(rng.r#gen::<u8>()),
            3 => FlagsValue::ReservedBits,
            _ => FlagsValue::MutuallyExclusive,
        }
    }
}

/// Hart ID mutation strategies
#[derive(Debug, Clone, Copy)]
pub enum HartIdValue {
    /// Current hart (0)
    Current,
    /// Valid hart in range
    Valid(u64),
    /// Non-existent hart
    NonExistent,
    /// Maximum value
    Max,
}

impl HartIdValue {
    pub fn to_u64<R: Rng>(self, rng: &mut R, max_harts: u64) -> u64 {
        match self {
            HartIdValue::Current => 0,
            HartIdValue::Valid(id) => id % max_harts,
            HartIdValue::NonExistent => max_harts + rng.gen_range(1..100),
            HartIdValue::Max => u64::MAX,
        }
    }

    pub fn random<R: Rng>(rng: &mut R) -> Self {
        match rng.gen_range(0..4) {
            0 => HartIdValue::Current,
            1 => HartIdValue::Valid(rng.gen_range(0..8)),
            2 => HartIdValue::NonExistent,
            _ => HartIdValue::Max,
        }
    }
}

/// Semantic mutation strategy
pub struct SemanticMutator {
    /// Maximum number of harts in the system
    pub max_harts: u64,
}

impl SemanticMutator {
    pub fn new(max_harts: u64) -> Self {
        Self { max_harts }
    }

    /// Mutate a single argument based on its semantic kind
    pub fn mutate_argument<R: Rng>(
        &self,
        kind: ArgumentKind,
        current_value: u64,
        rng: &mut R,
    ) -> u64 {
        match kind {
            ArgumentKind::Address | ArgumentKind::AddressLow | ArgumentKind::AddressHigh => {
                // 70% chance to use semantic address, 30% keep or random
                if rng.gen_bool(0.7) {
                    AddressValue::random(rng).to_u64()
                } else if rng.gen_bool(0.5) {
                    current_value
                } else {
                    rng.r#gen::<u64>()
                }
            }
            ArgumentKind::Size | ArgumentKind::Count => {
                // 70% chance to use boundary size, 30% keep or random
                if rng.gen_bool(0.7) {
                    SizeValue::random(rng).to_u64()
                } else if rng.gen_bool(0.5) {
                    current_value
                } else {
                    rng.r#gen::<u64>()
                }
            }
            ArgumentKind::Flags => {
                // 70% chance to use semantic flags, 30% keep or random
                if rng.gen_bool(0.7) {
                    FlagsValue::random(rng).to_u64(rng)
                } else if rng.gen_bool(0.5) {
                    current_value
                } else {
                    rng.r#gen::<u64>()
                }
            }
            ArgumentKind::HartId => {
                // 70% chance to use semantic hart ID, 30% keep or random
                if rng.gen_bool(0.7) {
                    HartIdValue::random(rng).to_u64(rng, self.max_harts)
                } else if rng.gen_bool(0.5) {
                    current_value
                } else {
                    rng.gen_range(0..self.max_harts * 2)
                }
            }
            ArgumentKind::HartMaskAddress => {
                // Hart mask is a direct bit-mask value.
                if rng.gen_bool(0.7) {
                    match rng.gen_range(0..5) {
                        0 => 0,
                        1 => 1,
                        2 => 1 << 1,
                        3 => 1 << 3,
                        _ => 0xff,
                    }
                } else if rng.gen_bool(0.5) {
                    current_value
                } else {
                    rng.r#gen::<u64>()
                }
            }
            ArgumentKind::SuspendType => {
                // Suspend type is typically 0 (retentive) or 0x80000000 (non-retentive)
                match rng.gen_range(0..5) {
                    0 => 0,
                    1 => 0x80000000,
                    2 => 0xFFFFFFFF, // Invalid
                    3 => current_value,
                    _ => rng.r#gen::<u64>(),
                }
            }
            ArgumentKind::Value | ArgumentKind::Opaque => {
                // Generic value - use random mutation
                if rng.gen_bool(0.3) {
                    current_value
                } else {
                    rng.r#gen::<u64>()
                }
            }
        }
    }

    /// Mutate input data using schema-aware strategies
    pub fn mutate_input<R: Rng>(&self, input: &mut InputData, rng: &mut R) {
        let schema = input.metadata.schema.unwrap_or_default();
        let original = input.args.clone();

        // Decide how many arguments to mutate (1-3)
        let num_mutations = rng.gen_range(1..=3);
        let mut mutated = 0;
        let mut attempts = 0;

        while mutated < num_mutations && attempts < 24 {
            let arg_index = rng.gen_range(0..6);
            let kind = schema.argument_kind(arg_index);
            let current_value = input.args.get(arg_index);
            let new_value = self.mutate_argument(kind, current_value, rng);
            attempts += 1;

            if new_value == current_value {
                continue;
            }

            match arg_index {
                0 => input.args.arg0 = new_value,
                1 => input.args.arg1 = new_value,
                2 => input.args.arg2 = new_value,
                3 => input.args.arg3 = new_value,
                4 => input.args.arg4 = new_value,
                5 => input.args.arg5 = new_value,
                _ => unreachable!(),
            }

            mutated += 1;
        }

        if input.args.arg0 == original.arg0
            && input.args.arg1 == original.arg1
            && input.args.arg2 == original.arg2
            && input.args.arg3 == original.arg3
            && input.args.arg4 == original.arg4
            && input.args.arg5 == original.arg5
        {
            input.args.arg0 = original.arg0 ^ 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Args, CallSchema};
    use rand::thread_rng;

    #[test]
    fn test_address_value_generation() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let addr = AddressValue::random(&mut rng);
            let value = addr.to_u64();
            // Just ensure it doesn't panic
            assert!(value == 0 || value > 0);
        }
    }

    #[test]
    fn test_size_value_generation() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let size = SizeValue::random(&mut rng);
            let value = size.to_u64();
            assert!(value == 0 || value > 0);
        }
    }

    #[test]
    fn test_semantic_mutator() {
        let mutator = SemanticMutator::new(4);
        let mut rng = thread_rng();

        let mut input = InputData {
            metadata: crate::Metadata {
                extension_name: "test".to_string(),
                source: "test".to_string(),
                schema: Some(CallSchema::new(
                    ArgumentKind::Address,
                    ArgumentKind::Size,
                    ArgumentKind::Flags,
                    ArgumentKind::HartId,
                    ArgumentKind::Value,
                    ArgumentKind::Value,
                )),
            },
            args: Args {
                eid: 0x48534D,
                fid: 0,
                arg0: 0x80000000,
                arg1: 0x1000,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
        };

        let original = input.clone();
        mutator.mutate_input(&mut input, &mut rng);

        // At least one argument should have changed
        assert!(
            input.args.arg0 != original.args.arg0
                || input.args.arg1 != original.args.arg1
                || input.args.arg2 != original.args.arg2
                || input.args.arg3 != original.args.arg3
                || input.args.arg4 != original.args.arg4
                || input.args.arg5 != original.args.arg5
        );
    }
}
