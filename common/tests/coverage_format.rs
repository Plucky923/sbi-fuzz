use common::*;

#[test]
fn coverage_buffer_round_trip() {
    let entries = vec![
        CoverageEntry { hart_id: 0, pc: 0x8000_1000 },
        CoverageEntry { hart_id: 0, pc: 0x8000_1010 },
        CoverageEntry { hart_id: 1, pc: 0x8000_2000 },
        CoverageEntry { hart_id: 0, pc: 0x8000_1010 },
    ];
    let encoded = encode_sbi_coverage_buffer(&entries, SBI_COVERAGE_PC_CAPACITY)
        .expect("encode shared coverage buffer");
    let decoded = parse_sbi_coverage_buffer(&encoded).expect("decode shared coverage buffer");

    assert_eq!(decoded.raw_count, entries.len());
    assert_eq!(decoded.entries, entries);
    assert_eq!(
        decoded.unique_pcs(),
        vec![0x8000_1000, 0x8000_1010, 0x8000_2000]
    );
    assert_eq!(decoded.unique_harts(), vec![0, 1]);
    assert_eq!(
        decoded.edge_pairs(),
        vec![
            (0x8000_1000, 0x8000_1010),
            // hart_id changes from 0 to 1 → skipped for (0x1010, 0x2000)
            // hart_id changes from 1 to 0 → skipped for (0x2000, 0x1010)
        ]
    );
}

#[test]
fn coverage_buffer_rejects_overflow_count() {
    // 3 words: count=3, but only 1 entry capacity (needs 2 words + 1 header = 3 words total)
    // Actually with 3 words, capacity = (3-1)/2 = 1. So count=3 exceeds capacity 1.
    let words = [3_u64, 0, 0x10];
    assert!(
        parse_sbi_coverage_words(&words)
            .expect_err("overflow count should fail")
            .contains("exceeds capacity")
    );
}

#[test]
fn zeroed_coverage_buffer_is_empty() {
    let decoded = parse_sbi_coverage_buffer(&sbi_coverage_zero_buffer(8))
        .expect("parse zeroed shared coverage buffer");
    assert_eq!(decoded.raw_count, 0);
    assert!(decoded.is_empty());
}

#[test]
fn coverage_hashing_is_stable() {
    let entries = vec![
        CoverageEntry { hart_id: 0, pc: 0x8000_1000 },
        CoverageEntry { hart_id: 0, pc: 0x8000_2000 },
        CoverageEntry { hart_id: 0, pc: 0x8000_1000 },
        CoverageEntry { hart_id: 0, pc: 0x8000_3000 },
    ];
    let mut map_a = vec![0_u8; 64];
    let mut map_b = vec![0_u8; 64];

    let max_a = fold_sbi_coverage_into_map(&entries, &mut map_a);
    let max_b = fold_sbi_coverage_into_map(&entries, &mut map_b);

    assert_eq!(map_a, map_b);
    assert_eq!(max_a, max_b);
    assert!(max_a > 0);
}

#[test]
fn coverage_edge_hashing_is_stable() {
    let entries = vec![
        CoverageEntry { hart_id: 0, pc: 0x8000_1000 },
        CoverageEntry { hart_id: 0, pc: 0x8000_2000 },
        CoverageEntry { hart_id: 1, pc: 0x8000_3000 },
        CoverageEntry { hart_id: 1, pc: 0x8000_4000 },
    ];
    let mut map_a = vec![0_u8; 64];
    let mut map_b = vec![0_u8; 64];

    let max_a = fold_sbi_coverage_into_edge_map(&entries, &mut map_a);
    let max_b = fold_sbi_coverage_into_edge_map(&entries, &mut map_b);

    assert_eq!(map_a, map_b);
    assert_eq!(max_a, max_b);
    assert!(max_a > 0);
}
