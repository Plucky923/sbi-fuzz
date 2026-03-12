use common::*;

#[test]
fn coverage_buffer_round_trip() {
    let pcs = [0x8000_1000, 0x8000_1010, 0x8000_2000, 0x8000_1010];
    let encoded = encode_sbi_coverage_buffer(&pcs, SBI_COVERAGE_PC_CAPACITY)
        .expect("encode shared coverage buffer");
    let decoded = parse_sbi_coverage_buffer(&encoded).expect("decode shared coverage buffer");

    assert_eq!(decoded.raw_count, pcs.len());
    assert_eq!(decoded.pcs, pcs);
    assert_eq!(
        decoded.unique_pcs(),
        vec![0x8000_1000, 0x8000_1010, 0x8000_2000]
    );
}

#[test]
fn coverage_buffer_rejects_overflow_count() {
    let words = [3_u64, 0x10, 0x20];
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
    let pcs = [0x8000_1000, 0x8000_2000, 0x8000_1000, 0x8000_3000];
    let mut map_a = vec![0_u8; 64];
    let mut map_b = vec![0_u8; 64];

    let max_a = fold_sbi_coverage_into_map(&pcs, &mut map_a);
    let max_b = fold_sbi_coverage_into_map(&pcs, &mut map_b);

    assert_eq!(map_a, map_b);
    assert_eq!(max_a, max_b);
    assert!(max_a > 0);
}
