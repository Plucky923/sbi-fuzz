use common::{generate_seed_variants, input_to_binary};
use std::collections::HashSet;

#[test]
fn seed_variants_include_semantic_hsm_cases() {
    let variants = generate_seed_variants(0x48534D, 0x0, "test-hsm");
    let suffixes = variants
        .iter()
        .map(|variant| variant.file_suffix.as_str())
        .collect::<Vec<_>>();

    assert!(suffixes.contains(&""));
    assert!(suffixes.contains(&"arg0-hart1"));
    assert!(suffixes.contains(&"arg1-guest"));
    assert!(suffixes.contains(&"arg1-unaligned"));

    let hart1 = variants
        .iter()
        .find(|variant| variant.file_suffix == "arg0-hart1")
        .expect("hart id variant should exist");
    assert_eq!(hart1.input.args.arg0, 1);
    assert_eq!(hart1.input.metadata.source, "test-hsm-arg0-hart1");
}

#[test]
fn seed_variants_are_deduplicated_after_normalization() {
    let variants = generate_seed_variants(0x4442_434e, 0x0, "test-console");
    let encoded = variants
        .iter()
        .map(|variant| input_to_binary(&variant.input))
        .collect::<Vec<_>>();
    let unique = encoded.iter().cloned().collect::<HashSet<_>>();

    assert_eq!(unique.len(), encoded.len());
    assert!(
        variants
            .iter()
            .any(|variant| variant.file_suffix == "arg0-tiny")
    );
    assert!(
        variants
            .iter()
            .any(|variant| variant.file_suffix == "arg1-guest-low")
    );
}
