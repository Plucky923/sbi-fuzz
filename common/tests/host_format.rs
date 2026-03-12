use common::*;

fn sample_host_input(mode: HostHarnessMode) -> HostHarnessInput {
    HostHarnessInput {
        target_kind: HostTargetKind::RustSbi,
        mode,
        call: HostCall::new(0x4442_434e, 0, [4, 0x8000_1000, 0, 0, 0, 0]),
        hart_id: 2,
        hart_state: HostHartState::Started,
        privilege: HostPrivilegeState::Supervisor,
        memory_regions: vec![HostMemoryRegion {
            guest_addr: 0x8000_1000,
            read: true,
            write: true,
            execute: false,
            bytes: b"test".to_vec(),
        }],
        platform_fault: HostPlatformFaultProfile {
            mode: HostPlatformFaultMode::ReturnSbiError,
            error: SbiError::Denied.code(),
            value: 0x55,
            duplicate_side_effects: true,
        },
        fdt_blob: vec![0xd0, 0x0d, 0xfe, 0xed],
        label: "sample".to_string(),
    }
}

#[test]
fn host_harness_input_round_trip() {
    let original = sample_host_input(HostHarnessMode::PlatformFault);
    let encoded = host_harness_input_to_bytes(&original);
    let decoded = host_harness_input_from_bytes(&encoded).expect("decode host harness input");

    assert_eq!(decoded, original);
    assert_eq!(decoded.target_kind, HostTargetKind::RustSbi);
    assert_eq!(decoded.hash_string().len(), 8);
}

#[test]
fn host_harness_input_rejects_bad_headers() {
    assert!(host_harness_input_from_bytes(b"short").is_err());

    let mut bad_magic = host_harness_input_to_bytes(&sample_host_input(HostHarnessMode::Ecall));
    bad_magic[0] = b'X';
    assert!(
        host_harness_input_from_bytes(&bad_magic)
            .expect_err("bad magic should fail")
            .contains("invalid host harness magic")
    );

    let mut bad_size = host_harness_input_to_bytes(&sample_host_input(HostHarnessMode::Fdt));
    let header_len = HOST_HARNESS_MAGIC.len();
    bad_size[header_len..header_len + 4].copy_from_slice(&(1_u32).to_le_bytes());
    assert!(
        host_harness_input_from_bytes(&bad_size)
            .expect_err("bad size should fail")
            .contains("payload length mismatch")
    );
}
