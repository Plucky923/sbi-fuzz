use common::*;

const FUZZ_HEADER_BYTES: usize = 88;

fn sample_host_input(mode: HostHarnessMode) -> HostHarnessInput {
    HostHarnessInput {
        target_kind: HostTargetKind::RustSbi,
        mode,
        call: HostCall::new(0x4442_434e, 0, [4, 0x8000_1000, 0, 0, 0, 0]),
        hart_id: 37,
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
fn host_harness_fuzz_bytes_round_trip() {
    let original = sample_host_input(HostHarnessMode::Ecall);
    let decoded = HostHarnessInput::from_fuzz_bytes(&original.to_fuzz_bytes());

    assert_eq!(decoded.target_kind, original.target_kind);
    assert_eq!(decoded.mode, original.mode);
    assert_eq!(decoded.call, original.call);
    assert_eq!(decoded.hart_id, original.hart_id);
    assert_eq!(decoded.hart_state, original.hart_state);
    assert_eq!(decoded.privilege, original.privilege);
    assert_eq!(decoded.memory_regions, original.memory_regions);
}

#[test]
fn host_harness_fuzz_decode_handles_empty_input() {
    let decoded = HostHarnessInput::from_fuzz_bytes(&[]);
    assert_eq!(decoded.mode, HostHarnessMode::Ecall);
    assert_eq!(decoded.call.extid, 0x10);
    assert_eq!(decoded.call.fid, 0);
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

#[test]
fn host_harness_fuzz_decode_clamps_region_count_and_region_size() {
    let mut bytes = vec![0_u8; FUZZ_HEADER_BYTES];
    bytes[87] = 0xff;

    for region_index in 0_u64..6 {
        bytes.extend_from_slice(&(0x8000_0000 + (region_index * 0x1000)).to_le_bytes());
        bytes.push(0b011);
        let declared_len = if region_index == 0 { u16::MAX } else { 4 };
        bytes.extend_from_slice(&declared_len.to_le_bytes());
        let payload_len = if region_index == 0 {
            HOST_HARNESS_FUZZ_MAX_REGION_BYTES
        } else {
            4
        };
        bytes.extend((0..payload_len).map(|offset| (offset as u8).wrapping_add(region_index as u8)));
    }

    let decoded = HostHarnessInput::from_fuzz_bytes(&bytes);

    assert_eq!(decoded.memory_regions.len(), HOST_HARNESS_FUZZ_MAX_REGIONS);
    assert_eq!(
        decoded.memory_regions[0].bytes.len(),
        HOST_HARNESS_FUZZ_MAX_REGION_BYTES
    );
    assert_eq!(&decoded.memory_regions[0].bytes[..4], &[0, 1, 2, 3]);
    assert_eq!(
        decoded.memory_regions[0].bytes[HOST_HARNESS_FUZZ_MAX_REGION_BYTES - 1],
        (HOST_HARNESS_FUZZ_MAX_REGION_BYTES as u8).wrapping_sub(1)
    );
    assert_eq!(decoded.memory_regions[1].bytes, vec![1, 2, 3, 4]);
}

#[test]
fn host_harness_fuzz_decode_pads_truncated_regions() {
    let mut bytes = vec![0_u8; FUZZ_HEADER_BYTES];
    bytes[87] = 1;
    bytes.extend_from_slice(&0x8000_2000_u64.to_le_bytes());
    bytes.push(0b011);
    bytes.extend_from_slice(&8_u16.to_le_bytes());
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

    let decoded = HostHarnessInput::from_fuzz_bytes(&bytes);

    assert_eq!(decoded.memory_regions.len(), 1);
    assert_eq!(decoded.memory_regions[0].bytes.len(), 8);
    assert_eq!(&decoded.memory_regions[0].bytes[..3], &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn host_harness_fuzz_decode_clamps_fdt_payload_to_4096_bytes() {
    let mut bytes = vec![0_u8; FUZZ_HEADER_BYTES];
    bytes[1] = 2;
    bytes.extend((0..5000).map(|value| (value % 251) as u8));

    let decoded = HostHarnessInput::from_fuzz_bytes(&bytes);

    assert_eq!(decoded.mode, HostHarnessMode::Fdt);
    assert_eq!(decoded.fdt_blob.len(), 4096);
    assert_eq!(decoded.fdt_blob[0], 0);
    assert_eq!(decoded.fdt_blob[4095], (4095 % 251) as u8);
}
