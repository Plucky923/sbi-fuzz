use common::*;

fn sample_input(
    eid: u64,
    fid: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> InputData {
    InputData {
        metadata: Metadata::from_call(eid, fid, format!("test-{eid:x}-{fid:x}")),
        args: Args {
            eid,
            fid,
            arg0,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
        },
    }
}

fn encode_varint(value: u64, out: &mut Vec<u8>) {
    let mut encoded = if (value as i64) < 0 {
        (!(value) << 1) | 1
    } else {
        value << 1
    };
    while encoded >= 0x80 {
        out.push((encoded as u8) | 0x80);
        encoded >>= 7;
    }
    out.push(encoded as u8);
}

fn malformed_bytes(
    call_id: u64,
    nargs: u64,
    arg_type: u64,
    arg_payload: &[u64],
    raw_data: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EXEC_MAGIC);
    encode_varint(1, &mut bytes);
    encode_varint(call_id, &mut bytes);
    encode_varint(EXEC_NO_COPYOUT, &mut bytes);
    encode_varint(nargs, &mut bytes);
    encode_varint(arg_type, &mut bytes);
    for value in arg_payload {
        encode_varint(*value, &mut bytes);
    }
    bytes.extend_from_slice(raw_data);
    encode_varint(u64::MAX, &mut bytes);
    bytes
}

#[test]
fn exec_props_are_encoded_and_described() {
    let target = exec_prop_target_hart(3);
    let busy_wait = exec_prop_busy_wait(0x1234);

    assert_eq!(decode_exec_prop(target), (EXEC_PROP_TARGET_HART, 3));
    assert_eq!(decode_exec_prop(busy_wait), (EXEC_PROP_BUSY_WAIT, 0x1234));
    assert_eq!(format_exec_prop(target), "target_hart=3");
    assert_eq!(format_exec_prop(busy_wait), "busy_wait=4660");
}

#[test]
fn oracle_buffer_round_trip_and_format() {
    let failure = ExecOracleFailure {
        kind: EXEC_ORACLE_KIND_PURE_CALL_MISMATCH,
        instr_index: 7,
        arg0: 0x10,
        arg1: 2,
        observed_error: 0,
        observed_value: 0x22,
        expected_error: 0,
        expected_value: 0x11,
    };

    let encoded = encode_exec_oracle_buffer(&failure);
    let decoded = parse_exec_oracle_buffer(&encoded)
        .expect("parse oracle buffer")
        .expect("oracle failure should be present");

    assert_eq!(decoded, failure);
    assert!(format_exec_oracle_failure(&decoded).contains("pure_call_mismatch"));
    assert!(
        parse_exec_oracle_buffer(&sbi_oracle_zero_buffer())
            .expect("parse zeroed oracle buffer")
            .is_none()
    );
}

#[test]
fn validate_registry_is_consistent() {
    validate_exec_call_table().expect("registry should validate");
    assert!(format_exec_call_table().contains("raw_ecall"));
    assert_eq!(exec_call_table().first().map(|desc| desc.id), Some(0));
}

#[test]
fn round_trip_fixed_and_raw_calls() {
    let samples = [
        sample_input(0x5449_4d45, 0, 0x1234_5678, 0, 0, 0, 0, 0),
        sample_input(0x4853_4d, 0, 1, 0x8123_4567, 0xbeef, 0, 0, 0),
        sample_input(0x4442_434e, 0, 0x40, 0x8000_0123, 0, 0, 0, 0),
        sample_input(0x504d_55, 8, 0x8000_1001, 0, 7, 0, 0, 0),
        sample_input(0xdead_beef, 0x55, 1, 2, 3, 4, 5, 6),
    ];

    for original in samples {
        let normalized = fix_input_args(original);
        let program = normalize_exec_program(exec_program_from_input(&normalized));
        let encoded = exec_program_to_bytes(&program);
        let decoded = exec_program_from_bytes(&encoded).expect("decode exec bytes");
        let recovered = exec_program_primary_input(&decoded).expect("recover primary input");

        assert_eq!(recovered.args.eid, normalized.args.eid);
        assert_eq!(recovered.args.fid, normalized.args.fid);
        assert_eq!(recovered.args.arg0, normalized.args.arg0);
        assert_eq!(recovered.args.arg1, normalized.args.arg1);
        assert_eq!(recovered.args.arg2, normalized.args.arg2);
        assert_eq!(recovered.args.arg3, normalized.args.arg3);
        assert_eq!(recovered.args.arg4, normalized.args.arg4);
        assert_eq!(recovered.args.arg5, normalized.args.arg5);
        assert_eq!(
            recovered.metadata.extension_name,
            normalized.metadata.extension_name
        );
    }
}

#[test]
fn round_trip_multi_call_program() {
    let program = ExecProgram {
        instructions: vec![
            ExecInstr::CopyIn {
                addr: 0x20,
                arg: ExecArg::Data(vec![1, 2, 3, 4]),
            },
            ExecInstr::Call {
                call_id: 1,
                copyout_index: 3,
                args: vec![
                    ExecArg::Const {
                        size: 8,
                        value: 0x1000,
                    },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                ],
            },
            ExecInstr::CopyOut {
                index: 3,
                addr: 0x20,
                size: 8,
            },
            ExecInstr::SetProps {
                value: exec_prop_target_hart(1),
            },
            ExecInstr::Call {
                call_id: 0,
                copyout_index: EXEC_NO_COPYOUT,
                args: vec![
                    ExecArg::Const {
                        size: 8,
                        value: 0x4853_4d,
                    },
                    ExecArg::Const { size: 8, value: 2 },
                    ExecArg::Result {
                        size: 8,
                        index: 3,
                        op_div: 0,
                        op_add: 1,
                        default: 7,
                    },
                    ExecArg::Addr64 { offset: 0x20 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                ],
            },
        ],
    };

    let encoded = exec_program_to_bytes(&program);
    let decoded = exec_program_from_bytes(&encoded).expect("decode multi-call program");
    assert_eq!(decoded, program);
    assert_eq!(decoded.call_count(), 2);
    assert!(exec_program_describe(&decoded).contains("copyout slot=3"));
    assert!(exec_program_describe(&decoded).contains("target_hart=1"));
}

#[test]
fn malformed_exec_bytes_are_rejected() {
    let no_magic = vec![0u8; 16];
    assert!(exec_program_from_bytes(&no_magic).is_err());

    let unknown_call = malformed_bytes(99, 0, 0, &[], &[]);
    assert!(
        exec_program_from_bytes(&unknown_call)
            .expect_err("unknown call should fail")
            .contains("unknown exec call id")
    );

    let unknown_arg = malformed_bytes(0, 1, 99, &[], &[]);
    assert!(
        exec_program_from_bytes(&unknown_arg)
            .expect_err("unknown arg should fail")
            .contains("unknown exec arg type")
    );

    let truncated_data = malformed_bytes(0, 1, 4, &[4], &[0xaa, 0xbb]);
    assert!(
        exec_program_from_bytes(&truncated_data)
            .expect_err("truncated data should fail")
            .contains("exec data arg overflow")
    );

    let mut bad_arity = Vec::new();
    bad_arity.extend_from_slice(EXEC_MAGIC);
    encode_varint(1, &mut bad_arity);
    encode_varint(2, &mut bad_arity);
    encode_varint(EXEC_NO_COPYOUT, &mut bad_arity);
    encode_varint(0, &mut bad_arity);
    encode_varint(u64::MAX, &mut bad_arity);
    assert!(
        exec_program_from_bytes(&bad_arity)
            .expect_err("fixed call with zero args should fail")
            .contains("unexpected arg count")
    );
}

#[test]
fn absurd_argument_count_is_rejected() {
    let bytes = malformed_bytes(0, usize::MAX as u64, 0, &[8, 0], &[]);
    assert!(
        exec_program_from_bytes(&bytes)
            .expect_err("huge nargs should fail")
            .contains("too many args")
    );
}

#[test]
fn call_count_mismatch_is_rejected() {
    let program = ExecProgram {
        instructions: vec![
            ExecInstr::Call {
                call_id: 2,
                copyout_index: EXEC_NO_COPYOUT,
                args: vec![
                    ExecArg::Const { size: 8, value: 1 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                ],
            },
            ExecInstr::Call {
                call_id: 2,
                copyout_index: EXEC_NO_COPYOUT,
                args: vec![
                    ExecArg::Const { size: 8, value: 2 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                    ExecArg::Const { size: 8, value: 0 },
                ],
            },
        ],
    };
    let mut encoded = exec_program_to_bytes(&program);
    encoded[EXEC_MAGIC.len()] = 2;
    assert!(
        exec_program_from_bytes(&encoded)
            .expect_err("call count mismatch should fail")
            .contains("call count mismatch")
    );
}

#[test]
fn invalid_const_size_is_rejected() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EXEC_MAGIC);
    encode_varint(1, &mut bytes);
    encode_varint(0, &mut bytes);
    encode_varint(EXEC_NO_COPYOUT, &mut bytes);
    encode_varint(8, &mut bytes);
    encode_varint(0, &mut bytes);
    encode_varint(0, &mut bytes);
    encode_varint(0, &mut bytes);
    for _ in 0..7 {
        encode_varint(0, &mut bytes);
        encode_varint(8, &mut bytes);
        encode_varint(0, &mut bytes);
    }
    encode_varint(u64::MAX, &mut bytes);
    assert!(
        exec_program_from_bytes(&bytes)
            .expect_err("invalid scalar size should fail")
            .contains("invalid scalar size")
    );
}

#[test]
fn fix_input_args_is_idempotent_for_known_calls() {
    let samples = [
        sample_input(0x4853_4d, 0, 1, 0x8123_4567, 0xbeef, 0, 0, 0),
        sample_input(0x4442_434e, 0, 0x40, 0x8000_0123, 0, 0, 0, 0),
        sample_input(0x504d_55, 8, 0x8000_1001, 0, 7, 0, 0, 0),
    ];

    for sample in samples {
        let once = fix_input_args(sample.clone());
        let twice = fix_input_args(once.clone());
        assert_eq!(once.args.eid, twice.args.eid);
        assert_eq!(once.args.fid, twice.args.fid);
        assert_eq!(once.args.arg0, twice.args.arg0);
        assert_eq!(once.args.arg1, twice.args.arg1);
        assert_eq!(once.args.arg2, twice.args.arg2);
        assert_eq!(once.args.arg3, twice.args.arg3);
        assert_eq!(once.args.arg4, twice.args.arg4);
        assert_eq!(once.args.arg5, twice.args.arg5);
    }
}

#[test]
fn data_arg_inside_call_is_rejected() {
    let program = ExecProgram {
        instructions: vec![ExecInstr::Call {
            call_id: 0,
            copyout_index: EXEC_NO_COPYOUT,
            args: vec![
                ExecArg::Const {
                    size: 8,
                    value: 0x10,
                },
                ExecArg::Const { size: 8, value: 0 },
                ExecArg::Const { size: 8, value: 0 },
                ExecArg::Const { size: 8, value: 0 },
                ExecArg::Data(vec![1, 2, 3, 4]),
                ExecArg::Const { size: 8, value: 0 },
                ExecArg::Const { size: 8, value: 0 },
                ExecArg::Const { size: 8, value: 0 },
            ],
        }],
    };
    let encoded = exec_program_to_bytes(&program);
    assert!(
        exec_program_from_bytes(&encoded)
            .expect_err("data arg in call should fail")
            .contains("data arg is only valid for copyin instructions")
    );
}

#[test]
fn sbi_error_code_mapping_is_stable() {
    let known = [
        (0, SbiError::Success),
        (-1, SbiError::Failed),
        (-2, SbiError::NotSupported),
        (-3, SbiError::InvalidParam),
        (-4, SbiError::Denied),
        (-5, SbiError::InvalidAddress),
        (-6, SbiError::AlreadyAvailable),
        (-7, SbiError::AlreadyStarted),
        (-8, SbiError::AlreadyStopped),
        (-9, SbiError::NoShmem),
        (-10, SbiError::InvalidState),
        (-11, SbiError::BadRange),
        (-12, SbiError::Timeout),
        (-13, SbiError::Io),
    ];

    for (code, kind) in known {
        assert_eq!(SbiError::from_code(code), Some(kind));
        assert_eq!(kind.code(), code);
        assert!(is_standard_sbi_error_code(code as u64));
        let ret = SbiRet::from_regs(code as u64, 0x1234);
        assert_eq!(ret.error_kind(), Some(kind));
        assert!(ret.is_valid());
        assert_eq!(ret.is_ok(), code == 0);
    }

    assert_eq!(SbiError::from_code(-14), None);
    assert!(!is_standard_sbi_error_code((-14_i64) as u64));
}
