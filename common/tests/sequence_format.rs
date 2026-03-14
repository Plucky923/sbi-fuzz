use common::{
    HostHartState, HostPlatformFaultMode, HostPlatformFaultProfile, HostPrivilegeState,
    HostTargetKind, SEQUENCE_MAGIC, SequenceArg, SequenceCallExpectation, SequenceEnv,
    SequenceMemoryObject, SequenceMetadata, SequenceProgram, SequenceStep,
    sequence_program_describe, sequence_program_from_bytes, sequence_program_from_exec,
    sequence_program_from_semantic_input, sequence_program_primary_input,
    sequence_program_semantic_signature, sequence_program_to_bytes, sequence_program_to_exec,
    validate_sequence_program,
};

fn sample_sequence() -> SequenceProgram {
    SequenceProgram {
        metadata: SequenceMetadata {
            name: "console-sequence".to_string(),
            source: "test".to_string(),
            note: "memory-aware call chain".to_string(),
        },
        env: SequenceEnv {
            smp: 2,
            impl_hint: Some(HostTargetKind::RustSbi),
            platform: "virt".to_string(),
        },
        memory: vec![SequenceMemoryObject {
            id: "console_buf".to_string(),
            slot_offset: 0x40,
            guest_addr: Some(0x8000_2040),
            read: true,
            write: true,
            execute: false,
            bytes: b"ping".to_vec(),
        }],
        steps: vec![
            SequenceStep::SetTargetHart { hart_id: 1 },
            SequenceStep::SetHartState {
                hart_id: 1,
                state: HostHartState::Started,
            },
            SequenceStep::SetPrivilege {
                privilege: HostPrivilegeState::Supervisor,
            },
            SequenceStep::BusyWait { iterations: 0x20 },
            SequenceStep::Call {
                label: "console-write".to_string(),
                eid: 0x4442_434e,
                fid: 0,
                args: vec![
                    SequenceArg::MemoryLen {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::MemoryAddrLow {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::MemoryAddrHigh {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                ],
                expect: Some(SequenceCallExpectation {
                    sbi_error: Some(0),
                    value: None,
                    extension_found: None,
                    classification: Some("ok".to_string()),
                }),
            },
            SequenceStep::SetPlatformFault {
                profile: HostPlatformFaultProfile {
                    mode: HostPlatformFaultMode::ReturnSbiError,
                    error: -2,
                    value: 0,
                    duplicate_side_effects: false,
                },
            },
        ],
    }
}

fn compileable_sequence() -> SequenceProgram {
    SequenceProgram {
        metadata: SequenceMetadata {
            name: "compileable-console".to_string(),
            source: "test".to_string(),
            note: String::new(),
        },
        env: SequenceEnv {
            smp: 2,
            impl_hint: Some(HostTargetKind::RustSbi),
            platform: "virt".to_string(),
        },
        memory: vec![SequenceMemoryObject {
            id: "console_buf".to_string(),
            slot_offset: 0x40,
            guest_addr: Some(0x8000_2040),
            read: true,
            write: true,
            execute: false,
            bytes: b"pong".to_vec(),
        }],
        steps: vec![
            SequenceStep::SetTargetHart { hart_id: 1 },
            SequenceStep::BusyWait { iterations: 0x20 },
            SequenceStep::Call {
                label: "console-write".to_string(),
                eid: 0x4442_434e,
                fid: 0,
                args: vec![
                    SequenceArg::MemoryLen {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::MemoryAddrLow {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::MemoryAddrHigh {
                        object: "console_buf".to_string(),
                    },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                    SequenceArg::Const { value: 0 },
                ],
                expect: None,
            },
        ],
    }
}

#[test]
fn sequence_binary_round_trip_and_describe() {
    let original = sample_sequence();
    let encoded = sequence_program_to_bytes(&original);
    assert!(encoded.starts_with(SEQUENCE_MAGIC));

    let decoded = sequence_program_from_bytes(&encoded).expect("decode sequence");
    assert_eq!(decoded, original);
    assert!(sequence_program_describe(&decoded).contains("console-write"));
    assert!(sequence_program_semantic_signature(&decoded).contains("call:4442434e:0"));
}

#[test]
fn sequence_compiles_to_exec_and_round_trips_back() {
    let sequence = compileable_sequence();
    let exec = sequence_program_to_exec(&sequence).expect("compile sequence to exec");
    assert_eq!(exec.call_count(), 1);

    let imported = sequence_program_from_exec(&exec).expect("import exec program");
    assert!(
        imported
            .steps
            .iter()
            .any(|step| matches!(step, SequenceStep::BusyWait { .. }))
    );
    assert!(imported.steps.iter().any(|step| matches!(
        step,
        SequenceStep::Call { eid, fid, .. } if *eid == 0x4442_434e && *fid == 0
    )));
}

#[test]
fn sequence_primary_input_tracks_first_call() {
    let input = sequence_program_primary_input(&sample_sequence()).expect("first call input");
    assert_eq!(input.args.eid, 0x4442_434e);
    assert_eq!(input.args.fid, 0);
    assert_eq!(input.args.arg0, 4);
}

#[test]
fn sequence_validation_rejects_bad_references() {
    let mut invalid = sample_sequence();
    invalid.steps.push(SequenceStep::Call {
        label: "bad".to_string(),
        eid: 0x10,
        fid: 0,
        args: vec![
            SequenceArg::CallResult {
                call_index: 9,
                op_div: 1,
                op_add: 0,
                default: 0,
            },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
            SequenceArg::Const { value: 0 },
        ],
        expect: None,
    });
    assert!(validate_sequence_program(&invalid).is_err());
}

#[test]
fn semantic_sequence_builder_materializes_console_memory_arguments() {
    let input = common::fix_input_args(common::InputData {
        metadata: common::Metadata::from_call(0x4442_434e, 0, "console-seed".to_string()),
        args: common::Args {
            eid: 0x4442_434e,
            fid: 0,
            arg0: 4,
            arg1: 0x8000_2040,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
    });

    let program = sequence_program_from_semantic_input(
        &input,
        "console-semantic".to_string(),
        "generated".to_string(),
        SequenceEnv::default(),
    );
    assert_eq!(program.memory.len(), 1);
    assert_eq!(program.memory[0].guest_addr, Some(0x8000_2040));
    match &program.steps[0] {
        SequenceStep::Call { args, .. } => {
            assert!(matches!(args[0], SequenceArg::MemoryLen { .. }));
            assert!(matches!(args[1], SequenceArg::MemoryAddrLow { .. }));
            assert!(matches!(args[2], SequenceArg::MemoryAddrHigh { .. }));
        }
        other => panic!("unexpected step: {other:?}"),
    }
}

#[test]
fn semantic_sequence_builder_keeps_hsm_hart_id_and_address_roles() {
    let variants = common::generate_seed_variants(0x4853_4d, 0x0, "hsm-seed");
    let input = variants
        .into_iter()
        .find(|variant| variant.file_suffix == "arg1-guest")
        .expect("address variant")
        .input;

    let program = sequence_program_from_semantic_input(
        &input,
        "hsm-semantic".to_string(),
        "generated".to_string(),
        SequenceEnv {
            smp: 4,
            impl_hint: Some(HostTargetKind::RustSbi),
            platform: String::new(),
        },
    );
    assert_eq!(program.memory.len(), 1);
    match &program.steps[0] {
        SequenceStep::Call { args, .. } => {
            assert!(matches!(args[0], SequenceArg::Const { value: 0 }));
            assert!(matches!(args[1], SequenceArg::MemoryAddr { .. }));
        }
        other => panic!("unexpected step: {other:?}"),
    }
}
