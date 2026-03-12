use common::{
    ExecArg, ExecInstr, ExecProgram, exec_call_id_for, exec_program_describe,
    exec_program_from_bytes, exec_program_to_bytes, exec_prop_busy_wait, exec_prop_target_hart,
};
use std::fs::{self, create_dir_all};
use std::path::PathBuf;

const SBI_EXT_HSM: u64 = 0x4853_4d;
const SBI_EXT_BASE: u64 = 0x10;
const SBI_EXT_DBCN: u64 = 0x4442_434e;
const SBI_EXT_PMU: u64 = 0x504d_55;

struct ScenarioSeed {
    name: &'static str,
    note: &'static str,
    program: ExecProgram,
}

pub fn generate_rustsbi_scenarios(output: PathBuf) {
    create_dir_all(&output).expect("create RustSBI scenario output directory");

    let scenarios = rustsbi_scenarios();
    for scenario in &scenarios {
        write_scenario(&output, scenario);
    }

    println!(
        "Generated {} RustSBI scenario seeds in {}",
        scenarios.len(),
        output.display()
    );
}

fn write_scenario(output: &PathBuf, scenario: &ScenarioSeed) {
    let binary = exec_program_to_bytes(&scenario.program);
    exec_program_from_bytes(&binary).expect("round-trip validate generated RustSBI scenario");

    let exec_path = output.join(format!("{}.exec", scenario.name));
    let desc_path = output.join(format!("{}.txt", scenario.name));

    fs::write(&exec_path, binary).expect("write RustSBI exec scenario");
    fs::write(
        &desc_path,
        format!(
            "scenario = {}\nnote = {}\n\n{}\n",
            scenario.name,
            scenario.note,
            exec_program_describe(&scenario.program)
        ),
    )
    .expect("write RustSBI scenario description");
}

fn rustsbi_scenarios() -> Vec<ScenarioSeed> {
    vec![
        ScenarioSeed {
            name: "base-identity-cross-hart",
            note: "Repeat Base identity queries across hart0, hart1, and hart2 so built-in pure-call oracles can detect inconsistent RustSBI responses.",
            program: ExecProgram {
                instructions: vec![
                    raw_call(
                        SBI_EXT_BASE,
                        0,
                        0,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    raw_call(
                        SBI_EXT_BASE,
                        2,
                        1,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(1),
                    set_busy_wait(0x200),
                    raw_call(
                        SBI_EXT_BASE,
                        0,
                        2,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    raw_call(
                        SBI_EXT_BASE,
                        2,
                        3,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(2),
                    raw_call(
                        SBI_EXT_BASE,
                        3,
                        4,
                        vec![
                            const_u64(SBI_EXT_HSM),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(0),
                    raw_call(
                        SBI_EXT_BASE,
                        3,
                        5,
                        vec![
                            const_u64(SBI_EXT_HSM),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                ],
            },
        },
        ScenarioSeed {
            name: "hsm-hart0-status-oracle",
            note: "Query hart0 HSM status from hart0, hart1, and hart2 after cross-hart dispatch so built-in hart0-state invariants can fire on semantic corruption.",
            program: ExecProgram {
                instructions: vec![
                    fixed_call(
                        SBI_EXT_HSM,
                        2,
                        0,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(1),
                    raw_call(
                        SBI_EXT_BASE,
                        0,
                        1,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    fixed_call(
                        SBI_EXT_HSM,
                        2,
                        2,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(2),
                    set_busy_wait(0x100),
                    raw_call(
                        SBI_EXT_BASE,
                        2,
                        3,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    fixed_call(
                        SBI_EXT_HSM,
                        2,
                        4,
                        vec![
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                ],
            },
        },
        ScenarioSeed {
            name: "hsm-start-status-chain",
            note: "Switch the calling hart between hart0 and hart1 while chaining HSM status/start/status responses.",
            program: ExecProgram {
                instructions: vec![
                    fixed_call(
                        SBI_EXT_HSM,
                        2,
                        0,
                        vec![
                            const_u64(1),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(1),
                    set_busy_wait(0x2000),
                    fixed_call(
                        SBI_EXT_HSM,
                        0,
                        1,
                        vec![
                            const_u64(1),
                            const_u64(0x8000_0000),
                            result_u64(0, 0x101),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(0),
                    fixed_call(
                        SBI_EXT_HSM,
                        2,
                        2,
                        vec![
                            const_u64(1),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                ],
            },
        },
        ScenarioSeed {
            name: "hsm-stop-start-status",
            note: "Drive HSM state transitions from three different caller harts with an injected busy-wait gap.",
            program: ExecProgram {
                instructions: vec![
                    fixed_call(
                        SBI_EXT_HSM,
                        1,
                        0,
                        vec![
                            const_u64(1),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(2),
                    set_busy_wait(0x1000),
                    fixed_call(
                        SBI_EXT_HSM,
                        0,
                        1,
                        vec![
                            const_u64(1),
                            const_u64(0x8000_1000),
                            result_u64(0, 0x202),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(1),
                    fixed_call(
                        SBI_EXT_HSM,
                        2,
                        2,
                        vec![
                            const_u64(1),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(3),
                    fixed_call(
                        SBI_EXT_HSM,
                        0,
                        3,
                        vec![
                            const_u64(2),
                            const_u64(0x8000_2000),
                            result_u64(2, 0x303),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                ],
            },
        },
        ScenarioSeed {
            name: "ipi-rfence-fanout",
            note: "Seed two hart masks in guest memory and alternate IPI / RFENCE requests from hart1 and hart2.",
            program: ExecProgram {
                instructions: vec![
                    copyin_const(0x80, 8, 0x2),
                    copyin_const(0x88, 8, 0x6),
                    set_target_hart(1),
                    fixed_call(
                        0x0073_5049,
                        0,
                        0,
                        vec![
                            addr64(0x80),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(2),
                    set_busy_wait(0x800),
                    fixed_call(
                        0x5246_4e43,
                        1,
                        1,
                        vec![
                            addr64(0x88),
                            const_u64(0x8000_0000),
                            const_u64(0x2000),
                            result_u64(0, 0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    set_target_hart(1),
                    fixed_call(
                        0x0073_5049,
                        0,
                        2,
                        vec![
                            addr64(0x88),
                            result_u64(1, 0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                ],
            },
        },
        ScenarioSeed {
            name: "console-pmu-pointer-flow",
            note: "Exercise raw ecall, copyin, copyout, result chaining, and hart affinity by moving Console/PMU calls across hart3 and hart2.",
            program: ExecProgram {
                instructions: vec![
                    copyin_data(0x100, b"RustSBI fuzz\n"),
                    copyin_addr64(0x20, 0x100),
                    copyout(0, 0x20, 4),
                    copyout(1, 0x24, 4),
                    set_target_hart(3),
                    raw_call(
                        SBI_EXT_DBCN,
                        0,
                        4,
                        vec![
                            const_u64(13),
                            result_u64(0, 0),
                            result_u64(1, 0),
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                    copyin_addr64(0x28, 0x180),
                    copyout(2, 0x28, 4),
                    copyout(3, 0x2c, 4),
                    set_target_hart(2),
                    set_busy_wait(0x400),
                    raw_call(
                        SBI_EXT_PMU,
                        8,
                        5,
                        vec![
                            result_u64(2, 0),
                            result_u64(3, 0),
                            ExecArg::Result {
                                size: 8,
                                index: 4,
                                op_div: 4,
                                op_add: 1,
                                default: 4,
                            },
                            const_u64(0),
                            const_u64(0),
                            const_u64(0),
                        ],
                    ),
                ],
            },
        },
    ]
}

fn fixed_call(eid: u64, fid: u64, copyout_index: u64, args: Vec<ExecArg>) -> ExecInstr {
    ExecInstr::Call {
        call_id: exec_call_id_for(eid, fid).expect("known fixed exec call"),
        copyout_index,
        args,
    }
}

fn raw_call(eid: u64, fid: u64, copyout_index: u64, args: Vec<ExecArg>) -> ExecInstr {
    let mut raw_args = Vec::with_capacity(8);
    raw_args.push(const_u64(eid));
    raw_args.push(const_u64(fid));
    raw_args.extend(args);

    ExecInstr::Call {
        call_id: 0,
        copyout_index,
        args: raw_args,
    }
}

fn copyin_const(addr: u64, size: u64, value: u64) -> ExecInstr {
    ExecInstr::CopyIn {
        addr,
        arg: ExecArg::Const { size, value },
    }
}

fn copyin_data(addr: u64, data: &[u8]) -> ExecInstr {
    ExecInstr::CopyIn {
        addr,
        arg: ExecArg::Data(data.to_vec()),
    }
}

fn copyin_addr64(addr: u64, offset: u64) -> ExecInstr {
    ExecInstr::CopyIn {
        addr,
        arg: ExecArg::Addr64 { offset },
    }
}

fn copyout(index: u64, addr: u64, size: u64) -> ExecInstr {
    ExecInstr::CopyOut { index, addr, size }
}

fn set_target_hart(hart_id: u64) -> ExecInstr {
    ExecInstr::SetProps {
        value: exec_prop_target_hart(hart_id),
    }
}

fn set_busy_wait(iterations: u64) -> ExecInstr {
    ExecInstr::SetProps {
        value: exec_prop_busy_wait(iterations),
    }
}

fn const_u64(value: u64) -> ExecArg {
    ExecArg::Const { size: 8, value }
}

fn result_u64(index: u64, default: u64) -> ExecArg {
    ExecArg::Result {
        size: 8,
        index,
        op_div: 0,
        op_add: 0,
        default,
    }
}

fn addr64(offset: u64) -> ExecArg {
    ExecArg::Addr64 { offset }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::EXEC_NO_COPYOUT;
    use tempfile::tempdir;

    #[test]
    fn generates_rustsbi_exec_scenarios() {
        let dir = tempdir().expect("create temp directory");
        generate_rustsbi_scenarios(dir.path().to_path_buf());

        let exec_paths = fs::read_dir(dir.path())
            .expect("read scenario directory")
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("exec"))
            .collect::<Vec<_>>();

        assert_eq!(exec_paths.len(), rustsbi_scenarios().len());
        for exec_path in exec_paths {
            let binary = fs::read(&exec_path).expect("read generated scenario");
            let program = exec_program_from_bytes(&binary).expect("decode generated scenario");
            assert!(program.call_count() >= 2);
            assert!(exec_path.with_extension("txt").exists());
        }
    }

    #[test]
    fn pointer_flow_uses_raw_ecall_and_copyout() {
        let scenario = rustsbi_scenarios()
            .into_iter()
            .find(|seed| seed.name == "console-pmu-pointer-flow")
            .expect("console/pmu scenario");

        assert!(
            scenario
                .program
                .instructions
                .iter()
                .any(|instr| matches!(instr, ExecInstr::CopyOut { .. }))
        );
        assert!(scenario.program.instructions.iter().any(|instr| {
            matches!(
                instr,
                ExecInstr::Call {
                    call_id: 0,
                    copyout_index,
                    ..
                } if *copyout_index != EXEC_NO_COPYOUT
            )
        }));
        assert!(
            scenario
                .program
                .instructions
                .iter()
                .any(|instr| matches!(instr, ExecInstr::SetProps { .. }))
        );
    }

    #[test]
    fn oracle_scenarios_cover_base_and_hsm_paths() {
        let scenarios = rustsbi_scenarios();
        assert!(
            scenarios
                .iter()
                .any(|seed| seed.name == "base-identity-cross-hart")
        );
        assert!(
            scenarios
                .iter()
                .any(|seed| seed.name == "hsm-hart0-status-oracle")
        );
    }
}
