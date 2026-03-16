use common::{
    SequenceArg, SequenceProgram, SequenceStep, mutate_call_arguments, mutate_sequence_program,
};
use rand::{SeedableRng, rngs::StdRng};

fn sample_program() -> SequenceProgram {
    SequenceProgram {
        metadata: Default::default(),
        env: Default::default(),
        memory: Vec::new(),
        steps: vec![SequenceStep::Call {
            label: "base".to_string(),
            eid: 0x10,
            fid: 0,
            args: vec![
                SequenceArg::Const { value: 0 },
                SequenceArg::Const { value: 0 },
                SequenceArg::Const { value: 0 },
                SequenceArg::Const { value: 0 },
                SequenceArg::Const { value: 0 },
                SequenceArg::Const { value: 0 },
            ],
            expect: None,
        }],
    }
}

#[test]
fn sequence_mutation_changes_program_shape() {
    let mut rng = StdRng::seed_from_u64(1);
    let mut program = sample_program();
    let original = program.clone();
    let mut mutated = false;
    for _ in 0..8 {
        if mutate_sequence_program(&mut program, &mut rng).is_some() {
            mutated = true;
            break;
        }
    }
    assert!(mutated, "mutation");
    assert_ne!(program.steps, original.steps);
}

#[test]
fn call_argument_mutation_changes_a_const() {
    let mut rng = StdRng::seed_from_u64(2);
    let mut step = sample_program().steps.remove(0);
    assert!(mutate_call_arguments(&mut step, &mut rng));
    let SequenceStep::Call { args, .. } = step else {
        panic!("expected call step");
    };
    assert!(matches!(args[0], SequenceArg::Const { value: 1 }));
}
