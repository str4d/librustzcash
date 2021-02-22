use bellman::{Circuit, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use bls12_381::Scalar;
use std::env;
use std::fmt;
use zcash_proofs::circuit::{
    sapling::{Output, Spend},
    sprout::{JSInput, JSOutput, JoinSplit},
};

fn compute_path(ns: &[String], this: String) -> String {
    if this.chars().any(|a| a == '/') {
        panic!("'/' is not allowed in names");
    }

    let mut name = String::new();

    let mut needs_separation = false;
    for ns in ns.iter().chain(Some(&this).into_iter()) {
        if needs_separation {
            name += "/";
        }

        name += ns;
        needs_separation = true;
    }

    name
}

/// Converts a bellman path to an ACL2 variable name.
fn acl2ize(s: &str) -> String {
    s.replace(' ', "_").replace('/', "_")
}

struct Acl2Cs {
    current_namespace: Vec<String>,
    inputs: Vec<String>,
    aux: Vec<String>,
    constraints: Vec<(
        LinearCombination<Scalar>,
        LinearCombination<Scalar>,
        LinearCombination<Scalar>,
    )>,
}

impl Acl2Cs {
    fn new() -> Self {
        Acl2Cs {
            current_namespace: vec![],
            inputs: vec!["1".into()],
            aux: vec![],
            constraints: vec![],
        }
    }
}

impl fmt::Display for Acl2Cs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(")?;

        // Hard-code the BLS12-381 scalar modulus.
        // In acl2 hex integers start with `#x`.
        writeln!(
            f,
            "(PRIME . #x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)"
        )?;

        // Circuit variables
        write!(f, "(VARS")?;
        // ACL2 format doesn't include the constant 1.
        for var in self.inputs.iter().skip(1) {
            write!(f, " {}", var)?;
        }
        for var in &self.aux {
            write!(f, " {}", var)?;
        }
        writeln!(f, ")")?;

        // Constraints.
        let write_lc = |f: &mut fmt::Formatter<'_>, name, lc: &LinearCombination<Scalar>| {
            write!(f, "({}", name)?;
            for (var, coeff) in lc.as_ref() {
                write!(
                    f,
                    " ({} {})",
                    coeff.to_string().replace("0x", "#x"),
                    match var.get_unchecked() {
                        Index::Input(i) => &self.inputs[i],
                        Index::Aux(i) => &self.aux[i],
                    }
                )?;
            }
            write!(f, ")")?;
            Ok(())
        };
        write!(f, "(CONSTRAINTS ")?;
        for (a, b, c) in &self.constraints {
            write!(f, "(")?;
            write_lc(f, "A", a)?;
            write_lc(f, "B", b)?;
            write_lc(f, "C", c)?;
            writeln!(f, ")")?;
        }
        write!(f, ")")?;

        writeln!(f, ")")
    }
}

impl ConstraintSystem<Scalar> for Acl2Cs {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, annotation: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.aux.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.aux.push(acl2ize(&path));
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(&mut self, annotation: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.inputs.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.inputs.push(acl2ize(&path));
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.constraints.push((a, b, c));
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name = name_fn().into();
        self.current_namespace.push(name);
    }

    fn pop_namespace(&mut self) {
        assert!(self.current_namespace.pop().is_some());
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

fn usage() {
    panic!("Usage: acl2 [sapling-spend | sapling-output | sprout]");
}

fn main() {
    let circuit = env::args().nth(1);

    let mut cs = Acl2Cs::new();

    match circuit.as_ref().map(|s| s.as_str()) {
        Some("sapling-spend") => {
            let circuit = Spend {
                value_commitment: None,
                proof_generation_key: None,
                payment_address: None,
                commitment_randomness: None,
                ar: None,
                auth_path: vec![None; 32],
                anchor: None,
            };
            circuit.synthesize(&mut cs).unwrap();
        }
        Some("sapling-output") => {
            let circuit = Output {
                value_commitment: None,
                payment_address: None,
                commitment_randomness: None,
                esk: None,
            };
            circuit.synthesize(&mut cs).unwrap();
        }
        Some("sprout") => {
            let circuit = JoinSplit {
                vpub_old: None,
                vpub_new: None,
                h_sig: None,
                phi: None,
                inputs: vec![
                    JSInput {
                        value: None,
                        a_sk: None,
                        rho: None,
                        r: None,
                        auth_path: [None; 29],
                    },
                    JSInput {
                        value: None,
                        a_sk: None,
                        rho: None,
                        r: None,
                        auth_path: [None; 29],
                    },
                ],
                outputs: vec![
                    JSOutput {
                        value: None,
                        a_pk: None,
                        r: None,
                    },
                    JSOutput {
                        value: None,
                        a_pk: None,
                        r: None,
                    },
                ],
                rt: None,
            };
            circuit.synthesize(&mut cs).unwrap();
        }
        _ => usage(),
    }

    print!("{}", cs);
}
