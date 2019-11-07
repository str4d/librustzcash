//! Demo implementation of TZE consensus rules.
//!
//! The demo program implements a dual-hash-lock encumbrance with the following form:
//!
//! > `hash = BLAKE2b_256(preimage_1 || BLAKE2b_256(preimage_2))`
//!
//! The two preimages are revealed in sequential transactions, demonstrating how TZEs can
//! impose constraints on how program modes are chained together.
//!
//! The demo program has two modes:
//!
//! - Mode 0: `hash_1 = BLAKE2b_256(preimage_1 || hash_2)`
//! - Mode 1: `hash_2 = BLAKE2b_256(preimage_2)`
//!
//! and uses the following transaction formats:
//!
//! - `tx_a`: `[ [any input types...] ----> TzeOut(value, hash_1) ]`
//! - `tx_b`: `[ TzeIn(tx_a, preimage_1) -> TzeOut(value, hash_2) ]`
//! - `tx_c`: `[ TzeIn(tx_b, preimage_2) -> [any output types...] ]`

use blake2b_simd::Params;

use super::context;
use crate::extensions::transparent::{demo, Predicate};

pub struct Program;

impl Program {
    /// Runs the program against the given predicate, witness, and context.
    ///
    /// At this point the predicate and witness have been parsed and validated
    /// non-contextually, and are guaranteed to both be for this program. All subsequent
    /// validation is this function's responsibility.
    pub(super) fn verify<'a>(
        predicate: &demo::Predicate,
        witness: &demo::Witness,
        ctx: &context::V1<'a>,
    ) -> Result<(), &'static str> {
        // This match statement is selecting the mode that the program is operating in,
        // based on the enums defined in the parser.
        match (predicate, witness) {
            (demo::Predicate::Open(p_open), demo::Witness::Open(w_open)) => {
                // In OPEN mode, we enforce that the transaction must only contain inputs
                // and outputs from this program. The consensus rules enforce that if a
                // transaction contains both TZE inputs and TZE outputs, they must all be
                // of the same program type. Therefore we only need to check that the
                // transaction does not contain any other type of input or output.
                if !ctx.is_tze_only() {
                    return Err(
                        "Demo TZE cannot be closed in a transaction with non-TZE inputs or outputs",
                    );
                }

                // Next, check that there is only a single TZE output of the correct type.
                match &ctx.tx_tze_outputs() {
                    [tze_out] => match &tze_out.predicate {
                        Predicate::Demo(demo::Predicate::Close(p_close)) => {
                            // Finally, check the predicate:
                            // predicate_open = BLAKE2b_256(witness_open || predicate_close)
                            let mut h = Params::new().hash_length(32).to_state();
                            h.update(&w_open.0);
                            h.update(&p_close.0);
                            let hash = h.finalize();
                            if hash.as_bytes() == p_open.0 {
                                Ok(())
                            } else {
                                Err("hash mismatch")
                            }
                        }
                        Predicate::Demo(_) => Err("Invalid TZE output mode"),
                        _ => Err("Invalid TZE output type"),
                    },
                    _ => Err("Invalid number of TZE outputs"),
                }
            }
            (demo::Predicate::Close(p), demo::Witness::Close(w)) => {
                // In CLOSE mode, we only require that the predicate is satisfied:
                // predicate_close = BLAKE2b_256(witness_close)
                let hash = Params::new().hash_length(32).hash(&w.0);
                if hash.as_bytes() == p.0 {
                    Ok(())
                } else {
                    Err("hash mismatch")
                }
            }
            _ => Err("Mode mismatch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        consensus::extensions::transparent::{Context, Programs},
        extensions::transparent::{self as tze, demo},
        transaction::{
            components::{Amount, OutPoint, TzeIn, TzeOut},
            TransactionData,
        },
    };
    use blake2b_simd::Params;

    #[test]
    fn demo_program() {
        let preimage_1 = [1; 32];
        let preimage_2 = [2; 32];

        let hash_2 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(Params::new().hash_length(32).hash(&preimage_2).as_bytes());
            hash
        };
        let hash_1 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(
                Params::new()
                    .hash_length(32)
                    .to_state()
                    .update(&preimage_1)
                    .update(&hash_2)
                    .finalize()
                    .as_bytes(),
            );
            hash
        };

        let mut mtx_a = TransactionData::nu4();
        mtx_a.tze_outputs.push(TzeOut {
            value: Amount::from_u64(1).unwrap(),
            predicate: tze::Predicate::Demo(demo::Predicate::open(hash_1)),
        });
        let tx_a = mtx_a.freeze().unwrap();

        let mut mtx_b = TransactionData::nu4();
        mtx_b.tze_inputs.push(TzeIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: tze::Witness::Demo(demo::Witness::open(preimage_1)),
        });
        mtx_b.tze_outputs.push(TzeOut {
            value: Amount::from_u64(1).unwrap(),
            predicate: tze::Predicate::Demo(demo::Predicate::close(hash_2)),
        });
        let tx_b = mtx_b.freeze().unwrap();

        let mut mtx_c = TransactionData::nu4();
        mtx_c.tze_inputs.push(TzeIn {
            prevout: OutPoint::new(tx_b.txid().0, 0),
            witness: tze::Witness::Demo(demo::Witness::close(preimage_2)),
        });
        let tx_c = mtx_c.freeze().unwrap();

        let programs = Programs::for_epoch(0x7473_6554).unwrap();

        // Verify tx_b
        {
            let ctx = Context::v1(1, &tx_b);
            assert_eq!(
                programs.verify(
                    &tx_a.tze_outputs[0].predicate,
                    &tx_b.tze_inputs[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_c
        {
            let ctx = Context::v1(2, &tx_c);
            assert_eq!(
                programs.verify(
                    &tx_b.tze_outputs[0].predicate,
                    &tx_c.tze_inputs[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }
    }
}
