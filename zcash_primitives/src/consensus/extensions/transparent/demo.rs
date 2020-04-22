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
use std::convert::{TryFrom, TryInto};
use std::fmt;


use crate::extensions::transparent::{Extension, ToPayload};
use crate::transaction::components::TzeOut;

mod open {
    pub const MODE: usize = 0;

    #[derive(Debug, PartialEq)]
    pub struct Predicate(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

mod close {
    pub const MODE: usize = 1;

    #[derive(Debug, PartialEq)]
    pub struct Predicate(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

#[derive(Debug, PartialEq)]
pub enum Predicate {
    Open(open::Predicate),
    Close(close::Predicate),
}

impl Predicate {
    pub fn open(hash: [u8; 32]) -> Self {
        Predicate::Open(open::Predicate(hash))
    }

    pub fn close(hash: [u8; 32]) -> Self {
        Predicate::Close(close::Predicate(hash))
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    IllegalPayloadLength(usize),
    ModeInvalid(usize),
    NonTzeTxn,
    HashMismatch, // include hashes?
    ModeMismatch,
    ExpectedClose,
    InvalidOutputQty(usize),
}

impl fmt::Display for Error {
    fn fmt<'a>(&self, f: &mut fmt::Formatter<'a>) -> fmt::Result {
        match self {
            Error::IllegalPayloadLength(sz) => write!(f, "Illegal payload length for demo: {}", sz),
            Error::ModeInvalid(m) => write!(f, "Invalid TZE mode for demo program: {}", m),
            Error::NonTzeTxn => write!(f, "Transaction has non-TZE inputs."),
            Error::HashMismatch => write!(f, "Hash mismatch"),
            Error::ModeMismatch => write!(f, "Extension operation mode mismatch."),
            Error::ExpectedClose => write!(f, "Got open, expected close."),
            Error::InvalidOutputQty(qty) => write!(f, "Incorrect number of outputs: {}", qty),
        }
    }
}

impl TryFrom<(usize, &[u8])> for Predicate {
    type Error = Error;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    Ok(Predicate::Open(open::Predicate(hash)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    Ok(Predicate::Close(close::Predicate(hash)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl TryFrom<(usize, &Vec<u8>)> for Predicate {
    type Error = Error;

    fn try_from((mode, payload): (usize, &Vec<u8>)) -> Result<Self, Self::Error> {
        (mode, &payload[..]).try_into()
    }
}

impl TryFrom<(usize, Predicate)> for Predicate {
    type Error = Error;

    fn try_from(from: (usize, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Predicate::Open(p)) => Ok(Predicate::Open(p)),
            (close::MODE, Predicate::Close(p)) => Ok(Predicate::Close(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl ToPayload for Predicate {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Predicate::Open(p) => (open::MODE, p.0.to_vec()),
            Predicate::Close(p) => (close::MODE, p.0.to_vec()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Witness {
    Open(open::Witness),
    Close(close::Witness),
}

impl Witness {
    pub fn open(preimage: [u8; 32]) -> Self {
        Witness::Open(open::Witness(preimage))
    }

    pub fn close(preimage: [u8; 32]) -> Self {
        Witness::Close(close::Witness(preimage))
    }
}

impl TryFrom<(usize, &[u8])> for Witness {
    type Error = Error;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 32 {
                    let mut preimage = [0; 32];
                    preimage.copy_from_slice(&payload);
                    Ok(Witness::Open(open::Witness(preimage)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut preimage = [0; 32];
                    preimage.copy_from_slice(&payload);
                    Ok(Witness::Close(close::Witness(preimage)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl TryFrom<(usize, &Vec<u8>)> for Witness {
    type Error = Error;

    fn try_from((mode, payload): (usize, &Vec<u8>)) -> Result<Self, Self::Error> {
        (mode, &payload[..]).try_into()
    }
}

impl TryFrom<(usize, Witness)> for Witness {
    type Error = Error;

    fn try_from(from: (usize, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Witness::Open(p)) => Ok(Witness::Open(p)),
            (close::MODE, Witness::Close(p)) => Ok(Witness::Close(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Witness::Open(w) => (open::MODE, w.0.to_vec()),
            Witness::Close(w) => (close::MODE, w.0.to_vec()),
        }
    }
}

pub trait Context {
    fn is_tze_only(&self) -> bool;
    fn tx_tze_outputs(&self) -> &[TzeOut];
}

pub struct Program;

impl<C: Context> Extension<C> for Program {
    type P = Predicate;
    type W = Witness;
    type Error = Error;

    /// Runs the program against the given predicate, witness, and context.
    ///
    /// At this point the predicate and witness have been parsed and validated
    /// non-contextually, and are guaranteed to both be for this program. All subsequent
    /// validation is this function's responsibility.
    fn verify_inner(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        context: &C,
    ) -> Result<(), Error> {
        // This match statement is selecting the mode that the program is operating in,
        // based on the enums defined in the parser.
        match (predicate, witness) {
            (Predicate::Open(p_open), Witness::Open(w_open)) => {
                // In OPEN mode, we enforce that the transaction must only contain inputs
                // and outputs from this program. The consensus rules enforce that if a
                // transaction contains both TZE inputs and TZE outputs, they must all be
                // of the same program type. Therefore we only need to check that the
                // transaction does not contain any other type of input or output.
                if !context.is_tze_only() {
                    return Err(Error::NonTzeTxn);
                }

                // Next, check that there is only a single TZE output of the correct type.
                let outputs = context.tx_tze_outputs();
                match outputs {
                    [tze_out] => match Predicate::try_from((
                        tze_out.predicate.mode,
                        &tze_out.predicate.payload,
                    )) {
                        Ok(Predicate::Close(p_close)) => {
                            // Finally, check the predicate:
                            // predicate_open = BLAKE2b_256(witness_open || predicate_close)
                            let mut h = Params::new().hash_length(32).to_state();
                            h.update(&w_open.0);
                            h.update(&p_close.0);
                            let hash = h.finalize();
                            if hash.as_bytes() == p_open.0 {
                                Ok(())
                            } else {
                                Err(Error::HashMismatch)
                            }
                        }
                        Ok(Predicate::Open(_)) => Err(Error::ExpectedClose),
                        Err(e) => Err(e),
                    },
                    _ => Err(Error::InvalidOutputQty(outputs.len())),
                }
            }
            (Predicate::Close(p), Witness::Close(w)) => {
                // In CLOSE mode, we only require that the predicate is satisfied:
                // predicate_close = BLAKE2b_256(witness_close)
                let hash = Params::new().hash_length(32).hash(&w.0);
                if hash.as_bytes() == p.0 {
                    Ok(())
                } else {
                    Err(Error::HashMismatch)
                }
            }
            _ => Err(Error::ModeMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        consensus::extensions::transparent::demo,
        consensus::extensions::transparent::demo::{Context, Program},
        extensions::transparent::{self as tze, Extension},
        transaction::{
            components::{Amount, OutPoint, TzeIn, TzeOut},
            Transaction, TransactionData,
        },
    };
    use blake2b_simd::Params;

    use std::convert::TryInto;

    use super::{close, open, Predicate, Witness};
    use crate::extensions::transparent::ToPayload;

    #[test]
    fn predicate_open_round_trip() {
        let data = vec![7; 32];
        let p: Predicate = (open::MODE, &data[..]).try_into().unwrap();
        assert_eq!(p, Predicate::Open(open::Predicate([7; 32])));
        assert_eq!(p.to_payload(), (open::MODE, data));
    }

    #[test]
    fn predicate_close_round_trip() {
        let data = vec![7; 32];
        let p: Predicate = (close::MODE, &data[..]).try_into().unwrap();
        assert_eq!(p, Predicate::Close(close::Predicate([7; 32])));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn predicate_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[31, 33] {
                let p: Result<Predicate, _> = (mode, &vec![7; *len]).try_into();
                assert!(p.is_err());
            }
        }
    }

    #[test]
    fn witness_open_round_trip() {
        let data = vec![7; 32];
        let w: Witness = (open::MODE, &data[..]).try_into().unwrap();
        assert_eq!(w, Witness::Open(open::Witness([7; 32])));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

    #[test]
    fn witness_close_round_trip() {
        let data = vec![7; 32];
        let p: Witness = (close::MODE, &data[..]).try_into().unwrap();
        assert_eq!(p, Witness::Close(close::Witness([7; 32])));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn witness_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[31, 33] {
                let p: Result<Witness, _> = (mode, &vec![7; *len]).try_into();
                assert!(p.is_err());
            }
        }
    }

    /// Dummy context
    pub struct Ctx<'a> {
        pub tx: &'a Transaction,
    }

    /// Implementation of required operations for the demo extension, as satisfied
    /// by the context.
    impl<'a> Context for Ctx<'a> {
        fn is_tze_only(&self) -> bool {
            self.tx.vin.is_empty()
                && self.tx.vout.is_empty()
                && self.tx.shielded_spends.is_empty()
                && self.tx.shielded_outputs.is_empty()
                && self.tx.joinsplits.is_empty()
        }

        fn tx_tze_outputs(&self) -> &[TzeOut] {
            &self.tx.tze_outputs
        }
    }

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
            predicate: tze::Predicate::from(0, &demo::Predicate::open(hash_1)),
        });
        let tx_a = mtx_a.freeze().unwrap();

        let mut mtx_b = TransactionData::nu4();
        mtx_b.tze_inputs.push(TzeIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: tze::Witness::from(0, &demo::Witness::open(preimage_1)),
        });
        mtx_b.tze_outputs.push(TzeOut {
            value: Amount::from_u64(1).unwrap(),
            predicate: tze::Predicate::from(0, &demo::Predicate::close(hash_2)),
        });
        let tx_b = mtx_b.freeze().unwrap();

        let mut mtx_c = TransactionData::nu4();
        mtx_c.tze_inputs.push(TzeIn {
            prevout: OutPoint::new(tx_b.txid().0, 0),
            witness: tze::Witness::from(0, &demo::Witness::close(preimage_2)),
        });
        let tx_c = mtx_c.freeze().unwrap();

        // Verify tx_b
        {
            let ctx = Ctx { tx: &tx_b };
            assert_eq!(
                Program.verify(
                    &tx_a.tze_outputs[0].predicate,
                    &tx_b.tze_inputs[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_c
        {
            let ctx = Ctx { tx: &tx_b };
            assert_eq!(
                Program.verify(
                    &tx_b.tze_outputs[0].predicate,
                    &tx_c.tze_inputs[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }
    }
}