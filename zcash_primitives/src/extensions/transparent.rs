//! Core traits and structs for Transparent Zcash Extensions.

use std::fmt;
// use crate::consensus::BranchId;
// use crate::transaction::TransactionData;
use crate::transaction::components::Amount;
use crate::transaction::components::OutPoint;

pub trait FromPayload<E>: Sized {
    /// Parses an extension type from a mode and payload.
    fn from_payload(mode: usize, payload: &[u8]) -> Result<Self, E>;
}

pub trait ToPayload {
    /// Returns a serialized payload and its corresponding mode.
    fn to_payload(&self) -> (usize, Vec<u8>);
}

/// A condition that can be used to encumber transparent funds.
#[derive(Debug)]
pub struct Precondition {
    pub extension_id: usize,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Precondition {
    pub fn from<P: ToPayload>(extension_id: usize, value: &P) -> Precondition {
        let (mode, payload) = value.to_payload();
        Precondition {
            extension_id,
            mode,
            payload,
        }
    }
}

/// Data that satisfies the precondition for prior encumbered funds, enabling them to be
/// spent.
#[derive(Debug)]
pub struct Witness {
    pub extension_id: usize,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Witness {
    pub fn from<P: ToPayload>(extension_id: usize, value: &P) -> Witness {
        let (mode, payload) = value.to_payload();
        Witness {
            extension_id,
            mode,
            payload,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Error<E> {
    InvalidForEpoch(u32, usize),
    InvalidExtensionId(usize),
    ProgramError(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidForEpoch(cid, ptype) => write!(
                f,
                "Program type {} is invalid for consensus branch id {}",
                ptype, cid
            ),

            Error::InvalidExtensionId(extension_id) => {
                write!(f, "Unrecognized program type id {}", extension_id)
            }

            Error::ProgramError(err) => write!(f, "Program error: {}", err),
        }
    }
}

pub trait Extension<C> {
    type P;
    type W;
    type Error;

    fn verify_inner(
        &self,
        precondition: &Self::P, 
        witness: &Self::W,
        context: &C,
    ) -> Result<(), Self::Error>;

    fn verify(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        context: &C,
    ) -> Result<(), Self::Error>
    where
        Self::P: FromPayload<Self::Error>,
        Self::W: FromPayload<Self::Error>,
    {
        self.verify_inner(
            &Self::P::from_payload(precondition.mode, &precondition.payload)?,
            &Self::W::from_payload(witness.mode, &witness.payload)?,
            &context,
        )
    }
}


// This extension trait is satisfied by the transaction::builder::Builder type. It provides a
// minimal contract for interacting with the transaction builder, that extension library authors
// can use to add extension-specific builder traits that may be used to interact with the
// transaction builder.  This may make it simpler for projects that include transaction-builder
// functionality to integrate with third-party extensions without those extensions being coupled to
// a particular transaction or builder representation.
pub trait ExtensionTxBuilder {
    type Error;

    fn add_tze_input<W: ToPayload>(
        &mut self, 
        extension_id: usize,
        from_prevout: OutPoint,
        with_evidence: &W
    ) -> Result<(), Self::Error>;

    fn add_tze_output<P: ToPayload>(
        &mut self,
        extension_id: usize,
        value: Amount,
        guarded_by: &P,
    ) -> Result<(), Self::Error>;
}

pub trait Epoch<Context> {
    type VerifyError;
    type CommitError;

    // Implementation of this method should check that the provided witness
    // satisfies the specified precondition, given the context. This verification
    // becomes part of the consensus rules.
    fn verify(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        ctx: &Context
    ) -> Result<(), Error<Self::VerifyError>>;

    // Implementation of this method should delegate to extensions the ability
    // to validate a transaction that is in the process of being constructed by
    // a transaction builder. 
    // fn check_transaction(
    //     &self,
    //     branch_id: &BranchId,
    //     transactionData: &TransactionData
    // ) -> Result<(), Error<Self::VerifyError>>;

    // fn commit(
    //     &self,
    //     tzein: &TzeIn,
    //     ctx: &Context
    // ) -> Result(Witness, Error<Self::
}


