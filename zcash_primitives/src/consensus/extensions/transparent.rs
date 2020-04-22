//! Consensus logic for Transparent Zcash Extensions.

use crate::extensions::transparent::{Context, Epoch, Error, Extension, Predicate, Witness};
use crate::transaction::components::TzeOut;
use std::convert::TryFrom;

mod demo;

/// The set of programs that have assigned type IDs within the Zcash consensus rules.
#[derive(Debug, Clone, Copy)]
pub enum ExtensionId {
    Demo,
}

pub struct InvalidExtId(usize);

impl TryFrom<usize> for ExtensionId {
    type Error = InvalidExtId;

    fn try_from(t: usize) -> Result<Self, Self::Error> {
        match t {
            0 => Ok(ExtensionId::Demo),
            n => Err(InvalidExtId(n)),
        }
    }
}

impl From<ExtensionId> for usize {
    fn from(type_id: ExtensionId) -> usize {
        match type_id {
            ExtensionId::Demo => 0,
        }
    }
}

/// Implementation of required operations for the demo extension, as satisfied
/// by the context.
impl<'a> demo::Context for Context<'a> {
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

/// Wire identifier for the dummy network upgrade epoch.
pub const V1_EPOCH_ID: u32 = 0x7473_6554;

/// A set of demo TZEs associated with the dummy network upgrade.
struct EpochV1;

impl Epoch for EpochV1 {
    type Error = String;

    fn verify<'a>(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        ctx: &Context<'a>,
    ) -> Result<(), Error<Self::Error>> {
        // This epoch contains the following set of programs:
        let ext_id = ExtensionId::try_from(predicate.extension_id)
            .map_err(|InvalidExtId(id)| Error::InvalidExtensionId(id))?;
        match ext_id {
            ExtensionId::Demo => demo::Program
                .verify(predicate, witness, ctx)
                .map_err(|e| Error::ProgramError(format!("Epoch v1 program error: {}", e))),
        }
    }
}

pub fn epoch_for_branch(consensus_branch_id: u32) -> Option<Box<dyn Epoch<Error = String>>> {
    // Map from consensus branch IDs to epochs.
    match consensus_branch_id {
        V1_EPOCH_ID => Some(Box::new(EpochV1)),
        _ => None,
    }
}
