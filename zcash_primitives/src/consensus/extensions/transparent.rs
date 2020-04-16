//! Consensus logic for Transparent Zcash Extensions.

use crate::extensions::transparent::{
    Context, Epoch, ExtErr, Extension, Predicate, ProgramType, Witness,
};

mod demo;

/// A set of demo TZEs associated with the dummy network upgrade.
struct EpochV1;

impl Epoch<String> for EpochV1 {
    fn verify<'a>(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        ctx: &Context<'a>,
    ) -> Result<(), ExtErr<String>> {
        // This epoch contains the following set of programs:
        match predicate.type_id {
            ProgramType::Demo => {
                let program = demo::Program { ctx };
                program
                    .verify(predicate, witness)
                    .map_err(|e| ExtErr::Program(format!("Epoch v1 error: {}", e)))
            }
            _ => {
                // All other program types are invalid in this epoch.
                Err(ExtErr::InvalidEpoch)
            }
        }
    }
}

pub fn epoch_for_branch(consensus_branch_id: u32) -> Option<Box<dyn Epoch<String>>> {
    // Map from consensus branch IDs to epochs.
    match consensus_branch_id {
        0x7473_6554 => Some(Box::new(EpochV1)),
        _ => None,
    }
}
