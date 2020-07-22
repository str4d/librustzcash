use pairing::bls12_381::Bls12;
use std::collections::HashMap;
use zcash_primitives::{
    consensus,
    note_encryption::Memo,
    primitives::{Diversifier, PaymentAddress},
    prover::TxProver,
    transaction::{
        builder::Builder,
        components::{Amount, OutPoint},
        Transaction, TxId,
    },
    zip32::ExtendedSpendingKey,
};

use crate::{address::RecipientAddress, proto::compact_formats::CompactBlock};

type Error = ();

struct AccountKey<'a> {
    account: u32,
    extsk: &'a ExtendedSpendingKey,
}

/// A proof that a transaction is included with a particular block.
///
/// For now, no proof is included, as the lightwalletd server is trusted to provide
/// accurate compact blocks. This will eventually include a FlyClient proof.
struct TxProof {
    block_hash: [u8; 32],
}

/// A transaction that was sent or received by the wallet.
struct WalletTx {
    /// The transaction.
    tx: Transaction,
    /// The time we first created or received this transaction.
    added: u64,
    /// Proof that the transaction is mined in the main chain.
    ///
    /// Will be `None` if the transaction is not mined. We may have received this directly
    /// from the sender, or it may be a transaction we detected in a block that was
    /// subsequently rolled back in a chain reorg.
    proof: Option<TxProof>,
}

struct Note {
    /// The viewing key for this note? Or its derivation path?
    ivk: [u8; 32], // TODO type
    /// The diversifier for the address this note was sent to.
    diversifier: Diversifier,
    /// The value of the note.
    value: Amount,
    /// The commitment randomness.
    rcm: [u8; 32], // TODO type
    /// The memo, if any.
    memo: Memo,
}

/// An in-memory wallet.
struct MemoryWallet {
    /// Transactions sent or received by the wallet.
    txs: HashMap<TxId, WalletTx>,
    /// Notes that have been received but not mined.
    // TODO: combine with mined_notes? We determine "verified" on the fly already.
    unmined_notes: HashMap<OutPoint, Note>,
    /// Notes that have been mined. These will have corresponding transactions in `txs`
    /// with proofs of inclusion.
    mined_notes: HashMap<OutPoint, Note>,
    /// Available witnesses for the notes.
    witnesses: HashMap<u32, ()>,
}

/// A byte-oriented backend for storing
trait StorageBackend {
    fn get_address(&self, account: u32) -> Result<String, Error>;

    fn get_note(&self, txid: &str, n: usize) -> Result<Vec<u8>, Error>;
}

pub trait PersistenceBackend {
    fn get_address(&self, account: u32) -> Result<String, Error>;

    fn get_note(&self, note: NoteRef) -> Result<Note, Error>;

    fn get_unspent_notes(&self) -> Result<Vec<NoteRef>, Error>;
}

struct FfiPersistence {
    backend: Box<dyn StorageBackend>,
}

impl PersistenceBackend for FfiPersistence {
    // fn get_address(&self, extsk: ExtendedSpendingKey) -> Result<PaymentAddress<Bls12>, Error> {
    //     self.backend.get_address(account).and_then(|addr| addr.parse())
    // }

    fn get_address(&self, account: u32) -> Result<PaymentAddress<Bls12>, Error> {
        self.backend
            .get_address(account)
            .and_then(|addr| addr.parse())
    }

    fn get_note(&self, note: NoteRef) -> Result<Note, Error> {
        self.backend
            .get_note(&note.txid.to_string(), note.n)
            .and_then(|bytes| Note::from(bytes))
    }
}

/// Callbacks.
pub trait ClientCallbacks {}

trait BlockConsumer {
    fn block_received(&mut self, block: CompactBlock) -> Result<(), Error>;
}

trait Wallet {
    fn get_address(&self, account: u32) -> Result<String, Error>;

    // fn get_note(&self, note: NoteRef) -> Result<Note, Error>;

    // fn get_memo(&self, note: NoteRef) -> Result<Memo, Error>;

    fn get_unspent_notes(&self) -> Result<Vec<Note>, Error>;

    fn lock_notes(&mut self, notes: &[OutPoint]) -> Result<(), Error>;

    fn get_balance(&self, account: u32) -> Result<Amount, Error> {
        self.get_unspent_notes().map(|notes| {
            notes
                .into_iter()
                // .map(|note| self.get_note(note))
                .fold(Amount::zero(), |total, note| total + note.value)
        })
    }

    fn get_verified_balance(&self, account: u32) -> Result<Amount, Error>;

    fn select_notes(&mut self, value: Amount) -> Result<Vec<Note>, Error> {
        let mut unspent = self.get_unspent_notes()?;

        // Selection policy: select the oldest notes until the required value is reached.

        Err(())
    }

    fn create_to_address(
        &mut self,
        consensus_branch_id: consensus::BranchId,
        prover: impl TxProver,
        account_key: AccountKey,
        to: &RecipientAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<Transaction, Error> {
        let notes = self.select_notes(value)?;

        // Create the transaction
        let mut builder = Builder::new(height);
        for selected in notes {
            builder.add_sapling_spend(
                account_key.extsk.clone(),
                selected.diversifier,
                selected.note,
                selected.witness,
            )?;
        }
        match to {
            RecipientAddress::Shielded(to) => {
                builder.add_sapling_output(ovk, to.clone(), value, memo.clone())
            }
            RecipientAddress::Transparent(to) => builder.add_transparent_output(&to, value),
        }?;
        let (tx, tx_metadata) = builder.build(consensus_branch_id, prover)?;

        Ok(tx)
    }
}

pub struct WalletBackend {
    storage: Box<dyn PersistenceBackend>,
    callbacks: Box<dyn ClientCallbacks>,
}

impl WalletBackend {
    pub fn init(storage: Box<dyn PersistenceBackend>, callbacks: Box<dyn ClientCallbacks>) -> Self {
        WalletBackend { storage, callbacks }
    }
}

// impl Wallet for WalletBackend {
//     fn get_address(&self, account: u32) -> Result<String, Error> {
//         self.storage.get_address(self.storage.get_key(account))
//     }

//     fn get_unspent_notes(&self) -> Result<Vec<Note>, Error> {
//         Err(())
//     }

//     fn lock_notes(&mut self, notes: &[Note]) -> Result<(), Error> {
//         Err(())
//     }
// }

pub struct AndroidWalletBackend(WalletBackend);

// impl Wallet for AndroidWalletBackend {
//     fn get_address(&self, account: u32) -> Result<String, Error> {
//         self.0.get_address(...)
//     }

//     fn select_notes(..) {
//     }

// }
