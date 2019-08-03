//! [ZIP 304] protocol for signing arbitrary messages with Sapling payment addresses.
//!
//! [ZIP 304]: https://zips.z.cash/zip-0304

use bellman::{
    gadgets::multipack,
    groth16::{create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof},
};
use bls12_381::Bls12;
use ff::Field;
use group::Curve;
use rand_core::OsRng;
use std::convert::TryInto;
use zcash_primitives::{
    constants::SPENDING_KEY_GENERATOR,
    keys::ExpandedSpendingKey,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    primitives::{Note, Nullifier, PaymentAddress, Rseed, ValueCommitment},
    redjubjub::{self, PrivateKey, PublicKey},
    sapling::{spend_sig, Node},
};

use crate::circuit::sapling::Spend;

const ZIP304_PERSONALIZATION_PREFIX: &'static [u8; 12] = b"ZIP304Signed";

/// A ZIP 304 signature over an arbitrary message, created with the spending key of a
/// Sapling payment address.
///
/// A normal (and desired) property of signatures is that all signatures for a specific
/// public key are linkable if the public key is known. ZIP 304 signatures have the
/// additional property that all signatures for a specific payment address are linkable
/// without knowing the payment address, as the first 32 bytes of each signature will be
/// identical.
///
/// A signature is bound to a specific diversified address of the spending key. Signatures
/// for different diversified addresses of the same spending key are unlinkable.
pub struct Signature {
    nullifier: Nullifier,
    rk: PublicKey,
    zkproof: [u8; 192],
    spend_auth_sig: redjubjub::Signature,
}

impl Signature {
    pub fn from_bytes(bytes: &[u8; 320]) -> Option<Self> {
        let nullifier = Nullifier(bytes[0..32].try_into().unwrap());

        let rk = match PublicKey::read(&bytes[32..64]) {
            Ok(p) => p,
            Err(_) => return None,
        };
        if rk.0.is_small_order().into() {
            return None;
        }

        let mut zkproof = [0; 192];
        zkproof.copy_from_slice(&bytes[64..256]);

        let spend_auth_sig = match redjubjub::Signature::read(&bytes[256..320]) {
            Ok(sig) => sig,
            Err(_) => return None,
        };

        Some(Signature {
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }

    pub fn to_bytes(&self) -> [u8; 320] {
        let mut bytes = [0; 320];
        bytes[0..32].copy_from_slice(&self.nullifier.0);
        self.rk.write(&mut bytes[32..64]).unwrap();
        bytes[64..256].copy_from_slice(&self.zkproof);
        self.spend_auth_sig.write(&mut bytes[256..320]).unwrap();
        bytes
    }
}

/// Signs an arbitrary message for the given [`PaymentAddress`] and [`SLIP 44`] coin type.
///
/// The coin type is used here in its index form, not its hardened form (i.e. 133 for
/// mainnet Zcash).
///
/// [`SLIP 44`]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub fn sign_message(
    expsk: ExpandedSpendingKey,
    payment_address: PaymentAddress,
    coin_type: u32,
    message: &str,
    proving_key: &Parameters<Bls12>,
) -> Signature {
    // Initialize secure RNG.
    let mut rng = OsRng;

    // Derive the necessary key components.
    let proof_generation_key = expsk.proof_generation_key();
    let g_d = payment_address
        .g_d()
        .expect("was a valid diversifier before");

    // We make a Sapling spend proof for a fake note with value of 1 zatoshi, setting rcm
    // and rcv to zero.
    let value = 1;
    let rcm = jubjub::Scalar::zero();
    let rcv = jubjub::Scalar::zero();

    // Create the fake note.
    let note = Note {
        value,
        g_d,
        pk_d: payment_address.pk_d().clone(),
        rseed: Rseed::BeforeZip212(rcm),
    };

    // Derive the note commitment.
    let cmu = note.cmu();

    // Create a fake tree containing the fake note, and witness it.
    let (anchor, witness) = {
        let mut tree = CommitmentTree::empty();
        tree.append(Node::new(cmu.into())).unwrap();
        (
            tree.root(),
            IncrementalWitness::from_tree(&tree).path().unwrap(),
        )
    };

    // Construct the value commitment.
    let value_commitment = ValueCommitment {
        value,
        randomness: rcv,
    };

    // Derive the nullifier for the fake note.
    let nullifier = {
        let vk = proof_generation_key.to_viewing_key();
        note.nf(&vk, witness.position)
    };

    // Re-randomize the payment address.
    let alpha = jubjub::Scalar::random(&mut rng);
    let rk =
        PublicKey(proof_generation_key.ak.clone().into()).randomize(alpha, SPENDING_KEY_GENERATOR);

    // We now have the full witness for our circuit!
    let instance = Spend {
        value_commitment: Some(value_commitment),
        proof_generation_key: Some(proof_generation_key),
        payment_address: Some(payment_address),
        commitment_randomness: Some(rcm),
        ar: Some(alpha),
        auth_path: witness
            .auth_path
            .into_iter()
            .map(|(node, b)| Some((node.into(), b)))
            .collect(),
        anchor: Some(anchor.into()),
    };

    // Create the proof.
    let mut zkproof = [0; 192];
    create_random_proof(instance, proving_key, &mut rng)
        .expect("proving should not fail")
        .write(&mut zkproof[..])
        .unwrap();

    // Compute the message digest to be signed.
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZIP304_PERSONALIZATION_PREFIX);
    personal[12..].copy_from_slice(&coin_type.to_le_bytes());
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(&personal)
        .to_state()
        .update(&zkproof)
        .update(message.as_bytes())
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap();

    // Create the signature.
    let spend_auth_sig = spend_sig(PrivateKey(expsk.ask), alpha, &digest, &mut rng);

    Signature {
        nullifier,
        rk,
        zkproof,
        spend_auth_sig,
    }
}

/// Verifies a [`Signature`] on a message with the given [`PaymentAddress`]  and
/// [`SLIP 44`] coin type.
///
/// The coin type is used here in its index form, not its hardened form (i.e. 133 for
/// mainnet Zcash).
///
/// [`SLIP 44`]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub fn verify_message(
    payment_address: &PaymentAddress,
    coin_type: u32,
    message: &str,
    signature: &Signature,
    verifying_key: &PreparedVerifyingKey<Bls12>,
) -> Result<(), ()> {
    // Compute the message digest that was signed.
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZIP304_PERSONALIZATION_PREFIX);
    personal[12..].copy_from_slice(&coin_type.to_le_bytes());
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(&personal)
        .to_state()
        .update(&signature.zkproof)
        .update(message.as_bytes())
        .finalize();

    // Verify the spend_auth_sig.
    let mut data_to_be_signed = [0u8; 64];
    signature
        .rk
        .write(&mut data_to_be_signed[0..32])
        .expect("message buffer should be 32 bytes");
    data_to_be_signed[32..64].copy_from_slice(digest.as_ref());
    if !signature.rk.verify(
        &data_to_be_signed,
        &signature.spend_auth_sig,
        SPENDING_KEY_GENERATOR,
    ) {
        return Err(());
    }

    // Parse the proof.
    let zkproof = Proof::read(&signature.zkproof[..]).map_err(|_| ())?;

    // We created the proof for a fake note with value of 1 zatoshi, setting rcm and rcv
    // to zero.
    let value = 1;
    let rcm = jubjub::Scalar::zero();
    let rcv = jubjub::Scalar::zero();

    // Recreate the fake note.
    let note = Note {
        value,
        g_d: payment_address
            .g_d()
            .expect("was a valid diversifier before"),
        pk_d: payment_address.pk_d().clone(),
        rseed: Rseed::BeforeZip212(rcm),
    };

    // Recreate the fake tree containing the fake note.
    let anchor = {
        let mut tree = CommitmentTree::empty();
        tree.append(Node::new(note.cmu().into())).unwrap();
        tree.root()
    };

    // Reconstruct the value commitment.
    let cv: jubjub::ExtendedPoint = ValueCommitment {
        value,
        randomness: rcv,
    }
    .commitment()
    .into();

    // Construct public input for circuit.
    let mut public_input = [bls12_381::Scalar::zero(); 7];
    {
        let affine = signature.rk.0.to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[0] = u;
        public_input[1] = v;
    }
    {
        let affine = cv.to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[2] = u;
        public_input[3] = v;
    }
    public_input[4] = anchor.into();

    // Add the nullifier through multiscalar packing.
    {
        let nullifier = multipack::bytes_to_bits_le(&signature.nullifier.0);
        let nullifier = multipack::compute_multipacking(&nullifier);

        assert_eq!(nullifier.len(), 2);

        public_input[5] = nullifier[0];
        public_input[6] = nullifier[1];
    }

    // Verify the proof.
    verify_proof(verifying_key, &zkproof, &public_input[..]).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use zcash_primitives::{keys::ExpandedSpendingKey, primitives::Diversifier};

    use super::{sign_message, verify_message};
    use crate::prover::LocalTxProver;

    #[test]
    fn test_signatures() {
        let local_prover = match LocalTxProver::with_default_location() {
            Some(prover) => prover,
            None => {
                panic!("Cannot locate the Zcash parameters. Please run 'cargo run --release --example download-params --features download-params' to download the parameters, and then re-run the tests.");
            }
        };
        let spend_params = local_prover.spend_params();
        let spend_vk = local_prover.spend_vk();

        let expsk = ExpandedSpendingKey::from_spending_key(&[42; 32][..]);
        let addr = {
            let diversifier = Diversifier([0; 11]);
            expsk
                .proof_generation_key()
                .to_viewing_key()
                .to_payment_address(diversifier)
                .unwrap()
        };

        let msg1 = "Foo bar";
        let msg2 = "Spam eggs";

        let sig1 = sign_message(expsk.clone(), addr.clone(), 1, msg1, spend_params);
        let sig2 = sign_message(expsk.clone(), addr.clone(), 1, msg2, spend_params);

        // The signatures are bound to the specific message they were created over
        assert!(verify_message(&addr, 1, msg1, &sig1, spend_vk).is_ok());
        assert!(verify_message(&addr, 1, msg2, &sig2, spend_vk).is_ok());
        assert!(verify_message(&addr, 1, msg1, &sig2, spend_vk).is_err());
        assert!(verify_message(&addr, 1, msg2, &sig1, spend_vk).is_err());

        // ... and the signatures are unique but trivially linkable by the nullifier
        assert_ne!(&sig1.to_bytes()[..], &sig2.to_bytes()[..]);
        assert_eq!(sig1.nullifier, sig2.nullifier);

        // Generate a signature with a diversified address
        let addr_b = {
            let diversifier = Diversifier([5; 11]);
            expsk
                .proof_generation_key()
                .to_viewing_key()
                .to_payment_address(diversifier)
                .unwrap()
        };
        let sig1_b = sign_message(expsk.clone(), addr_b.clone(), 1, msg1, spend_params);

        // The signatures are bound to the specific address they were created with
        assert!(verify_message(&addr_b, 1, msg1, &sig1_b, spend_vk).is_ok());
        assert!(verify_message(&addr_b, 1, msg1, &sig1, spend_vk).is_err());
        assert!(verify_message(&addr, 1, msg1, &sig1_b, spend_vk).is_err());

        // ... and the signatures are unlinkable
        assert_ne!(&sig1.to_bytes()[..], &sig1_b.to_bytes()[..]);
        assert_ne!(sig1.nullifier, sig1_b.nullifier);
    }
}
