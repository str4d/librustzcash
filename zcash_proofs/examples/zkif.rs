use bellman::Circuit;
use bls12_381::Scalar;
use std::env;
use zcash_proofs::circuit::sapling::{Output, Spend};
use zkinterface_bellman::zkif_cs::ZkifCS;

fn usage() {
    panic!("Usage: zkif FOLDER [sapling-spend | sapling-output]");
}

/// We need to construct fake assignments due to a bug in `zkinterface_bellman`:
/// https://github.com/QED-it/zkinterface-bellman/issues/2
fn sapling_spend(cs: &mut ZkifCS<Scalar>) {
    use ff::{Field, PrimeField};
    use group::{Curve, Group};
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use zcash_primitives::{
        pedersen_hash,
        primitives::{Diversifier, Note, ProofGenerationKey, Rseed, ValueCommitment},
    };

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let tree_depth = 32;
    let i = 0;

    let value_commitment = ValueCommitment {
        value: i,
        randomness: jubjub::Fr::from_str(&(1000 * (i + 1)).to_string()).unwrap(),
    };

    let proof_generation_key = ProofGenerationKey {
        ak: jubjub::SubgroupPoint::random(&mut rng),
        nsk: jubjub::Fr::random(&mut rng),
    };

    let viewing_key = proof_generation_key.to_viewing_key();

    let payment_address;

    loop {
        let diversifier = {
            let mut d = [0; 11];
            rng.fill_bytes(&mut d);
            Diversifier(d)
        };

        if let Some(p) = viewing_key.to_payment_address(diversifier) {
            payment_address = p;
            break;
        }
    }

    let g_d = payment_address.diversifier().g_d().unwrap();
    let commitment_randomness = jubjub::Fr::random(&mut rng);
    let auth_path =
        vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth];
    let ar = jubjub::Fr::random(&mut rng);

    let note = Note {
        value: value_commitment.value,
        g_d,
        pk_d: *payment_address.pk_d(),
        rseed: Rseed::BeforeZip212(commitment_randomness),
    };

    let cmu = note.cmu();
    let mut cur = cmu;

    for (i, val) in auth_path.clone().into_iter().enumerate() {
        let (uncle, b) = val.unwrap();

        let mut lhs = cur;
        let mut rhs = uncle;

        if b {
            ::std::mem::swap(&mut lhs, &mut rhs);
        }

        let lhs = lhs.to_le_bits();
        let rhs = rhs.to_le_bits();

        cur = jubjub::ExtendedPoint::from(pedersen_hash::pedersen_hash(
            pedersen_hash::Personalization::MerkleTree(i),
            lhs.into_iter()
                .take(bls12_381::Scalar::NUM_BITS as usize)
                .chain(rhs.into_iter().take(bls12_381::Scalar::NUM_BITS as usize))
                .cloned(),
        ))
        .to_affine()
        .get_u();
    }

    let instance = Spend {
        value_commitment: Some(value_commitment.clone()),
        proof_generation_key: Some(proof_generation_key.clone()),
        payment_address: Some(payment_address.clone()),
        commitment_randomness: Some(commitment_randomness),
        ar: Some(ar),
        auth_path: auth_path.clone(),
        anchor: Some(cur),
    };

    instance.synthesize(cs).unwrap();
}

/// We need to construct fake assignments due to a bug in `zkinterface_bellman`:
/// https://github.com/QED-it/zkinterface-bellman/issues/2
fn sapling_output(cs: &mut ZkifCS<Scalar>) {
    use ff::Field;
    use group::Group;
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use zcash_primitives::primitives::{Diversifier, ProofGenerationKey, ValueCommitment};

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let value_commitment = ValueCommitment {
        value: rng.next_u64(),
        randomness: jubjub::Fr::random(&mut rng),
    };

    let nsk = jubjub::Fr::random(&mut rng);
    let ak = jubjub::SubgroupPoint::random(&mut rng);

    let proof_generation_key = ProofGenerationKey { ak, nsk };

    let viewing_key = proof_generation_key.to_viewing_key();

    let payment_address;

    loop {
        let diversifier = {
            let mut d = [0; 11];
            rng.fill_bytes(&mut d);
            Diversifier(d)
        };

        if let Some(p) = viewing_key.to_payment_address(diversifier) {
            payment_address = p;
            break;
        }
    }

    let commitment_randomness = jubjub::Fr::random(&mut rng);
    let esk = jubjub::Fr::random(&mut rng);

    let instance = Output {
        value_commitment: Some(value_commitment.clone()),
        payment_address: Some(payment_address.clone()),
        commitment_randomness: Some(commitment_randomness),
        esk: Some(esk),
    };
    instance.synthesize(cs).unwrap();
}

fn main() {
    let args: Vec<_> = env::args().skip(1).take(2).collect();
    if args.len() != 2 {
        usage();
    }

    // We can't use generation mode due to a bug in `zkinterface_bellman`:
    // https://github.com/QED-it/zkinterface-bellman/issues/2
    let mut cs = ZkifCS::<Scalar>::new(&args[0], true);

    match args[1].as_str() {
        "sapling-spend" => sapling_spend(&mut cs),
        "sapling-output" => sapling_output(&mut cs),
        _ => usage(),
    }

    cs.finish(&args[1]).unwrap();
}
