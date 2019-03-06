//! Add a Sapling output to a PCZT.

use blake2b_simd::{Hash as Blake2bResult, Params as Blake2b};
use failure::Error;
use ff::{PrimeField, PrimeFieldRepr};
use pczt::proto::pczt::PartiallyCreatedTransaction;
use protobuf::{parse_from_bytes, Message};
use rand_core::OsRng;
use std::env;
use std::io;
use zcash_primitives::{
    consensus,
    jubjub::fs::{Fs, FsRepr},
    redjubjub::PrivateKey,
    sapling::spend_sig,
    transaction::{signature_hash_data, SIGHASH_ALL},
    zip32::{ChildIndex, ExtendedSpendingKey},
    JUBJUB,
};

pub const ZIP32_HDSEED_FP_PERSONALIZATION: &'static [u8; 16] = b"Zcash_HD_Seed_FP";

pub fn seed_fingerprint(seed: &[u8]) -> Blake2bResult {
    let mut h = Blake2b::new()
        .hash_length(32)
        .personal(ZIP32_HDSEED_FP_PERSONALIZATION)
        .to_state();
    // TODO: This should be a compact size
    h.update(&[32]);
    h.update(seed);
    h.finalize()
}

pub fn sign_pczt(
    pczt: &[u8],
    seed: [u8; 32],
    consensus_branch_id: consensus::BranchId,
) -> Result<Vec<u8>, Error> {
    let mut pczt: PartiallyCreatedTransaction = parse_from_bytes(&pczt).unwrap();

    let mut rng = OsRng;
    let mtx = pczt.to_data()?;

    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&signature_hash_data(
        &mtx,
        consensus_branch_id,
        SIGHASH_ALL,
        None,
    ));

    let seed_fp = seed_fingerprint(&seed);
    let master = ExtendedSpendingKey::master(&seed);

    for spend in pczt.mut_spends().iter_mut() {
        let path: Vec<_> = spend
            .get_key()
            .derivationPath
            .iter()
            .map(|i| ChildIndex::from_index(*i))
            .collect();

        let extsk = ExtendedSpendingKey::from_path(&master, &path);

        // TODO: if it isn't our input, continue
        if spend.get_key().masterFingerprint != seed_fp.as_bytes() {
            continue;
        }

        let alpha = {
            let mut r = FsRepr::default();
            r.read_le(&spend.alpha[..])?;
            Fs::from_repr(r).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        };

        // Create Sapling spendAuth signature
        let spend_auth_sig = spend_sig(
            PrivateKey(extsk.expsk.ask),
            alpha,
            &sighash,
            &mut rng,
            &JUBJUB,
        );
        spend_auth_sig.write(&mut spend.spendAuthSig)?;
    }

    Ok(pczt.write_to_bytes().unwrap())
}

fn main() {
    let options = vec![
        ":/pczt#The PCZT to sign",
        ":/seed#The HD seed to sign with, as a hex string",
    ];

    let mut vars = match pirate::vars("add_output", &options) {
        Ok(v) => v,
        Err(why) => panic!("Error: {}", why),
    };

    let args: Vec<String> = env::args().collect();
    let matches = match pirate::matches(&args, &mut vars) {
        Ok(m) => m,
        Err(why) => {
            println!("Error: {}", why);
            pirate::usage(&vars);
            return;
        }
    };

    let pczt = {
        let encoded = matches.get("pczt").unwrap();
        base64::decode(encoded).unwrap()
    };

    let seed = {
        let encoded = matches.get("seed").unwrap();
        let data = hex::decode(encoded).unwrap();
        let mut seed = [0; 32];
        seed.copy_from_slice(&data);
        seed
    };

    let pczt = sign_pczt(&pczt, seed, consensus::BranchId::Blossom).unwrap();

    println!("Updated PCZT: {}", base64::encode(&pczt));
}
