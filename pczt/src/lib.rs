use failure::{format_err, Error};
use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::Bls12;
use protobuf::{parse_from_bytes, Message};
use rand_core::OsRng;
use zcash_primitives::{
    jubjub::{
        edwards,
        fs::{Fs, FsRepr},
    },
    keys::OutgoingViewingKey,
    note_encryption::Memo,
    primitives::PaymentAddress,
    prover::TxProver,
    transaction::{builder::SaplingOutput, components::Amount},
    JUBJUB,
};
use zcash_proofs::sapling::SaplingProvingContext;

pub mod proto;

use crate::proto::pczt::{PartiallyCreatedTransaction, PcztOutput};

pub fn add_sapling_output<P: TxProver<SaplingProvingContext = SaplingProvingContext>>(
    pczt: &[u8],
    ovk: OutgoingViewingKey,
    to: PaymentAddress<Bls12>,
    value: Amount,
    memo: Option<Memo>,
    prover: &P,
) -> Result<Vec<u8>, Error> {
    let mut pczt: PartiallyCreatedTransaction = parse_from_bytes(&pczt).unwrap();

    let mut ctx = if pczt.get_global().bsk.is_empty() && pczt.get_global().bvk.is_empty() {
        SaplingProvingContext::new()
    } else {
        let bsk = {
            let mut r = FsRepr::default();
            r.read_le(&pczt.get_global().bsk[..])?;
            match Fs::from_repr(r) {
                Ok(p) => p,
                Err(_) => return Err(format_err!("Invalid bsk")),
            }
        };

        let bvk = edwards::Point::<Bls12, _>::read(&pczt.get_global().bvk[..], &JUBJUB)?;

        SaplingProvingContext::from_parts(bsk, bvk)
    };

    let mut rng = OsRng;
    let (odesc, rcv) = SaplingOutput::new(&mut rng, ovk, to, value, memo)
        .map_err(|e| format_err!("Failed to build Sapling output: {:?}", e))?
        .build(prover, &mut ctx, &mut rng);
    let (bsk, cv_sum) = ctx.into_parts();

    let mut output = PcztOutput::new();
    odesc.cv.write(&mut output.cv)?;
    odesc.cmu.into_repr().write_le(&mut output.cmu)?;
    odesc.ephemeral_key.write(&mut output.epk)?;
    output
        .encCiphertext
        .extend_from_slice(&odesc.enc_ciphertext);
    output
        .outCiphertext
        .extend_from_slice(&odesc.out_ciphertext);
    output.zkproof.extend_from_slice(&odesc.zkproof);
    output.value = value.into();
    rcv.into_repr().write_le(&mut output.rcv)?;
    pczt.outputs.push(output);

    pczt.mut_global().valueBalance -= i64::from(value);
    pczt.mut_global().clear_bsk();
    pczt.mut_global().clear_bvk();
    bsk.into_repr().write_le(&mut pczt.mut_global().bsk)?;
    cv_sum.write(&mut pczt.mut_global().bvk)?;

    Ok(pczt.write_to_bytes().unwrap())
}
