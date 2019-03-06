pub mod pczt;

use failure::Error;
use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use std::fmt;
use std::io;
use zcash_primitives::{
    jubjub::{edwards, Unknown},
    redjubjub::{PublicKey, Signature},
    transaction::{
        components::{Amount, OutputDescription, SpendDescription, GROTH_PROOF_SIZE},
        TransactionData,
    },
    JUBJUB,
};

impl fmt::Display for pczt::PartiallyCreatedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PCZT(")?;

        let global = self.get_global();
        writeln!(f, "  version: {},", global.version)?;
        writeln!(f, "  versionGroupId: {:#08x},", global.versionGroupId)?;
        writeln!(f, "  lockTime: {},", global.lockTime)?;
        writeln!(f, "  expiryHeight: {},", global.expiryHeight)?;
        writeln!(f, "  valueBalance: {},", global.valueBalance)?;
        writeln!(
            f,
            "  saplingAnchor: {},",
            hex::encode(&global.saplingAnchor)
        )?;

        if self.get_spends().is_empty() {
            writeln!(f, "  spends: [],")?;
        } else {
            writeln!(f, "  spends: [")?;
            for spend in self.get_spends() {
                writeln!(f, "    (")?;
                writeln!(f, "      value: {},", spend.value)?;
                writeln!(f, "      proofCreated: {},", !spend.zkproof.is_empty())?;
                writeln!(f, "      signed: {},", !spend.spendAuthSig.is_empty())?;
                writeln!(f, "    ),")?;
            }
            writeln!(f, "  ],")?;
        }

        if self.get_outputs().is_empty() {
            writeln!(f, "  outputs: [],")?;
        } else {
            writeln!(f, "  outputs: [")?;
            for output in self.get_outputs() {
                writeln!(f, "    (")?;
                writeln!(f, "      to: {},", output.value)?;
                writeln!(f, "      value: {},", output.value)?;
                writeln!(f, "      proofCreated: {},", !output.zkproof.is_empty())?;
                writeln!(f, "    ),")?;
            }
            writeln!(f, "  ],")?;
        }

        writeln!(f, ")")
    }
}

impl pczt::PcztSpend {
    pub fn to_data(&self, anchor: Fr) -> Result<SpendDescription, Error> {
        let cv = edwards::Point::<Bls12, Unknown>::read(&self.cv[..], &JUBJUB)?;

        let mut nullifier = [0; 32];
        nullifier.copy_from_slice(&self.nf);

        let rk = PublicKey::<Bls12>::read(&self.rk[..], &JUBJUB)?;

        let mut zkproof = [0; GROTH_PROOF_SIZE];
        zkproof.copy_from_slice(&self.zkproof);

        let spend_auth_sig = if self.spendAuthSig.is_empty() {
            None
        } else {
            Some(Signature::read(&self.spendAuthSig[..])?)
        };

        Ok(SpendDescription {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }
}

impl pczt::PcztOutput {
    pub fn to_data(&self) -> Result<OutputDescription, Error> {
        let cv = edwards::Point::<Bls12, Unknown>::read(&self.cv[..], &JUBJUB)?;

        let cmu = {
            let mut f = FrRepr::default();
            f.read_le(&self.cmu[..])?;
            Fr::from_repr(f).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        };

        let ephemeral_key = edwards::Point::<Bls12, Unknown>::read(&self.epk[..], &JUBJUB)?;

        let mut enc_ciphertext = [0; 580];
        enc_ciphertext.copy_from_slice(&self.encCiphertext);

        let mut out_ciphertext = [0; 80];
        out_ciphertext.copy_from_slice(&self.outCiphertext);

        let mut zkproof = [0; GROTH_PROOF_SIZE];
        zkproof.copy_from_slice(&self.zkproof);

        Ok(OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }
}

impl pczt::PartiallyCreatedTransaction {
    pub fn to_data(&self) -> Result<TransactionData, Error> {
        let value_balance = Amount::from_i64(self.get_global().valueBalance)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid valueBalance"))?;

        let anchor = {
            let mut f = FrRepr::default();
            f.read_le(&self.get_global().saplingAnchor[..])?;
            Fr::from_repr(f).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        };

        let shielded_spends = self
            .get_spends()
            .iter()
            .map(|spend| spend.to_data(anchor))
            .collect::<Result<_, _>>()?;

        let shielded_outputs = self
            .get_outputs()
            .iter()
            .map(|output| output.to_data())
            .collect::<Result<_, _>>()?;

        Ok(TransactionData {
            overwintered: true,
            version: self.get_global().version,
            version_group_id: self.get_global().versionGroupId,
            vin: vec![],
            vout: vec![],
            lock_time: self.get_global().lockTime,
            expiry_height: self.get_global().expiryHeight,
            value_balance,
            shielded_spends,
            shielded_outputs,
            joinsplits: vec![],
            joinsplit_pubkey: None,
            joinsplit_sig: None,
            binding_sig: None,
        })
    }
}
