#![deny(warnings)]
use super::{
    components::{Amount, Script},
    sighash::signature_hash,
    Transaction,
};

#[cfg(test)]
mod testdata;

#[test]
fn tx_read_write() {
    // TxID: 64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639
    // From testnet block 280003.
    let data = testdata::TX_READ_WRITE;
    let tx = Transaction::read(&data[..]).unwrap();

    let mut encoded = Vec::with_capacity(data.len());
    tx.write(&mut encoded).unwrap();
    assert_eq!(&data[..], &encoded[..]);
}

pub struct TestVector {
    tx: Vec<u8>,
    script_code: Vec<u8>,
    transparent_input: Option<u32>,
    hash_type: u32,
    amount: i64,
    consensus_branch_id: u32,
    sighash: [u8; 32],
}

#[test]
fn zip_0143() {
    // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zip_0143.py
    for tv in self::testdata::make_zip_0143_test_vectors() {
        let tx = Transaction::read(&tv.tx[..]).unwrap();
        let transparent_input = if let Some(n) = tv.transparent_input {
            Some((n as usize, Script(tv.script_code), Amount(tv.amount)))
        } else {
            None
        };

        assert_eq!(
            signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, transparent_input,),
            tv.sighash
        );
    }
}

#[test]
fn zip_0243() {
    // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zip_0243.py
    for tv in self::testdata::make_zip_0243_test_vectors() {
        let tx = Transaction::read(&tv.tx[..]).unwrap();
        let transparent_input = if let Some(n) = tv.transparent_input {
            Some((n as usize, Script(tv.script_code), Amount(tv.amount)))
        } else {
            None
        };

        assert_eq!(
            signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, transparent_input,),
            tv.sighash
        );
    }
}
