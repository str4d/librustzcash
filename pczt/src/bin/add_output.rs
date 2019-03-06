//! Add a Sapling output to a PCZT.

use pczt::add_sapling_output;
use rand_core::{OsRng, RngCore};
use std::env;
use zcash_client_backend::{
    constants::testnet::{HRP_SAPLING_EXTENDED_SPENDING_KEY, HRP_SAPLING_PAYMENT_ADDRESS},
    encoding::{decode_extended_spending_key, decode_payment_address},
};
use zcash_primitives::{keys::OutgoingViewingKey, transaction::components::Amount};
use zcash_proofs::prover::LocalTxProver;

fn main() {
    let options = vec![
        "f/from#The Sapling ExtendedFullViewingKey to make this output decryptable by; default=undecryptable:",
        ":/pczt#The PCZT to modify",
        ":/to#A Sapling address",
        ":/value#The amount, in zatoshis, of the output",
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

    let ovk = {
        if let Some(encoded) = matches.get("from") {
            let extsk = decode_extended_spending_key(HRP_SAPLING_EXTENDED_SPENDING_KEY, encoded)
                .unwrap()
                .unwrap();
            extsk.expsk.ovk
        } else {
            let mut rng = OsRng;
            let mut ovk = [0; 32];
            rng.fill_bytes(&mut ovk);
            OutgoingViewingKey(ovk)
        }
    };

    let to = {
        let encoded = matches.get("to").unwrap();
        decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, encoded)
            .unwrap()
            .unwrap()
    };

    let value = {
        let value = matches.get("value").unwrap();
        Amount::from_u64(value.parse::<u64>().unwrap()).unwrap()
    };

    let prover = LocalTxProver::with_default_location().unwrap();

    let pczt = add_sapling_output(&pczt, ovk, to, value, None, &prover).unwrap();

    println!("Updated PCZT: {}", base64::encode(&pczt));
}
