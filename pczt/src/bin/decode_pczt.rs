//! Decode a PCZT.

use pczt::proto::pczt::PartiallyCreatedTransaction;
use protobuf::parse_from_bytes;
use std::env;

fn main() {
    let options = vec![":/pczt#The PCZT to decode"];

    let mut vars = match pirate::vars("decode_pczt", &options) {
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

    let pczt: PartiallyCreatedTransaction = {
        let encoded = matches.get("pczt").unwrap();
        let data = base64::decode(encoded).unwrap();
        parse_from_bytes(&data).unwrap()
    };

    println!("{:?}", pczt);
}
