//! Creates a PCZT.

use pczt::proto::pczt::PartiallyCreatedTransaction;
use protobuf::Message;

fn default_pczt() -> PartiallyCreatedTransaction {
    let mut pczt = PartiallyCreatedTransaction::new();
    {
        let global = pczt.mut_global();
        global.version = 4;
        global.versionGroupId = 0x892F2085;
    }
    pczt
}

fn main() {
    let pczt = default_pczt();

    println!("PCZT: {}", base64::encode(&pczt.write_to_bytes().unwrap()));
}
