//! An example light client wallet based on the `zcash_client_sqlite` crate.
//!
//! This is **NOT IMPLEMENTED SECURELY**, and it is not written to be efficient or usable!
//! It is only intended to show the overall light client workflow using this crate.

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use futures::executor;
use grpc::ClientStub;
use gumdrop::Options;
use httpbis::ClientTlsOption;
use protobuf::Message;
use rusqlite::{Connection, ToSql, NO_PARAMS};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tls_api::{TlsConnector, TlsConnectorBuilder};
use zcash_client_backend::{address::RecipientAddress, keys::spending_key, proto::compact_formats};
use zcash_client_sqlite::{
    init::{init_accounts_table, init_blocks_table, init_cache_database, init_data_database},
    query::{get_address, get_balance, get_verified_balance},
    scan::scan_cached_blocks,
    transact::{create_to_address, OvkPolicy},
};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, BranchId, Parameters, TEST_NETWORK},
    transaction::{components::Amount, TxId},
};
use zcash_proofs::prover::LocalTxProver;

mod error;
mod service;
mod service_grpc;

const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const KEYS_FILE: &str = "keys.txt";
const CACHE_DB: &str = "cache.sqlite";
const DATA_DB: &str = "data.sqlite";

const ACCOUNT: u32 = 0;

const LIGHTWALLETD_HOST: &str = "lightwalletd.testnet.electriccoin.co";
const LIGHTWALLETD_PORT: u16 = 9067;
const BATCH_SIZE: u32 = 10_000;

const CHECKPOINT_HEIGHT: i32 = 950_000;
const CHECKPOINT_HASH: BlockHash = BlockHash([
    0x5d, 0xf7, 0xc0, 0x2b, 0x2a, 0x07, 0x29, 0x4f, 0x29, 0x51, 0xe2, 0xfe, 0xdc, 0x3b, 0x83, 0xd5,
    0x66, 0x31, 0x3d, 0xab, 0xf4, 0x7e, 0x5c, 0x92, 0x9b, 0x1b, 0xe3, 0x2c, 0x0d, 0x05, 0x05, 0x00,
]);
const CHECKPOINT_TIME: u32 = 1_591_609_525;
const CHECKPOINT_TREE: &[u8] = &[
    0x01, 0xf0, 0x63, 0x72, 0x35, 0xc4, 0xa6, 0x99, 0xd4, 0x9b, 0xa9, 0x96, 0x45, 0x7a, 0x6c, 0x4e,
    0xb7, 0xc6, 0x7e, 0xdd, 0x82, 0x70, 0x94, 0x80, 0x65, 0x68, 0x3d, 0xeb, 0x19, 0xef, 0x21, 0x83,
    0x63, 0x01, 0x9f, 0x65, 0xa9, 0x69, 0x2c, 0xef, 0xc7, 0xb9, 0x0b, 0x42, 0xc1, 0x53, 0x8a, 0xc1,
    0xf3, 0x8f, 0x7a, 0x75, 0x98, 0x54, 0x90, 0x89, 0xc4, 0x56, 0x13, 0x15, 0xb4, 0x82, 0xf3, 0x78,
    0x52, 0x30, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x8d, 0x30, 0xd0, 0x03, 0x92, 0x77,
    0xb0, 0x5a, 0xb9, 0xe0, 0xc3, 0x99, 0x0d, 0x53, 0x03, 0x7c, 0x45, 0x89, 0x2b, 0xf1, 0x7a, 0xf2,
    0xd0, 0x4f, 0xef, 0x40, 0xed, 0x48, 0xc1, 0x64, 0xad, 0x22, 0x01, 0xff, 0x5d, 0x86, 0xbb, 0xbe,
    0x36, 0x0e, 0x31, 0x37, 0x8e, 0x78, 0x3b, 0x74, 0x0f, 0x8b, 0x05, 0xdb, 0x2c, 0xf4, 0x24, 0x6b,
    0x95, 0xaa, 0x38, 0x51, 0xd2, 0x2e, 0xd4, 0x55, 0x54, 0x75, 0x03, 0x00, 0x01, 0x0c, 0xef, 0xb2,
    0x57, 0x43, 0xd5, 0xdd, 0x60, 0x62, 0xef, 0x3a, 0xfb, 0xa4, 0x38, 0x73, 0x1c, 0xd5, 0xb3, 0x5b,
    0xef, 0xc1, 0x03, 0x8e, 0xcc, 0xa3, 0x07, 0x6f, 0xd2, 0x05, 0x82, 0x9e, 0x55, 0x00, 0x01, 0xc1,
    0x90, 0x52, 0x38, 0x6d, 0x8b, 0xbe, 0x3c, 0x07, 0xa1, 0xfa, 0xf3, 0x02, 0x28, 0x1d, 0x67, 0x94,
    0x6c, 0xc9, 0x54, 0x7e, 0x7e, 0x18, 0x90, 0xff, 0x56, 0xb3, 0xa3, 0xec, 0x69, 0xc0, 0x31, 0x00,
    0x01, 0xbe, 0x53, 0xa6, 0xcd, 0x33, 0xda, 0x04, 0x42, 0xc7, 0xc6, 0x36, 0x2c, 0x01, 0x72, 0x24,
    0x1f, 0x42, 0xe1, 0x3c, 0x6d, 0xc8, 0x93, 0x43, 0x6a, 0x66, 0x1a, 0x1c, 0xbf, 0x49, 0x77, 0x5c,
    0x1f, 0x00, 0x01, 0x1f, 0x83, 0x22, 0xef, 0x80, 0x6e, 0xb2, 0x43, 0x0d, 0xc4, 0xa7, 0xa4, 0x1c,
    0x1b, 0x34, 0x4b, 0xea, 0x5b, 0xe9, 0x46, 0xef, 0xc7, 0xb4, 0x34, 0x9c, 0x1c, 0x9e, 0xdb, 0x14,
    0xff, 0x9d, 0x39,
];

//
// Helpers
//

fn get_keys_file<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<BufReader<File>, error::Error> {
    let mut p = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    p.push(KEYS_FILE);
    Ok(BufReader::new(File::open(p)?))
}

fn get_wallet_seed<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<Seed, error::Error> {
    let keys_file = get_keys_file(wallet_dir)?;
    Mnemonic::from_phrase(
        keys_file
            .lines()
            .next()
            .ok_or(error::Error::InvalidKeysFile)??
            .split('#')
            .next()
            .ok_or(error::Error::InvalidKeysFile)?
            .trim(),
        Language::English,
    )
    .map_err(|e| error::Error::InvalidMnemonicPhrase(format!("{}", e)))
    .map(|mnemonic| Seed::new(&mnemonic, ""))
}

// fn get_wallet_birthday<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<BlockHeight, error::Error> {
//     let keys_file = get_keys_file(wallet_dir)?;
//     keys_file
//         .lines()
//         .nth(1)
//         .ok_or(error::Error::InvalidKeysFile)??
//         .split('#')
//         .next()
//         .ok_or(error::Error::InvalidKeysFile)?
//         .trim()
//         .parse::<u32>()
//         .map(BlockHeight::from)
//         .map_err(|_| error::Error::InvalidKeysFile)
// }

fn get_db_paths<P: AsRef<Path>>(wallet_dir: Option<P>) -> (PathBuf, PathBuf) {
    let mut a = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    let mut b = a.clone();
    a.push(CACHE_DB);
    b.push(DATA_DB);
    (a, b)
}

fn connect_to_lightwalletd() -> Result<service_grpc::CompactTxStreamerClient, error::Error> {
    let tls = {
        let mut tls_connector = tls_api_rustls::TlsConnector::builder()?;
        if tls_api_rustls::TlsConnector::supports_alpn() {
            tls_connector.set_alpn_protocols(&[b"h2"])?;
        }
        let tls_connector = Arc::new(tls_connector.build()?);
        ClientTlsOption::Tls(LIGHTWALLETD_HOST.to_owned(), tls_connector)
    };

    let grpc_client = Arc::new(
        grpc::ClientBuilder::new(LIGHTWALLETD_HOST, LIGHTWALLETD_PORT)
            .explicit_tls(tls)
            .build()?,
    );

    Ok(service_grpc::CompactTxStreamerClient::with_client(
        grpc_client,
    ))
}

//
// App
//

#[derive(Debug, Options)]
struct MyOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "path to the wallet directory")]
    wallet_dir: Option<String>,

    #[options(command)]
    command: Option<Command>,
}

#[derive(Debug, Options)]
enum Command {
    #[options(help = "initialise a new light wallet")]
    Init(InitOpts),

    #[options(help = "scan the chain and sync the wallet")]
    Sync(SyncOpts),

    #[options(help = "get the balance in the wallet")]
    Balance(BalanceOpts),

    #[options(help = "send funds to the given address")]
    Send(SendOpts),
}

// Options accepted for the `init` command
#[derive(Debug, Options)]
struct InitOpts {
    #[options(help = "mnemonic phrase to initialise the wallet with (default is new phrase)")]
    phrase: Option<String>,
}

// Options accepted for the `sync` command
#[derive(Debug, Options)]
struct SyncOpts {}

// Options accepted for the `balance` command
#[derive(Debug, Options)]
struct BalanceOpts {}

// Options accepted for the `send` command
#[derive(Debug, Options)]
struct SendOpts {
    #[options(help = "the recipient's Sapling or transparent address")]
    address: String,

    #[options(help = "the amount in zatoshis")]
    value: u64,
}

fn main() -> Result<(), error::Error> {
    let opts = MyOptions::parse_args_default_or_exit();

    match opts.command {
        Some(Command::Init(init_opts)) => init(opts.wallet_dir, init_opts),
        Some(Command::Sync { .. }) => sync(opts.wallet_dir),
        Some(Command::Balance { .. }) => balance(opts.wallet_dir),
        Some(Command::Send(send_opts)) => send(opts.wallet_dir, send_opts),
        _ => Ok(()),
    }
}

fn init(wallet_dir: Option<String>, opts: InitOpts) -> Result<(), error::Error> {
    let params = TEST_NETWORK;

    // Get the current chain height (for the wallet's birthday).
    let client = connect_to_lightwalletd()?;
    let birthday = executor::block_on(
        client
            .get_latest_block(grpc::RequestOptions::new(), service::ChainSpec::default())
            .drop_metadata(),
    )?
    .height;

    // Create the wallet directory.
    let wallet_dir = PathBuf::from(wallet_dir.unwrap_or(DEFAULT_WALLET_DIR.to_owned()));
    create_dir_all(&wallet_dir)?;

    // Parse or create the wallet's mnemonic phrase.
    let mnemonic = if let Some(phrase) = opts.phrase {
        Mnemonic::from_phrase(&phrase, Language::English)
            .map_err(|e| error::Error::InvalidMnemonicPhrase(format!("{}", e)))?
    } else {
        Mnemonic::new(MnemonicType::Words24, Language::English)
    };

    // Write the mnemonic phrase to disk along with its birthday.
    let mut keys_file = {
        let mut p = wallet_dir.clone();
        p.push(KEYS_FILE);
        OpenOptions::new().create_new(true).write(true).open(p)
    }?;
    writeln!(
        &mut keys_file,
        "{} # wallet mnemonic phrase",
        mnemonic.phrase()
    )?;
    writeln!(&mut keys_file, "{} # wallet birthday", birthday)?;

    // Initialise the cache and data DBs.
    let (db_cache, db_data) = get_db_paths(Some(wallet_dir));
    init_cache_database(&db_cache)?;
    init_data_database(&db_data)?;

    // Load the checkpoint into the data DB.
    init_blocks_table(
        &db_data,
        CHECKPOINT_HEIGHT,
        CHECKPOINT_HASH,
        CHECKPOINT_TIME,
        CHECKPOINT_TREE,
    )?;

    // Add one account.
    let seed = Seed::new(&mnemonic, "");
    let extsk = spending_key(seed.as_bytes(), params.coin_type(), ACCOUNT);
    init_accounts_table(&db_data, &params, &[(&extsk).into()])?;

    Ok(())
}

fn sync(wallet_dir: Option<String>) -> Result<(), error::Error> {
    let params = TEST_NETWORK;
    let (db_cache, db_data) = get_db_paths(wallet_dir.as_ref());

    println!("Connecting to {}:{}", LIGHTWALLETD_HOST, LIGHTWALLETD_PORT);
    let client = connect_to_lightwalletd()?;

    // Download all the CompactBlocks we need.
    let latest_height = {
        let cache = Connection::open(&db_cache)?;
        let mut stmt_cache_block =
            cache.prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")?;

        // Recall where we synced up to previously.
        // If we have never synced, use wallet birthday to fetch all relevant CompactBlocks.
        let mut start_height: BlockHeight = cache
            .query_row("SELECT MAX(height) FROM compactblocks", NO_PARAMS, |row| {
                Ok(row
                    .get::<_, u32>(0)
                    .map(BlockHeight::from)
                    .map(|h| h + 1)
                    .ok())
            })?
            .unwrap_or(BlockHeight::from(CHECKPOINT_HEIGHT as u32));

        let mut buf = vec![];
        loop {
            // Get the latest height.
            let latest_height: BlockHeight = executor::block_on(
                client
                    .get_latest_block(grpc::RequestOptions::new(), service::ChainSpec::default())
                    .drop_metadata(),
            )?
            .height
            .into();

            // Calculate the next batch size.
            let end_height = if u32::from(latest_height - start_height) < BATCH_SIZE {
                latest_height
            } else {
                start_height + BATCH_SIZE - 1
            };

            // Request the next batch of blocks.
            println!("Fetching blocks {}..{}", start_height, end_height);
            let mut start = service::BlockID::new();
            start.set_height(start_height.into());
            let mut end = service::BlockID::new();
            end.set_height(end_height.into());
            let mut range = service::BlockRange::new();
            range.set_start(start);
            range.set_end(end);
            let blocks = executor::block_on_stream(
                client
                    .get_block_range(grpc::RequestOptions::new(), range)
                    .drop_metadata(),
            );

            for block in blocks {
                let block = block?;
                block.write_to_vec(&mut buf)?;
                stmt_cache_block
                    .execute(&[(block.height as i64).to_sql()?, buf.as_slice().to_sql()?])?;
                buf.clear();
            }

            if end_height == latest_height {
                break latest_height;
            } else {
                start_height = end_height + 1
            }
        }
    };

    // Scan the cached CompactBlocks.
    loop {
        let last_height = {
            let data = Connection::open(&db_data)?;
            data.query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
                row.get::<_, u32>(0)
                    .map(BlockHeight::from)
                    .map(Some)
                    .or(Ok(None))
            })?
        };
        match last_height {
            Some(h) if h >= latest_height => break,
            Some(h) if h + BATCH_SIZE > latest_height => {
                println!("Scanning blocks {}..{}", h, latest_height)
            }
            Some(h) => println!("Scanning blocks {}..{}", h, h + BATCH_SIZE),
            None => (),
        }
        scan_cached_blocks(&params, &db_cache, &db_data, Some(BATCH_SIZE))?;
    }

    Ok(())
}

fn balance(wallet_dir: Option<String>) -> Result<(), error::Error> {
    let (_, db_data) = get_db_paths(wallet_dir);

    let address = get_address(&db_data, ACCOUNT)?;
    let balance = get_balance(&db_data, ACCOUNT)?;
    let verified_balance = get_verified_balance(&db_data, ACCOUNT)?;

    println!("{}", address);
    println!("  Balance:  {} zatoshis", u64::from(balance));
    println!("  Verified: {} zatoshis", u64::from(verified_balance));

    Ok(())
}

fn send(wallet_dir: Option<String>, send_opts: SendOpts) -> Result<(), error::Error> {
    let params = TEST_NETWORK;
    let (_, db_data) = get_db_paths(wallet_dir.as_ref());

    let seed = get_wallet_seed(wallet_dir)?;
    let extsk = spending_key(seed.as_bytes(), params.coin_type(), ACCOUNT);

    println!("Connecting to {}:{}", LIGHTWALLETD_HOST, LIGHTWALLETD_PORT);
    let client = connect_to_lightwalletd()?;

    // Get the latest height.
    let latest_height: BlockHeight = executor::block_on(
        client
            .get_latest_block(grpc::RequestOptions::new(), service::ChainSpec::default())
            .drop_metadata(),
    )?
    .height
    .into();

    // Create the transaction.
    println!("Creating transaction...");
    let prover = LocalTxProver::with_default_location().ok_or(error::Error::MissingParameters)?;
    let id_tx = create_to_address(
        &db_data,
        &params,
        BranchId::for_height(&params, latest_height),
        prover,
        (ACCOUNT, &extsk),
        &RecipientAddress::decode(&params, &send_opts.address)
            .ok_or(error::Error::InvalidRecipient)?,
        Amount::from_u64(send_opts.value).map_err(|_| error::Error::InvalidAmount)?,
        None,
        OvkPolicy::Sender,
    )?;

    // Send the transaction.
    println!("Sending transaction...");
    let data = Connection::open(&db_data)?;
    let (txid, raw_tx) = data.query_row(
        "SELECT txid, raw FROM transactions WHERE id_tx = ?",
        &[id_tx],
        |row| {
            let mut txid = TxId([0; 32]);
            txid.0.copy_from_slice(&row.get::<_, Vec<u8>>(0)?);
            let mut raw_tx = service::RawTransaction::new();
            raw_tx.set_data(row.get::<_, Vec<u8>>(1)?);
            Ok((txid, raw_tx))
        },
    )?;
    let response = executor::block_on(
        client
            .send_transaction(grpc::RequestOptions::new(), raw_tx)
            .drop_metadata(),
    )?;

    if response.get_errorCode() != 0 {
        Err(error::Error::SendFailed {
            code: response.get_errorCode(),
            reason: response.get_errorMessage().to_owned(),
        })
    } else {
        println!("{}", txid);
        Ok(())
    }
}
