use std::io;

#[derive(Debug)]
pub enum Error {
    InvalidAmount,
    InvalidRecipient,
    InvalidKeysFile,
    InvalidMnemonicPhrase(String),
    MissingParameters,
    SendFailed { code: i32, reason: String },
    Database(rusqlite::Error),
    Grpc(grpc::Error),
    Io(io::Error),
    Proto(protobuf::error::ProtobufError),
    Tls(tls_api::Error),
    Wallet(zcash_client_sqlite::error::Error),
}

impl From<grpc::Error> for Error {
    fn from(e: grpc::Error) -> Self {
        Error::Grpc(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<protobuf::error::ProtobufError> for Error {
    fn from(e: protobuf::error::ProtobufError) -> Self {
        Error::Proto(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Database(e)
    }
}

impl From<tls_api::Error> for Error {
    fn from(e: tls_api::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<zcash_client_sqlite::error::Error> for Error {
    fn from(e: zcash_client_sqlite::error::Error) -> Self {
        Error::Wallet(e)
    }
}
