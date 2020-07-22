use zcash_client_backend::api::PersistenceBackend;

pub struct SqliteBackend {
    conn: Connection,
}

impl SqliteBackend {
    pub fn new<P: AsRef<Path>>(db_data: P) -> Result<Self, Error> {
        let conn = Connection::open(db_data)?;

        Ok(SqliteBackend { conn })
    }
}

impl PersistenceBackend for SqliteBackend {
    fn get_address(&self, account: u32) -> Result<String, Error> {
        let addr = self.conn.query_row(
            "SELECT address FROM accounts
            WHERE account = ?",
            &[account],
            |row| row.get(0),
        )?;

        Ok(addr)
    }

    fn get_note(&self, note: NoteRef) -> Result<Note<Bls12>, Error> {}
}
