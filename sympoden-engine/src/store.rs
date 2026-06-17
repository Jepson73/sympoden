//! Local encrypted store: SQLite + SQLCipher, one `notes` table.
//!
//! The schema is exactly the table Slice 01 specifies — `(id, author_pubkey, body,
//! created_at, signature)` — plus one bookkeeping column, `synced_at`, needed to avoid
//! re-pushing a note that's already on the relay. Incoming notes are deduplicated by
//! their content-addressed `id` instead.

use std::path::Path;

use rusqlite::{Connection, params};

use crate::error::StoreError;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNote {
    pub id: String,            // hex SHA-256 content address
    pub author_pubkey: String, // hex Ed25519 public key
    pub body: String,
    pub created_at: i64,   // unix seconds
    pub signature: String, // hex Ed25519 signature
    pub synced_at: Option<i64>,
}

impl Store {
    /// Open (creating if absent) the SQLCipher-encrypted database at `path`, keyed by
    /// `db_key`. A wrong key fails cleanly on first read, never panics.
    pub fn open(path: &Path, db_key: &[u8; 32]) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(db_key)))?;

        // PRAGMA key alone doesn't validate it — SQLCipher only checks the key against
        // the file's contents on first real read. Force that check now so a wrong key
        // surfaces immediately as a clean error, not on some later, confusing query.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StoreError::InvalidKey)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                author_pubkey TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                signature TEXT NOT NULL,
                synced_at INTEGER
            );",
        )?;

        Ok(Self { conn })
    }

    /// Insert a note. Own notes are inserted with `synced_at = NULL`; incoming notes
    /// are deduplicated by their content-addressed `id` via `INSERT OR IGNORE`.
    pub fn insert_note(&self, note: &StoredNote) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO notes (id, author_pubkey, body, created_at, signature, synced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                note.id,
                note.author_pubkey,
                note.body,
                note.created_at,
                note.signature,
                note.synced_at,
            ],
        )?;
        Ok(())
    }

    /// Mark a note as pushed to the relay.
    pub fn mark_synced(&self, id: &str, synced_at: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE notes SET synced_at = ?1 WHERE id = ?2",
            params![synced_at, id],
        )?;
        Ok(())
    }

    /// This identity's own notes that haven't been pushed to the relay yet.
    pub fn unsynced_own_notes(&self, my_pubkey_hex: &str) -> Result<Vec<StoredNote>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, author_pubkey, body, created_at, signature, synced_at
             FROM notes WHERE author_pubkey = ?1 AND synced_at IS NULL
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![my_pubkey_hex], Self::row_to_note)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// All locally stored notes, oldest first.
    pub fn list_notes(&self) -> Result<Vec<StoredNote>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, author_pubkey, body, created_at, signature, synced_at
             FROM notes ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], Self::row_to_note)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    fn row_to_note(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredNote> {
        Ok(StoredNote {
            id: row.get(0)?,
            author_pubkey: row.get(1)?,
            body: row.get(2)?,
            created_at: row.get(3)?,
            signature: row.get(4)?,
            synced_at: row.get(5)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_note(id: &str, author: &str, synced_at: Option<i64>) -> StoredNote {
        StoredNote {
            id: id.to_string(),
            author_pubkey: author.to_string(),
            body: "the quick brown fox".to_string(),
            created_at: 1_700_000_000,
            signature: "deadbeef".to_string(),
            synced_at,
        }
    }

    #[test]
    fn insert_and_list_roundtrip() {
        let dir = tempdir().unwrap();
        let key = [7u8; 32];
        let store = Store::open(&dir.path().join("notes.sqlite"), &key).unwrap();

        store
            .insert_note(&sample_note("id1", "alice", None))
            .unwrap();
        let notes = store.list_notes().unwrap();

        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, "id1");
        assert_eq!(notes[0].body, "the quick brown fox");
    }

    #[test]
    fn duplicate_insert_is_ignored_by_content_address() {
        let dir = tempdir().unwrap();
        let key = [7u8; 32];
        let store = Store::open(&dir.path().join("notes.sqlite"), &key).unwrap();

        store
            .insert_note(&sample_note("id1", "alice", None))
            .unwrap();
        store
            .insert_note(&sample_note("id1", "alice", None))
            .unwrap();

        assert_eq!(store.list_notes().unwrap().len(), 1);
    }

    #[test]
    fn mark_synced_excludes_note_from_unsynced_query() {
        let dir = tempdir().unwrap();
        let key = [7u8; 32];
        let store = Store::open(&dir.path().join("notes.sqlite"), &key).unwrap();

        store
            .insert_note(&sample_note("id1", "alice", None))
            .unwrap();
        assert_eq!(store.unsynced_own_notes("alice").unwrap().len(), 1);

        store.mark_synced("id1", 1_700_000_100).unwrap();
        assert_eq!(store.unsynced_own_notes("alice").unwrap().len(), 0);
        assert_eq!(
            store.list_notes().unwrap()[0].synced_at,
            Some(1_700_000_100)
        );
    }

    #[test]
    fn unsynced_own_notes_excludes_other_authors_and_already_synced() {
        let dir = tempdir().unwrap();
        let key = [7u8; 32];
        let store = Store::open(&dir.path().join("notes.sqlite"), &key).unwrap();

        store
            .insert_note(&sample_note("id1", "alice", None))
            .unwrap();
        store.insert_note(&sample_note("id2", "bob", None)).unwrap();
        store
            .insert_note(&sample_note("id3", "alice", Some(1)))
            .unwrap();

        let pending = store.unsynced_own_notes("alice").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "id1");
    }

    #[test]
    fn wrong_key_fails_cleanly_on_existing_database() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("notes.sqlite");

        {
            let store = Store::open(&path, &[1u8; 32]).unwrap();
            store
                .insert_note(&sample_note("id1", "alice", None))
                .unwrap();
        }

        let result = Store::open(&path, &[2u8; 32]);
        assert!(matches!(result, Err(StoreError::InvalidKey)));
    }

    #[test]
    fn database_file_does_not_contain_the_plaintext_note_body() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("notes.sqlite");
        let key = [9u8; 32];

        let store = Store::open(&path, &key).unwrap();
        let secret_body = "the eagle has landed at midnight";
        store
            .insert_note(&StoredNote {
                id: "id1".to_string(),
                author_pubkey: "alice".to_string(),
                body: secret_body.to_string(),
                created_at: 1_700_000_000,
                signature: "deadbeef".to_string(),
                synced_at: None,
            })
            .unwrap();
        drop(store);

        let raw = std::fs::read(&path).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains(secret_body));
    }
}
