//! Local encrypted store: SQLite + SQLCipher, a `notes` table and a `peers` table.
//!
//! The `notes` schema is exactly the table Slice 01 specifies — `(id, author_pubkey,
//! body, created_at, signature)` — plus one bookkeeping column, `synced_at`, needed to
//! avoid re-pushing a note that's already on the relay. Incoming notes are deduplicated
//! by their content-addressed `id` instead.
//!
//! The `peers` table (Slice 02) holds trust-on-first-use pins: a label and the two
//! pinned public keys (hex, matching `notes.author_pubkey`'s encoding) plus a first-seen
//! timestamp. It is schema-shaped to hold a set, but Slice 02 enforces at most one row
//! at a time (see `add_peer`) — see `docs/slices/SLICE-02.md` D2 for why.

use std::path::Path;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::StoreError;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredNote {
    pub id: String,            // hex SHA-256 content address
    pub author_pubkey: String, // hex Ed25519 public key
    pub body: String,
    pub created_at: i64,   // unix seconds
    pub signature: String, // hex Ed25519 signature
    pub synced_at: Option<i64>,
}

/// A trust-on-first-use pin: a local label bound to the two public keys from a peer's
/// card, plus when it was first pinned. Both keys are hex, matching `StoredNote`'s
/// `author_pubkey` encoding, so comparing a note's author against a pin is a plain
/// string (or decoded-byte) comparison with no encoding mismatch to get wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedPeer {
    pub label: String,
    pub ed25519_pubkey: String, // hex
    pub x25519_pubkey: String,  // hex
    pub first_seen: i64,        // unix seconds
}

impl Store {
    /// Open (creating if absent) the SQLCipher-encrypted database at `path`, keyed by
    /// `db_key`. A wrong key fails cleanly on first read, never panics.
    pub fn open(path: &Path, db_key: &[u8; 32]) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        // Both the hex encoding of the raw key and the PRAGMA string built from it are
        // transient copies of secret key material on the heap; zeroize each on drop
        // rather than leaving them for the allocator to hand out unwiped.
        let hex_key = Zeroizing::new(hex::encode(db_key));
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", *hex_key));
        conn.execute_batch(&pragma)?;

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
            );
            CREATE TABLE IF NOT EXISTS peers (
                label TEXT PRIMARY KEY,
                ed25519_pubkey TEXT NOT NULL,
                x25519_pubkey TEXT NOT NULL,
                first_seen INTEGER NOT NULL
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
    ///
    /// The `author_pubkey = ?1` clause is a correctness guard, not an optimization:
    /// received (foreign-authored) notes are stored with `synced_at = NULL` too (see
    /// `insert_note`), so without this filter sync would re-push someone else's note
    /// back to the relay under our own routing key. Do not loosen or drop it.
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

    /// Pin `label` to the given keys. Trust-on-first-use: succeeds and persists the pin
    /// if `label` is new (and no other peer is configured - this slice enforces a single
    /// correspondent, see SLICE-02 D2); is a no-op success if `label` already exists with
    /// these exact keys; and is rejected with a typed error - never a silent overwrite -
    /// if `label` exists with *different* keys, or if a *different* label is already
    /// configured.
    pub fn add_peer(
        &self,
        label: &str,
        ed25519_pubkey: &str,
        x25519_pubkey: &str,
        first_seen: i64,
    ) -> Result<(), StoreError> {
        let existing = self.list_peers()?;

        if let Some(peer) = existing.iter().find(|p| p.label == label) {
            if peer.ed25519_pubkey == ed25519_pubkey && peer.x25519_pubkey == x25519_pubkey {
                return Ok(());
            }
            return Err(StoreError::PeerKeyMismatch {
                label: label.to_string(),
            });
        }

        if let Some(other) = existing.first() {
            return Err(StoreError::PeerAlreadyConfigured {
                existing_label: other.label.clone(),
            });
        }

        self.conn.execute(
            "INSERT INTO peers (label, ed25519_pubkey, x25519_pubkey, first_seen)
             VALUES (?1, ?2, ?3, ?4)",
            params![label, ed25519_pubkey, x25519_pubkey, first_seen],
        )?;
        Ok(())
    }

    /// All pinned peers. Typed as a `Vec` (rather than `Option<PinnedPeer>`) so the
    /// shape survives Phase 1's real multi-peer work without a second migration, even
    /// though this slice's `add_peer` enforces at most one row.
    pub fn list_peers(&self) -> Result<Vec<PinnedPeer>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT label, ed25519_pubkey, x25519_pubkey, first_seen FROM peers
             ORDER BY first_seen ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PinnedPeer {
                label: row.get(0)?,
                ed25519_pubkey: row.get(1)?,
                x25519_pubkey: row.get(2)?,
                first_seen: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
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

    #[test]
    fn add_peer_then_list_roundtrip() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        let peers = store.list_peers().unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].label, "bob");
        assert_eq!(peers[0].ed25519_pubkey, "ed-bob");
        assert_eq!(peers[0].x25519_pubkey, "x-bob");
    }

    #[test]
    fn add_peer_is_idempotent_on_identical_resubmission() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_500).unwrap();

        assert_eq!(store.list_peers().unwrap().len(), 1);
    }

    #[test]
    fn add_peer_rejects_a_changed_key_under_the_same_label() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        let result = store.add_peer("bob", "ed-bob-NEW", "x-bob", 1_700_000_500);

        assert!(matches!(
            result,
            Err(StoreError::PeerKeyMismatch { label }) if label == "bob"
        ));
        // The original pin must survive a rejected re-pin attempt untouched.
        let peers = store.list_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ed25519_pubkey, "ed-bob");
    }

    #[test]
    fn add_peer_rejects_a_second_distinct_label() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        let result = store.add_peer("carol", "ed-carol", "x-carol", 1_700_000_500);

        assert!(matches!(
            result,
            Err(StoreError::PeerAlreadyConfigured { existing_label }) if existing_label == "bob"
        ));
        assert_eq!(store.list_peers().unwrap().len(), 1);
    }

    #[test]
    fn list_peers_is_empty_before_any_peer_is_added() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        assert_eq!(store.list_peers().unwrap(), Vec::new());
    }
}
