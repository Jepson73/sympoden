//! Local encrypted store: SQLite + SQLCipher, a `notes` table, a `peers` table, and a
//! `note_sends` table.
//!
//! The `notes` schema is exactly the table Slice 01 specifies — `(id, author_pubkey,
//! body, created_at, signature)` — plus one bookkeeping column, `synced_at`, which
//! Slice 03 no longer reads or writes (see SLICE-03.md's "honest leftover": it stays
//! only because `content.rs::to_stored()` sets it and is held at zero diff this slice).
//! Incoming notes are deduplicated by their content-addressed `id`.
//!
//! The `peers` table (Slice 02) holds trust-on-first-use pins. As of Slice 03 it is
//! re-keyed on the public key, not the label (see SLICE-03.md D1): `ed25519_pubkey TEXT
//! PRIMARY KEY, x25519_pubkey TEXT NOT NULL, label TEXT NOT NULL, first_seen INTEGER NOT
//! NULL`. A label is a non-unique, user-chosen annotation on a key, never the other way
//! around.
//!
//! The `note_sends` table (Slice 03, new) tracks delivery per `(note, recipient key)` —
//! see SLICE-03.md D7. It is the sole source of truth for what's been pushed to whom;
//! `notes.synced_at` is not consulted.
//!
//! The `blocked_keys` table (Slice 04, new) holds receive-side blocks, keyed on
//! `ed25519_pubkey` alone — deliberately with no foreign key to `peers` (SLICE-04.md
//! D-A): a key can be blocked whether or not it is, or ever was, pinned.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::StoreError;
use crate::identity::fingerprint_hex;

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

/// A trust-on-first-use pin: a key (the peer's actual identity, Slice 03 D1) plus a
/// local, non-unique label and when it was first pinned. Keys are hex, matching
/// `StoredNote`'s `author_pubkey` encoding, so comparing a note's author against a pin
/// is a plain string (or decoded-byte) comparison with no encoding mismatch to get
/// wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedPeer {
    pub label: String,
    pub ed25519_pubkey: String, // hex - the peer's identity (primary key in `peers`)
    pub x25519_pubkey: String,  // hex
    pub first_seen: i64,        // unix seconds
}

/// What pinning a key actually did. See SLICE-03.md D2/Adjustment 1: there is no
/// X25519 comparison anywhere in `add_peer` - only whether this Ed25519 key, and
/// (if so) this exact label, were already on file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AddPeerOutcome {
    /// A new key, pinned under `label`.
    Added,
    /// This exact `(ed25519_pubkey, label)` was already pinned - a silent no-op.
    AlreadyPinned,
    /// This `ed25519_pubkey` was already pinned, but under a *different* label. The
    /// data is unchanged (the stored label does not move) - this is a loud no-op, not
    /// a silent one: `relabel_peer` is the only function that changes a label.
    AlreadyPinnedUnderLabel { existing_label: String },
}

/// Who a posted note is addressed to. `Broadcast` resolves to every currently-pinned
/// key at the moment `record_pending_sends` runs, not live thereafter (SLICE-03.md D3/
/// Known Limitation h). `Directed` holds already-resolved `ed25519_pubkey` hex strings;
/// resolving a user-typed label/fingerprint query to a key is the caller's job
/// (`resolve_peer_query`), not this type's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendTargets {
    Broadcast,
    Directed(Vec<String>),
}

/// One pending `(note, recipient)` delivery: a note still owed to a pinned peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSend {
    pub note: StoredNote,
    pub peer: PinnedPeer,
}

/// A receive-side block on a key (SLICE-04.md D-A). Independent of `peers`: a key may
/// be blocked whether or not it is pinned, and blocking never reads or writes `peers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedKey {
    pub ed25519_pubkey: String, // hex
    pub blocked_at: i64,        // unix seconds
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
                ed25519_pubkey TEXT PRIMARY KEY,
                x25519_pubkey TEXT NOT NULL,
                label TEXT NOT NULL,
                first_seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS note_sends (
                note_id TEXT NOT NULL,
                peer_key TEXT NOT NULL,
                pushed_at INTEGER,
                PRIMARY KEY (note_id, peer_key)
            );
            CREATE TABLE IF NOT EXISTS blocked_keys (
                ed25519_pubkey TEXT PRIMARY KEY,
                blocked_at INTEGER NOT NULL
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

    /// Pin `ed25519_pubkey` under `label`. Key-as-identity (SLICE-03.md D1/D2): there is
    /// no comparison against any *other* peer's key or label here - that's
    /// `check_label_collision`, run by the caller beforehand if it cares (D3). The only
    /// question this function answers is whether *this* key was already on file:
    /// new key -> `Added`; same key, same label -> `AlreadyPinned` (silent no-op); same
    /// key, different label -> `AlreadyPinnedUnderLabel` (loud no-op - the label does
    /// not change; `relabel_peer` is the only function that changes one).
    pub fn add_peer(
        &self,
        label: &str,
        ed25519_pubkey: &str,
        x25519_pubkey: &str,
        first_seen: i64,
    ) -> Result<AddPeerOutcome, StoreError> {
        if let Some(existing) = self.get_peer_by_key(ed25519_pubkey)? {
            return Ok(if existing.label == label {
                AddPeerOutcome::AlreadyPinned
            } else {
                AddPeerOutcome::AlreadyPinnedUnderLabel {
                    existing_label: existing.label,
                }
            });
        }

        self.conn.execute(
            "INSERT INTO peers (ed25519_pubkey, x25519_pubkey, label, first_seen)
             VALUES (?1, ?2, ?3, ?4)",
            params![ed25519_pubkey, x25519_pubkey, label, first_seen],
        )?;
        Ok(AddPeerOutcome::Added)
    }

    /// The pinned peer with this exact key, if any.
    pub fn get_peer_by_key(&self, ed25519_pubkey: &str) -> Result<Option<PinnedPeer>, StoreError> {
        self.conn
            .query_row(
                "SELECT label, ed25519_pubkey, x25519_pubkey, first_seen
                 FROM peers WHERE ed25519_pubkey = ?1",
                params![ed25519_pubkey],
                Self::row_to_peer,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Every *other* pinned peer (a different key) already using `label`. Empty means
    /// no collision. Used as a pre-check by callers (CLI/app) before deciding whether
    /// to warn-and-proceed or refuse on `add_peer`/`relabel_peer` (SLICE-03.md D3) - this
    /// function never refuses anything itself, it only reports.
    pub fn check_label_collision(
        &self,
        label: &str,
        ed25519_pubkey: &str,
    ) -> Result<Vec<PinnedPeer>, StoreError> {
        Ok(self
            .list_peers()?
            .into_iter()
            .filter(|p| p.label == label && p.ed25519_pubkey != ed25519_pubkey)
            .collect())
    }

    /// Change a pinned peer's label, addressed by key. Never touches
    /// `ed25519_pubkey` or `x25519_pubkey` - there is no function anywhere in this
    /// module that mutates an existing peer's key (SLICE-03.md D4). Errors with
    /// `UnknownPeerKey` if no peer has this key.
    pub fn relabel_peer(&self, ed25519_pubkey: &str, new_label: &str) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE peers SET label = ?1 WHERE ed25519_pubkey = ?2",
            params![new_label, ed25519_pubkey],
        )?;
        if rows == 0 {
            return Err(StoreError::UnknownPeerKey {
                query: ed25519_pubkey.to_string(),
            });
        }
        Ok(())
    }

    /// Unpin a peer (SLICE-04.md AC1/AC9). Idempotent — deleting an already-gone peer
    /// reaches the same end state whether or not a row existed, so this never errors
    /// (D-D). Trust reclassification needs no further action here: `classify_author`
    /// (`trust.rs`, unchanged) recomputes from the current `peers` table on every call,
    /// so the very next `list_notes`/`list` reclassifies every note from this key to
    /// `Unknown` for free.
    ///
    /// Also purges any not-yet-pushed `note_sends` row addressed to this key (the
    /// decided fork in SLICE-04.md's Components/D-A: deleting cancels the outstanding
    /// send intent, so re-pinning the same key later doesn't silently resurrect and push
    /// a long-stale queued note). An already-*pushed* row for this key is left
    /// untouched — it is the historical record of what was actually sent, never erased.
    pub fn delete_peer(&self, ed25519_pubkey: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM peers WHERE ed25519_pubkey = ?1",
            params![ed25519_pubkey],
        )?;
        self.conn.execute(
            "DELETE FROM note_sends WHERE peer_key = ?1 AND pushed_at IS NULL",
            params![ed25519_pubkey],
        )?;
        Ok(())
    }

    /// All pinned peers, sorted by label then first-pinned, so same-labeled peers sort
    /// adjacent for display.
    pub fn list_peers(&self) -> Result<Vec<PinnedPeer>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT label, ed25519_pubkey, x25519_pubkey, first_seen FROM peers
             ORDER BY label ASC, first_seen ASC",
        )?;
        let rows = stmt.query_map([], Self::row_to_peer)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    fn row_to_peer(row: &rusqlite::Row<'_>) -> rusqlite::Result<PinnedPeer> {
        Ok(PinnedPeer {
            label: row.get(0)?,
            ed25519_pubkey: row.get(1)?,
            x25519_pubkey: row.get(2)?,
            first_seen: row.get(3)?,
        })
    }

    /// Record which peer(s) a freshly-posted note is addressed to. Must be called, and
    /// must succeed, *before* `insert_note` (SLICE-03.md D7): a `Directed` target that
    /// doesn't resolve to a pinned key is rejected here, before the note exists, so a
    /// bad target never leaves an orphaned, unaddressed note behind.
    pub fn record_pending_sends(
        &self,
        note_id: &str,
        targets: &SendTargets,
    ) -> Result<(), StoreError> {
        let keys: Vec<String> = match targets {
            SendTargets::Broadcast => self
                .list_peers()?
                .into_iter()
                .map(|p| p.ed25519_pubkey)
                .collect(),
            SendTargets::Directed(keys) => {
                let pinned = self.list_peers()?;
                for key in keys {
                    if !pinned.iter().any(|p| &p.ed25519_pubkey == key) {
                        return Err(StoreError::UnknownPeerKey { query: key.clone() });
                    }
                }
                keys.clone()
            }
        };

        for key in &keys {
            self.conn.execute(
                "INSERT OR IGNORE INTO note_sends (note_id, peer_key, pushed_at)
                 VALUES (?1, ?2, NULL)",
                params![note_id, key],
            )?;
        }
        Ok(())
    }

    /// Every `(note, recipient)` pair still owed a push, oldest note first. Joins
    /// against `notes` and `peers` so the caller (the sync push loop) needs no further
    /// lookups per row.
    pub fn pending_sends(&self) -> Result<Vec<PendingSend>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT n.id, n.author_pubkey, n.body, n.created_at, n.signature, n.synced_at,
                    p.label, p.ed25519_pubkey, p.x25519_pubkey, p.first_seen
             FROM note_sends s
             JOIN notes n ON n.id = s.note_id
             JOIN peers p ON p.ed25519_pubkey = s.peer_key
             WHERE s.pushed_at IS NULL
             ORDER BY n.created_at ASC, p.ed25519_pubkey ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PendingSend {
                note: StoredNote {
                    id: row.get(0)?,
                    author_pubkey: row.get(1)?,
                    body: row.get(2)?,
                    created_at: row.get(3)?,
                    signature: row.get(4)?,
                    synced_at: row.get(5)?,
                },
                peer: PinnedPeer {
                    label: row.get(6)?,
                    ed25519_pubkey: row.get(7)?,
                    x25519_pubkey: row.get(8)?,
                    first_seen: row.get(9)?,
                },
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    /// Mark one `(note, recipient)` pair as handed to the relay. After this, that pair
    /// no longer appears in `pending_sends` - it is never re-pushed.
    pub fn mark_send_pushed(
        &self,
        note_id: &str,
        peer_key: &str,
        pushed_at: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE note_sends SET pushed_at = ?1 WHERE note_id = ?2 AND peer_key = ?3",
            params![pushed_at, note_id, peer_key],
        )?;
        Ok(())
    }

    /// Block a key, independent of whether it is pinned (SLICE-04.md D-A). Idempotent —
    /// blocking an already-blocked key reaches the same end state either way, so this
    /// never errors (D-D).
    pub fn block_key(&self, ed25519_pubkey: &str, blocked_at: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO blocked_keys (ed25519_pubkey, blocked_at)
             VALUES (?1, ?2)",
            params![ed25519_pubkey, blocked_at],
        )?;
        Ok(())
    }

    /// Lift a block. Idempotent — unblocking an already-unblocked key is a no-op, not
    /// an error (D-D). Has no retroactive effect: notes already dropped while the block
    /// was active were never kept, and notes stored before the block began stay (the
    /// no-unsend boundary, FOUNDATION §4).
    pub fn unblock_key(&self, ed25519_pubkey: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM blocked_keys WHERE ed25519_pubkey = ?1",
            params![ed25519_pubkey],
        )?;
        Ok(())
    }

    /// Whether this key is currently blocked. Called from the pull loop, between
    /// `receive_incoming` and `insert_note` (SLICE-04.md D-C) — a `true` here means the
    /// decrypted, signature-verified note is dropped before it ever reaches `notes`.
    pub fn is_blocked(&self, ed25519_pubkey: &str) -> Result<bool, StoreError> {
        self.conn
            .query_row(
                "SELECT 1 FROM blocked_keys WHERE ed25519_pubkey = ?1",
                params![ed25519_pubkey],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(StoreError::from)
    }

    /// Every currently blocked key, so blocking isn't write-only.
    pub fn list_blocked(&self) -> Result<Vec<BlockedKey>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT ed25519_pubkey, blocked_at FROM blocked_keys ORDER BY blocked_at ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok(BlockedKey {
                ed25519_pubkey: row.get(0)?,
                blocked_at: row.get(1)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }
}

/// Resolve a user-typed recipient/relabel-target query against the current peer list.
/// Pure (`&[PinnedPeer]` in, no I/O) - identical logic for the CLI's `--to`/
/// `relabel-peer` and the app's recipient picker (SLICE-03.md D6).
///
/// Tried in order: (1) `label#fingerprint` - exact match on both; (2) a bare label that
/// uniquely matches exactly one peer - tried *before* fingerprint, so a label that
/// happens to look like a fingerprint still resolves as a label first; (3) a bare
/// fingerprint, tried only if (2) found no label match at all. No match anywhere ->
/// `UnknownPeerKey`; more than one match at the same step -> `AmbiguousPeerQuery`.
pub fn resolve_peer_query<'a>(
    query: &str,
    peers: &'a [PinnedPeer],
) -> Result<&'a PinnedPeer, StoreError> {
    if let Some((label, fp)) = query.split_once('#') {
        let matches: Vec<&PinnedPeer> = peers
            .iter()
            .filter(|p| p.label == label && fingerprint_hex(&p.ed25519_pubkey) == fp)
            .collect();
        return match matches.len() {
            1 => Ok(matches[0]),
            0 => Err(StoreError::UnknownPeerKey {
                query: query.to_string(),
            }),
            _ => Err(StoreError::AmbiguousPeerQuery {
                query: query.to_string(),
                candidates: matches.into_iter().cloned().collect(),
            }),
        };
    }

    let label_matches: Vec<&PinnedPeer> = peers.iter().filter(|p| p.label == query).collect();
    match label_matches.len() {
        1 => return Ok(label_matches[0]),
        n if n > 1 => {
            return Err(StoreError::AmbiguousPeerQuery {
                query: query.to_string(),
                candidates: label_matches.into_iter().cloned().collect(),
            });
        }
        _ => {}
    }

    let fp_matches: Vec<&PinnedPeer> = peers
        .iter()
        .filter(|p| fingerprint_hex(&p.ed25519_pubkey) == query)
        .collect();
    match fp_matches.len() {
        1 => Ok(fp_matches[0]),
        0 => Err(StoreError::UnknownPeerKey {
            query: query.to_string(),
        }),
        _ => Err(StoreError::AmbiguousPeerQuery {
            query: query.to_string(),
            candidates: fp_matches.into_iter().cloned().collect(),
        }),
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

        let outcome = store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        assert_eq!(outcome, AddPeerOutcome::Added);

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
        let outcome = store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_500).unwrap();

        assert_eq!(outcome, AddPeerOutcome::AlreadyPinned);
        assert_eq!(store.list_peers().unwrap().len(), 1);
    }

    #[test]
    fn add_peer_with_an_already_pinned_key_under_a_different_label_is_a_loud_no_op() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        let outcome = store
            .add_peer("robert", "ed-bob", "x-bob-different", 1_700_000_500)
            .unwrap();

        assert_eq!(
            outcome,
            AddPeerOutcome::AlreadyPinnedUnderLabel {
                existing_label: "bob".to_string()
            }
        );
        // The label - and the rest of the row - must not have changed. In particular,
        // there is no X25519 comparison/update at all (Adjustment 1): the differing
        // x25519_pubkey passed above is silently ignored, not written.
        let peers = store.list_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].label, "bob");
        assert_eq!(peers[0].x25519_pubkey, "x-bob");
    }

    #[test]
    fn add_peer_under_a_second_distinct_label_succeeds_the_cap_is_gone() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        let outcome = store
            .add_peer("carol", "ed-carol", "x-carol", 1_700_000_500)
            .unwrap();
        assert_eq!(outcome, AddPeerOutcome::Added);

        let third = store
            .add_peer("dave", "ed-dave", "x-dave", 1_700_001_000)
            .unwrap();
        assert_eq!(third, AddPeerOutcome::Added);

        assert_eq!(store.list_peers().unwrap().len(), 3);
    }

    #[test]
    fn add_peer_under_a_label_another_peer_already_uses_succeeds_a_collision_not_a_cap() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("alice", "ed-alice-real", "x-alice-real", 1_700_000_000).unwrap();
        let outcome = store
            .add_peer("alice", "ed-alice-impostor", "x-alice-impostor", 1_700_000_500)
            .unwrap();

        assert_eq!(outcome, AddPeerOutcome::Added);
        assert_eq!(store.list_peers().unwrap().len(), 2);
    }

    #[test]
    fn list_peers_is_empty_before_any_peer_is_added() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        assert_eq!(store.list_peers().unwrap(), Vec::new());
    }

    #[test]
    fn check_label_collision_excludes_the_same_key_and_finds_others() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("alice", "ed-alice-real", "x-alice-real", 1_700_000_000).unwrap();

        // Re-checking the same key under the same label: not a collision with itself.
        assert_eq!(
            store.check_label_collision("alice", "ed-alice-real").unwrap(),
            Vec::new()
        );

        // A different key proposing the same label: a real collision.
        let collisions = store
            .check_label_collision("alice", "ed-alice-impostor")
            .unwrap();
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].ed25519_pubkey, "ed-alice-real");
    }

    #[test]
    fn relabel_peer_changes_the_label_not_the_key() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("alice-impostor", "ed-eve", "x-eve", 1_700_000_000).unwrap();
        store.relabel_peer("ed-eve", "eve").unwrap();

        let peer = store.get_peer_by_key("ed-eve").unwrap().unwrap();
        assert_eq!(peer.label, "eve");
        assert_eq!(peer.ed25519_pubkey, "ed-eve");
        assert_eq!(peer.x25519_pubkey, "x-eve");
    }

    #[test]
    fn relabel_peer_rejects_an_unknown_key() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        let result = store.relabel_peer("ed-nobody", "anyone");
        assert!(matches!(
            result,
            Err(StoreError::UnknownPeerKey { query }) if query == "ed-nobody"
        ));
    }

    #[test]
    fn resolve_peer_query_finds_a_unique_label() {
        let peers = vec![PinnedPeer {
            label: "bob".to_string(),
            ed25519_pubkey: "ed-bob".to_string(),
            x25519_pubkey: "x-bob".to_string(),
            first_seen: 1_700_000_000,
        }];
        let resolved = resolve_peer_query("bob", &peers).unwrap();
        assert_eq!(resolved.ed25519_pubkey, "ed-bob");
    }

    #[test]
    fn resolve_peer_query_is_ambiguous_on_a_shared_label() {
        let peers = vec![
            PinnedPeer {
                label: "alice".to_string(),
                ed25519_pubkey: "ed-alice-real".to_string(),
                x25519_pubkey: "x-alice-real".to_string(),
                first_seen: 1_700_000_000,
            },
            PinnedPeer {
                label: "alice".to_string(),
                ed25519_pubkey: "ed-alice-impostor".to_string(),
                x25519_pubkey: "x-alice-impostor".to_string(),
                first_seen: 1_700_000_500,
            },
        ];
        let result = resolve_peer_query("alice", &peers);
        assert!(matches!(
            result,
            Err(StoreError::AmbiguousPeerQuery { candidates, .. }) if candidates.len() == 2
        ));
    }

    #[test]
    fn resolve_peer_query_disambiguates_via_label_hash_fingerprint() {
        // fingerprint_hex falls back to a fixed value for non-hex input (so it never
        // panics on a malformed key) - which means two *non-hex* placeholder keys would
        // collapse to the same fingerprint and defeat this very test. Use real hex.
        let peers = vec![
            PinnedPeer {
                label: "alice".to_string(),
                ed25519_pubkey: "aa".repeat(32),
                x25519_pubkey: "x-alice-real".to_string(),
                first_seen: 1_700_000_000,
            },
            PinnedPeer {
                label: "alice".to_string(),
                ed25519_pubkey: "bb".repeat(32),
                x25519_pubkey: "x-alice-impostor".to_string(),
                first_seen: 1_700_000_500,
            },
        ];
        let fp = fingerprint_hex(&"bb".repeat(32));
        let query = format!("alice#{fp}");
        let resolved = resolve_peer_query(&query, &peers).unwrap();
        assert_eq!(resolved.ed25519_pubkey, "bb".repeat(32));
    }

    #[test]
    fn resolve_peer_query_returns_unknown_peer_key_when_nothing_matches() {
        let peers = vec![PinnedPeer {
            label: "bob".to_string(),
            ed25519_pubkey: "ed-bob".to_string(),
            x25519_pubkey: "x-bob".to_string(),
            first_seen: 1_700_000_000,
        }];
        let result = resolve_peer_query("nobody", &peers);
        assert!(matches!(
            result,
            Err(StoreError::UnknownPeerKey { query }) if query == "nobody"
        ));
    }

    /// Regression guard for SLICE-03.md D6's precedence rule: a peer's *label*
    /// happening to look exactly like a *different* peer's fingerprint must not cause
    /// the label query to resolve to the wrong peer via a coincidental fingerprint
    /// match. Label match is tried first and must win outright.
    #[test]
    fn resolve_peer_query_prefers_an_exact_label_match_over_a_coincidental_fingerprint_clash() {
        let other_fp = fingerprint_hex("ed-someone-else");
        let peers = vec![
            PinnedPeer {
                label: other_fp.clone(),
                ed25519_pubkey: "ed-labeled-like-a-fingerprint".to_string(),
                x25519_pubkey: "x-1".to_string(),
                first_seen: 1_700_000_000,
            },
            PinnedPeer {
                label: "someone-else".to_string(),
                ed25519_pubkey: "ed-someone-else".to_string(),
                x25519_pubkey: "x-2".to_string(),
                first_seen: 1_700_000_500,
            },
        ];

        let resolved = resolve_peer_query(&other_fp, &peers).unwrap();
        assert_eq!(resolved.ed25519_pubkey, "ed-labeled-like-a-fingerprint");
    }

    #[test]
    fn record_pending_sends_broadcast_targets_every_pinned_peer() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.add_peer("carol", "ed-carol", "x-carol", 1_700_000_500).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();

        store
            .record_pending_sends("note1", &SendTargets::Broadcast)
            .unwrap();

        let pending = store.pending_sends().unwrap();
        assert_eq!(pending.len(), 2);
        let mut recipients: Vec<String> = pending.iter().map(|p| p.peer.ed25519_pubkey.clone()).collect();
        recipients.sort();
        assert_eq!(recipients, vec!["ed-bob".to_string(), "ed-carol".to_string()]);
    }

    #[test]
    fn record_pending_sends_directed_targets_only_the_named_keys() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.add_peer("carol", "ed-carol", "x-carol", 1_700_000_500).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();

        store
            .record_pending_sends("note1", &SendTargets::Directed(vec!["ed-bob".to_string()]))
            .unwrap();

        let pending = store.pending_sends().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].peer.ed25519_pubkey, "ed-bob");
    }

    #[test]
    fn record_pending_sends_rejects_an_unpinned_directed_target_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();

        let result = store.record_pending_sends(
            "note1",
            &SendTargets::Directed(vec!["ed-bob".to_string(), "ed-nobody".to_string()]),
        );
        assert!(matches!(
            result,
            Err(StoreError::UnknownPeerKey { query }) if query == "ed-nobody"
        ));
        // Nothing partial was written - not even the valid "ed-bob" target.
        assert_eq!(store.pending_sends().unwrap().len(), 0);
    }

    #[test]
    fn mark_send_pushed_removes_the_row_from_pending_sends() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.add_peer("carol", "ed-carol", "x-carol", 1_700_000_500).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();
        store
            .record_pending_sends("note1", &SendTargets::Broadcast)
            .unwrap();

        store.mark_send_pushed("note1", "ed-bob", 1_700_001_000).unwrap();

        let pending = store.pending_sends().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].peer.ed25519_pubkey, "ed-carol");
    }

    #[test]
    fn pending_sends_does_not_resurrect_a_pushed_row_on_a_later_call() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();
        store
            .record_pending_sends("note1", &SendTargets::Broadcast)
            .unwrap();
        store.mark_send_pushed("note1", "ed-bob", 1_700_001_000).unwrap();

        assert_eq!(store.pending_sends().unwrap().len(), 0);
        // Calling record_pending_sends again for the same note/target must not
        // resurrect it (INSERT OR IGNORE - the row already exists, now pushed).
        store
            .record_pending_sends("note1", &SendTargets::Broadcast)
            .unwrap();
        assert_eq!(store.pending_sends().unwrap().len(), 0);
    }

    // -- Slice 04: delete_peer, block_key/unblock_key/is_blocked/list_blocked --

    #[test]
    fn delete_peer_removes_the_pin_so_the_key_is_no_longer_pinned() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        assert!(store.get_peer_by_key("ed-bob").unwrap().is_some());

        store.delete_peer("ed-bob").unwrap();

        assert!(store.get_peer_by_key("ed-bob").unwrap().is_none());
    }

    #[test]
    fn delete_peer_is_idempotent_on_an_already_absent_key() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        // No peer named "ed-nobody" was ever pinned - this must not error (D-D).
        store.delete_peer("ed-nobody").unwrap();
    }

    #[test]
    fn delete_peer_purges_only_the_not_yet_pushed_note_sends_row() {
        // AC9/AC10: a peer holding both a pushed and a pending note_sends row at
        // delete time. The pushed row is the historical record of what was actually
        // sent and must survive untouched; only the pending row is purged.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();
        store.insert_note(&sample_note("note2", "me", None)).unwrap();
        store
            .record_pending_sends("note1", &SendTargets::Directed(vec!["ed-bob".to_string()]))
            .unwrap();
        store
            .record_pending_sends("note2", &SendTargets::Directed(vec!["ed-bob".to_string()]))
            .unwrap();
        store.mark_send_pushed("note1", "ed-bob", 1_700_001_000).unwrap();
        // note2 stays pending (never pushed).

        store.delete_peer("ed-bob").unwrap();

        // The pending row (note2) is gone - querying note_sends directly, since
        // pending_sends() also requires the peer row, which is now also gone.
        let pending_row_count: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM note_sends WHERE note_id = 'note2' AND peer_key = 'ed-bob'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_row_count, 0);

        // The pushed row (note1) survives, untouched, as the historical send record.
        let pushed_at: i64 = store
            .conn
            .query_row(
                "SELECT pushed_at FROM note_sends WHERE note_id = 'note1' AND peer_key = 'ed-bob'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pushed_at, 1_700_001_000);
    }

    #[test]
    fn delete_peer_never_touches_blocked_keys() {
        // D-A's separable-underneath property: deleting a peer issues no SQL against
        // blocked_keys at all.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.block_key("ed-bob", 1_700_000_500).unwrap();

        store.delete_peer("ed-bob").unwrap();

        assert!(store.is_blocked("ed-bob").unwrap());
    }

    #[test]
    fn block_key_works_on_a_never_pinned_key() {
        // The stranger case (D-A): no foreign key to peers, so a key that was never
        // pinned at all can still be blocked.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        assert!(store.get_peer_by_key("ed-stranger").unwrap().is_none());

        store.block_key("ed-stranger", 1_700_000_000).unwrap();

        assert!(store.is_blocked("ed-stranger").unwrap());
        assert!(store.get_peer_by_key("ed-stranger").unwrap().is_none());
    }

    #[test]
    fn block_key_is_idempotent() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.block_key("ed-bob", 1_700_000_000).unwrap();
        store.block_key("ed-bob", 1_700_000_500).unwrap();

        assert!(store.is_blocked("ed-bob").unwrap());
    }

    #[test]
    fn unblock_key_lifts_the_block_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.block_key("ed-bob", 1_700_000_000).unwrap();
        store.unblock_key("ed-bob").unwrap();
        assert!(!store.is_blocked("ed-bob").unwrap());

        // Unblocking an already-unblocked key must not error (D-D).
        store.unblock_key("ed-bob").unwrap();
        assert!(!store.is_blocked("ed-bob").unwrap());
    }

    #[test]
    fn unblock_key_never_touches_peers() {
        // D-A's separable-underneath property the other way: blocking/unblocking a
        // key issues no SQL against peers at all.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.block_key("ed-bob", 1_700_000_500).unwrap();
        store.unblock_key("ed-bob").unwrap();

        assert!(store.get_peer_by_key("ed-bob").unwrap().is_some());
    }

    #[test]
    fn list_blocked_returns_every_blocked_key() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.block_key("ed-bob", 1_700_000_000).unwrap();
        store.block_key("ed-carol", 1_700_000_500).unwrap();

        let blocked = store.list_blocked().unwrap();
        assert_eq!(blocked.len(), 2);
        assert_eq!(blocked[0].ed25519_pubkey, "ed-bob");
        assert_eq!(blocked[1].ed25519_pubkey, "ed-carol");
    }

    #[test]
    fn re_adding_a_deleted_and_blocked_peer_leaves_the_block_standing() {
        // D-B: re-add restores the pin; the block, being independent (D-A), is
        // untouched by either the delete or the re-add.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.block_key("ed-bob", 1_700_000_500).unwrap();
        store.delete_peer("ed-bob").unwrap();
        assert!(store.is_blocked("ed-bob").unwrap());

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_001_000).unwrap();

        assert!(store.get_peer_by_key("ed-bob").unwrap().is_some());
        assert!(store.is_blocked("ed-bob").unwrap());
    }

    #[test]
    fn re_adding_a_deleted_peer_does_not_resurrect_a_purged_pending_send() {
        // AC6/AC9 consistency: re-add restores the pin and (if blocked) leaves the
        // block standing, but never resurrects a pending note_sends row purged by an
        // earlier delete.
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("notes.sqlite"), &[3u8; 32]).unwrap();

        store.add_peer("bob", "ed-bob", "x-bob", 1_700_000_000).unwrap();
        store.insert_note(&sample_note("note1", "me", None)).unwrap();
        store
            .record_pending_sends("note1", &SendTargets::Directed(vec!["ed-bob".to_string()]))
            .unwrap();

        store.delete_peer("ed-bob").unwrap();
        store.add_peer("bob", "ed-bob", "x-bob", 1_700_001_000).unwrap();

        // The peer is back, but note1's send to them was purged on delete and must
        // not have come back just because the peer was re-added.
        assert_eq!(store.pending_sends().unwrap().len(), 0);
    }
}
