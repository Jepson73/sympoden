//! Tauri shell: a thin view over sympoden-engine. No security logic lives here -
//! identity, crypto, storage, and sync are all the engine's job.
//!
//! Every `#[tauri::command]` below is a thin lock-and-delegate wrapper around a plain
//! function (no Tauri types in its signature) that does the actual work. That split
//! exists so the security-critical path - identity unlock, posting, syncing - can be
//! unit-tested headlessly, by calling the plain functions directly, without spinning
//! up a webview or a display server. See the `tests` module at the bottom.
//!
//! This app emits no Tauri events; the only data that crosses the IPC boundary is
//! each command's `Result<T, String>` return value, so auditing those return types
//! (see `tests::secrets_never_appear_in_command_return_types`) covers the whole
//! boundary, not just part of it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, State};
use thiserror::Error;

use sympoden_engine::content::Note;
use sympoden_engine::error::{CardError, ContentError, IdentityError, StoreError, SyncError};
use sympoden_engine::identity::{
    Identity, PublicCard, SignedCard, check_card_against_pin, fingerprint_hex, format_fingerprint,
};
use sympoden_engine::store::{AddPeerOutcome, BlockedKey, PinnedPeer, SendTargets, Store};
use sympoden_engine::sync::{self, RelayClient};
use sympoden_engine::trust::{self, TrustedNote};

const KEYFILE_NAME: &str = "identity.keyfile.json";
const DB_NAME: &str = "notes.sqlite";

/// Everything that exists only while the identity is unlocked: the signing/key-
/// agreement keys and the open database. Dropped (and zeroized, for the key
/// material) on app exit or on re-unlock (the old `Session` is dropped when the
/// `Mutex`'s contents are replaced). Deliberately holds no `Serialize` impl - see
/// `tests::session_and_its_secrets_cannot_be_serialized` for why that's the load-
/// bearing guarantee behind AC3, not just convention.
struct Session {
    identity: Identity,
    store: Store,
}

struct AppState {
    data_dir: PathBuf,
    session: Mutex<Option<Session>>,
}

/// Errors from the plain functions below. Mirrors `sympoden-cli`'s `CliError`: each
/// `#[tauri::command]` wrapper flattens this to `.to_string()` for the frontend (a
/// typed message, never a panic), the same way the CLI flattens it to a printed line.
#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Content(#[from] ContentError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Card(#[from] CardError),
    #[error("not unlocked")]
    NotUnlocked,
}

fn keyfile_path(dir: &Path) -> PathBuf {
    dir.join(KEYFILE_NAME)
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_NAME)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A pinned peer as shown to the frontend: label plus its key (the value to submit
/// back for recipient selection / relabeling) plus its display fingerprint (Slice 03
/// D5) - never a bare label, since a label no longer identifies one peer by itself.
#[derive(Debug, Serialize, Clone)]
struct PeerView {
    label: String,
    ed25519_pubkey: String,
    fingerprint: String,
}

impl From<&PinnedPeer> for PeerView {
    fn from(peer: &PinnedPeer) -> Self {
        Self {
            label: peer.label.clone(),
            ed25519_pubkey: peer.ed25519_pubkey.clone(),
            fingerprint: format_fingerprint(&fingerprint_hex(&peer.ed25519_pubkey)),
        }
    }
}

/// A note as shown to the frontend: the trust-annotated note plus the author's display
/// fingerprint, computed here from `StoredNote::author_pubkey` - never threaded through
/// `AuthorTrust` itself, which is what keeps `trust.rs` zero-diff (SLICE-03.md D5). The
/// only way to construct one is `From<TrustedNote>`, so - same as `TrustedNote` itself -
/// there is no path to a `NoteView` that skipped classification.
#[derive(Serialize)]
struct NoteView {
    note: sympoden_engine::store::StoredNote,
    trust: sympoden_engine::trust::AuthorTrust,
    fingerprint: String,
}

impl From<TrustedNote> for NoteView {
    fn from(trusted: TrustedNote) -> Self {
        let fingerprint = format_fingerprint(&fingerprint_hex(&trusted.note().author_pubkey));
        Self {
            note: trusted.note().clone(),
            trust: trusted.trust().clone(),
            fingerprint,
        }
    }
}

/// What `add_peer_card` did, or whether it needs the frontend to confirm a label
/// collision first (SLICE-03.md D3 - the app's side of the same engine seam the CLI's
/// `--strict` flag exercises).
#[derive(Debug, Serialize)]
enum AddPeerResult {
    NeedsCollisionConfirmation { existing: Vec<PeerView> },
    /// SLICE-04.md D-D: a call-site guard, not an engine check - `Store::AddPeerOutcome`
    /// gains nothing, this is an outcome of the Tauri command alone.
    IsSelf,
    Outcome {
        outcome: AddPeerOutcome,
        /// SLICE-04.md D-B: re-adding a previously deleted-and-blocked key restores
        /// the pin but never lifts the block - this tells the frontend so it can say
        /// so plainly, the same notice the CLI prints inline.
        still_blocked: bool,
    },
}

/// A blocked key as shown to the frontend: the key itself plus its display
/// fingerprint and when it was blocked - mirrors `PeerView`'s shape.
#[derive(Debug, Serialize)]
struct BlockedKeyView {
    ed25519_pubkey: String,
    fingerprint: String,
    blocked_at: i64,
}

impl From<&BlockedKey> for BlockedKeyView {
    fn from(blocked: &BlockedKey) -> Self {
        Self {
            ed25519_pubkey: blocked.ed25519_pubkey.clone(),
            fingerprint: format_fingerprint(&fingerprint_hex(&blocked.ed25519_pubkey)),
            blocked_at: blocked.blocked_at,
        }
    }
}

#[derive(Debug, Serialize)]
enum RelabelResult {
    NeedsCollisionConfirmation { existing: Vec<PeerView> },
    Relabeled,
}

// ---------------------------------------------------------------------------------
// Plain functions: all engine-calling logic, no Tauri types in any signature. Each
// one maps 1:1 to a Tauri command below and is exercised directly in `tests`.
// ---------------------------------------------------------------------------------

fn has_identity_at(dir: &Path) -> bool {
    keyfile_path(dir).exists()
}

fn create_identity_session(dir: &Path, passphrase: &str) -> Result<Session, AppError> {
    let identity = Identity::create(&keyfile_path(dir), passphrase)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;
    Ok(Session { identity, store })
}

fn unlock_identity_session(dir: &Path, passphrase: &str) -> Result<Session, AppError> {
    let identity = Identity::unlock(&keyfile_path(dir), passphrase)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;
    Ok(Session { identity, store })
}

fn whoami_card(session: &Session) -> String {
    session.identity.card_encoded()
}

/// Pin a peer's card under `label`. Key-as-identity (SLICE-03.md D1-D3): if the card's
/// key is genuinely new and would collide with an existing, different peer's label,
/// and the frontend hasn't already confirmed it (`confirm_collision`), nothing is
/// written - the caller gets back the colliding peer(s) to show in a confirm dialog.
/// Otherwise delegates straight to `Store::add_peer`, whose own outcome (including the
/// loud `AlreadyPinnedUnderLabel` no-op, Adjustment 3) is returned as-is.
fn add_peer_card(
    session: &Session,
    label: &str,
    card: &str,
    confirm_collision: bool,
) -> Result<AddPeerResult, AppError> {
    // SignedCard::parse_and_verify (SLICE-05.md D-D) is the only way card bytes ever
    // turn into trusted keys - base64 decode, structural checks, then signature
    // verification, all before anything below sees the card. `card` is raw base64
    // text now (D-E(2)) - the frontend no longer decodes it first.
    let verified = SignedCard::parse_and_verify(card)?;
    let ed25519_pubkey = hex::encode(verified.ed25519_pubkey.as_bytes());
    let x25519_pubkey = hex::encode(verified.x25519_pubkey.to_bytes());

    // D-C: if this Ed25519 key is already pinned, its X25519 key must match the one
    // this card offers - a validly-signed card claiming a different X25519 key for an
    // already-pinned identity is rejected loudly, before add_peer is ever reached.
    if let Some(existing) = session.store.get_peer_by_key(&ed25519_pubkey)? {
        check_card_against_pin(&verified, &existing)?;
    }

    // Self-add rejection (SLICE-04.md D-D): a call-site guard, not an engine check -
    // Store stays identity-free. Rejected before check_label_collision or add_peer is
    // ever reached, so the engine never sees the candidate key.
    let my_key_hex = hex::encode(session.identity.signing_key.verifying_key().as_bytes());
    if ed25519_pubkey == my_key_hex {
        return Ok(AddPeerResult::IsSelf);
    }

    if !confirm_collision && session.store.get_peer_by_key(&ed25519_pubkey)?.is_none() {
        let collisions = session.store.check_label_collision(label, &ed25519_pubkey)?;
        if !collisions.is_empty() {
            return Ok(AddPeerResult::NeedsCollisionConfirmation {
                existing: collisions.iter().map(PeerView::from).collect(),
            });
        }
    }

    let outcome = session
        .store
        .add_peer(label, &ed25519_pubkey, &x25519_pubkey, now_unix())?;
    // D-B: re-adding a previously deleted-and-blocked key restores the pin but never
    // lifts the block - surfaced here so it's not undiscoverable.
    let still_blocked = session.store.is_blocked(&ed25519_pubkey)?;
    Ok(AddPeerResult::Outcome {
        outcome,
        still_blocked,
    })
}

/// Rename a pinned peer's label, addressed by the peer's exact key.
///
/// Deliberately takes `ed25519_pubkey`, not a `resolve_peer_query`-style typed query:
/// the GUI already holds the peer's exact key (it came straight from `list_peers`,
/// rendered into the relabel button's own data attribute) - it never needs, and must
/// never go through, fuzzy label/fingerprint resolution. `resolve_peer_query` exists
/// for *human-typed* input (the CLI's `--to`/`relabel-peer <query>` arguments), not for
/// a value the caller already knows exactly. Routing an exact key through it was the
/// bug: a raw 64-hex pubkey matches neither a label nor a 20-hex fingerprint, so it
/// always resolved to `UnknownPeerKey` no matter which peer was clicked.
fn relabel_peer_now(
    session: &Session,
    ed25519_pubkey: &str,
    new_label: &str,
    confirm_collision: bool,
) -> Result<RelabelResult, AppError> {
    if !confirm_collision {
        let collisions = session
            .store
            .check_label_collision(new_label, ed25519_pubkey)?;
        if !collisions.is_empty() {
            return Ok(RelabelResult::NeedsCollisionConfirmation {
                existing: collisions.iter().map(PeerView::from).collect(),
            });
        }
    }

    session.store.relabel_peer(ed25519_pubkey, new_label)?;
    Ok(RelabelResult::Relabeled)
}

fn list_peers_inner(session: &Session) -> Result<Vec<PeerView>, AppError> {
    Ok(session.store.list_peers()?.iter().map(PeerView::from).collect())
}

/// Unpin a peer. By default also blocks their key (the coupled default action);
/// `keep_unblocked: true` is the delete-without-block escape hatch, so the two stay
/// independently invokable from the frontend (SLICE-04.md's stated UI requirement).
fn remove_peer_now(
    session: &Session,
    ed25519_pubkey: &str,
    keep_unblocked: bool,
) -> Result<(), AppError> {
    session.store.delete_peer(ed25519_pubkey)?;
    if !keep_unblocked {
        session.store.block_key(ed25519_pubkey, now_unix())?;
    }
    Ok(())
}

/// Standalone block-without-delete: never touches `peers` (D-A's separable-underneath
/// property). Takes the peer's/sender's exact key, the same way `relabel_peer_now`
/// does - the frontend already holds it, from `list_peers` or a note's own
/// `author_pubkey`, never a typed query to resolve.
fn block_key_now(session: &Session, ed25519_pubkey: &str) -> Result<(), AppError> {
    session.store.block_key(ed25519_pubkey, now_unix())?;
    Ok(())
}

fn unblock_key_now(session: &Session, ed25519_pubkey: &str) -> Result<(), AppError> {
    session.store.unblock_key(ed25519_pubkey)?;
    Ok(())
}

fn list_blocked_inner(session: &Session) -> Result<Vec<BlockedKeyView>, AppError> {
    Ok(session
        .store
        .list_blocked()?
        .iter()
        .map(BlockedKeyView::from)
        .collect())
}

/// `recipients`: `None` or an empty list addresses every currently pinned peer
/// (broadcast); a non-empty list addresses exactly those keys (directed). The frontend
/// resolves its checkbox selection to keys itself (it is keyed by `ed25519_pubkey`, not
/// label, so there's no ambiguous-query problem to solve here the way the CLI's `--to`
/// has to). Send targets are recorded *before* the note is inserted (SLICE-03.md D7),
/// so an invalid target never leaves an orphaned, unaddressed note behind.
fn post_note_now(
    session: &Session,
    body: String,
    created_at: i64,
    recipients: Option<Vec<String>>,
) -> Result<String, AppError> {
    let targets = match recipients {
        Some(keys) if !keys.is_empty() => SendTargets::Directed(keys),
        _ => SendTargets::Broadcast,
    };

    let note = Note::new(&session.identity.signing_key, body, created_at);
    session.store.record_pending_sends(&note.id_hex(), &targets)?;
    session.store.insert_note(&note.to_stored())?;
    Ok(note.id_hex())
}

#[derive(Serialize)]
struct SyncResult {
    pushed: Vec<String>,
    received: Option<NoteView>,
}

fn sync_now_inner(session: &Session, relay: String) -> Result<SyncResult, AppError> {
    let client = RelayClient::new(relay);
    let my_key = session.identity.signing_key.verifying_key();

    let mut pushed = Vec::new();
    for send in session.store.pending_sends()? {
        let note = Note::from_stored(&send.note)?;
        let card = PublicCard::from_pinned_peer(&send.peer)?;
        let (routing_key, envelope_bytes) = sync::prepare_outgoing(&note, &card)?;
        match client.push(&routing_key, &envelope_bytes)? {
            sync::PushOutcome::Accepted => {
                session
                    .store
                    .mark_send_pushed(&send.note.id, &send.peer.ed25519_pubkey, now_unix())?;
                pushed.push(send.note.id);
            }
            sync::PushOutcome::RecipientSlotOccupied => {
                // This recipient hasn't pulled their previous note yet. Leave this row
                // pending and move on to the next one - one occupied slot must never
                // block delivery to any other recipient of the same note.
            }
        }
    }

    let peers = session.store.list_peers()?;
    let my_routing_key = sympoden_engine::crypto::routing_key_for(&my_key);
    let received = match client.pull(&my_routing_key)? {
        Some(envelope_bytes) => {
            // receive_incoming (decrypt, verify) is unchanged (SLICE-04.md D-C) - the
            // block check is a new step between it and insert_note. The relay has
            // already freed this recipient's slot by the pull above, regardless of
            // what happens next.
            let note = sync::receive_incoming(&envelope_bytes, &session.identity.x25519_secret)?;
            let author_hex = hex::encode(note.author_pubkey.as_bytes());
            if session.store.is_blocked(&author_hex)? {
                None
            } else {
                let trusted = trust::classify_stored_note(note.to_stored(), &my_key, &peers)?;
                session.store.insert_note(trusted.note())?;
                Some(NoteView::from(trusted))
            }
        }
        None => None,
    };

    Ok(SyncResult { pushed, received })
}

fn list_notes_inner(session: &Session) -> Result<Vec<NoteView>, AppError> {
    let peers = session.store.list_peers()?;
    let my_key = session.identity.signing_key.verifying_key();

    session
        .store
        .list_notes()?
        .into_iter()
        .map(|note| {
            trust::classify_stored_note(note, &my_key, &peers)
                .map(NoteView::from)
                .map_err(AppError::from)
        })
        .collect()
}

// ---------------------------------------------------------------------------------
// Tauri commands: thin lock-and-delegate wrappers. No engine logic of their own.
// ---------------------------------------------------------------------------------

#[tauri::command]
fn has_identity(state: State<AppState>) -> bool {
    has_identity_at(&state.data_dir)
}

#[tauri::command]
fn create_identity(state: State<AppState>, passphrase: String) -> Result<(), String> {
    let session = create_identity_session(&state.data_dir, &passphrase).map_err(|e| e.to_string())?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    *guard = Some(session);
    Ok(())
}

#[tauri::command]
fn unlock_identity(state: State<AppState>, passphrase: String) -> Result<(), String> {
    let session = unlock_identity_session(&state.data_dir, &passphrase).map_err(|e| e.to_string())?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    *guard = Some(session);
    Ok(())
}

#[tauri::command]
fn whoami(state: State<AppState>) -> Result<String, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    Ok(whoami_card(session))
}

#[tauri::command]
fn add_peer(
    state: State<AppState>,
    label: String,
    card: String,
    confirm_collision: bool,
) -> Result<AddPeerResult, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    add_peer_card(session, &label, &card, confirm_collision).map_err(|e| e.to_string())
}

#[tauri::command]
fn relabel_peer(
    state: State<AppState>,
    ed25519_pubkey: String,
    new_label: String,
    confirm_collision: bool,
) -> Result<RelabelResult, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    relabel_peer_now(session, &ed25519_pubkey, &new_label, confirm_collision).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_peers(state: State<AppState>) -> Result<Vec<PeerView>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    list_peers_inner(session).map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_peer(
    state: State<AppState>,
    ed25519_pubkey: String,
    keep_unblocked: bool,
) -> Result<(), String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    remove_peer_now(session, &ed25519_pubkey, keep_unblocked).map_err(|e| e.to_string())
}

#[tauri::command]
fn block_key(state: State<AppState>, ed25519_pubkey: String) -> Result<(), String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    block_key_now(session, &ed25519_pubkey).map_err(|e| e.to_string())
}

#[tauri::command]
fn unblock_key(state: State<AppState>, ed25519_pubkey: String) -> Result<(), String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    unblock_key_now(session, &ed25519_pubkey).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_blocked(state: State<AppState>) -> Result<Vec<BlockedKeyView>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    list_blocked_inner(session).map_err(|e| e.to_string())
}

#[tauri::command]
fn post_note(
    state: State<AppState>,
    body: String,
    recipients: Option<Vec<String>>,
) -> Result<String, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    post_note_now(session, body, now_unix(), recipients).map_err(|e| e.to_string())
}

#[tauri::command]
fn sync_now(state: State<AppState>, relay: String) -> Result<SyncResult, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    sync_now_inner(session, relay).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_notes(state: State<AppState>) -> Result<Vec<NoteView>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    list_notes_inner(session).map_err(|e| e.to_string())
}

fn main() {
    let result = tauri::Builder::default()
        .setup(|app| {
            // SYMPODEN_DATA_DIR overrides the OS app-data directory, so two
            // instances can run side by side on one machine for local testing -
            // matching the CLI's --data-dir. Real installs just leave it unset.
            let data_dir = match std::env::var_os("SYMPODEN_DATA_DIR") {
                Some(dir) => PathBuf::from(dir),
                None => app
                    .path()
                    .app_data_dir()
                    .map_err(|e| format!("could not resolve app data dir: {e}"))?,
            };
            std::fs::create_dir_all(&data_dir)?;
            app.manage(AppState {
                data_dir,
                session: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            has_identity,
            create_identity,
            unlock_identity,
            whoami,
            add_peer,
            relabel_peer,
            list_peers,
            remove_peer,
            block_key,
            unblock_key,
            list_blocked,
            post_note,
            sync_now,
            list_notes,
        ])
        .run(tauri::generate_context!());

    // `run` only errors if the webview framework itself fails to initialize - there's
    // no UI left to report into, so stderr plus a nonzero exit is the cleanest this
    // can do. Still never panics: a failure here is an environment problem (missing
    // webview, display server, ...), not a bug to crash loudly over.
    if let Err(e) = result {
        eprintln!("error while running the sympoden-app: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::SocketAddr;
    use tempfile::tempdir;

    // AC3, primary proof: the secret-bearing types literally cannot be returned from
    // a Tauri command, because Tauri command returns must be `Serialize` and these
    // types don't implement it - not "we were careful," but "it wouldn't compile."
    // `Identity` holds the signing key, the x25519 secret, and the db key; `Store`
    // holds a live `rusqlite::Connection`; `Session` holds both. None derive or
    // implement `Serialize`.
    #[test]
    fn session_and_its_secrets_cannot_be_serialized() {
        static_assertions::assert_not_impl_any!(Session: serde::Serialize);
        static_assertions::assert_not_impl_any!(Identity: serde::Serialize);
        static_assertions::assert_not_impl_any!(Store: serde::Serialize);
    }

    // AC3, secondary/runtime check: walk what every command actually returns (or, for
    // errors, what string actually crosses the boundary) and confirm by inspection
    // that only display data is present. This app emits no Tauri events, so command
    // return values and error strings are the entire IPC surface - there is no third
    // channel to also check.
    #[test]
    fn secrets_never_appear_in_command_return_types() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "correct horse battery staple").unwrap();

        // whoami -> a ready-to-paste base64 string (SLICE-05.md D-E(2)): decode it back
        // to the SignedCard JSON it wraps and confirm only public, non-secret fields
        // are present - the two public keys, the version, and a signature over them
        // (a signature is not secret; only the private key that produced it is).
        use base64::Engine as _;
        let card_bytes = base64::engine::general_purpose::STANDARD
            .decode(whoami_card(&session).trim())
            .unwrap();
        let card_json: serde_json::Value = serde_json::from_slice(&card_bytes).unwrap();
        let card_obj = card_json.as_object().unwrap();
        let card_keys: std::collections::BTreeSet<String> = card_obj.keys().cloned().collect();
        let expected_card_keys: std::collections::BTreeSet<String> =
            ["version", "ed25519_public", "x25519_public", "signature"]
                .into_iter()
                .map(String::from)
                .collect();
        assert_eq!(card_keys, expected_card_keys);

        // post_note -> a content-addressed id (String), then list_notes ->
        // Vec<NoteView>: {note: {id/author_pubkey/body/created_at/signature/
        // synced_at}, trust: ..., fingerprint: ...}. The body is the one piece of
        // plaintext a command is meant to surface - the user's own note, read back to
        // them. Nothing else is secret: the pubkey, signature, trust label, and
        // fingerprint are public/local-judgment/derived-from-public data, not key
        // material.
        let secret_body = "only the body should ever leave the process";
        post_note_now(&session, secret_body.to_string(), 1_700_000_000, None).unwrap();
        let notes = list_notes_inner(&session).unwrap();
        let note_json = serde_json::to_value(&notes[0]).unwrap();
        let note_obj = note_json.as_object().unwrap();
        assert_eq!(
            note_obj
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["note", "trust", "fingerprint"]
                .into_iter()
                .map(String::from)
                .collect()
        );
        let inner = note_obj["note"].as_object().unwrap();
        assert_eq!(
            inner
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["id", "author_pubkey", "body", "created_at", "signature", "synced_at"]
                .into_iter()
                .map(String::from)
                .collect()
        );
        assert_eq!(inner["body"], secret_body);
    }

    #[test]
    fn has_identity_reflects_keyfile_presence() {
        let dir = tempdir().unwrap();
        assert!(!has_identity_at(dir.path()));

        create_identity_session(dir.path(), "passphrase").unwrap();
        assert!(has_identity_at(dir.path()));
    }

    #[test]
    fn create_then_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let created = create_identity_session(dir.path(), "correct horse battery staple").unwrap();
        let unlocked = unlock_identity_session(dir.path(), "correct horse battery staple").unwrap();

        assert_eq!(
            created.identity.signing_key.verifying_key(),
            unlocked.identity.signing_key.verifying_key()
        );
    }

    #[test]
    fn wrong_passphrase_fails_cleanly_with_a_typed_error() {
        let dir = tempdir().unwrap();
        create_identity_session(dir.path(), "correct horse battery staple").unwrap();

        // `Session` deliberately has no `Debug` impl (it would be an easy way to
        // accidentally print key material), so `Result::unwrap_err` - which requires
        // `T: Debug` - isn't available here; match on the error directly instead.
        let err = match unlock_identity_session(dir.path(), "wrong passphrase") {
            Err(e) => e,
            Ok(_) => panic!("wrong passphrase must not unlock"),
        };
        assert!(matches!(
            err,
            AppError::Identity(IdentityError::InvalidPassphrase)
        ));
        // What a command wrapper would actually hand to the frontend: a clean typed
        // message, not a panic and not a stack trace.
        assert_eq!(err.to_string(), "incorrect passphrase");
    }

    #[test]
    fn wrong_passphrase_error_never_echoes_the_attempted_passphrase() {
        let dir = tempdir().unwrap();
        create_identity_session(dir.path(), "correct horse battery staple").unwrap();

        let probe = "marker-zzqv-should-never-appear-in-any-error-string";
        let message = match unlock_identity_session(dir.path(), probe) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("probe passphrase must not unlock"),
        };
        assert!(!message.contains(probe));
    }

    #[test]
    fn add_peer_rejects_a_malformed_card_cleanly() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let result = add_peer_card(&session, "bob", "not json at all", false);
        assert!(matches!(
            result,
            Err(AppError::Card(CardError::NotBase64(_)))
        ));
    }

    #[test]
    fn add_peer_under_a_second_and_third_distinct_label_succeeds_the_cap_is_gone() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        let carol_dir = dir.path().join("carol");
        fs::create_dir_all(&bob_dir).unwrap();
        fs::create_dir_all(&carol_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let carol = create_identity_session(&carol_dir, "carol-pass").unwrap();

        let bob_card = whoami_card(&bob);
        let carol_card = whoami_card(&carol);

        let first = add_peer_card(&session, "bob", &bob_card, false).unwrap();
        assert!(matches!(
            first,
            AddPeerResult::Outcome {
                outcome: AddPeerOutcome::Added,
                ..
            }
        ));

        let second = add_peer_card(&session, "carol", &carol_card, false).unwrap();
        assert!(matches!(
            second,
            AddPeerResult::Outcome {
                outcome: AddPeerOutcome::Added,
                ..
            }
        ));

        assert_eq!(list_peers_inner(&session).unwrap().len(), 2);
    }

    #[test]
    fn add_peer_under_a_shared_label_needs_confirmation_then_succeeds() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        let eve_dir = dir.path().join("eve");
        fs::create_dir_all(&bob_dir).unwrap();
        fs::create_dir_all(&eve_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let eve = create_identity_session(&eve_dir, "eve-pass").unwrap();

        let bob_card = whoami_card(&bob);
        let eve_card = whoami_card(&eve);
        add_peer_card(&session, "bob", &bob_card, false).unwrap();

        // A different key under the same label, without confirmation: nothing is
        // written, the existing peer is surfaced for a confirm dialog.
        let needs_confirm = add_peer_card(&session, "bob", &eve_card, false).unwrap();
        match needs_confirm {
            AddPeerResult::NeedsCollisionConfirmation { existing } => {
                assert_eq!(existing.len(), 1);
                assert_eq!(existing[0].label, "bob");
            }
            other => panic!("expected a collision confirmation prompt, got {other:?}"),
        }
        assert_eq!(list_peers_inner(&session).unwrap().len(), 1);

        // Confirmed: now it proceeds, and both peers - same label, different keys -
        // coexist.
        let confirmed = add_peer_card(&session, "bob", &eve_card, true).unwrap();
        assert!(matches!(
            confirmed,
            AddPeerResult::Outcome {
                outcome: AddPeerOutcome::Added,
                ..
            }
        ));
        assert_eq!(list_peers_inner(&session).unwrap().len(), 2);
    }

    #[test]
    fn add_peer_with_an_already_pinned_key_under_a_new_label_is_a_loud_no_op() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let bob_card = whoami_card(&bob);

        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        let result = add_peer_card(&session, "robert", &bob_card, false).unwrap();

        match result {
            AddPeerResult::Outcome {
                outcome: AddPeerOutcome::AlreadyPinnedUnderLabel { existing_label },
                ..
            } => {
                assert_eq!(existing_label, "bob");
            }
            other => panic!("expected AlreadyPinnedUnderLabel, got {other:?}"),
        }
        let peers = list_peers_inner(&session).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].label, "bob");
    }

    // Regression test for a real GUI bug: the frontend's Rename button passes the
    // peer's exact `ed25519_pubkey` (a raw 64-hex string, taken straight from
    // `list_peers`'s own output) as the identifier - never a label, never a
    // fingerprint. `relabel_peer_now` must accept that key directly; routing it
    // through `resolve_peer_query` (label/fingerprint resolution meant for *typed*
    // CLI input) was the bug, since a raw pubkey matches neither and always resolved
    // to `UnknownPeerKey`, no matter which peer was clicked. This test passes exactly
    // the shape the frontend sends - it would have caught the original bug, where a
    // test that passed the label "bob" (as this one used to) could not.
    #[test]
    fn relabel_peer_renames_by_exact_key_without_changing_it() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let bob_card = whoami_card(&bob);
        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        let original_key = list_peers_inner(&session).unwrap()[0].ed25519_pubkey.clone();
        assert_eq!(original_key.len(), 64, "sanity check: a raw hex Ed25519 key, not a label or fingerprint");

        let result = relabel_peer_now(&session, &original_key, "robert", false).unwrap();
        assert!(matches!(result, RelabelResult::Relabeled));

        let peers = list_peers_inner(&session).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].label, "robert");
        assert_eq!(peers[0].ed25519_pubkey, original_key);
    }

    #[test]
    fn relabel_peer_rejects_an_unpinned_key_cleanly() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();

        let result = relabel_peer_now(&session, "ab".repeat(32).as_str(), "anyone", false);
        assert!(matches!(
            result,
            Err(AppError::Store(StoreError::UnknownPeerKey { .. }))
        ));
    }

    #[test]
    fn post_then_list_roundtrip() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();

        post_note_now(&session, "hello, world".to_string(), 1_700_000_000, None).unwrap();
        let notes = list_notes_inner(&session).unwrap();

        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note.body, "hello, world");
    }

    // AC11 (Slice 02): the user's own posted note must classify as Own ("you"), never
    // Unknown - its author_pubkey is this identity's own key, which never needs to
    // (and must not need to) appear in the peers table.
    #[test]
    fn own_posted_note_classifies_as_own_not_unknown() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();

        post_note_now(&session, "hello, world".to_string(), 1_700_000_000, None).unwrap();
        let notes = list_notes_inner(&session).unwrap();

        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].trust,
            sympoden_engine::trust::AuthorTrust::Own
        );
    }

    /// A real, in-process relay: a live TCP listener backed by a shared `HashMap`
    /// that genuinely stores a pushed blob and returns those exact bytes on a later
    /// pull (one-blob-per-key, via `Entry`'s occupied/vacant check - same semantics
    /// as `sympoden-relay`'s actual rejection-not-overwrite behavior). This is not a
    /// canned single-response double: `full_two_session_sync_exchange_via_relay`
    /// below pushes through one `sync_now_inner` call and pulls through a second,
    /// separate call, so the blob only round-trips correctly if this listener
    /// actually persists it across connections - exactly the store-and-forward this
    /// is here to prove `sync_now_inner` (the app's own push+pull+receive
    /// orchestration, untouched by `scripts/demo.sh`, which exercises the CLI's
    /// separate `cmd_sync` instead) gets right. It speaks the same wire format as
    /// `sympoden_relay::main` and is structured the same way as that crate's own
    /// `start_test_relay` test helper, but is a separate implementation - by design,
    /// nothing here depends on the relay crate (the blind relay must structurally
    /// share no crypto/identity dependency with anything that understands envelopes).
    fn start_test_relay() -> SocketAddr {
        use std::collections::HashMap;
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex as StdMutex};

        #[derive(serde::Deserialize)]
        #[serde(tag = "op", rename_all = "lowercase")]
        enum Request {
            Push {
                routing_key: String,
                blob: String,
                // Not enforced by this mock (tests run well within any real TTL);
                // present only so it deserializes the same request shape RelayClient
                // actually sends.
                #[serde(default)]
                #[allow(dead_code)]
                ttl_secs: Option<u64>,
            },
            Pull {
                routing_key: String,
            },
        }

        #[derive(serde::Serialize, Default)]
        struct Response {
            ok: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            blob: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<String>,
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store: Arc<StdMutex<HashMap<String, Vec<u8>>>> = Arc::new(StdMutex::new(HashMap::new()));

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let store = Arc::clone(&store);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let response = match serde_json::from_str::<Request>(line.trim_end()) {
                    Ok(Request::Push {
                        routing_key, blob, ..
                    }) => {
                        use base64::Engine as _;
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(&blob)
                            .unwrap();
                        let mut guard = store.lock().unwrap();
                        match guard.entry(routing_key) {
                            std::collections::hash_map::Entry::Occupied(_) => Response {
                                ok: false,
                                blob: None,
                                error: Some("occupied".to_string()),
                            },
                            std::collections::hash_map::Entry::Vacant(slot) => {
                                slot.insert(bytes);
                                Response {
                                    ok: true,
                                    ..Default::default()
                                }
                            }
                        }
                    }
                    Ok(Request::Pull { routing_key }) => {
                        use base64::Engine as _;
                        let blob = store
                            .lock()
                            .unwrap()
                            .remove(&routing_key)
                            .map(|b| base64::engine::general_purpose::STANDARD.encode(b));
                        Response {
                            ok: true,
                            blob,
                            error: None,
                        }
                    }
                    Err(e) => Response {
                        ok: false,
                        blob: None,
                        error: Some(e.to_string()),
                    },
                };
                let mut serialized = serde_json::to_vec(&response).unwrap();
                serialized.push(b'\n');
                let _ = stream.write_all(&serialized);
            }
        });

        addr
    }

    #[test]
    fn full_two_session_sync_exchange_via_relay() {
        let workdir = tempdir().unwrap();
        let alice_dir = workdir.path().join("alice");
        let bob_dir = workdir.path().join("bob");
        fs::create_dir_all(&alice_dir).unwrap();
        fs::create_dir_all(&bob_dir).unwrap();

        let alice = create_identity_session(&alice_dir, "alice-pass").unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();

        let bob_card = whoami_card(&bob);
        add_peer_card(&alice, "bob", &bob_card, false).unwrap();
        // Bob also pins Alice, so the note that flows (Alice -> Bob) classifies as
        // Known on Bob's side, not Unknown - without this, the test would never
        // exercise SLICE-02's actual headline property.
        let alice_card = whoami_card(&alice);
        add_peer_card(&bob, "alice", &alice_card, false).unwrap();

        let body = "hello bob, from a headless two-session test".to_string();
        post_note_now(&alice, body.clone(), 1_700_000_000, None).unwrap();

        let relay_addr = start_test_relay();

        // Alice pushes to the relay (broadcast - her only pinned peer, Bob), then (in
        // spirit) goes fully offline - nothing about her session is touched again in
        // this test.
        let alice_sync = sync_now_inner(&alice, relay_addr.to_string()).unwrap();
        assert_eq!(alice_sync.pushed.len(), 1);
        assert!(alice_sync.received.is_none());

        // Bob syncs later and should see Alice's note arrive, verified, decrypted,
        // and bound to her pinned label - not a raw key.
        let bob_sync = sync_now_inner(&bob, relay_addr.to_string()).unwrap();
        let received = bob_sync
            .received
            .expect("bob should have received alice's note from the relay");
        assert_eq!(received.note.body, body);
        assert_eq!(
            received.trust,
            sympoden_engine::trust::AuthorTrust::Known("alice".to_string())
        );

        let bob_notes = list_notes_inner(&bob).unwrap();
        assert!(bob_notes.iter().any(|n| n.note.body == body));
    }

    #[test]
    fn broadcast_post_reaches_every_pinned_peer_directed_reaches_only_the_subset() {
        let workdir = tempdir().unwrap();
        let alice_dir = workdir.path().join("alice");
        let bob_dir = workdir.path().join("bob");
        let carol_dir = workdir.path().join("carol");
        fs::create_dir_all(&alice_dir).unwrap();
        fs::create_dir_all(&bob_dir).unwrap();
        fs::create_dir_all(&carol_dir).unwrap();

        let alice = create_identity_session(&alice_dir, "alice-pass").unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let carol = create_identity_session(&carol_dir, "carol-pass").unwrap();

        let bob_card = whoami_card(&bob);
        let carol_card = whoami_card(&carol);
        add_peer_card(&alice, "bob", &bob_card, false).unwrap();
        add_peer_card(&alice, "carol", &carol_card, false).unwrap();
        let bob_key = list_peers_inner(&alice)
            .unwrap()
            .into_iter()
            .find(|p| p.label == "bob")
            .unwrap()
            .ed25519_pubkey;

        // Directed: only Bob.
        post_note_now(
            &alice,
            "for bob only".to_string(),
            1_700_000_000,
            Some(vec![bob_key]),
        )
        .unwrap();
        let pending = alice.store.pending_sends().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].peer.label, "bob");
    }

    // -- Slice 04: delete a peer, block a key --

    #[test]
    fn add_peer_card_rejects_pinning_ones_own_whoami_card() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let own_card = whoami_card(&session);

        let result = add_peer_card(&session, "myself", &own_card, false).unwrap();

        assert!(matches!(result, AddPeerResult::IsSelf));
        assert_eq!(list_peers_inner(&session).unwrap().len(), 0);
    }

    #[test]
    fn delete_peer_reclassifies_existing_notes_to_unknown_and_readd_restores_known() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let bob_card = whoami_card(&bob);
        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        let bob_key = list_peers_inner(&session).unwrap()[0].ed25519_pubkey.clone();

        // A note authored by Bob, inserted directly (as if it had arrived via sync).
        session
            .store
            .insert_note(&sympoden_engine::store::StoredNote {
                id: "note-from-bob".to_string(),
                author_pubkey: bob_key.clone(),
                body: "hi".to_string(),
                created_at: 1_700_000_000,
                signature: "deadbeef".to_string(),
                synced_at: None,
            })
            .unwrap();
        assert_eq!(
            list_notes_inner(&session).unwrap()[0].trust,
            sympoden_engine::trust::AuthorTrust::Known("bob".to_string())
        );

        remove_peer_now(&session, &bob_key, true).unwrap();
        assert_eq!(
            list_notes_inner(&session).unwrap()[0].trust,
            sympoden_engine::trust::AuthorTrust::Unknown
        );

        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        assert_eq!(
            list_notes_inner(&session).unwrap()[0].trust,
            sympoden_engine::trust::AuthorTrust::Known("bob".to_string())
        );
    }

    #[test]
    fn remove_peer_default_couples_block_keep_unblocked_does_not() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let bob_card = whoami_card(&bob);
        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        let bob_key = list_peers_inner(&session).unwrap()[0].ed25519_pubkey.clone();

        remove_peer_now(&session, &bob_key, false).unwrap();
        assert!(session.store.is_blocked(&bob_key).unwrap());

        // Re-pin and delete again, this time keeping it unblocked.
        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        session.store.unblock_key(&bob_key).unwrap();
        remove_peer_now(&session, &bob_key, true).unwrap();
        assert!(!session.store.is_blocked(&bob_key).unwrap());
    }

    #[test]
    fn block_key_now_works_on_a_never_pinned_sender() {
        // The stranger case (D-A): block_key_now never resolves through peers - it
        // takes the exact key directly, the same way a note's author_pubkey would be
        // passed from a "block this sender" frontend action.
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();

        block_key_now(&session, "ed-a-stranger-who-was-never-pinned").unwrap();

        assert!(
            session
                .store
                .is_blocked("ed-a-stranger-who-was-never-pinned")
                .unwrap()
        );
    }

    #[test]
    fn re_adding_after_delete_and_block_surfaces_still_blocked_in_the_result() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let bob_card = whoami_card(&bob);
        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        let bob_key = list_peers_inner(&session).unwrap()[0].ed25519_pubkey.clone();

        remove_peer_now(&session, &bob_key, false).unwrap(); // delete + block (default)

        let result = add_peer_card(&session, "bob", &bob_card, false).unwrap();
        match result {
            AddPeerResult::Outcome {
                outcome: AddPeerOutcome::Added,
                still_blocked,
            } => assert!(still_blocked, "D-B: re-add must report the standing block"),
            other => panic!("expected Outcome::Added, got {other:?}"),
        }
    }

    #[test]
    fn sync_now_drops_a_note_from_a_blocked_sender_before_storing_it() {
        let workdir = tempdir().unwrap();
        let alice_dir = workdir.path().join("alice");
        let bob_dir = workdir.path().join("bob");
        fs::create_dir_all(&alice_dir).unwrap();
        fs::create_dir_all(&bob_dir).unwrap();

        let alice = create_identity_session(&alice_dir, "alice-pass").unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();

        let bob_card = whoami_card(&bob);
        add_peer_card(&alice, "bob", &bob_card, false).unwrap();
        let alice_card = whoami_card(&alice);
        add_peer_card(&bob, "alice", &alice_card, false).unwrap();

        post_note_now(&alice, "hello bob".to_string(), 1_700_000_000, None).unwrap();
        let relay_addr = start_test_relay();
        sync_now_inner(&alice, relay_addr.to_string()).unwrap();

        // Bob blocks Alice's key before syncing - the note is decrypted/verified
        // (unchanged path) and then dropped, never stored, never returned.
        let alice_key = list_peers_inner(&bob).unwrap()[0].ed25519_pubkey.clone();
        block_key_now(&bob, &alice_key).unwrap();

        let bob_sync = sync_now_inner(&bob, relay_addr.to_string()).unwrap();
        assert!(bob_sync.received.is_none());
        assert_eq!(list_notes_inner(&bob).unwrap().len(), 0);
    }

    #[test]
    fn list_blocked_reflects_block_and_unblock() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();

        block_key_now(&session, "ed-bob").unwrap();
        block_key_now(&session, "ed-carol").unwrap();
        assert_eq!(list_blocked_inner(&session).unwrap().len(), 2);

        unblock_key_now(&session, "ed-bob").unwrap();
        let blocked = list_blocked_inner(&session).unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].ed25519_pubkey, "ed-carol");
    }

    // -- Slice 05: self-signed peer cards (bind X25519 to Ed25519) --

    /// Decode a `card_encoded()`/`whoami_card()` string back into its `SignedCard`
    /// JSON `Value`, tamper one field, and re-encode - the same shape a corrupted or
    /// forged card would have.
    fn tamper_card(card_base64: &str, field: &str, value: serde_json::Value) -> String {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(card_base64.trim())
            .unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json[field] = value;
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&json).unwrap())
    }

    /// Decode a card's `x25519_public` field as a bare string, without needing to name
    /// any x25519-dalek type in this crate.
    fn card_x25519_public_field(card_base64: &str) -> String {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(card_base64.trim())
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["x25519_public"].as_str().unwrap().to_string()
    }

    #[test]
    fn add_peer_rejects_a_card_with_a_tampered_x25519_key() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();
        let eve_dir = dir.path().join("eve");
        fs::create_dir_all(&eve_dir).unwrap();
        let eve = create_identity_session(&eve_dir, "eve-pass").unwrap();

        let bob_card = whoami_card(&bob);
        let eve_x25519 = card_x25519_public_field(&whoami_card(&eve));
        let tampered = tamper_card(
            &bob_card,
            "x25519_public",
            serde_json::Value::String(eve_x25519),
        );

        let result = add_peer_card(&session, "bob", &tampered, false);
        assert!(matches!(
            result,
            Err(AppError::Card(CardError::SignatureInvalid))
        ));
        assert_eq!(list_peers_inner(&session).unwrap().len(), 0);
    }

    #[test]
    fn add_peer_rejects_a_card_with_a_tampered_signature() {
        use base64::Engine as _;

        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();

        let bob_card = whoami_card(&bob);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bob_card.trim())
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(json["signature"].as_str().unwrap())
            .unwrap();
        sig_bytes[0] ^= 0xFF;
        let tampered = tamper_card(
            &bob_card,
            "signature",
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(sig_bytes)),
        );

        let result = add_peer_card(&session, "bob", &tampered, false);
        assert!(matches!(
            result,
            Err(AppError::Card(CardError::SignatureInvalid))
        ));
        assert_eq!(list_peers_inner(&session).unwrap().len(), 0);
    }

    #[test]
    fn add_peer_rejects_a_legacy_unsigned_card_with_a_friendly_message() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();

        // Today's pre-Slice-05 shape: only the two bare keys, no version/signature -
        // `Identity::public_card` (kept for sync.rs's tests, SLICE-05.md's deviation
        // note) produces exactly this shape.
        use base64::Engine as _;
        let legacy = bob.identity.public_card();
        let legacy_card = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&legacy).unwrap());

        let result = add_peer_card(&session, "bob", &legacy_card, false);
        assert!(matches!(
            result,
            Err(AppError::Card(CardError::LegacyUnsigned))
        ));
    }

    #[test]
    fn add_peer_rejects_a_conflicting_x25519_key_for_an_already_pinned_peer() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();
        let bob_dir = dir.path().join("bob");
        fs::create_dir_all(&bob_dir).unwrap();
        let bob = create_identity_session(&bob_dir, "bob-pass").unwrap();

        let bob_card = whoami_card(&bob);
        add_peer_card(&session, "bob", &bob_card, false).unwrap();
        let pinned_x25519_before = list_peers_inner(&session).unwrap()[0].ed25519_pubkey.clone();

        // A validly-signed card for Bob's Ed25519 key but a *different* X25519 key -
        // not a tamper (the signature verifies fine), a genuine claim of a new key.
        // Constructed by reusing Bob's real signing key with an unrelated identity's
        // freshly generated X25519 secret and calling the real `card_encoded()` on it
        // - the same composition production code uses, no duplicated crypto in the
        // test, and no need to name any x25519-dalek type in this crate (the fresh
        // secret is *moved* out of a throwaway `Identity::create`d session).
        let bob2_dir = dir.path().join("bob2");
        fs::create_dir_all(&bob2_dir).unwrap();
        let bob_new_keys = create_identity_session(&bob2_dir, "bob2-pass").unwrap();
        let bob_new_x25519_identity = Identity {
            signing_key: bob.identity.signing_key.clone(),
            x25519_secret: bob_new_keys.identity.x25519_secret,
            db_key: bob.identity.db_key.clone(),
        };
        let conflicting_card = bob_new_x25519_identity.card_encoded();

        let result = add_peer_card(&session, "bob", &conflicting_card, false);
        match result {
            Err(AppError::Card(CardError::PinnedKeyConflict {
                label,
                ed25519_fingerprint,
                existing_x25519_display,
                offered_x25519_display,
            })) => {
                assert_eq!(label, "bob");
                assert!(!ed25519_fingerprint.is_empty());
                assert_ne!(existing_x25519_display, offered_x25519_display);
            }
            other => panic!("expected PinnedKeyConflict, got {other:?}"),
        }
        // The pin's stored X25519 key is left untouched.
        let peers = list_peers_inner(&session).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ed25519_pubkey, pinned_x25519_before);
    }
}
