//! Tauri shell for Slice 01: a thin view over sympoden-engine. No security logic
//! lives here - identity, crypto, storage, and sync are all the engine's job.
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
use sympoden_engine::error::{ContentError, IdentityError, StoreError, SyncError};
use sympoden_engine::identity::{Identity, PublicCard};
use sympoden_engine::store::{Store, StoredNote};
use sympoden_engine::sync::{self, RelayClient};

const KEYFILE_NAME: &str = "identity.keyfile.json";
const DB_NAME: &str = "notes.sqlite";
const PEER_NAME: &str = "peer.json";

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
    #[error("invalid peer card: {0}")]
    InvalidCard(String),
    #[error("not unlocked")]
    NotUnlocked,
}

fn keyfile_path(dir: &Path) -> PathBuf {
    dir.join(KEYFILE_NAME)
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_NAME)
}

fn peer_path(dir: &Path) -> PathBuf {
    dir.join(PEER_NAME)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

fn whoami_card(session: &Session) -> PublicCard {
    session.identity.public_card()
}

fn add_peer_card(dir: &Path, card: &str) -> Result<(), AppError> {
    let parsed: PublicCard =
        serde_json::from_str(card).map_err(|e| AppError::InvalidCard(e.to_string()))?;

    // Validate the card actually parses into real keys before saving it.
    parsed.ed25519_verifying_key()?;
    parsed.x25519_public_key()?;

    let serialized =
        serde_json::to_vec_pretty(&parsed).map_err(|e| AppError::InvalidCard(e.to_string()))?;
    std::fs::write(peer_path(dir), serialized)?;
    Ok(())
}

fn load_peer(dir: &Path) -> Option<PublicCard> {
    let raw = std::fs::read(peer_path(dir)).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn post_note_now(session: &Session, body: String, created_at: i64) -> Result<String, AppError> {
    let note = Note::new(&session.identity.signing_key, body, created_at);
    session.store.insert_note(&note.to_stored())?;
    Ok(note.id_hex())
}

#[derive(Serialize)]
struct SyncResult {
    pushed: Vec<String>,
    received: Option<StoredNote>,
}

fn sync_now_inner(session: &Session, dir: &Path, relay: String) -> Result<SyncResult, AppError> {
    let client = RelayClient::new(relay);

    let mut pushed = Vec::new();
    if let Some(peer) = load_peer(dir) {
        let my_pubkey_hex = hex::encode(session.identity.signing_key.verifying_key().as_bytes());
        let pending = session.store.unsynced_own_notes(&my_pubkey_hex)?;
        for stored in pending {
            let note = Note::from_stored(&stored)?;
            let (routing_key, envelope_bytes) = sync::prepare_outgoing(&note, &peer)?;
            match client.push(&routing_key, &envelope_bytes)? {
                sync::PushOutcome::Accepted => {
                    session.store.mark_synced(&stored.id, now_unix())?;
                    pushed.push(stored.id);
                }
                sync::PushOutcome::RecipientSlotOccupied => {
                    // The peer hasn't pulled their previous note yet - the relay
                    // holds only one blob per recipient. Stop pushing for now; this
                    // note (and any after it) stay pending for the next sync.
                    break;
                }
            }
        }
    }

    let my_routing_key =
        sympoden_engine::crypto::routing_key_for(&session.identity.signing_key.verifying_key());
    let received = match client.pull(&my_routing_key)? {
        Some(envelope_bytes) => {
            let note = sync::receive_incoming(&envelope_bytes, &session.identity.x25519_secret)?;
            let stored = note.to_stored();
            session.store.insert_note(&stored)?;
            Some(stored)
        }
        None => None,
    };

    Ok(SyncResult { pushed, received })
}

fn list_notes_inner(session: &Session) -> Result<Vec<StoredNote>, AppError> {
    Ok(session.store.list_notes()?)
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
    serde_json::to_string(&whoami_card(session)).map_err(|e| e.to_string())
}

#[tauri::command]
fn add_peer(state: State<AppState>, card: String) -> Result<(), String> {
    add_peer_card(&state.data_dir, &card).map_err(|e| e.to_string())
}

#[tauri::command]
fn post_note(state: State<AppState>, body: String) -> Result<String, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    post_note_now(session, body, now_unix()).map_err(|e| e.to_string())
}

#[tauri::command]
fn sync_now(state: State<AppState>, relay: String) -> Result<SyncResult, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = guard.as_ref().ok_or_else(|| AppError::NotUnlocked.to_string())?;
    sync_now_inner(session, &state.data_dir, relay).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_notes(state: State<AppState>) -> Result<Vec<StoredNote>, String> {
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

        // whoami -> PublicCard (serialized to a String by the command wrapper): only
        // the two public keys, nothing else.
        let card_json = serde_json::to_value(whoami_card(&session)).unwrap();
        let card_obj = card_json.as_object().unwrap();
        let card_keys: std::collections::BTreeSet<String> = card_obj.keys().cloned().collect();
        let expected_card_keys: std::collections::BTreeSet<String> =
            ["ed25519_public", "x25519_public"]
                .into_iter()
                .map(String::from)
                .collect();
        assert_eq!(card_keys, expected_card_keys);

        // post_note -> a content-addressed id (String), then list_notes ->
        // Vec<StoredNote>: id/author_pubkey/body/created_at/signature/synced_at. The
        // body is the one piece of plaintext a command is meant to surface - the
        // user's own note, read back to them. Nothing else is secret: the pubkey and
        // signature are public verification data, not key material.
        let secret_body = "only the body should ever leave the process";
        post_note_now(&session, secret_body.to_string(), 1_700_000_000).unwrap();
        let notes = list_notes_inner(&session).unwrap();
        let note_json = serde_json::to_value(&notes[0]).unwrap();
        let note_obj = note_json.as_object().unwrap();
        assert_eq!(
            note_obj
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["id", "author_pubkey", "body", "created_at", "signature", "synced_at"]
                .into_iter()
                .map(String::from)
                .collect()
        );
        assert_eq!(note_obj["body"], secret_body);
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
        let result = add_peer_card(dir.path(), "not json at all");
        assert!(matches!(result, Err(AppError::InvalidCard(_))));
    }

    #[test]
    fn post_then_list_roundtrip() {
        let dir = tempdir().unwrap();
        let session = create_identity_session(dir.path(), "passphrase").unwrap();

        post_note_now(&session, "hello, world".to_string(), 1_700_000_000).unwrap();
        let notes = list_notes_inner(&session).unwrap();

        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].body, "hello, world");
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

        let bob_card_json = serde_json::to_string(&whoami_card(&bob)).unwrap();
        add_peer_card(&alice_dir, &bob_card_json).unwrap();

        let body = "hello bob, from a headless two-session test".to_string();
        post_note_now(&alice, body.clone(), 1_700_000_000).unwrap();

        let relay_addr = start_test_relay();

        // Alice pushes to the relay, then (in spirit) goes fully offline - nothing
        // about her session is touched again in this test.
        let alice_sync = sync_now_inner(&alice, &alice_dir, relay_addr.to_string()).unwrap();
        assert_eq!(alice_sync.pushed.len(), 1);
        assert!(alice_sync.received.is_none());

        // Bob syncs later and should see Alice's note arrive, verified and decrypted.
        let bob_sync = sync_now_inner(&bob, &bob_dir, relay_addr.to_string()).unwrap();
        let received = bob_sync
            .received
            .expect("bob should have received alice's note from the relay");
        assert_eq!(received.body, body);

        let bob_notes = list_notes_inner(&bob).unwrap();
        assert!(bob_notes.iter().any(|n| n.body == body));
    }
}
