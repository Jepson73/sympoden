//! Tauri shell for Slice 01: a thin view over sympoden-engine. No security logic
//! lives here - identity, crypto, storage, and sync are all the engine's job; this
//! file only wires Tauri commands to engine calls and tracks per-session state
//! (the unlocked identity + open database) while the app is running.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, State};

use sympoden_engine::content::Note;
use sympoden_engine::identity::{Identity, PublicCard};
use sympoden_engine::store::{Store, StoredNote};
use sympoden_engine::sync::{self, RelayClient};

const KEYFILE_NAME: &str = "identity.keyfile.json";
const DB_NAME: &str = "notes.sqlite";
const PEER_NAME: &str = "peer.json";

/// Everything that exists only while the identity is unlocked: the signing/key-
/// agreement keys and the open database. Dropped (and zeroized, for the key
/// material) on app exit.
struct Session {
    identity: Identity,
    store: Store,
}

struct AppState {
    data_dir: PathBuf,
    session: Mutex<Option<Session>>,
}

fn keyfile_path(dir: &std::path::Path) -> PathBuf {
    dir.join(KEYFILE_NAME)
}

fn db_path(dir: &std::path::Path) -> PathBuf {
    dir.join(DB_NAME)
}

fn peer_path(dir: &std::path::Path) -> PathBuf {
    dir.join(PEER_NAME)
}

#[tauri::command]
fn has_identity(state: State<AppState>) -> bool {
    keyfile_path(&state.data_dir).exists()
}

#[tauri::command]
fn create_identity(state: State<AppState>, passphrase: String) -> Result<(), String> {
    let identity =
        Identity::create(&keyfile_path(&state.data_dir), &passphrase).map_err(|e| e.to_string())?;
    let store =
        Store::open(&db_path(&state.data_dir), &identity.db_key).map_err(|e| e.to_string())?;

    let mut session = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    *session = Some(Session { identity, store });
    Ok(())
}

#[tauri::command]
fn unlock_identity(state: State<AppState>, passphrase: String) -> Result<(), String> {
    let identity =
        Identity::unlock(&keyfile_path(&state.data_dir), &passphrase).map_err(|e| e.to_string())?;
    let store =
        Store::open(&db_path(&state.data_dir), &identity.db_key).map_err(|e| e.to_string())?;

    let mut session = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    *session = Some(Session { identity, store });
    Ok(())
}

#[tauri::command]
fn whoami(state: State<AppState>) -> Result<String, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = session.as_ref().ok_or("not unlocked")?;
    let card = session.identity.public_card();
    serde_json::to_string(&card).map_err(|e| e.to_string())
}

#[tauri::command]
fn add_peer(state: State<AppState>, card: String) -> Result<(), String> {
    let parsed: PublicCard = serde_json::from_str(&card).map_err(|e| e.to_string())?;
    parsed.ed25519_verifying_key().map_err(|e| e.to_string())?;
    parsed.x25519_public_key().map_err(|e| e.to_string())?;

    let serialized = serde_json::to_vec_pretty(&parsed).map_err(|e| e.to_string())?;
    std::fs::write(peer_path(&state.data_dir), serialized).map_err(|e| e.to_string())?;
    Ok(())
}

fn load_peer(dir: &std::path::Path) -> Option<PublicCard> {
    let raw = std::fs::read(peer_path(dir)).ok()?;
    serde_json::from_slice(&raw).ok()
}

#[tauri::command]
fn post_note(state: State<AppState>, body: String) -> Result<String, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = session.as_ref().ok_or("not unlocked")?;

    let created_at = now_unix();
    let note = Note::new(&session.identity.signing_key, body, created_at);
    session
        .store
        .insert_note(&note.to_stored())
        .map_err(|e| e.to_string())?;
    Ok(note.id_hex())
}

#[derive(Serialize)]
struct SyncResult {
    pushed: Vec<String>,
    received: Option<StoredNote>,
}

#[tauri::command]
fn sync_now(state: State<AppState>, relay: String) -> Result<SyncResult, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = session.as_ref().ok_or("not unlocked")?;
    let client = RelayClient::new(relay);

    let mut pushed = Vec::new();
    if let Some(peer) = load_peer(&state.data_dir) {
        let my_pubkey_hex = hex::encode(session.identity.signing_key.verifying_key().as_bytes());
        let pending = session
            .store
            .unsynced_own_notes(&my_pubkey_hex)
            .map_err(|e| e.to_string())?;
        for stored in pending {
            let note = Note::from_stored(&stored).map_err(|e| e.to_string())?;
            let (routing_key, envelope_bytes) =
                sync::prepare_outgoing(&note, &peer).map_err(|e| e.to_string())?;
            let outcome = client
                .push(&routing_key, &envelope_bytes)
                .map_err(|e| e.to_string())?;
            match outcome {
                sync::PushOutcome::Accepted => {
                    session
                        .store
                        .mark_synced(&stored.id, now_unix())
                        .map_err(|e| e.to_string())?;
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
    let received = match client.pull(&my_routing_key).map_err(|e| e.to_string())? {
        Some(envelope_bytes) => {
            let note = sync::receive_incoming(&envelope_bytes, &session.identity.x25519_secret)
                .map_err(|e| e.to_string())?;
            let stored = note.to_stored();
            session
                .store
                .insert_note(&stored)
                .map_err(|e| e.to_string())?;
            Some(stored)
        }
        None => None,
    };

    Ok(SyncResult { pushed, received })
}

#[tauri::command]
fn list_notes(state: State<AppState>) -> Result<Vec<StoredNote>, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "internal error".to_string())?;
    let session = session.as_ref().ok_or("not unlocked")?;
    session.store.list_notes().map_err(|e| e.to_string())
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

    // Standard Tauri pattern: `run` only errors if the webview framework itself
    // fails to initialize, which is unrecoverable - there's no UI left to report
    // into. Every Tauri app does this; it's the framework's intended top level.
    #[allow(clippy::expect_used)]
    result.expect("error while running the sympoden-app");
}
