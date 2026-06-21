//! Headless CLI harness for Slice 01: create an identity, post a note, sync it
//! through a blind relay to a peer who is never online at the same time.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand};
use thiserror::Error;

use sympoden_engine::content::Note;
use sympoden_engine::error::{ContentError, IdentityError, StoreError, SyncError};
use sympoden_engine::identity::{Identity, PublicCard};
use sympoden_engine::store::Store;
use sympoden_engine::sync::{self, RelayClient};
use sympoden_engine::trust::{self, AuthorTrust};

const KEYFILE_NAME: &str = "identity.keyfile.json";
const DB_NAME: &str = "notes.sqlite";

#[derive(Parser)]
#[command(name = "sympoden-cli", about = "Sympoden CLI")]
struct Cli {
    /// Directory holding this instance's keyfile, database, and peer card.
    #[arg(long, default_value = "./sympoden-data")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new identity and local database in --data-dir.
    Init,
    /// Print this identity's public card, to share with a peer out-of-band.
    Whoami,
    /// Pin a peer's public card (as printed by their `whoami`) under a local label.
    /// Trust-on-first-use: a second, different label is rejected (one peer per
    /// identity this slice), and re-adding the same label with a different key is
    /// rejected too - re-pinning is never silent.
    AddPeer { label: String, card: String },
    /// Write and sign a new note, stored locally.
    Post { body: String },
    /// Push any unsynced notes to the relay, then pull anything waiting for us.
    Sync {
        #[arg(long, default_value = "127.0.0.1:7878")]
        relay: String,
    },
    /// List all locally stored notes.
    List,
}

#[derive(Debug, Error)]
enum CliError {
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
    #[error("passphrases did not match")]
    PassphraseMismatch,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sympoden-cli: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Init => cmd_init(&cli.data_dir),
        Command::Whoami => cmd_whoami(&cli.data_dir),
        Command::AddPeer { label, card } => cmd_add_peer(&cli.data_dir, &label, &card),
        Command::Post { body } => cmd_post(&cli.data_dir, body),
        Command::Sync { relay } => cmd_sync(&cli.data_dir, &relay),
        Command::List => cmd_list(&cli.data_dir),
    }
}

fn keyfile_path(dir: &Path) -> PathBuf {
    dir.join(KEYFILE_NAME)
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_NAME)
}

/// Prompt for a passphrase, hidden, via the controlling TTY. When there is no TTY
/// (scripted/automated use, e.g. tests) there is no terminal to hide input from
/// anyway, so fall back to a plain line on stdin rather than failing outright.
fn prompt_passphrase(prompt: &str) -> Result<String, CliError> {
    use std::io::IsTerminal;

    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(prompt)?)
    } else {
        eprint!("{prompt}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
}

fn unlock(dir: &Path) -> Result<Identity, CliError> {
    let passphrase = prompt_passphrase("Passphrase: ")?;
    Ok(Identity::unlock(&keyfile_path(dir), &passphrase)?)
}

fn cmd_init(dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(dir)?;

    let passphrase = prompt_passphrase("Choose a passphrase: ")?;
    let confirm = prompt_passphrase("Confirm passphrase: ")?;
    if passphrase != confirm {
        return Err(CliError::PassphraseMismatch);
    }

    let identity = Identity::create(&keyfile_path(dir), &passphrase)?;
    Store::open(&db_path(dir), &identity.db_key)?;

    println!("Identity created in {}", dir.display());
    Ok(())
}

fn cmd_whoami(dir: &Path) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let card = identity.public_card();
    let encoded =
        BASE64.encode(serde_json::to_vec(&card).map_err(|e| CliError::InvalidCard(e.to_string()))?);
    println!("{encoded}");
    Ok(())
}

fn cmd_add_peer(dir: &Path, label: &str, card: &str) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;

    let decoded = BASE64
        .decode(card.trim())
        .map_err(|e| CliError::InvalidCard(e.to_string()))?;
    let parsed: PublicCard =
        serde_json::from_slice(&decoded).map_err(|e| CliError::InvalidCard(e.to_string()))?;

    // Validate the card actually parses into real keys before pinning it.
    let ed25519_pubkey = hex::encode(parsed.ed25519_verifying_key()?.as_bytes());
    let x25519_pubkey = hex::encode(parsed.x25519_public_key()?.to_bytes());

    store.add_peer(label, &ed25519_pubkey, &x25519_pubkey, now_unix())?;

    println!("Peer \"{label}\" pinned.");
    Ok(())
}

fn cmd_post(dir: &Path, body: String) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;

    let note = Note::new(&identity.signing_key, body, now_unix());
    store.insert_note(&note.to_stored())?;

    println!("Posted note {}", note.id_hex());
    Ok(())
}

fn cmd_sync(dir: &Path, relay_addr: &str) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;
    let client = RelayClient::new(relay_addr.to_string());
    let peers = store.list_peers()?;

    if let Some(peer) = peers.first() {
        let card = PublicCard::from_pinned_peer(peer)?;
        let my_pubkey_hex = hex::encode(identity.signing_key.verifying_key().as_bytes());
        for stored in store.unsynced_own_notes(&my_pubkey_hex)? {
            let note = Note::from_stored(&stored)?;
            let (routing_key, envelope_bytes) = sync::prepare_outgoing(&note, &card)?;
            match client.push(&routing_key, &envelope_bytes)? {
                sync::PushOutcome::Accepted => {
                    store.mark_synced(&stored.id, now_unix())?;
                    // "Handed to the relay", not "delivered" - the relay buffers it
                    // until the peer's next sync, within its retention window; if
                    // that window lapses first, the relay forgets it (invariant #6:
                    // best-effort is labelled best-effort, not overstated as done).
                    println!(
                        "Handed note {} to the relay (delivered once your peer next syncs)",
                        stored.id
                    );
                }
                sync::PushOutcome::RecipientSlotOccupied => {
                    // The peer hasn't pulled their previous note yet - the relay
                    // holds only one blob per recipient. Stop pushing for now; this
                    // note (and any after it) stay pending for the next sync.
                    println!(
                        "Peer hasn't picked up their previous note yet - note {} stays pending.",
                        stored.id
                    );
                    break;
                }
            }
        }
    } else {
        println!("No peer configured - skipping push.");
    }

    let my_routing_key =
        sympoden_engine::crypto::routing_key_for(&identity.signing_key.verifying_key());
    match client.pull(&my_routing_key)? {
        Some(envelope_bytes) => {
            let note = sync::receive_incoming(&envelope_bytes, &identity.x25519_secret)?;
            let trusted = trust::classify_stored_note(
                note.to_stored(),
                &identity.signing_key.verifying_key(),
                &peers,
            )?;
            println!(
                "Received note from {}: {}",
                trust_label(trusted.trust()),
                trusted.note().body
            );
            store.insert_note(trusted.note())?;
        }
        None => println!("Nothing new from the relay."),
    }

    Ok(())
}

fn cmd_list(dir: &Path) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;
    let peers = store.list_peers()?;
    let my_key = identity.signing_key.verifying_key();

    for note in store.list_notes()? {
        let trusted = trust::classify_stored_note(note, &my_key, &peers)?;
        println!(
            "[{}] {} ({}): {}",
            trusted.note().created_at,
            &trusted.note().id[..8.min(trusted.note().id.len())],
            trust_label(trusted.trust()),
            trusted.note().body
        );
    }
    Ok(())
}

/// How a trust classification reads in plain text output. The unknown case is
/// prefixed distinctly (`⚠`) so it cannot be mistaken for a known peer's label at a
/// glance - that distinctness is the security point of this slice (SLICE-02 D3).
fn trust_label(trust: &AuthorTrust) -> String {
    match trust {
        AuthorTrust::Own => "you".to_string(),
        AuthorTrust::Known(label) => label.clone(),
        AuthorTrust::Unknown => "⚠ unknown sender".to_string(),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
