//! Headless CLI harness: create an identity, post a note (broadcast or directed to a
//! subset of pinned peers), sync it through a blind relay, and manage pinned peers
//! (key-as-identity, Slice 03 — see docs/slices/SLICE-03.md).

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
use sympoden_engine::identity::{Identity, PublicCard, fingerprint_hex, format_fingerprint};
use sympoden_engine::store::{AddPeerOutcome, PinnedPeer, SendTargets, Store, resolve_peer_query};
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
    /// A peer is identified by key, not label: a different key may share a label with
    /// an existing peer (a collision, warned about by default and rejected with
    /// --strict); re-adding an already-pinned key under a different label never
    /// silently renames it - use relabel-peer for that.
    AddPeer {
        label: String,
        card: String,
        /// Refuse (instead of warn-and-proceed) when this label is already used by a
        /// different pinned peer.
        #[arg(long)]
        strict: bool,
    },
    /// Rename a pinned peer's label without changing its key. The peer is addressed by
    /// label, fingerprint, or "label#fingerprint" (see list-peers for fingerprints).
    RelabelPeer {
        query: String,
        new_label: String,
        /// Refuse (instead of warn-and-proceed) when new_label is already used by a
        /// different pinned peer.
        #[arg(long)]
        strict: bool,
    },
    /// List all pinned peers, each shown as label and fingerprint.
    ListPeers,
    /// Write and sign a new note, stored locally, addressed to all pinned peers
    /// (broadcast, the default) or to an explicit subset (repeatable --to).
    Post {
        body: String,
        /// A recipient, by label, fingerprint, or "label#fingerprint". Repeatable. If
        /// omitted, the note is addressed to every currently pinned peer.
        #[arg(long = "to")]
        to: Vec<String>,
    },
    /// Push any unsynced notes to the relay (per pending recipient), then pull
    /// anything waiting for us.
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
    #[error("\"{label}\" is already pinned to a different peer - refusing under --strict")]
    LabelCollisionRefused {
        label: String,
        candidates: Vec<PinnedPeer>,
    },
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
        Command::AddPeer { label, card, strict } => {
            cmd_add_peer(&cli.data_dir, &label, &card, strict)
        }
        Command::RelabelPeer {
            query,
            new_label,
            strict,
        } => cmd_relabel_peer(&cli.data_dir, &query, &new_label, strict),
        Command::ListPeers => cmd_list_peers(&cli.data_dir),
        Command::Post { body, to } => cmd_post(&cli.data_dir, body, to),
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

/// Short "label (fingerprint)" form used everywhere a peer is printed.
fn describe_peer(peer: &PinnedPeer) -> String {
    format!(
        "{} ({})",
        peer.label,
        format_fingerprint(&fingerprint_hex(&peer.ed25519_pubkey))
    )
}

/// Print a warning naming each colliding peer, or return an error if `strict`. Returns
/// `Ok(())` (after optionally warning) when the caller should proceed.
fn handle_collision(
    label: &str,
    collisions: Vec<PinnedPeer>,
    strict: bool,
) -> Result<(), CliError> {
    if collisions.is_empty() {
        return Ok(());
    }
    if strict {
        return Err(CliError::LabelCollisionRefused {
            label: label.to_string(),
            candidates: collisions,
        });
    }
    for existing in &collisions {
        eprintln!(
            "warning: \"{label}\" is already used by a pinned peer ({}) - pinning a second, different peer under the same label",
            format_fingerprint(&fingerprint_hex(&existing.ed25519_pubkey))
        );
    }
    Ok(())
}

fn cmd_add_peer(dir: &Path, label: &str, card: &str, strict: bool) -> Result<(), CliError> {
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

    // The collision pre-check only matters for a genuinely new key - if this key is
    // already pinned, add_peer's own outcome (AlreadyPinned/AlreadyPinnedUnderLabel)
    // is the whole story and nothing new is being written.
    if store.get_peer_by_key(&ed25519_pubkey)?.is_none() {
        let collisions = store.check_label_collision(label, &ed25519_pubkey)?;
        handle_collision(label, collisions, strict)?;
    }

    match store.add_peer(label, &ed25519_pubkey, &x25519_pubkey, now_unix())? {
        AddPeerOutcome::Added => println!("Peer \"{label}\" pinned."),
        AddPeerOutcome::AlreadyPinned => println!("Peer \"{label}\" already pinned (no change)."),
        AddPeerOutcome::AlreadyPinnedUnderLabel { existing_label } => {
            println!("already pinned as \"{existing_label}\" - use relabel-peer to rename");
        }
    }
    Ok(())
}

fn cmd_relabel_peer(dir: &Path, query: &str, new_label: &str, strict: bool) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;
    let peers = store.list_peers()?;

    let target = resolve_peer_query(query, &peers)?.clone();

    let collisions = store.check_label_collision(new_label, &target.ed25519_pubkey)?;
    handle_collision(new_label, collisions, strict)?;

    store.relabel_peer(&target.ed25519_pubkey, new_label)?;
    println!("Relabeled \"{}\" to \"{new_label}\".", target.label);
    Ok(())
}

fn cmd_list_peers(dir: &Path) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;

    for peer in store.list_peers()? {
        println!("{}", describe_peer(&peer));
    }
    Ok(())
}

fn cmd_post(dir: &Path, body: String, to: Vec<String>) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;

    let targets = if to.is_empty() {
        SendTargets::Broadcast
    } else {
        let peers = store.list_peers()?;
        let mut keys = Vec::with_capacity(to.len());
        for query in &to {
            match resolve_peer_query(query, &peers) {
                Ok(peer) => keys.push(peer.ed25519_pubkey.clone()),
                Err(StoreError::AmbiguousPeerQuery { candidates, .. }) => {
                    eprintln!("\"{query}\" is ambiguous - matches:");
                    for candidate in &candidates {
                        eprintln!("  {}", describe_peer(candidate));
                    }
                    return Err(StoreError::AmbiguousPeerQuery {
                        query: query.clone(),
                        candidates,
                    }
                    .into());
                }
                Err(e) => return Err(e.into()),
            }
        }
        SendTargets::Directed(keys)
    };

    // Resolve and record targets *before* the note exists, so an unresolvable
    // recipient never leaves an orphaned, unaddressed note behind.
    let note = Note::new(&identity.signing_key, body, now_unix());
    store.record_pending_sends(&note.id_hex(), &targets)?;
    store.insert_note(&note.to_stored())?;

    println!("Posted note {}", note.id_hex());
    Ok(())
}

fn cmd_sync(dir: &Path, relay_addr: &str) -> Result<(), CliError> {
    let identity = unlock(dir)?;
    let store = Store::open(&db_path(dir), &identity.db_key)?;
    let client = RelayClient::new(relay_addr.to_string());

    let pending = store.pending_sends()?;
    if pending.is_empty() {
        println!("Nothing pending to push.");
    }
    for send in pending {
        let note = Note::from_stored(&send.note)?;
        let card = PublicCard::from_pinned_peer(&send.peer)?;
        let (routing_key, envelope_bytes) = sync::prepare_outgoing(&note, &card)?;
        match client.push(&routing_key, &envelope_bytes)? {
            sync::PushOutcome::Accepted => {
                store.mark_send_pushed(&send.note.id, &send.peer.ed25519_pubkey, now_unix())?;
                // "Handed to the relay", not "delivered" - the relay buffers it until
                // the peer's next sync, within its retention window; if that window
                // lapses first, the relay forgets it (invariant #6: best-effort is
                // labelled best-effort, not overstated as done).
                println!(
                    "Handed note {} to the relay for {}",
                    send.note.id,
                    describe_peer(&send.peer)
                );
            }
            sync::PushOutcome::RecipientSlotOccupied => {
                // This recipient hasn't pulled their previous note yet - the relay
                // holds only one blob per recipient. Leave this row pending and move
                // on to the next pending recipient; one occupied slot must never block
                // delivery to anyone else.
                println!(
                    "{} hasn't picked up their previous note yet - note {} stays pending for them.",
                    describe_peer(&send.peer),
                    send.note.id
                );
            }
        }
    }

    let peers = store.list_peers()?;
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
                trust_label(trusted.trust(), &trusted.note().author_pubkey),
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
            trust_label(trusted.trust(), &trusted.note().author_pubkey),
            trusted.note().body
        );
    }
    Ok(())
}

/// How a trust classification reads in plain text output. The unknown case is
/// prefixed distinctly (`⚠`) so it cannot be mistaken for a known peer's label at a
/// glance - that distinctness is the security point of Slice 02 (SLICE-02 D3). Known
/// and Unknown both also carry the author's fingerprint (Slice 03 D5) - computed here
/// from the raw author key, not from `AuthorTrust` itself - so two different
/// same-labeled or unpinned senders read as visibly different, not just two different
/// instances of the same string.
fn trust_label(trust: &AuthorTrust, author_pubkey_hex: &str) -> String {
    let fingerprint = || format_fingerprint(&fingerprint_hex(author_pubkey_hex));
    match trust {
        AuthorTrust::Own => "you".to_string(),
        AuthorTrust::Known(label) => format!("{label} ({})", fingerprint()),
        AuthorTrust::Unknown => format!("⚠ unknown sender ({})", fingerprint()),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
