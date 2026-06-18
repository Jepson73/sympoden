//! Composes a note into a relay-bound envelope and back, and talks to the relay
//! over its TCP+JSON protocol. This is the engine-internal glue between `content`
//! and `crypto`, plus the one place in the engine that does network I/O.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

use crate::content::Note;
use crate::crypto::{self, Envelope};
use crate::error::SyncError;
use crate::identity::PublicCard;

/// Seal `note` for `peer`, returning the relay routing key to push it under and the
/// envelope bytes to push. The relay only ever sees these two opaque values.
pub fn prepare_outgoing(note: &Note, peer: &PublicCard) -> Result<([u8; 32], Vec<u8>), SyncError> {
    let peer_x25519 = peer.x25519_public_key()?;
    let peer_ed25519 = peer.ed25519_verifying_key()?;

    let routing_key = crypto::routing_key_for(&peer_ed25519);
    let wire_bytes = note.to_wire_bytes()?;
    let envelope = crypto::seal_for_recipient(&wire_bytes, &peer_x25519)?;

    Ok((routing_key, envelope.to_bytes()))
}

/// Open an envelope pulled from the relay, verifying the contained note's signature
/// before returning it. Never trusts the relay's framing alone.
pub fn receive_incoming(
    envelope_bytes: &[u8],
    my_x25519_secret: &StaticSecret,
) -> Result<Note, SyncError> {
    let envelope = Envelope::from_bytes(envelope_bytes)?;
    let plaintext = crypto::open_envelope(&envelope, my_x25519_secret)?;
    let note = Note::from_wire_bytes(&plaintext)?;
    note.verify()?;
    Ok(note)
}

const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
// Matches sympoden-relay's OCCUPIED_ERROR sentinel. No shared crate between the two,
// so this is duplicated deliberately, same as the rest of the wire protocol.
const OCCUPIED_ERROR: &str = "occupied";

/// The relay holds at most one undelivered blob per routing key. A push when that
/// slot is already occupied is a normal, expected outcome (the recipient hasn't
/// pulled the previous note yet) - not a transport error.
#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted,
    RecipientSlotOccupied,
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum RelayRequest {
    Push {
        routing_key: String,
        blob: String,
        ttl_secs: u64,
    },
    Pull {
        routing_key: String,
    },
}

#[derive(Deserialize)]
struct RelayResponse {
    ok: bool,
    blob: Option<String>,
    error: Option<String>,
}

/// A client for the blind relay's TCP+JSON protocol. Speaks the same wire format as
/// `sympoden-relay` but shares no code or dependency with it.
pub struct RelayClient {
    addr: String,
}

impl RelayClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    /// Push an envelope to the relay under `routing_key`. Returns
    /// `PushOutcome::RecipientSlotOccupied` (not an error) if the recipient hasn't
    /// pulled their previous note yet - the relay holds only one blob per key.
    pub fn push(&self, routing_key: &[u8; 32], blob: &[u8]) -> Result<PushOutcome, SyncError> {
        let request = RelayRequest::Push {
            routing_key: hex::encode(routing_key),
            blob: BASE64.encode(blob),
            ttl_secs: DEFAULT_TTL_SECS,
        };
        let response = self.send(&request)?;
        if response.ok {
            return Ok(PushOutcome::Accepted);
        }
        if response.error.as_deref() == Some(OCCUPIED_ERROR) {
            return Ok(PushOutcome::RecipientSlotOccupied);
        }
        Err(SyncError::Relay(
            response.error.unwrap_or_else(|| "push failed".to_string()),
        ))
    }

    /// Pull whatever is waiting under our own routing key, if anything.
    pub fn pull(&self, routing_key: &[u8; 32]) -> Result<Option<Vec<u8>>, SyncError> {
        let request = RelayRequest::Pull {
            routing_key: hex::encode(routing_key),
        };
        let response = self.send(&request)?;
        if !response.ok {
            return Err(SyncError::Relay(
                response.error.unwrap_or_else(|| "pull failed".to_string()),
            ));
        }
        match response.blob {
            Some(encoded) => {
                let bytes = BASE64
                    .decode(&encoded)
                    .map_err(|e| SyncError::Relay(e.to_string()))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    fn send(&self, request: &RelayRequest) -> Result<RelayResponse, SyncError> {
        let mut stream =
            TcpStream::connect(&self.addr).map_err(|e| SyncError::Relay(e.to_string()))?;

        let mut line = serde_json::to_vec(request).map_err(|e| SyncError::Relay(e.to_string()))?;
        line.push(b'\n');
        stream
            .write_all(&line)
            .map_err(|e| SyncError::Relay(e.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|e| SyncError::Relay(e.to_string()))?;
        serde_json::from_str(&response_line).map_err(|e| SyncError::Relay(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand_core::OsRng;
    use tempfile::tempdir;

    #[test]
    fn round_trip_through_envelope() {
        let dir = tempdir().unwrap();
        let alice = Identity::create(&dir.path().join("alice.json"), "alice-pw").unwrap();
        let bob = Identity::create(&dir.path().join("bob.json"), "bob-pw").unwrap();
        let bob_card = bob.public_card();

        let note = Note::new(&alice.signing_key, "hello bob".to_string(), 1_700_000_000);
        let (routing_key, envelope_bytes) = prepare_outgoing(&note, &bob_card).unwrap();

        assert_eq!(
            routing_key,
            crypto::routing_key_for(&bob.signing_key.verifying_key())
        );

        let received = receive_incoming(&envelope_bytes, &bob.x25519_secret).unwrap();
        assert_eq!(received, note);
    }

    #[test]
    fn receive_incoming_fails_with_wrong_recipient_key() {
        use x25519_dalek::StaticSecret as Secret;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let note = Note::new(&signing_key, "hello".to_string(), 1_700_000_000);

        let recipient_secret = Secret::random_from_rng(OsRng);
        let recipient_public = x25519_dalek::PublicKey::from(&recipient_secret);
        let envelope =
            crypto::seal_for_recipient(&note.to_wire_bytes().unwrap(), &recipient_public).unwrap();

        let wrong_secret = Secret::random_from_rng(OsRng);
        let result = receive_incoming(&envelope.to_bytes(), &wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn receive_incoming_rejects_a_decryptable_envelope_with_a_bad_signature() {
        // The envelope decrypts cleanly (correct recipient key) but the note inside
        // carries a corrupted signature. This pins down that `note.verify()?` in
        // receive_incoming actually fires after decryption, not just that the
        // signature primitive rejects bad signatures in isolation (crypto.rs already
        // covers that).
        let dir = tempdir().unwrap();
        let alice = Identity::create(&dir.path().join("alice.json"), "alice-pw").unwrap();
        let bob = Identity::create(&dir.path().join("bob.json"), "bob-pw").unwrap();
        let bob_card = bob.public_card();

        let mut note = Note::new(&alice.signing_key, "hello bob".to_string(), 1_700_000_000);
        let mut sig_bytes = note.signature.to_bytes();
        sig_bytes[0] ^= 0xFF;
        note.signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let peer_x25519 = bob_card.x25519_public_key().unwrap();
        let envelope =
            crypto::seal_for_recipient(&note.to_wire_bytes().unwrap(), &peer_x25519).unwrap();

        let result = receive_incoming(&envelope.to_bytes(), &bob.x25519_secret);
        assert!(result.is_err());
    }

    #[test]
    fn receive_incoming_rejects_malformed_bytes() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let result = receive_incoming(b"not an envelope", &secret);
        assert!(result.is_err());
    }

    /// A minimal stand-in for sympoden-relay: replies to one request per connection
    /// with a canned response, so we can test RelayClient's wire-format handling
    /// without depending on the relay binary.
    fn start_mock_relay(response_body: impl Into<String>) -> std::net::SocketAddr {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let response_body = response_body.into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let _ = stream.write_all(response_body.as_bytes());
                let _ = stream.write_all(b"\n");
            }
        });

        addr
    }

    #[test]
    fn relay_client_push_succeeds_on_ok_response() {
        let addr = start_mock_relay(r#"{"ok":true}"#);
        let client = RelayClient::new(addr.to_string());

        let result = client.push(&[0u8; 32], b"ciphertext");
        assert_eq!(result.unwrap(), PushOutcome::Accepted);
    }

    #[test]
    fn relay_client_push_reports_occupied_slot_without_erroring() {
        let addr = start_mock_relay(r#"{"ok":false,"error":"occupied"}"#);
        let client = RelayClient::new(addr.to_string());

        let result = client.push(&[0u8; 32], b"ciphertext");
        assert_eq!(result.unwrap(), PushOutcome::RecipientSlotOccupied);
    }

    #[test]
    fn relay_client_pull_decodes_returned_blob() {
        let blob = BASE64.encode(b"opaque ciphertext");
        let addr = start_mock_relay(format!(r#"{{"ok":true,"blob":"{blob}"}}"#));
        let client = RelayClient::new(addr.to_string());

        let result = client.pull(&[0u8; 32]).unwrap();
        assert_eq!(result, Some(b"opaque ciphertext".to_vec()));
    }

    #[test]
    fn relay_client_pull_returns_none_when_nothing_pending() {
        let addr = start_mock_relay(r#"{"ok":true}"#);
        let client = RelayClient::new(addr.to_string());

        let result = client.pull(&[0u8; 32]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn relay_client_surfaces_error_responses() {
        let addr = start_mock_relay(r#"{"ok":false,"error":"boom"}"#);
        let client = RelayClient::new(addr.to_string());

        let result = client.push(&[0u8; 32], b"ciphertext");
        assert!(matches!(result, Err(SyncError::Relay(msg)) if msg == "boom"));
    }

    #[test]
    fn relay_client_fails_cleanly_when_relay_is_unreachable() {
        // Port 0 never accepts connections; this exercises the connect-failure path
        // without depending on any particular port being closed in the test sandbox.
        let client = RelayClient::new("127.0.0.1:0");
        let result = client.pull(&[0u8; 32]);
        assert!(result.is_err());
    }
}
