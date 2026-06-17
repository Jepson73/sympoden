//! Composes a note into a relay-bound envelope and back. No network I/O lives here —
//! that's the relay client, wired up alongside the CLI/UI once the relay binary
//! exists. This module is the engine-internal glue between `content` and `crypto`.

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
    fn receive_incoming_rejects_malformed_bytes() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let result = receive_incoming(b"not an envelope", &secret);
        assert!(result.is_err());
    }
}
