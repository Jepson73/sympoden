//! Trust-on-first-use classification (Slice 02): binds a note's already-verified
//! author to a pinned peer, purely locally and after the fact. This module never
//! affects whether a note is accepted, decrypted, or signature-verified (that's
//! `sync::receive_incoming` and `content::Note::verify`, both untouched) - it only
//! decides how an already-trusted-as-authentic note is *displayed*. See
//! `docs/slices/SLICE-02.md` for the property this closes and why "changed key" is a
//! re-pin-time check (`Store::add_peer`), not a per-note classification.

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::error::ContentError;
use crate::store::{PinnedPeer, StoredNote};

/// Who, locally, a note's author resolves to. Computed fresh against the *current*
/// peers table every time a note is classified - never frozen at receive time (SLICE-02
/// D3): if a peer is pinned after some of their notes already arrived as `Unknown`,
/// reclassifying shows those same notes as `Known` on the next pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AuthorTrust {
    /// The note's author is this identity itself.
    Own,
    /// The note's author exactly matches a pinned peer's Ed25519 key.
    Known(String),
    /// The note's author matches no pinned peer (including when none is pinned yet).
    /// Must always be rendered distinctly and unmistakably - never confusable with a
    /// known peer's label. The note itself is still verified and stored; this is
    /// identification, not a delivery gate.
    Unknown,
}

/// Classify `author_pubkey` against `my_verifying_key` (this identity) and `peers` (the
/// current pin set). Pure and side-effect-free - the only inputs are already-decoded
/// key material, so this has no I/O and no fallible path of its own.
pub fn classify_author(
    author_pubkey: &VerifyingKey,
    my_verifying_key: &VerifyingKey,
    peers: &[PinnedPeer],
) -> AuthorTrust {
    if author_pubkey == my_verifying_key {
        return AuthorTrust::Own;
    }

    let author_hex = hex::encode(author_pubkey.as_bytes());
    match peers.iter().find(|peer| peer.ed25519_pubkey == author_hex) {
        Some(peer) => AuthorTrust::Known(peer.label.clone()),
        None => AuthorTrust::Unknown,
    }
}

/// A note paired with its author's trust classification. Fields are private and there
/// is no public constructor other than `classify_stored_note` below - this is SLICE-02
/// D1's non-bypassability requirement made structural: no display code anywhere can
/// hold a `TrustedNote` without having gone through classification, because there is no
/// other way to produce one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedNote {
    note: StoredNote,
    trust: AuthorTrust,
}

impl TrustedNote {
    pub fn note(&self) -> &StoredNote {
        &self.note
    }

    pub fn trust(&self) -> &AuthorTrust {
        &self.trust
    }
}

/// Decode `note.author_pubkey` (hex) and classify it, wrapping the result. The only
/// error path is a malformed stored pubkey - notes already passed `Note::verify()`
/// before ever reaching the store, so in practice this only fires on a corrupted
/// database row, never on a legitimately received note.
pub fn classify_stored_note(
    note: StoredNote,
    my_verifying_key: &VerifyingKey,
    peers: &[PinnedPeer],
) -> Result<TrustedNote, ContentError> {
    let author_pubkey = decode_hex_verifying_key(&note.author_pubkey)?;
    let trust = classify_author(&author_pubkey, my_verifying_key, peers);
    Ok(TrustedNote { note, trust })
}

fn decode_hex_verifying_key(hex_str: &str) -> Result<VerifyingKey, ContentError> {
    let bytes = hex::decode(hex_str).map_err(|e| ContentError::Malformed(e.to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ContentError::Malformed("author_pubkey has the wrong length".to_string()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| ContentError::Malformed(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::content::Note;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn pinned(label: &str, key: &VerifyingKey) -> PinnedPeer {
        PinnedPeer {
            label: label.to_string(),
            ed25519_pubkey: hex::encode(key.as_bytes()),
            x25519_pubkey: "irrelevant-for-author-classification".to_string(),
            first_seen: 1_700_000_000,
        }
    }

    #[test]
    fn own_key_classifies_as_own_even_with_peers_pinned() {
        let me = SigningKey::generate(&mut OsRng).verifying_key();
        let bob = SigningKey::generate(&mut OsRng).verifying_key();
        let peers = vec![pinned("bob", &bob)];

        assert_eq!(classify_author(&me, &me, &peers), AuthorTrust::Own);
    }

    #[test]
    fn a_pinned_peers_key_classifies_as_known_by_label() {
        // Regression guard for the hex/base64 encoding trap: this only passes if the
        // peers-table encoding and the comparison encoding actually agree.
        let me = SigningKey::generate(&mut OsRng).verifying_key();
        let bob = SigningKey::generate(&mut OsRng).verifying_key();
        let peers = vec![pinned("bob", &bob)];

        assert_eq!(
            classify_author(&bob, &me, &peers),
            AuthorTrust::Known("bob".to_string())
        );
    }

    #[test]
    fn an_unpinned_key_classifies_as_unknown() {
        let me = SigningKey::generate(&mut OsRng).verifying_key();
        let bob = SigningKey::generate(&mut OsRng).verifying_key();
        let stranger = SigningKey::generate(&mut OsRng).verifying_key();
        let peers = vec![pinned("bob", &bob)];

        assert_eq!(classify_author(&stranger, &me, &peers), AuthorTrust::Unknown);
    }

    #[test]
    fn no_pinned_peers_at_all_classifies_as_unknown_not_a_panic() {
        let me = SigningKey::generate(&mut OsRng).verifying_key();
        let someone = SigningKey::generate(&mut OsRng).verifying_key();

        assert_eq!(classify_author(&someone, &me, &[]), AuthorTrust::Unknown);
    }

    #[test]
    fn classify_stored_note_marks_a_self_authored_note_as_own_not_unknown() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let me = signing_key.verifying_key();
        let note = Note::new(&signing_key, "hello".to_string(), 1_700_000_000);

        let trusted = classify_stored_note(note.to_stored(), &me, &[]).unwrap();
        assert_eq!(*trusted.trust(), AuthorTrust::Own);
    }

    #[test]
    fn classify_stored_note_rejects_a_malformed_author_pubkey() {
        let me = SigningKey::generate(&mut OsRng).verifying_key();
        let mut bad = Note::new(
            &SigningKey::generate(&mut OsRng),
            "hello".to_string(),
            1_700_000_000,
        )
        .to_stored();
        bad.author_pubkey = "not hex".to_string();

        let result = classify_stored_note(bad, &me, &[]);
        assert!(matches!(result, Err(ContentError::Malformed(_))));
    }
}
