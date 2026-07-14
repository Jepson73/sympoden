//! Test-fixture-only binary for `scripts/demo.sh`'s SLICE-05.md D-C acceptance case:
//! a *validly signed* card for an already-pinned Ed25519 identity, carrying a
//! genuinely different X25519 key.
//!
//! This scenario cannot be produced by editing bytes (that only ever yields
//! `CardError::SignatureInvalid` - see the tampered-card demo.sh cases): the whole
//! point of Slice 05 is that only the real Ed25519 private key can produce a signature
//! that verifies over a new X25519 claim. Producing that scenario for the acceptance
//! demo therefore requires unlocking the keyfile and signing with the real key -
//! exactly the capability `sympoden-cli` deliberately does not expose as a subcommand
//! (rotation is an explicit non-goal; a general "sign arbitrary bytes with my key"
//! command would be a real capability addition, not a test fixture). This example is
//! not part of any shipped binary or crate surface; it exists only for `demo.sh`.
//!
//! Usage: mint_conflicting_card <keyfile-path> <passphrase>
//! Prints one line: a `SignedCard` for the keyfile's real Ed25519 key, paired with a
//! freshly generated (unrelated) X25519 key, signed by the keyfile's real signing key.

use std::path::Path;

use rand_core::OsRng;
use sympoden_engine::identity::Identity;
use x25519_dalek::StaticSecret;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, keyfile, passphrase] = args.as_slice() else {
        eprintln!("usage: mint_conflicting_card <keyfile-path> <passphrase>");
        std::process::exit(2);
    };

    let identity = Identity::unlock(Path::new(keyfile), passphrase).unwrap_or_else(|e| {
        eprintln!("failed to unlock {keyfile}: {e}");
        std::process::exit(1);
    });

    // Same Ed25519 identity, a fresh, unrelated X25519 key - the identity's own key
    // signs the new pairing, so the resulting card is validly signed, not tampered.
    let conflicting = Identity {
        signing_key: identity.signing_key,
        x25519_secret: StaticSecret::random_from_rng(OsRng),
        db_key: identity.db_key,
    };

    println!("{}", conflicting.card_encoded());
}
