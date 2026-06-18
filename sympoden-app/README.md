# sympoden-app

The Tauri desktop shell for Slice 01 — a thin view over `sympoden-engine`. No
security logic lives here; see `src/main.rs` for the (small) set of Tauri commands
that wrap the engine, and `ui/` for the hand-written, build-step-free HTML/JS frontend.

**Unverified in this repo's dev sandbox**: it has no display server and is missing
the system webview libraries Tauri needs to even compile on Linux, so this crate is
excluded from the workspace's `default-members` (`cargo build`/`cargo test` with no
`-p` flag skip it) and could not be built or run end-to-end here. `cargo check -p
sympoden-app` was attempted and got as far as resolving and starting to build the
full dependency tree before failing at a missing system library, which is the
expected failure mode, not a code error - but the crate's own source has not been
type-checked by a compiler. Treat it as a careful first draft, not a verified build.

## Building on a real desktop

Install the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your
OS. On Debian/Ubuntu:

```
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev \
    libayatana-appindicator3-dev patchelf build-essential
```

Then, from the repo root:

```
cargo install tauri-cli --version "^2"
cd sympoden-app
cargo tauri dev
```

## Trying the Slice 01 flow

1. Start a relay: `../target/debug/sympoden-relay 127.0.0.1:7878`.
2. In one terminal: `SYMPODEN_DATA_DIR=/tmp/alice-app cargo tauri dev`. In another:
   `SYMPODEN_DATA_DIR=/tmp/bob-app cargo tauri dev`. (Without this override the app
   uses the OS app-data directory, which is what a real install should leave it at.)
3. In each window: create an identity, copy the "Your card" value into the *other*
   window's "Add a peer" box and click "Add peer".
4. In Alice's window: write a note, click "Post", then click "Sync now". Close her
   window entirely.
5. In Bob's window (already running, or launched fresh later): click "Sync now" —
   Alice's note should appear in the list.

## Known limitation: "handed to the relay" is not "delivered"

The relay holds at most one undelivered blob per recipient, with a 24h default TTL.
"Sync now" reports a note as handed to the relay, not delivered — it's delivered once
the peer actually syncs. If the peer doesn't sync before the relay's TTL lapses, the
relay forgets the blob and there's no automatic re-send; re-post (or re-sync once the
peer has caught up on whatever was occupying their slot) to retry. Reliable
re-delivery/retention is a Phase-1 concern (see `docs/ARCHITECTURE.md` §6); Slice 01's
job is to prove the async exchange works at all, not to make it durable.
