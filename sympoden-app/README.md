# sympoden-app

The Tauri desktop shell for Slice 01 — a thin view over `sympoden-engine`. No
security logic lives here; see `src/main.rs` for the (small) set of Tauri commands
that wrap the engine, and `ui/` for the hand-written, build-step-free HTML/JS frontend.

Every `#[tauri::command]` is a thin lock-and-delegate wrapper over a plain function
(no Tauri types in its signature) that does the actual work, so the security-critical
path - identity create/unlock, post, sync - is unit-tested headlessly by calling those
plain functions directly, with no webview or display server involved. See the `tests`
module at the bottom of `src/main.rs`: create/unlock roundtrip, a wrong passphrase
failing cleanly (and never echoing the attempted passphrase back in the error), a
post-then-list roundtrip, a full two-session sync exchange through a real in-process
relay (a live TCP listener with a genuine store-and-forward `HashMap`, not a canned
single-response double - push and pull happen as two separate `sync_now_inner` calls,
so the blob only round-trips if the listener actually persists it across connections;
this is the only test proving the app's own push+pull+receive orchestration is
correct, since `scripts/demo.sh` exercises the CLI's separate sync path instead), and
two tests proving no secret ever crosses into a command's return value -
one at the type level (`Session`/`Identity`/`Store` don't implement `Serialize`, so a
command literally cannot return them) and one that inspects the actual JSON shape of
every return type. The app emits no Tauri events, so command return values and error
strings are the whole IPC surface; there is no separate event channel to also audit.

## Build status

This crate is excluded from the workspace's `default-members` (`cargo build`/`cargo
test` with no `-p` flag skip it) because it needs system webview libraries a plain
dev/CI box may not have - see "Building on a real desktop" below. With those
libraries present, `cargo build -p sympoden-app` and `cargo test -p sympoden-app` both
succeed and have been verified to do so. `cargo clippy -p sympoden-app --all-targets`
is clean.

## Known residual risk: the webview glue itself is untested

What's verified above is the engine logic behind each button - the Rust side of
identity, storage, and sync. The webview glue (`ui/main.js` calling
`window.__TAURI__.core.invoke`, the resulting render into the DOM) has **no**
automated coverage, and can't get any in a sandbox with no display server and no
WebDriver/`tauri-driver` tooling installed. "Done" here means compile-clean and
headless-verified at the command layer, not "the two-button GUI was clicked through."
A manual two-instance GUI walkthrough on a real desktop (see "Trying the Slice 01
flow" below) is still outstanding and is the one acceptance step this crate's own
test suite cannot stand in for.

`icons/icon.png` is a solid-grey 256x256 placeholder, present only because
`tauri.conf.json`'s window/bundle config requires an icon file to exist for the build
to succeed at all. Replace it with real artwork whenever Slice 01 gets a visual design
pass - explicitly out of scope here (see the slice's non-goals: no styling).

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
