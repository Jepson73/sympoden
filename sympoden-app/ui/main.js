// Plain vanilla JS, no build step. Talks to the Rust engine only through the
// Tauri commands registered in src/main.rs - no security logic lives here.

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);

const statusEl = document.getElementById("status");
const unlockSection = document.getElementById("unlock-section");
const unlockHeading = document.getElementById("unlock-heading");
const appSection = document.getElementById("app-section");
const passphraseInput = document.getElementById("passphrase");
const unlockBtn = document.getElementById("unlock-btn");
const createBtn = document.getElementById("create-btn");
const myCardEl = document.getElementById("my-card");
const peerLabelInput = document.getElementById("peer-label");
const peerCardInput = document.getElementById("peer-card");
const addPeerBtn = document.getElementById("add-peer-btn");
const peerListEl = document.getElementById("peer-list");
const blockedListEl = document.getElementById("blocked-list");
const recipientListEl = document.getElementById("recipient-list");
const noteBodyInput = document.getElementById("note-body");
const postBtn = document.getElementById("post-btn");
const relayAddrInput = document.getElementById("relay-addr");
const syncBtn = document.getElementById("sync-btn");
const notesList = document.getElementById("notes");

function showStatus(message, isError) {
  statusEl.textContent = message || "";
  statusEl.style.color = isError ? "#a00" : "#070";
}

// `trust` is the JSON form of the engine's AuthorTrust: "Own" | "Unknown" |
// {"Known": "<label>"}. Unknown must always read as unmistakably distinct from a
// known peer's label - that distinctness is the whole security point of Slice 02
// (see docs/slices/SLICE-02.md), so it gets its own class and a warning glyph, never
// just the absence of a label.
function describeTrust(trust) {
  if (trust === "Own") {
    return { text: "you", cssClass: "trust-own" };
  }
  if (trust === "Unknown") {
    return { text: "⚠ unknown sender", cssClass: "trust-unknown" };
  }
  if (trust && typeof trust === "object" && typeof trust.Known === "string") {
    return { text: trust.Known, cssClass: "trust-known" };
  }
  // Defensive fallback: an unrecognized shape must still read as untrusted, never as
  // a silently-passed-through known peer.
  return { text: "⚠ unknown sender", cssClass: "trust-unknown" };
}

// Spaced-out grouping already arrives from the engine's format_fingerprint - the
// frontend never recomputes the hash itself (Slice 03 D5: fingerprinting hashes the
// key, so it stays a Rust-side computation, not something trivially redone in JS).
function fingerprintSpan(fingerprint) {
  return `<span class="fingerprint">${escapeHtml(fingerprint)}</span>`;
}

async function refreshNotes() {
  const notes = await invoke("list_notes");
  notesList.innerHTML = "";
  for (const item of notes) {
    const { text: trustText, cssClass } = describeTrust(item.trust);
    const li = document.createElement("li");
    const when = new Date(item.note.created_at * 1000).toLocaleString();
    // "Block sender" passes the note's own author_pubkey directly - the exact key
    // already present in this note, never through label/fingerprint resolution. This
    // is the only route to block a stranger from the notes list itself (they have no
    // peer row to act on). Omitted for the user's own notes - blocking yourself is
    // meaningless (post_note never checks is_blocked).
    const blockBtn = item.trust === "Own" ? "" : ` <button data-block-sender="${escapeHtml(item.note.author_pubkey)}">Block sender</button>`;
    li.innerHTML = `<div>${escapeHtml(item.note.body)}</div><div class="meta">${when} — <span class="${cssClass}">${escapeHtml(trustText)}</span> ${fingerprintSpan(item.fingerprint)}${blockBtn}</div>`;
    notesList.appendChild(li);
  }
  for (const button of notesList.querySelectorAll("[data-block-sender]")) {
    button.addEventListener("click", async () => {
      await doBlockKey(button.getAttribute("data-block-sender"));
    });
  }
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// Outcome of add_peer/relabel_peer's "Outcome" variant - AddPeerOutcome's JSON form is
// the bare string "Added"/"AlreadyPinned", or {"AlreadyPinnedUnderLabel": {...}} for
// the loud no-op (Slice 03 Adjustment 3): re-adding an already-pinned key under a new
// label never silently renames it - relabel is the only way to do that.
function describeAddPeerOutcome(outcome) {
  if (outcome === "Added") return "Peer pinned.";
  if (outcome === "AlreadyPinned") return "Already pinned (no change).";
  if (outcome && outcome.AlreadyPinnedUnderLabel) {
    return `Already pinned as "${outcome.AlreadyPinnedUnderLabel.existing_label}" - use relabel to rename, not add-peer.`;
  }
  return "Peer pin outcome unrecognized.";
}

function describeCollision(existing) {
  return existing.map((p) => `${p.label} (${p.fingerprint})`).join(", ");
}

// The peer row exposes delete and block as two independently invokable controls,
// not one coupled action (SLICE-04.md §6/D-A's separable-underneath property): the
// "Remove" button is the default coupled action (delete + block), the "keep
// unblocked" checkbox next to it is the delete-without-block half, and the
// standalone "Block" button is the block-without-delete half - usable on a peer you
// want to keep pinned but stop hearing from.
async function refreshPeers() {
  const peers = await invoke("list_peers");

  peerListEl.innerHTML = "";
  recipientListEl.innerHTML = "";

  for (const peer of peers) {
    const key = peer.ed25519_pubkey;
    const li = document.createElement("li");
    li.innerHTML = `${escapeHtml(peer.label)} ${fingerprintSpan(peer.fingerprint)}
      <span class="relabel-form">
        <input type="text" placeholder="new label" data-relabel-for="${escapeHtml(key)}" />
        <button data-relabel-btn-for="${escapeHtml(key)}">Rename</button>
      </span>
      <span class="peer-actions">
        <button data-remove-btn-for="${escapeHtml(key)}">Remove</button>
        <label><input type="checkbox" data-keep-unblocked-for="${escapeHtml(key)}" /> keep unblocked</label>
        <button data-block-btn-for="${escapeHtml(key)}">Block</button>
      </span>`;
    peerListEl.appendChild(li);

    const recipientLi = document.createElement("li");
    const checkboxId = `recipient-${key}`;
    recipientLi.innerHTML = `<label><input type="checkbox" id="${checkboxId}" data-recipient-key="${escapeHtml(key)}" checked /> ${escapeHtml(peer.label)} ${fingerprintSpan(peer.fingerprint)}</label>`;
    recipientListEl.appendChild(recipientLi);
  }

  for (const button of peerListEl.querySelectorAll("[data-relabel-btn-for]")) {
    button.addEventListener("click", async () => {
      const key = button.getAttribute("data-relabel-btn-for");
      const input = peerListEl.querySelector(`[data-relabel-for="${key}"]`);
      const newLabel = input.value.trim();
      if (!newLabel) return;
      await doRelabel(key, newLabel);
    });
  }

  for (const button of peerListEl.querySelectorAll("[data-remove-btn-for]")) {
    button.addEventListener("click", async () => {
      const key = button.getAttribute("data-remove-btn-for");
      const checkbox = peerListEl.querySelector(`[data-keep-unblocked-for="${key}"]`);
      await doRemovePeer(key, checkbox.checked);
    });
  }

  for (const button of peerListEl.querySelectorAll("[data-block-btn-for]")) {
    button.addEventListener("click", async () => {
      await doBlockKey(button.getAttribute("data-block-btn-for"));
    });
  }

  // Render-on-pin/unpin (SLICE-04.md's stated property): list_notes always
  // recomputes trust fresh against the current peers table, so the fix is just
  // calling it after every peer-table mutation, not a backend change.
  await refreshNotes();
}

async function refreshBlocked() {
  const blocked = await invoke("list_blocked");
  blockedListEl.innerHTML = "";
  for (const entry of blocked) {
    const li = document.createElement("li");
    li.innerHTML = `${fingerprintSpan(entry.fingerprint)} <button data-unblock-btn-for="${escapeHtml(entry.ed25519_pubkey)}">Unblock</button>`;
    blockedListEl.appendChild(li);
  }
  for (const button of blockedListEl.querySelectorAll("[data-unblock-btn-for]")) {
    button.addEventListener("click", async () => {
      await doUnblockKey(button.getAttribute("data-unblock-btn-for"));
    });
  }
}

async function doRemovePeer(ed25519Pubkey, keepUnblocked) {
  try {
    await invoke("remove_peer", { ed25519Pubkey, keepUnblocked });
    showStatus(keepUnblocked ? "Removed (left unblocked)." : "Removed and blocked.", false);
    await refreshPeers();
    await refreshBlocked();
  } catch (err) {
    showStatus(String(err), true);
  }
}

async function doBlockKey(ed25519Pubkey) {
  try {
    await invoke("block_key", { ed25519Pubkey });
    showStatus("Blocked.", false);
    await refreshBlocked();
  } catch (err) {
    showStatus(String(err), true);
  }
}

async function doUnblockKey(ed25519Pubkey) {
  try {
    await invoke("unblock_key", { ed25519Pubkey });
    showStatus("Unblocked.", false);
    await refreshBlocked();
  } catch (err) {
    showStatus(String(err), true);
  }
}

// `ed25519Pubkey` is the peer's exact key (straight from list_peers's own output, the
// same value rendered into the relabel button's data attribute) - never a label or a
// fingerprint to resolve. The GUI already knows exactly which peer it means; sending
// anything other than the exact key here is what caused the original "no pinned peer
// matches <64-hex-key>" bug (the backend used to run this through label/fingerprint
// resolution meant for typed CLI input, which a raw key never matches).
async function doRelabel(ed25519Pubkey, newLabel, confirmCollision) {
  try {
    const result = await invoke("relabel_peer", {
      ed25519Pubkey,
      newLabel,
      confirmCollision: !!confirmCollision,
    });
    if (result.NeedsCollisionConfirmation) {
      const existing = result.NeedsCollisionConfirmation.existing;
      if (confirm(`"${newLabel}" is already used by: ${describeCollision(existing)}. Rename anyway?`)) {
        await doRelabel(ed25519Pubkey, newLabel, true);
      }
      return;
    }
    showStatus(`Relabeled to "${newLabel}".`, false);
    await refreshPeers();
  } catch (err) {
    showStatus(String(err), true);
  }
}

async function enterApp() {
  unlockSection.classList.add("hidden");
  appSection.classList.remove("hidden");
  const card = await invoke("whoami");
  myCardEl.value = card;
  await refreshPeers(); // also refreshes notes, at its end
  await refreshBlocked();
}

async function init() {
  const exists = await invoke("has_identity");
  unlockHeading.textContent = exists ? "Unlock identity" : "Create identity";
  unlockBtn.classList.toggle("hidden", !exists);
  createBtn.classList.toggle("hidden", exists);
}

unlockBtn.addEventListener("click", async () => {
  try {
    await invoke("unlock_identity", { passphrase: passphraseInput.value });
    showStatus("Unlocked.", false);
    await enterApp();
  } catch (err) {
    showStatus(String(err), true);
  }
});

createBtn.addEventListener("click", async () => {
  try {
    await invoke("create_identity", { passphrase: passphraseInput.value });
    showStatus("Identity created.", false);
    await enterApp();
  } catch (err) {
    showStatus(String(err), true);
  }
});

async function doAddPeer(label, card, confirmCollision) {
  const result = await invoke("add_peer", { label, card, confirmCollision: !!confirmCollision });
  if (result === "IsSelf") {
    showStatus("That's your own card - refusing to pin yourself.", true);
    return;
  }
  if (result.NeedsCollisionConfirmation) {
    const existing = result.NeedsCollisionConfirmation.existing;
    if (confirm(`"${label}" is already used by: ${describeCollision(existing)}. Pin this as a second, different peer anyway?`)) {
      return doAddPeer(label, card, true);
    }
    showStatus("Add-peer cancelled.", false);
    return;
  }
  let message = describeAddPeerOutcome(result.Outcome.outcome);
  // D-B: re-adding a previously deleted-and-blocked key restores the pin but never
  // lifts the block - say so plainly, never silently leave it undiscoverable.
  if (result.Outcome.still_blocked) {
    message += " Note: this key is still blocked - mail from them will keep being dropped until you unblock it.";
  }
  showStatus(message, false);
  await refreshPeers();
}

addPeerBtn.addEventListener("click", async () => {
  try {
    await doAddPeer(peerLabelInput.value.trim(), peerCardInput.value.trim(), false);
  } catch (err) {
    showStatus(String(err), true);
  }
});

postBtn.addEventListener("click", async () => {
  try {
    const checkboxes = [...recipientListEl.querySelectorAll("[data-recipient-key]")];
    const checked = checkboxes.filter((cb) => cb.checked).map((cb) => cb.getAttribute("data-recipient-key"));
    // All checked (the default, and the common case with no peers yet) is exactly a
    // broadcast - send `recipients: undefined` rather than the full list, so the
    // common path matches the engine's own Broadcast target instead of happening to
    // enumerate the same set directedly.
    const recipients = checked.length === checkboxes.length ? undefined : checked;
    await invoke("post_note", { body: noteBodyInput.value, recipients });
    noteBodyInput.value = "";
    showStatus("Posted.", false);
    await refreshNotes();
  } catch (err) {
    showStatus(String(err), true);
  }
});

syncBtn.addEventListener("click", async () => {
  try {
    const result = await invoke("sync_now", { relay: relayAddrInput.value });
    const parts = [];
    // "Handed to the relay", not "delivered" - it's delivered once the peer syncs,
    // within the relay's retention window (best-effort is labelled best-effort).
    if (result.pushed.length) parts.push(`handed ${result.pushed.length} note(s) to the relay`);
    parts.push(result.received ? "received a new note" : "nothing new from the relay");
    showStatus(parts.join(", ") + ".", false);
    await refreshNotes();
  } catch (err) {
    showStatus(String(err), true);
  }
});

init();
