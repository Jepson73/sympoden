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

async function refreshNotes() {
  const trustedNotes = await invoke("list_notes");
  notesList.innerHTML = "";
  for (const trusted of trustedNotes) {
    const note = trusted.note;
    const { text: trustText, cssClass } = describeTrust(trusted.trust);
    const li = document.createElement("li");
    const when = new Date(note.created_at * 1000).toLocaleString();
    li.innerHTML = `<div>${escapeHtml(note.body)}</div><div class="meta">${when} — <span class="${cssClass}">${escapeHtml(trustText)}</span></div>`;
    notesList.appendChild(li);
  }
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

async function enterApp() {
  unlockSection.classList.add("hidden");
  appSection.classList.remove("hidden");
  const card = await invoke("whoami");
  myCardEl.value = btoa(card);
  await refreshNotes();
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

addPeerBtn.addEventListener("click", async () => {
  try {
    const decoded = atob(peerCardInput.value.trim());
    await invoke("add_peer", { label: peerLabelInput.value.trim(), card: decoded });
    showStatus("Peer added.", false);
    await refreshNotes();
  } catch (err) {
    showStatus(String(err), true);
  }
});

postBtn.addEventListener("click", async () => {
  try {
    await invoke("post_note", { body: noteBodyInput.value });
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
