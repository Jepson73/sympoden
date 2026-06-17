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

async function refreshNotes() {
  const notes = await invoke("list_notes");
  notesList.innerHTML = "";
  for (const note of notes) {
    const li = document.createElement("li");
    const when = new Date(note.created_at * 1000).toLocaleString();
    li.innerHTML = `<div>${escapeHtml(note.body)}</div><div class="meta">${when} — ${note.author_pubkey.slice(0, 8)}…</div>`;
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
    await invoke("add_peer", { card: decoded });
    showStatus("Peer added.", false);
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
    if (result.pushed.length) parts.push(`pushed ${result.pushed.length} note(s)`);
    parts.push(result.received ? "received a new note" : "nothing new from the relay");
    showStatus(parts.join(", ") + ".", false);
    await refreshNotes();
  } catch (err) {
    showStatus(String(err), true);
  }
});

init();
