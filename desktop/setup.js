const params = new URLSearchParams(location.search);
const input = document.getElementById("address");
const errorEl = document.getElementById("error"), statusEl = document.getElementById("status");
const busyButtons = [document.getElementById("connect"), document.getElementById("find")];
errorEl.textContent = params.get("error") || "";
input.value = (params.get("box") || "").replace(/^https:\/\//, "");

let busy = false;
function setBusy(text) {
  busy = !!text;
  statusEl.textContent = text || "";
  for (const b of busyButtons) b.disabled = busy;
}

async function connect(address) {
  if (busy || !address) return;
  errorEl.textContent = "";
  setBusy(`Connecting to ${address}…`);
  const r = await window.cellowallaDesktop.connect(address).catch((e) => ({ error: e.message }));
  if (r.error) { setBusy(""); errorEl.textContent = r.error; } else setBusy("Opening the dashboard…");
}

document.getElementById("form").addEventListener("submit", (e) => { e.preventDefault(); connect(input.value.trim()); });

document.getElementById("find").addEventListener("click", async () => {
  if (busy) return;
  errorEl.textContent = "";
  setBusy("Looking for your box on this network… (up to 10 seconds)");
  const { found, nets } = await window.cellowallaDesktop.find().catch(() => ({ found: [], nets: [] }));
  setBusy("");
  document.querySelectorAll(".chip.found").forEach((c) => c.remove());
  if (!found.length) {
    errorEl.textContent = `No Cellowalla box answered on ${nets.length ? nets.map((n) => `${n}.x`).join(" or ") : "this network"}. Check the box is switched on and on the same Wi-Fi as this computer.`;
    return;
  }
  const row = document.getElementById("found");
  for (const h of found.reverse()) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "chip found on"; b.textContent = `Box at ${h}`;
    b.addEventListener("click", () => { input.value = h; connect(h); });
    row.prepend(b);
  }
  statusEl.textContent = found.length === 1 ? "Found your box. Click it to connect." : "Found these boxes. Click yours to connect.";
  if (found.length === 1) input.value = found[0];
});

const themeChips = document.querySelectorAll(".chip[data-theme]");
const markTheme = (mode) => themeChips.forEach((c) => { c.classList.toggle("on", c.dataset.theme === mode); c.setAttribute("aria-checked", String(c.dataset.theme === mode)); });
window.cellowallaDesktop.theme().then(markTheme);
themeChips.forEach((c) => c.addEventListener("click", () => { window.cellowallaDesktop.themeChanged(c.dataset.theme); markTheme(c.dataset.theme); }));
for (const b of document.querySelectorAll(".chip[data-a]")) b.addEventListener("click", () => { input.value = b.dataset.a; input.focus(); });

// Opened with a saved box: try it straight away (the page shows what's happening).
if (params.get("auto") && input.value) connect(input.value);