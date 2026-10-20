// Cellowalla dashboard. Plain JavaScript, no build step: one screen per tab, redrawn from the API.

const root = document.getElementById("app");
const ui = { tab: localGet("tab") || "home", timer: null, unread: 0 };

function localGet(k) { try { return localStorage.getItem(`cw.${k}`); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem(`cw.${k}`, v); } catch { /* private window */ } }

// ---- small helpers ------------------------------------------------------------------------------

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
  return el;
}

async function api(method, path, body) {
  const r = await fetch(path, { method, headers: { "content-type": "application/json", "x-cellowalla": "1" }, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { showAuth(); throw new Error("Sign in"); }
  if (!r.ok) throw new Error(data.error || `Error ${r.status}`);
  return data;
}

function toast(msg, bad = false) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const t = h("div", { class: `toast${bad ? " bad" : ""}`, role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 3200);
}

/** Runs an action; shows its error as a toast. Returns the result (or undefined). */
async function act(fn, done) {
  try { const r = await fn(); if (done) toast(done); return r; } catch (e) { if (e.message !== "Sign in") toast(e.message, true); }
}

function toggle(checked, onchange, label) {
  const input = h("input", { type: "checkbox", checked, "aria-label": label || "On or off" });
  input.addEventListener("change", async () => {
    input.disabled = true;
    try { await onchange(input.checked); } catch (e) { input.checked = !input.checked; toast(e.message, true); }
    input.disabled = false;
  });
  return h("label", { class: "switch" }, input, h("span"));
}

function sheet(title, build) {
  const close = () => { bg.remove(); document.removeEventListener("keydown", esc); };
  const esc = (e) => { if (e.key === "Escape") close(); };
  const body = h("div");
  const append = body.append.bind(body);
  body.append = (...kids) => append(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false));
  const box = h("div", { class: "sheet", role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "head" }, h("h2", {}, title), h("button", { class: "iconbtn", "aria-label": "Close", onclick: close }, "✕")), body);
  const bg = h("div", { class: "sheet-bg", onclick: (e) => { if (e.target === bg) close(); } }, box);
  document.addEventListener("keydown", esc);
  document.body.append(bg);
  build(body, close);
  return { close, body };
}

function confirmSheet(title, text, yes, onYes) {
  sheet(title, (b, close) => b.append(h("p", {}, text), h("div", { class: "btns" },
    h("button", { class: "btn danger", onclick: async () => { close(); await onYes(); } }, yes),
    h("button", { class: "btn", onclick: close }, "Cancel"))));
}

const fmtNum = (n) => Number(n || 0).toLocaleString();
function fmtBytes(n) {
  n = Number(n || 0);
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}
function ago(t) {
  if (!t) return "never";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(t).toLocaleDateString();
}
const until = (t) => new Date(t).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const CUT = { blocked: ["Blocked", "bad"], paused: ["Paused", "warn"], bedtime: ["Bedtime", "warn"], lobby: ["In the Lobby", "warn"] };

function minutesToMorning() {
  const now = new Date(), t = new Date(now); t.setHours(7, 0, 0, 0);
  if (t <= now) t.setDate(t.getDate() + 1);
  return Math.round((t - now) / 60000);
}

// ---- sign in / first setup ----------------------------------------------------------------------

async function start() {
  let hello;
  try { hello = await fetch("/api/hello").then((r) => r.json()); } catch { root.replaceChildren(h("div", { class: "auth card" }, h("p", {}, "Can't reach the box."))); return; }
  if (!hello.signedIn) return showAuth(hello.setUp);
  shell();
}

function showAuth(setUp = true) {
  clearInterval(ui.timer);
  const err = h("p", { class: "muted", role: "alert" });
  const code = h("input", { type: "text", autocomplete: "off", autocapitalize: "characters", placeholder: "e.g. K7QM2XWD" });
  const pw = h("input", { type: "password", autocomplete: setUp ? "current-password" : "new-password" });
  const pw2 = h("input", { type: "password", autocomplete: "new-password" });
  const form = h("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      if (setUp) await api("POST", "/api/login", { password: pw.value });
      else {
        if (pw.value !== pw2.value) throw new Error("The two passwords don't match");
        await api("POST", "/api/setup", { code: code.value, password: pw.value });
      }
      shell();
    } catch (e2) { err.textContent = e2.message; }
  } },
    setUp ? [h("h1", {}, "Sign in"), h("label", { class: "field" }, h("span", {}, "Password"), pw)]
      : [h("h1", {}, "Welcome to Cellowalla"),
        h("p", { class: "muted" }, "Pick the password that guards this box. You'll need the setup code the installer showed (it's also in /var/lib/cellowalla/setup-code.txt on the box)."),
        h("label", { class: "field" }, h("span", {}, "Setup code"), code),
        h("label", { class: "field" }, h("span", {}, "New password (10+ characters)"), pw),
        h("label", { class: "field" }, h("span", {}, "Same password again"), pw2)],
    err,
    h("div", { class: "btns" }, h("button", { class: "btn primary", type: "submit" }, setUp ? "Sign in" : "Set password"), h("a", { class: "btn", href: "guide.html" }, "User guide")));
  root.replaceChildren(h("div", { class: "auth" }, h("div", { class: "logo" }, h("img", { src: "icon.svg", alt: "" }), h("h1", {}, "Cellowalla")), form));
  (setUp ? pw : code).focus();
}

// ---- the frame ----------------------------------------------------------------------------------

const TABS = [
  ["home", "⌂", "Home"],
  ["shield", "🛡", "Shield"],
  ["roster", "▤", "Roster"],
  ["rules", "☾", "House Rules"],
  ["tunnel", "⇄", "Tunnel"],
];
let content, bell;

function shell() {
  content = h("main");
  bell = h("button", { class: "iconbtn", "aria-label": "Pings", onclick: () => go("pings") }, "🔔");
  const top = h("header", { class: "top" },
    h("div", { class: "logo" }, h("img", { src: "icon.svg", alt: "" }), "Cellowalla"),
    themeButton(),
    h("a", { class: "iconbtn", href: "guide.html", "aria-label": "User guide", title: "User guide" }, "?"),
    bell,
    h("button", { class: "iconbtn", "aria-label": "Settings", onclick: () => go("settings") }, "⚙"));
  const nav = h("nav", { class: "tabs" }, TABS.map(([k, ic, label]) => h("button", { "data-tab": k, onclick: () => go(k) }, h("span", { class: "ic", "aria-hidden": "true" }, ic), label)));
  root.replaceChildren(top, content, nav);
  go(ui.tab in SCREENS ? ui.tab : "home");
}

// ---- Light / Dark / Auto (theme.js does the work) -------------------------------------------------

const THEMES = [["auto", "Auto", "◐"], ["light", "Light", "☀"], ["dark", "Dark", "☾"]];

/** The header button: each press moves Auto → Light → Dark → Auto. */
function themeButton() {
  const b = h("button", { class: "iconbtn", onclick: () => { const i = THEMES.findIndex(([k]) => k === window.cwTheme()); window.cwSetTheme(THEMES[(i + 1) % 3][0]); } });
  const show = () => { const t = THEMES.find(([k]) => k === window.cwTheme()) || THEMES[0]; b.textContent = t[2]; b.title = `Theme: ${t[1]} (tap to change)`; b.setAttribute("aria-label", b.title); };
  document.addEventListener("cw-theme", show);
  show();
  return b;
}

/** Three choices, for Settings. */
function themeChips() {
  const row = h("div", { class: "chips", role: "radiogroup", "aria-label": "Theme" });
  const draw = () => (row.isConnected || !row.childElementCount ? row : (document.removeEventListener("cw-theme", draw), null))?.replaceChildren(...THEMES.map(([k, label]) => h("button", { class: `chip${window.cwTheme() === k ? " on" : ""}`, role: "radio", "aria-checked": String(window.cwTheme() === k), onclick: () => window.cwSetTheme(k) }, label)));
  document.addEventListener("cw-theme", draw);
  draw();
  return row;
}

function go(tab) {
  ui.tab = tab; localSet("tab", tab);
  document.querySelectorAll("nav.tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab));
  draw();
  clearInterval(ui.timer);
  if (["home", "roster", "tunnel"].includes(tab)) ui.timer = setInterval(() => { if (!document.querySelector(".sheet-bg")) draw(true); }, 15000);
}

async function draw(quiet = false) {
  const tab = ui.tab;
  try {
    const el = await SCREENS[tab]();
    if (ui.tab !== tab) return;
    const y = window.scrollY;
    content.replaceChildren(el);
    if (quiet) window.scrollTo(0, y);
  } catch (e) {
    if (e.message !== "Sign in" && !quiet) content.replaceChildren(h("div", { class: "card" }, h("p", {}, e.message)));
  }
  api("GET", "/api/status").then((s) => setUnread(s.pings.unread)).catch(() => {});
}

function setUnread(n) {
  ui.unread = n;
  bell.querySelector(".dot")?.remove();
  if (n) bell.append(h("span", { class: "dot" }, n > 99 ? "99+" : n));
}

// ---- Home ---------------------------------------------------------------------------------------

async function homeScreen() {
  const s = await api("GET", "/api/status");
  const paused = s.shield.pausedUntil > Date.now();
  const good = s.shield.on && !paused;
  const pct = s.shield.lookups ? Math.round((s.shield.blocked / s.shield.lookups) * 100) : 0;
  const max = Math.max(1, ...s.shield.hours.map((x) => x.q));
  return h("div", {},
    s.dry ? h("div", { class: "note warn" }, "Test mode: this copy isn't running on the box, so nothing on the network is changed.") : null,
    h("div", { class: `card hero${good ? "" : " warn"}` },
      h("div", { class: "badge", "aria-hidden": "true" }, good ? "🛡" : "⚠"),
      h("div", { class: "grow" },
        h("div", { class: "t" }, good ? "Your network is guarded" : paused ? `Shield paused until ${until(s.shield.pausedUntil)}` : "Shield is off"),
        h("div", { class: "muted" }, `${s.mode === "gatekeeper" ? "Gatekeeper" : "Lookout"} mode · box at ${s.boxIp}`)),
      paused || !s.shield.on
        ? h("button", { class: "btn small primary", onclick: () => act(async () => { await api("POST", "/api/shield/pause", { minutes: 0 }); if (!s.shield.on) await api("PUT", "/api/shield", { on: true }); draw(); }) }, "Resume")
        : h("button", { class: "btn small", onclick: () => pauseShieldSheet() }, "Pause")),
    h("div", { class: "grid" },
      stat(fmtNum(s.shield.lookups), "lookups (24 h)"),
      stat(`${fmtNum(s.shield.blocked)}`, `blocked (${pct}%)`, () => go("shield")),
      stat(`${s.devices.online}/${s.devices.total}`, "devices online", () => go("roster")),
      stat(`${s.tunnel.on ? s.tunnel.online : "–"}`, s.tunnel.on ? "Tunnel connected" : "Tunnel off", () => go("tunnel"))),
    s.devices.waiting ? h("div", { class: "note warn" }, `${s.devices.waiting} new device${s.devices.waiting > 1 ? "s are" : " is"} waiting in the Lobby. `, h("a", { href: "#", onclick: (e) => { e.preventDefault(); go("roster"); } }, "Let them in or block them")) : null,
    h("div", { class: "card" },
      h("h2", {}, "Last 24 hours"),
      h("div", { class: "chart", role: "img", "aria-label": "Lookups per hour, blocked shown in color" },
        s.shield.hours.length ? last24(s.shield.hours).map((x) => {
          const col = h("div", { class: "col", title: `${new Date(x.hour * 3600000).toLocaleTimeString([], { hour: "numeric" })}: ${x.q} lookups, ${x.b} blocked` });
          const q = h("div", { class: "q" }), b = h("div", { class: "b" });
          q.style.height = `${((x.q - x.b) / max) * 100}%`; b.style.height = `${(x.b / max) * 100}%`;
          col.append(q, b);
          return col;
        }) : h("div", { class: "muted" }, "Nothing yet.")),
      h("div", { class: "legend" }, h("span", {}, h("i"), "allowed"), h("span", {}, h("i", { class: "b" }), "blocked"))),
    s.shield.top.length ? h("div", { class: "card flat" },
      h("div", { class: "row" }, h("h2", { class: "grow" }, "Most blocked")),
      s.shield.top.map(([name, n]) => h("div", { class: "row" }, h("div", { class: "grow title" }, name), h("span", { class: "pill gray" }, fmtNum(n))))) : null);
}

/** 24 hourly slots ending now (hours with no look-ups are empty). */
function last24(hours) {
  const now = Math.floor(Date.now() / 3600000), by = new Map(hours.map((x) => [x.hour, x]));
  return Array.from({ length: 24 }, (_, i) => by.get(now - 23 + i) || { hour: now - 23 + i, q: 0, b: 0 });
}

function stat(n, l, onclick) {
  return h("div", { class: `stat${onclick ? " link" : ""}`, onclick, role: onclick ? "button" : null, tabindex: onclick ? "0" : null }, h("div", { class: "n" }, n), h("div", { class: "l" }, l));
}

function pauseShieldSheet() {
  sheet("Pause Shield", (b, close) => {
    b.append(h("p", { class: "muted" }, "Everything is allowed until the time is up (House Rules still apply). Useful when a site breaks."),
      h("div", { class: "btns" }, [[5, "5 min"], [15, "15 min"], [60, "1 hour"]].map(([m, l]) =>
        h("button", { class: "btn", onclick: () => act(async () => { await api("POST", "/api/shield/pause", { minutes: m }); close(); draw(); }, `Shield paused for ${l}`) }, l))));
  });
}

// ---- Shield -------------------------------------------------------------------------------------

async function shieldScreen() {
  const s = await api("GET", "/api/shield");
  const set = (patch) => api("PUT", "/api/shield", patch);
  const names = (which) => {
    const input = h("input", { type: "text", placeholder: which === "deny" ? "e.g. annoying-site.com" : "e.g. needed-site.com", autocapitalize: "off" });
    const add = () => act(async () => { await api("POST", "/api/shield/names", { list: which, name: input.value }); draw(); });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
    return h("div", {},
      h("div", { class: "inline" }, input, h("button", { class: "btn", onclick: add }, "Add")),
      h("div", { class: "chips" }, s[which].map((n) => h("button", { class: "chip", title: "Remove", onclick: () => act(async () => { await api("DELETE", "/api/shield/names", { name: n }); draw(); }) }, `${n} ✕`))));
  };
  const listInfo = (c) => c.size ? `${fmtNum(c.size)} names${c.updated ? ` · updated ${ago(c.updated)}` : ""}${c.error ? " · last download failed" : ""}` : c.error ? `couldn't download (${c.error})` : "downloading…";

  return h("div", {},
    h("div", { class: "card flat" },
      h("div", { class: "row" }, h("div", { class: "grow" }, h("div", { class: "title" }, "Shield"), h("div", { class: "sub" }, "Answers every device's DNS and stops the names below.")),
        toggle(s.on, (v) => set({ on: v }), "Shield")),
      h("div", { class: "row" }, h("div", { class: "grow" }, h("div", { class: "title" }, "Clean Search"), h("div", { class: "sub" }, "Google, Bing, DuckDuckGo, Brave and YouTube in their family-safe modes, for everyone.")),
        toggle(s.cleanSearch, (v) => set({ cleanSearch: v }), "Clean Search")),
      h("div", { class: "row" }, h("div", { class: "grow" }, h("div", { class: "title" }, "Home address guard"), h("div", { class: "sub" }, "Refuse outside names that point into your home network (stops DNS rebinding tricks).")),
        toggle(s.rebinding, (v) => set({ rebinding: v }), "Home address guard"))),

    h("h3", {}, "What to block for everyone"),
    h("div", { class: "card flat" }, s.catalog.map((c) => h("div", { class: "row" },
      h("div", { class: "grow" }, h("div", { class: "title" }, c.title), h("div", { class: "sub" }, c.about), h("div", { class: "sub" }, listInfo(c))),
      toggle(c.on, (v) => set({ lists: { [c.key]: v } }), c.title)))),
    h("p", { class: "muted" }, "Want a category for just the kids? Turn it on in their Crew under House Rules instead."),

    h("h3", {}, "Always block"), h("div", { class: "card" }, names("deny")),
    h("h3", {}, "Never block"), h("div", { class: "card" }, h("p", { class: "muted" }, "Sites that broke because of a list. Covers everything under the name too."), names("allow")),

    h("h3", {}, "Your own lists"),
    h("div", { class: "card flat" },
      s.custom.length ? s.custom.map((c) => h("div", { class: "row" },
        h("div", { class: "grow" }, h("div", { class: "title" }, c.name), h("div", { class: "sub" }, c.url), h("div", { class: "sub" }, listInfo(s.customInfo[c.id] || {}))),
        toggle(c.on, (v) => api("PUT", "/api/shield/custom", { id: c.id, on: v }), c.name),
        h("button", { class: "iconbtn", "aria-label": `Remove ${c.name}`, onclick: () => act(async () => { await api("DELETE", "/api/shield/custom", { id: c.id }); draw(); }) }, "✕")))
        : h("div", { class: "empty" }, "None. Add any hosts file or domain list by its https:// address."),
      h("div", { class: "row" }, h("button", { class: "btn", onclick: addListSheet }, "Add a list"),
        h("button", { class: "btn", onclick: (e) => { e.target.disabled = true; e.target.textContent = "Downloading…"; act(async () => { await api("POST", "/api/shield/refresh"); draw(); }, "Lists updated"); } }, "Update lists now"))),

    h("h3", {}, "Look-up log"),
    h("div", { class: "card" }, h("p", { class: "muted" }, "The last few thousand look-ups, kept only in the box's memory."), h("button", { class: "btn", onclick: () => logSheet() }, "Open the log")),

    h("h3", {}, "Upstream"),
    h("div", { class: "card" }, (() => {
      const up = h("input", { type: "url", value: s.upstream });
      return [h("p", { class: "muted" }, "Where allowed look-ups are sent, encrypted (DNS-over-HTTPS)."),
        h("div", { class: "inline" }, up, h("button", { class: "btn", onclick: () => act(() => set({ upstream: up.value }), "Saved") }, "Save")),
        h("div", { class: "chips" }, [["Cloudflare", "https://1.1.1.1/dns-query"], ["Quad9", "https://9.9.9.9/dns-query"], ["Google", "https://8.8.8.8/dns-query"]].map(([n, u]) =>
          h("button", { class: "chip", onclick: () => { up.value = u; } }, n)))];
    })()));
}

function addListSheet() {
  sheet("Add a list", (b, close) => {
    const name = h("input", { type: "text", placeholder: "e.g. Extra trackers" });
    const url = h("input", { type: "url", placeholder: "https://…/hosts.txt" });
    b.append(h("p", { class: "muted" }, "Hosts files (0.0.0.0 name), one-name-per-line lists and ||name^ lists all work."),
      h("label", { class: "field" }, h("span", {}, "Name"), name), h("label", { class: "field" }, h("span", {}, "Address"), url),
      h("div", { class: "btns" }, h("button", { class: "btn primary", onclick: () => act(async () => { await api("POST", "/api/shield/custom", { name: name.value, url: url.value }); close(); draw(); }, "Added; downloading") }, "Add")));
  });
}

async function logSheet(dev = null, devLabel = null) {
  sheet(devLabel ? `Look-ups: ${devLabel}` : "Look-up log", (b) => {
    const q = h("input", { type: "text", placeholder: "Search names", autocapitalize: "off" });
    const only = h("select", {}, h("option", { value: "" }, "Everything"), h("option", { value: "blocked" }, "Only blocked"));
    const list = h("div", { class: "card flat log" });
    const load = async () => {
      const p = new URLSearchParams();
      if (dev) p.set("dev", dev); if (q.value) p.set("q", q.value.toLowerCase()); if (only.value) p.set("only", only.value);
      const r = await api("GET", `/api/log?${p}`);
      list.replaceChildren(...(r.entries.length ? r.entries.map((e) => {
        const blocked = e.v.startsWith("blocked") || e.v === "cut";
        return h("div", { class: "row" },
          h("div", { class: "grow" }, h("div", { class: "name" }, e.name), h("div", { class: "sub" }, `${new Date(e.t).toLocaleTimeString()} · ${e.ip}${e.v !== "ok" ? ` · ${e.v.replace("blocked:", "blocked by ")}` : ""}`)),
          blocked ? h("button", { class: "btn small", onclick: () => act(() => api("POST", "/api/shield/names", { list: "allow", name: e.name }), `${e.name} will never be blocked`) }, "Allow")
            : h("button", { class: "btn small", onclick: () => act(() => api("POST", "/api/shield/names", { list: "deny", name: e.name }), `${e.name} is now blocked`) }, "Block"));
      }) : [h("div", { class: "empty" }, "No look-ups match.")]));
    };
    let t; q.addEventListener("input", () => { clearTimeout(t); t = setTimeout(load, 250); });
    only.addEventListener("change", load);
    b.append(h("div", { class: "inline" }, q, only), h("p"), list);
    load().catch((e) => toast(e.message, true));
  });
}

// ---- Roster -------------------------------------------------------------------------------------

async function rosterScreen() {
  const [{ devices, lobby }, { crews }] = await Promise.all([api("GET", "/api/devices"), api("GET", "/api/crews")]);
  const waiting = devices.filter((d) => d.cut === "lobby");
  const row = (d) => h("div", { class: "row click", onclick: () => deviceSheet(d, crews), role: "button", tabindex: "0" },
    h("span", { class: `status${d.online ? " on" : ""}`, title: d.online ? "Online" : "Offline" }),
    h("div", { class: "grow" }, h("div", { class: "title" }, d.label),
      h("div", { class: "sub" }, [d.ip, d.kind === "tunnel" ? "Tunnel pass" : d.vendor, d.crewName ? `Crew: ${d.crewName}` : null, d.online ? null : ago(d.lastSeen)].filter(Boolean).join(" · "))),
    d.cut ? h("span", { class: `pill ${CUT[d.cut][1]}` }, CUT[d.cut][0]) : null);
  return h("div", {},
    h("div", { class: "card flat" },
      h("div", { class: "row" }, h("div", { class: "grow" }, h("div", { class: "title" }, "Lobby"), h("div", { class: "sub" }, "New devices get no internet until you let them in.")),
        toggle(lobby.on, async (v) => { await api("PUT", "/api/lobby", { on: v }); draw(); }, "Lobby"))),
    waiting.length ? [h("h3", {}, "Waiting in the Lobby"), h("div", { class: "card flat" }, waiting.map((d) => h("div", { class: "row" },
      h("div", { class: "grow" }, h("div", { class: "title" }, d.label), h("div", { class: "sub" }, `${d.ip} · ${d.vendor || d.mac} · arrived ${ago(d.firstSeen)}`)),
      h("button", { class: "btn small primary", onclick: () => act(async () => { await api("PUT", "/api/devices", { mac: d.mac, approve: true }); draw(); }, "Let in") }, "Let in"),
      h("button", { class: "btn small danger", onclick: () => act(async () => { await api("PUT", "/api/devices", { mac: d.mac, approve: true, blocked: true }); draw(); }, "Blocked") }, "Block"))))] : null,
    h("h3", {}, `Devices (${devices.length})`),
    h("div", { class: "card flat" }, devices.length ? devices.filter((d) => d.cut !== "lobby").map(row) : h("div", { class: "empty" }, "No devices yet. They appear as soon as they use the network.")));
}

function deviceSheet(d, crews) {
  sheet(d.label, (b, close) => {
    const name = h("input", { type: "text", value: d.name || "", placeholder: d.host || d.vendor || "Name this device" });
    const crew = h("select", {}, h("option", { value: "" }, "No crew (household rules)"), crews.map((c) => h("option", { value: c.id, selected: c.id === d.crew }, c.name)));
    const save = (patch, msg) => act(async () => { await api("PUT", "/api/devices", { mac: d.mac, ...patch }); close(); draw(); }, msg);
    b.append(
      d.cut ? h("div", { class: "note warn" }, `${CUT[d.cut][0]}${d.cut === "paused" && d.pausedUntil > Date.now() ? ` until ${until(d.pausedUntil)}` : ""}. This device has no internet right now.`) : null,
      h("p", { class: "muted" }, [d.ip, d.kind === "tunnel" ? null : d.mac, d.vendor, d.host ? `calls itself "${d.host}"` : null].filter(Boolean).join(" · ")),
      h("p", { class: "muted" }, `First seen ${ago(d.firstSeen)} · ${d.online ? "online now" : `last seen ${ago(d.lastSeen)}`}`),
      h("div", { class: "grid" },
        stat(fmtNum(d.dns.q), "look-ups"), stat(fmtNum(d.dns.b), "blocked"),
        d.traffic && (d.traffic.up || d.traffic.down) ? [stat(fmtBytes(d.traffic.down), "downloaded"), stat(fmtBytes(d.traffic.up), "uploaded")] : null),
      h("label", { class: "field" }, h("span", {}, "Name"), h("div", { class: "inline" }, name, h("button", { class: "btn", onclick: () => save({ name: name.value }, "Renamed") }, "Save"))),
      h("label", { class: "field" }, h("span", {}, "Crew (House Rules)"), h("div", { class: "inline" }, crew, h("button", { class: "btn", onclick: () => save({ crew: crew.value || null }, "Saved") }, "Save"))),
      h("h3", {}, "Pause the internet"),
      h("div", { class: "btns" }, [[30, "30 min"], [60, "1 hour"], [120, "2 hours"], [minutesToMorning(), "Until 7 am"]].map(([m, l]) => h("button", { class: "btn", onclick: () => save({ pauseMinutes: m }, `Paused for ${l.toLowerCase()}`) }, l)),
        d.pausedUntil > Date.now() ? h("button", { class: "btn primary", onclick: () => save({ pauseMinutes: 0 }, "Unpaused") }, "Unpause") : null),
      h("h3", {}, "More"),
      h("div", { class: "btns" },
        h("button", { class: "btn", onclick: () => { close(); logSheet(d.mac, d.label); } }, "Look-ups"),
        d.cut === "lobby" ? h("button", { class: "btn primary", onclick: () => save({ approve: true }, "Let in") }, "Let in") : null,
        h("button", { class: `btn${d.blocked ? " primary" : " danger"}`, onclick: () => save({ blocked: !d.blocked, approve: true }, d.blocked ? "Unblocked" : "Blocked") }, d.blocked ? "Unblock" : "Block for good"),
        d.kind === "lan" ? h("button", { class: "btn danger", onclick: () => confirmSheet("Forget this device?", "Its name and settings are removed. If it comes back it shows up as new.", "Forget", async () => { await act(() => api("DELETE", "/api/devices", { mac: d.mac }), "Forgotten"); close(); draw(); }) }, "Forget") : null));
  });
}

// ---- House Rules --------------------------------------------------------------------------------

async function rulesScreen() {
  const [{ crews, catalog }, { devices }] = await Promise.all([api("GET", "/api/crews"), api("GET", "/api/devices")]);
  return h("div", {},
    h("p", { class: "muted" }, "A Crew is a group of devices (say, one child's phone, tablet and console) with its own rules: extra things to block, Clean Search, bedtimes and a pause button."),
    h("div", { class: "card flat" },
      crews.length ? crews.map((c) => {
        const n = c.members.length;
        const paused = c.pausedUntil > Date.now();
        return h("div", { class: "row click", role: "button", tabindex: "0", onclick: () => crewSheet(c, catalog, devices) },
          h("div", { class: "grow" }, h("div", { class: "title" }, c.name),
            h("div", { class: "sub" }, [`${n} device${n === 1 ? "" : "s"}`, c.bedtimes.length ? `${c.bedtimes.length} bedtime${c.bedtimes.length > 1 ? "s" : ""}` : null,
              Object.entries(c.lists).filter(([, v]) => v).map(([k]) => catalog.find((x) => x.key === k)?.title).filter(Boolean).join(", ") || null, c.cleanSearch ? "Clean Search" : null].filter(Boolean).join(" · "))),
          paused ? h("span", { class: "pill warn" }, "Paused") : c.cutNow ? h("span", { class: "pill warn" }, "Bedtime") : null);
      }) : h("div", { class: "empty" }, "No crews yet."),
      h("div", { class: "row" }, h("button", { class: "btn primary", onclick: () => sheet("New crew", (b, close) => {
        const name = h("input", { type: "text", placeholder: "e.g. Kids, Sam, Guests" });
        b.append(h("label", { class: "field" }, h("span", {}, "Name"), name), h("div", { class: "btns" }, h("button", { class: "btn primary", onclick: () => act(async () => {
          const c = await api("POST", "/api/crews", { name: name.value }); close(); await draw();
          crewSheet({ ...c, members: [] }, catalog, devices);
        }) }, "Create")));
        name.focus();
      }) }, "New crew"))));
}

function crewSheet(c, catalog, devices) {
  sheet(c.name, (b, close) => {
    const st = { lists: { ...c.lists }, cleanSearch: c.cleanSearch, members: new Set(c.members), bedtimes: c.bedtimes.map((x) => ({ ...x, days: [...x.days] })) };
    const name = h("input", { type: "text", value: c.name });
    const deny = h("textarea", { placeholder: "One per line, e.g. roblox.com" }); deny.value = c.deny.join("\n");
    const bedBox = h("div");
    const drawBeds = () => bedBox.replaceChildren(...st.bedtimes.map((t, i) => {
      const from = h("input", { type: "time", value: t.from }), to = h("input", { type: "time", value: t.to });
      from.addEventListener("change", () => { t.from = from.value; }); to.addEventListener("change", () => { t.to = to.value; });
      return h("div", { class: "card" },
        h("div", { class: "chips" }, DAYS.map((dn, di) => h("button", { class: `chip${t.days.includes(di) ? " on" : ""}`, "aria-pressed": String(t.days.includes(di)), onclick: (e) => {
          t.days = t.days.includes(di) ? t.days.filter((x) => x !== di) : [...t.days, di]; e.target.classList.toggle("on"); e.target.setAttribute("aria-pressed", String(t.days.includes(di)));
        } }, dn))),
        h("div", { class: "inline" }, h("label", { class: "field" }, h("span", {}, "Starts"), from), h("label", { class: "field" }, h("span", {}, "Ends"), to)),
        h("button", { class: "btn small danger", onclick: () => { st.bedtimes.splice(i, 1); drawBeds(); } }, "Remove"));
    }));
    drawBeds();
    const quick = (patch, msg) => act(async () => { await api("PUT", "/api/crews", { id: c.id, ...patch }); close(); draw(); }, msg);
    const paused = c.pausedUntil > Date.now();

    b.append(
      paused ? h("div", { class: "note warn" }, `Paused until ${until(c.pausedUntil)}.`) : c.cutNow ? h("div", { class: "note warn" }, "It's bedtime for this crew right now.") : null,
      h("div", { class: "btns" },
        paused ? h("button", { class: "btn primary", onclick: () => quick({ pauseMinutes: 0 }, "Unpaused") }, "Unpause")
          : [[30, "Pause 30 min"], [60, "Pause 1 hour"], [minutesToMorning(), "Pause until 7 am"]].map(([m, l]) => h("button", { class: "btn", onclick: () => quick({ pauseMinutes: m }, "Paused") }, l)),
        c.cutNow ? h("button", { class: "btn", onclick: () => quick({ graceMinutes: 30 }, "30 more minutes granted") }, "30 more minutes") : null),
      h("label", { class: "field" }, h("span", {}, "Name"), name),
      h("h3", {}, "Devices in this crew"),
      h("div", { class: "card flat" }, devices.length ? devices.map((d) => {
        const cb = h("input", { type: "checkbox", checked: st.members.has(d.mac), "aria-label": d.label });
        cb.addEventListener("change", () => { if (cb.checked) st.members.add(d.mac); else st.members.delete(d.mac); });
        return h("label", { class: "row click" }, cb, h("div", { class: "grow" }, h("div", { class: "title" }, d.label), h("div", { class: "sub" }, [d.ip, d.crewName && d.crew !== c.id ? `now in ${d.crewName}` : null].filter(Boolean).join(" · "))));
      }) : h("div", { class: "empty" }, "No devices yet.")),
      h("h3", {}, "Also block for this crew"),
      h("div", { class: "card flat" }, catalog.map((k) => h("div", { class: "row" }, h("div", { class: "grow title" }, k.title),
        k.everyone ? h("span", { class: "pill gray", title: "Turned on for everyone on the Shield screen" }, "Blocked for everyone") : toggle(!!st.lists[k.key], (v) => { st.lists[k.key] = v; }, k.title))),
        h("div", { class: "row" }, h("div", { class: "grow" }, h("div", { class: "title" }, "Clean Search"), h("div", { class: "sub" }, "Family-safe search and YouTube")), toggle(st.cleanSearch, (v) => { st.cleanSearch = v; }, "Clean Search"))),
      h("label", { class: "field" }, h("span", {}, "Extra sites to block"), deny),
      h("h3", {}, "Bedtimes"),
      h("p", { class: "muted" }, "No internet between these times. Pick the days the bedtime starts on (a 21:00–07:00 bedtime on Sunday runs into Monday morning)."),
      bedBox,
      h("button", { class: "btn", onclick: () => { st.bedtimes.push({ days: [0, 1, 2, 3, 4], from: "21:00", to: "07:00" }); drawBeds(); } }, "Add a bedtime"),
      h("div", { class: "btns" },
        h("button", { class: "btn primary", onclick: () => act(async () => {
          await api("PUT", "/api/crews", { id: c.id, name: name.value, lists: st.lists, cleanSearch: st.cleanSearch, members: [...st.members], deny: deny.value.split(/[\s,]+/).filter(Boolean), bedtimes: st.bedtimes });
          close(); draw();
        }, "Saved") }, "Save"),
        h("button", { class: "btn danger", onclick: () => confirmSheet(`Delete ${c.name}?`, "Its devices go back to the household rules.", "Delete", async () => { await act(() => api("DELETE", "/api/crews", { id: c.id }), "Deleted"); close(); draw(); }) }, "Delete crew")));
  });
}

// ---- Tunnel -------------------------------------------------------------------------------------

async function tunnelScreen() {
  const t = await api("GET", "/api/tunnel");
  const endpoint = h("input", { type: "text", value: t.endpoint, placeholder: "home.example.com or your public IP" });
  const port = h("input", { type: "number", value: t.port, min: "1024", max: "65535" });
  return h("div", {},
    h("div", { class: "card flat" },
      h("div", { class: "row" }, h("div", { class: "grow" }, h("div", { class: "title" }, "Tunnel"), h("div", { class: "sub" }, "Your phone and laptop come home through WireGuard: reach home devices and stay guarded by Shield on any Wi-Fi.")),
        toggle(t.on, async (v) => { await api("PUT", "/api/tunnel", { on: v }); draw(); }, "Tunnel"))),
    t.on ? [
      h("h3", {}, "Passes"),
      h("div", { class: "card flat" },
        t.passes.length ? t.passes.map((p) => h("div", { class: "row" },
          h("span", { class: `status${p.online ? " on" : ""}` }),
          h("div", { class: "grow" }, h("div", { class: "title" }, p.name),
            h("div", { class: "sub" }, [p.ip, p.full ? "all traffic" : "home only", p.online ? `connected${p.from ? ` from ${p.from.replace(/:\d+$/, "")}` : ""}` : `last connected ${ago(p.lastHandshake)}`, p.rx || p.tx ? `${fmtBytes(p.rx)} in / ${fmtBytes(p.tx)} out` : null].filter(Boolean).join(" · "))),
          h("button", { class: "btn small", onclick: () => act(async () => { const r = await api("GET", `/api/tunnel/pass?id=${encodeURIComponent(p.id)}`); passSheet(r.name, r.conf); }) }, "Show"),
          h("button", { class: "iconbtn", "aria-label": `Remove ${p.name}`, onclick: () => confirmSheet(`Remove ${p.name}?`, "That phone can't connect any more.", "Remove", async () => { await act(() => api("DELETE", "/api/tunnel/passes", { id: p.id }), "Removed"); draw(); }) }, "✕")))
          : h("div", { class: "empty" }, "No passes yet. Make one for each phone or laptop."),
        h("div", { class: "row" }, h("button", { class: "btn primary", onclick: newPassSheet }, "New pass"))),
      h("h3", {}, "Reaching the box from outside"),
      h("div", { class: "card" },
        h("p", { class: "muted" }, `Your router must send UDP port ${t.port} to the box. See "Tunnel" in the user guide.`),
        h("label", { class: "field" }, h("span", {}, "Home address (what phones dial)"), endpoint),
        h("label", { class: "field" }, h("span", {}, "Port"), port),
        h("div", { class: "btns" }, h("button", { class: "btn", onclick: () => act(async () => { await api("PUT", "/api/tunnel", { endpoint: endpoint.value, port: Number(port.value) }); draw(); }, "Saved. Existing passes need to be shown and scanned again if you changed these.") }, "Save")),
        h("p", { class: "muted" }, "Box key: ", h("code", {}, t.publicKey || "–")))] : null);
}

function newPassSheet() {
  sheet("New pass", (b, close) => {
    const name = h("input", { type: "text", placeholder: "e.g. Ana's phone" });
    const full = h("input", { type: "checkbox", checked: true });
    b.append(h("label", { class: "field" }, h("span", {}, "Who is it for?"), name),
      h("label", { class: "row" }, full, h("div", { class: "grow" }, h("div", { class: "title" }, "Send all traffic home"), h("div", { class: "sub" }, "On: Shield guards the phone everywhere. Off: only home devices go through the Tunnel."))),
      h("div", { class: "btns" }, h("button", { class: "btn primary", onclick: () => act(async () => {
        const r = await api("POST", "/api/tunnel/passes", { name: name.value || "Phone", full: full.checked });
        close(); draw(); passSheet(name.value || "Phone", r.conf);
      }) }, "Make pass")));
    name.focus();
  });
}

function passSheet(name, conf) {
  sheet(name, (b) => {
    const qrBox = h("div", { class: "qr" });
    try {
      const qr = window.qrcode(0, "M"); qr.addData(conf); qr.make();
      qrBox.append(h("img", { src: qr.createDataURL(6, 2), alt: `Tunnel QR code for ${name}` }));
    } catch { qrBox.append(h("p", {}, "Couldn't draw the QR code; use the file instead.")); }
    const file = URL.createObjectURL(new Blob([conf], { type: "text/plain" }));
    b.append(h("p", {}, "On the phone: install the WireGuard app, tap +, choose ", h("b", {}, "Scan from QR code"), " and point it here."),
      qrBox,
      window.CellowallaApp
        ? h("div", { class: "btns" }, h("button", { class: "btn primary", onclick: () => window.CellowallaApp.shareConf(name, conf) }, "Add to WireGuard on this phone"))
        : h("div", { class: "btns" }, h("a", { class: "btn", href: file, download: `${name.replace(/[^A-Za-z0-9 _-]/g, "").trim() || "cellowalla"}.conf` }, "Download file (for laptops)")),
      h("div", { class: "note warn" }, "This code is a key to your home network. Don't post or share screenshots of it."),
      h("details", {}, h("summary", {}, "Show the settings as text"), h("pre", {}, conf)));
  });
}

// ---- Pings --------------------------------------------------------------------------------------

async function pingsScreen() {
  const { pings, settings } = await api("GET", "/api/pings");
  if (pings.some((p) => !p.read)) api("POST", "/api/pings/read").then(() => setUnread(0)).catch(() => {});
  const ICON = { newDevice: "＋", tunnel: "⇄", malware: "⚠", bedtime: "☾", system: "ℹ" };
  const ntfy = h("input", { type: "url", value: settings.ntfy, placeholder: "https://ntfy.sh/your-secret-topic" });
  const hook = h("input", { type: "url", value: settings.webhook, placeholder: "https://…" });
  const EV = [["newDevice", "A new device joins"], ["malware", "Malware or a scam site was stopped"], ["tunnel", "A phone connects through the Tunnel"], ["bedtime", "Bedtime starts or ends"], ["system", "The box starts or has a problem"]];
  return h("div", {},
    h("div", { class: "card flat" },
      pings.length ? pings.map((p) => h("div", { class: "row" }, h("span", { "aria-hidden": "true" }, ICON[p.kind] || "•"),
        h("div", { class: "grow" }, h("div", {}, p.text), h("div", { class: "sub" }, ago(p.at))), p.read ? null : h("span", { class: "pill" }, "new")))
        : h("div", { class: "empty" }, "Nothing to report."),
      pings.length ? h("div", { class: "row" }, h("button", { class: "btn small", onclick: () => act(async () => { await api("DELETE", "/api/pings"); draw(); }) }, "Clear all")) : null),
    h("h3", {}, "Send Pings to my phone"),
    h("div", { class: "card" },
      h("p", { class: "muted" }, "Install the free ntfy app, subscribe to a long, hard-to-guess topic name, and paste its address here."),
      h("label", { class: "field" }, h("span", {}, "ntfy address"), ntfy),
      h("label", { class: "field" }, h("span", {}, "Webhook (optional, JSON POST)"), hook),
      EV.map(([k, l]) => h("div", { class: "row" }, h("div", { class: "grow" }, l), toggle(settings.events[k] !== false, (v) => api("PUT", "/api/pings/settings", { events: { [k]: v } }), l))),
      h("div", { class: "btns" },
        h("button", { class: "btn primary", onclick: () => act(() => api("PUT", "/api/pings/settings", { ntfy: ntfy.value, webhook: hook.value }), "Saved") }, "Save"),
        h("button", { class: "btn", onclick: () => act(() => api("POST", "/api/pings/test"), "Test sent") }, "Send a test"))));
}

// ---- Settings -----------------------------------------------------------------------------------

/** Settings → Updates: the automatic-updates switch, and checking by hand. */
function updatesCard(u) {
  const line = h("p", { class: "muted" });
  const btns = h("div", { class: "btns" });
  const show = (s) => {
    line.textContent = s.busy === "installing" ? `Installing Cellowalla ${s.latest}… The box restarts in a minute or two.`
      : s.error ? `Couldn't check for updates: ${s.error}`
      : s.available ? `Cellowalla ${s.latest} is ready to install (this box has ${s.current}).`
      : s.checkedAt ? `Cellowalla ${s.current} is the newest version (checked ${ago(s.checkedAt)}).`
      : `This box has Cellowalla ${s.current}.`;
    btns.replaceChildren(
      h("button", { class: "btn", disabled: !!s.busy, onclick: () => act(async () => show(await api("POST", "/api/updates/check"))) }, "Check now"),
      s.available && !s.busy ? h("button", { class: "btn primary", onclick: () => act(async () => show(await api("POST", "/api/updates/check", { install: true }))) }, `Update to ${s.latest}`) : null);
  };
  show(u);
  return h("div", { class: "card" }, h("h2", {}, "Box updates"),
    h("div", { class: "row" }, h("div", { class: "grow" }, h("div", {}, "Update the box automatically"),
      h("div", { class: "sub" }, "Once a day the box looks for a new version and puts it in by itself. Only versions signed by Cellowalla's owner are ever installed.")),
    toggle(u.auto, (v) => api("PUT", "/api/updates", { auto: v }), "Update the box automatically")),
    line, btns);
}

/** Settings → "This app": the Cellowalla app's own updates, when the dashboard is open in it. */
function appUpdatesCard() {
  const phone = window.CellowallaApp?.updates ? window.CellowallaApp : null;
  const pc = window.cellowallaDesktop?.updates ? window.cellowallaDesktop : null;
  if (!phone && !pc) return null;
  const line = h("p", { class: "muted" });
  const btns = h("div", { class: "btns" });
  const sw = h("div");
  const show = (s) => {
    line.textContent = s.ready ? `Version ${s.ready} is ready to go in.`
      : s.error ? `Couldn't check for updates: ${s.error}`
      : s.last || (s.latest && s.latest !== s.current ? `Cellowalla ${s.latest} is out.` : `This app is Cellowalla ${s.current}.`);
    sw.replaceChildren(toggle(s.auto, async (v) => show(phone ? JSON.parse(phone.setAutoUpdate(v)) : await pc.setAutoUpdate(v)), "Update this app automatically"));
    btns.replaceChildren(
      h("button", { class: "btn", onclick: async () => { line.textContent = "Checking…"; if (phone) phone.checkUpdates(); else show(await pc.checkUpdates()); } }, "Check now"),
      s.ready && pc ? h("button", { class: "btn primary", onclick: () => pc.installUpdate() }, "Restart to update") : null);
  };
  window.cwAppUpdates = (json) => { if (line.isConnected) show(JSON.parse(json)); };
  const card = h("div", { class: "card" }, h("h2", {}, "This app"),
    h("div", { class: "row" }, h("div", { class: "grow" }, h("div", {}, "Update this app automatically"),
      h("div", { class: "sub" }, "The Cellowalla app on this " + (phone ? "phone" : "computer") + " puts in new versions by itself. Only versions signed by Cellowalla's owner are installed.")), sw),
    line, btns);
  Promise.resolve(phone ? JSON.parse(phone.updates()) : pc.updates()).then(show).catch(() => {});
  return card;
}

/** Settings → Backup: everything the box remembers, as a file to keep somewhere safe. */
function backupCard() {
  const pick = h("input", { type: "file", accept: ".json,application/json", hidden: true, onchange: () => {
    const f = pick.files[0];
    pick.value = "";
    if (!f) return;
    confirmSheet("Restore this backup?", "Everything on this box (devices, House Rules, Tunnel passes, Shield settings and the password) is replaced by what's in the file. You'll sign in again with the password from the backup.", "Restore", () => act(async () => {
      let backup;
      try { backup = JSON.parse(await f.text()); } catch { throw new Error("That isn't a Cellowalla backup file"); }
      await api("POST", "/api/backup/restore", { backup });
      showAuth(true);
    }, "Restored"));
  } });
  const save = () => act(async () => {
    const b = await api("GET", "/api/backup");
    const name = `cellowalla-backup-${b.made.slice(0, 10)}.json`;
    if (window.CellowallaApp?.saveFile) return window.CellowallaApp.saveFile(name, JSON.stringify(b, null, 1)); // (the Android app's WebView can't save downloads itself)
    const url = URL.createObjectURL(new Blob([JSON.stringify(b, null, 1)], { type: "application/json" }));
    h("a", { href: url, download: name }).click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    toast("Backup saved");
  });
  return h("div", { class: "card" }, h("h2", {}, "Backup"),
    h("p", { class: "muted" }, "Save a copy of everything this box remembers. If the box's memory card ever fails, install Cellowalla on a new card and restore this file."),
    h("div", { class: "note warn" }, "The file holds your Tunnel keys and the password's fingerprint. Keep it private, like a house key."),
    h("div", { class: "btns" }, h("button", { class: "btn primary", onclick: save }, "Download backup"), h("button", { class: "btn", onclick: () => pick.click() }, "Restore from a file…"), pick));
}

async function settingsScreen() {
  const [s, u] = await Promise.all([api("GET", "/api/settings"), api("GET", "/api/updates")]);
  const cur = h("input", { type: "password", autocomplete: "current-password" }), pw = h("input", { type: "password", autocomplete: "new-password" });
  const homeDns = h("input", { type: "text", value: s.net.homeDns || "", placeholder: "e.g. 192.168.1.1" });
  return h("div", {},
    h("div", { class: "card" },
      h("h2", {}, "This box"),
      h("p", {}, h("b", {}, s.mode === "gatekeeper" ? "Gatekeeper mode" : "Lookout mode"), s.mode === "gatekeeper" ? ": the box is your router; every device goes through it." : ": the box answers DNS for the network; your router does the routing."),
      h("p", { class: "muted" }, `Address ${s.net.boxIp} · network ${s.net.lanCidr} · home port ${s.net.lanIf}${s.mode === "gatekeeper" ? ` · internet port ${s.net.wanIf}` : ""}`),
      h("p", { class: "muted" }, "To switch modes, run the installer again on the box (see the user guide)."),
      h("p", { class: "muted" }, `Cellowalla ${s.version}${s.dry ? " (test mode)" : ""}`)),
    s.mode === "lookout" ? h("div", { class: "card" }, h("h2", {}, "Home names"),
      h("p", { class: "muted" }, "If your router gives devices names like printer.lan, enter its address so those names keep working."),
      h("div", { class: "inline" }, homeDns, h("button", { class: "btn", onclick: () => act(() => api("PUT", "/api/settings", { homeDns: homeDns.value }), "Saved") }, "Save"))) : null,
    updatesCard(u),
    appUpdatesCard(),
    backupCard(),
    h("div", { class: "card" }, h("h2", {}, "Appearance"),
      h("p", { class: "muted" }, "Auto follows this device's own light or dark setting."), themeChips()),
    h("div", { class: "card" }, h("h2", {}, "Password"),
      h("label", { class: "field" }, h("span", {}, "Current password"), cur), h("label", { class: "field" }, h("span", {}, "New password (10+ characters)"), pw),
      h("div", { class: "btns" }, h("button", { class: "btn", onclick: () => act(async () => { await api("POST", "/api/password", { current: cur.value, password: pw.value }); showAuth(true); }, "Password changed; sign in again") }, "Change password"))),
    h("div", { class: "btns" }, h("a", { class: "btn", href: "guide.html" }, "User guide"), h("button", { class: "btn danger", onclick: () => act(async () => { await api("POST", "/api/logout"); showAuth(true); }) }, "Sign out")));
}

const SCREENS = { home: homeScreen, shield: shieldScreen, roster: rosterScreen, rules: rulesScreen, tunnel: tunnelScreen, pings: pingsScreen, settings: settingsScreen };
start();
