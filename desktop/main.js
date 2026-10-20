// Cellowalla for Windows and Linux: opens your box's dashboard in its own window, sits in the tray,
// shows Pings as desktop notifications, and pauses Shield from the tray menu.
//
// The box makes its own certificate (it's only reachable at home), so the first connection asks
// you to trust it, and from then on only that exact certificate is accepted.

const { app, BrowserWindow, Tray, Menu, Notification, dialog, ipcMain, session, shell, nativeImage, nativeTheme } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const crypto = require("node:crypto");

const ICON = path.join(__dirname, "icon.png");
if (process.env.CELLOWALLA_PROFILE && !app.isPackaged) app.setPath("userData", process.env.CELLOWALLA_PROFILE); // (testing)
let win = null, tray = null, quitting = false, signedIn = false;
const configFile = () => path.join(app.getPath("userData"), "config.json");

function loadConfig() {
  try { return { seen: [], ...JSON.parse(fs.readFileSync(configFile(), "utf8")) }; } catch { return { box: process.env.CELLOWALLA_BOX || "", fingerprint: "", seen: [], autostart: false }; }
}
let config = loadConfig();
function saveConfig() { fs.mkdirSync(path.dirname(configFile()), { recursive: true }); fs.writeFileSync(configFile(), JSON.stringify(config, null, 1)); }

const boxOrigin = () => { try { return new URL(config.box).origin; } catch { return null; } };
const boxHost = () => { try { return new URL(config.box).hostname; } catch { return null; } };

if (!app.requestSingleInstanceLock()) { app.quit(); }
app.on("second-instance", () => show());

function show() {
  if (!win) return createWindow();
  if (win.isMinimized()) win.restore();
  win.show(); win.focus();
}

function createWindow() {
  win = new BrowserWindow({
    width: 1100, height: 780, minWidth: 380, minHeight: 500, icon: ICON, title: "Cellowalla", backgroundColor: nativeTheme.shouldUseDarkColors ? "#0e1412" : "#f4f6f5", autoHideMenuBar: true,
    show: !process.argv.includes("--hidden"),
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, sandbox: true, nodeIntegration: false },
  });
  win.removeMenu();
  win.on("close", (e) => { if (!quitting) { e.preventDefault(); win.hide(); } });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://") || url.startsWith("http://")) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (e, url) => {
    if (url.startsWith("file:")) return;
    try { if (new URL(url).origin === boxOrigin()) return; } catch { /* bad url */ }
    e.preventDefault(); shell.openExternal(url);
  });
  win.webContents.on("did-fail-load", (_e, code, desc, url, isMain) => {
    if (!isMain || code === -3) return;
    showSetup({ error: `Couldn't reach ${config.box} (${desc}).`, box: config.box });
  });
  win.webContents.on("did-finish-load", () => pushTheme());
  // A saved box is checked from the setup page first, so an unreachable one shows "Connecting…" and
  // then a clear message instead of a blank window for half a minute.
  showSetup(config.box ? { auto: "1", box: config.box } : {});
}

function showSetup(query = {}) {
  win.loadFile(path.join(__dirname, "setup.html"), { query }).catch(() => {});
}

// ---- Light / Dark / Auto ------------------------------------------------------------------------------
// One setting for the whole app: the window frame, the setup page and the dashboard all follow it.

const THEMES = { auto: "Auto (follow the system)", light: "Light", dark: "Dark" };

function setTheme(mode, fromPage = false) {
  if (!(mode in THEMES)) mode = "auto";
  config.theme = mode; saveConfig();
  nativeTheme.themeSource = mode === "auto" ? "system" : mode;
  if (!fromPage) pushTheme();
  buildMenu();
}
function pushTheme() {
  win?.webContents.executeJavaScript(`window.cwSetTheme && window.cwSetTheme(${JSON.stringify(config.theme || "auto")}, true)`).catch(() => {});
}
ipcMain.on("cellowalla:theme", (_e, mode) => setTheme(mode, true));
ipcMain.handle("cellowalla:get-theme", () => config.theme || "auto");

// ---- the box's certificate (trust on first use) --------------------------------------------------

function trustBox() {
  session.defaultSession.setCertificateVerifyProc((req, done) => {
    if (req.hostname !== boxHost()) return done(-3); // everything else: normal checks
    if (req.verificationResult === "net::OK") return done(0);
    // The connect check below already asked about this certificate, so this never has to wait for
    // a person (a modal *sync* question here froze the app and Chromium's network service crashed).
    if (config.fingerprint && config.fingerprint === req.certificate.fingerprint) return done(0);
    done(-2);
  });
}

/** Asks once whether to trust the box's own certificate; resolves true when trusted. */
async function askTrust(host, fp) {
  const opts = { type: "question", buttons: ["Trust this box", "Cancel"], defaultId: 0, cancelId: 1, title: "Cellowalla",
    message: `First connection to ${host}`,
    detail: `Your box made its own certificate, so your computer can't vouch for it. If this is your Cellowalla box, trust it once; after that only this exact certificate is accepted.\n\nFingerprint:\n${fp}` };
  const { response } = await (win ? dialog.showMessageBox(win, opts) : dialog.showMessageBox(opts));
  return response === 0;
}

// ---- talking to the box from the tray (same sign-in as the window) ---------------------------------

async function api(method, p, body) {
  if (!boxOrigin()) throw new Error("No box set");
  const r = await session.defaultSession.fetch(boxOrigin() + p, { method, credentials: "include", headers: { "content-type": "application/json", "x-cellowalla": "1" }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { signedIn = false; throw new Error("Sign in first"); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
  signedIn = true;
  return r.json();
}

async function checkPings() {
  try {
    const { pings } = await api("GET", "/api/pings");
    const seen = new Set(config.seen);
    const fresh = pings.filter((p) => !p.read && !seen.has(p.id)).slice(0, 5).reverse();
    for (const p of fresh) {
      const n = new Notification({ title: { newDevice: "New device", malware: "Malware blocked", tunnel: "Tunnel", bedtime: "Bedtime", system: "Cellowalla" }[p.kind] || "Cellowalla", body: p.text, icon: ICON });
      n.on("click", show);
      n.show();
    }
    config.seen = pings.map((p) => p.id).slice(0, 300); saveConfig();
  } catch { /* not signed in or box away */ }
  buildMenu();
}

function pause(minutes) {
  api("POST", "/api/shield/pause", { minutes })
    .then(() => new Notification({ title: "Cellowalla", body: minutes ? `Shield paused for ${minutes} minutes.` : "Shield is back on.", icon: ICON }).show())
    .catch((e) => dialog.showErrorBox("Cellowalla", `${e.message}. Open Cellowalla and sign in.`));
}

function buildMenu() {
  if (!tray) return;
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open Cellowalla", click: show },
    { type: "separator" },
    { label: "Pause Shield for 15 minutes", enabled: signedIn, click: () => pause(15) },
    { label: "Pause Shield for 1 hour", enabled: signedIn, click: () => pause(60) },
    { label: "Resume Shield", enabled: signedIn, click: () => pause(0) },
    { type: "separator" },
    { label: "Appearance", submenu: Object.entries(THEMES).map(([k, label]) => ({ label, type: "radio", checked: (config.theme || "auto") === k, click: () => setTheme(k) })) },
    { label: "Change box…", click: () => { config.box = ""; config.fingerprint = ""; saveConfig(); show(); showSetup(); } },
    { label: "Start when I sign in", type: "checkbox", checked: !!config.autostart, click: (i) => setAutostart(i.checked) },
    { type: "separator" },
    { label: "Quit", click: () => { quitting = true; app.quit(); } },
  ]));
}

function setAutostart(on) {
  config.autostart = on; saveConfig();
  if (process.platform === "linux") {
    const dir = path.join(app.getPath("home"), ".config", "autostart"), file = path.join(dir, "cellowalla.desktop");
    if (on) {
      const exec = process.env.APPIMAGE || process.execPath;
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, `[Desktop Entry]\nType=Application\nName=Cellowalla\nExec="${exec}" --hidden\nIcon=cellowalla\nX-GNOME-Autostart-enabled=true\n`);
    } else fs.rmSync(file, { force: true });
  } else app.setLoginItemSettings({ openAtLogin: on, args: ["--hidden"] });
}

// ---- the setup page asks for the box's address -------------------------------------------------------

// Asks an address whether it's a Cellowalla box (GET /api/hello), before the window goes there. This
// is only "who are you?": no cookie or password is sent, so the certificate is checked afterwards,
// by the trust-on-first-use step, when the dashboard itself loads.
function hello(origin, timeout = 6000) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL("/api/hello", origin); } catch { return resolve({ error: "bad" }); }
    if (u.protocol !== "https:") return resolve({ error: "http" });
    const req = https.get(u, { rejectUnauthorized: false, timeout, headers: { accept: "application/json" } }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (d) => { if (text.length < 4096) text += d; });
      // Same form as Electron's certificate.fingerprint: "sha256/<base64>".
      const raw = res.socket.getPeerCertificate?.()?.raw;
      const fp = raw ? "sha256/" + crypto.createHash("sha256").update(raw).digest("base64") : "";
      res.on("end", () => {
        try { const j = JSON.parse(text); if (typeof j.setUp === "boolean") return resolve({ ok: true, fp }); } catch { /* not JSON */ }
        resolve({ error: "notbox" });
      });
    });
    req.on("timeout", () => { req.destroy(); resolve({ error: "timeout" }); });
    req.on("error", (e) => resolve({ error: e.code === "ENOTFOUND" || e.code === "EAI_AGAIN" ? "name" : e.code === "ECONNREFUSED" ? "refused" : "timeout" }));
  });
}

/** This computer's own IPv4 networks ("192.168.253"), for hints and for Find my box. */
function localNets() {
  const nets = new Set();
  for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) {
    if (a.family === "IPv4" && !a.internal && !a.address.startsWith("169.254.")) nets.add(a.address.split(".").slice(0, 3).join("."));
  }
  return [...nets];
}

function whyNot(host, error) {
  const nets = localNets();
  const here = nets.length ? ` This computer is on ${nets.map((n) => `${n}.x`).join(" and ")}, so your box's address usually starts with ${nets[0]}.` : "";
  if (error === "name") return `This computer can't find "${host}". That name only works once your devices use the box for DNS: type the box's number address instead, or use Find my box.`;
  if (error === "notbox") return `Something answered at ${host}, but it isn't a Cellowalla box (it may be your router).${here} Try Find my box.`;
  if (error === "refused") return `${host} is there but isn't running Cellowalla's dashboard. Check the box finished installing.`;
  return `Nothing answered at ${host}. Make sure the box is switched on and this computer is on the same Wi-Fi.${here} Try Find my box.`;
}

ipcMain.handle("cellowalla:connect", async (_e, address) => {
  let url;
  const a = String(address || "").trim();
  try { url = new URL(/^https?:\/\//i.test(a) ? a.replace(/^http:/i, "https:") : `https://${a}`); } catch { return { error: "That doesn't look like an address." }; }
  if (!url.hostname) return { error: "That doesn't look like an address." };
  const r = await hello(url.origin);
  if (!r.ok) return { error: whyNot(url.host, r.error) };
  const pinned = url.hostname === boxHost() ? config.fingerprint : "";
  if (pinned && r.fp !== pinned) {
    return { error: `${url.host}'s certificate changed. If you didn't reinstall Cellowalla, something may be pretending to be your box, so the connection was refused. To trust the new one, use "Change box…" in the tray menu and connect again.` };
  }
  if (!pinned) {
    if (!r.fp || !(await askTrust(url.host, r.fp))) return { error: "Not connected: the box's certificate wasn't trusted." };
  }
  config.box = url.origin; config.fingerprint = pinned || r.fp; saveConfig();
  win.loadURL(config.box).catch(() => {}); // a failure lands in did-fail-load
  return { ok: true };
});
ipcMain.handle("cellowalla:current", () => config.box);

// Find my box: asks every address on this computer's own networks (and cellowalla.lan) at once.
ipcMain.handle("cellowalla:find", async () => {
  const candidates = ["cellowalla.lan"];
  for (const n of localNets().slice(0, 4)) for (let i = 1; i < 255; i++) candidates.push(`${n}.${i}`);
  const found = [];
  let next = 0;
  const worker = async () => {
    while (next < candidates.length) {
      const h = candidates[next++];
      if ((await hello(`https://${h}`, 1500)).ok) found.push(h);
    }
  };
  await Promise.all(Array.from({ length: 128 }, worker));
  return { found, nets: localNets() };
});

app.whenReady().then(() => {
  if (process.platform === "win32") app.setAppUserModelId("com.cellowalla.desktop");
  trustBox();
  nativeTheme.themeSource = config.theme === "light" || config.theme === "dark" ? config.theme : "system";
  tray = new Tray(nativeImage.createFromPath(ICON).resize({ width: 16, height: 16 }));
  tray.setToolTip("Cellowalla");
  tray.on("click", show);
  buildMenu();
  createWindow();
  setInterval(checkPings, 60_000);
  setTimeout(checkPings, 8000);
});
app.on("window-all-closed", () => { /* stays in the tray */ });
app.on("before-quit", () => { quitting = true; });
