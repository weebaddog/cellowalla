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
const { spawn } = require("node:child_process");
const { signedRelease, newer, saveVerified, downloadUrl, installCommand, SITE } = require("./updates.js");

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
  win.on("hide", () => { if (update.ready && autoUpdate()) installUpdate(true); }); // nobody's looking: a good moment
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
    { label: "Update automatically", type: "checkbox", checked: autoUpdate(), click: (i) => setAutoUpdate(i.checked) },
    update.ready ? { label: `Restart to update (${update.ready.version})`, click: () => installUpdate(false) }
      : { label: "Check for updates", click: async () => {
        const s = await checkUpdates();
        if (!s.ready) dialog.showMessageBox({ type: "info", title: "Cellowalla", message: s.error ? `Couldn't check for updates: ${s.error}` : s.latest && newer(s.latest, s.current) ? `Cellowalla ${s.latest} is out.` : `Cellowalla ${s.current} is the newest version.` });
      } },
    { type: "separator" },
    { label: "Quit", click: () => { quitting = true; app.quit(); } },
  ]));
}

// ---- automatic updates (only versions signed by the owner: see updates.js) ---------------------------

const UPDATE_NAME = process.platform === "win32" ? "cellowallaWindows" : "cellowallaLinux";
const update = { ready: null, latest: null, checkedAt: 0, error: null, told: "" };
const autoUpdate = () => config.autoUpdate !== false;
const updateStatus = () => ({ auto: autoUpdate(), current: app.getVersion(), latest: update.latest, ready: update.ready?.version || null,
  checkedAt: update.checkedAt, error: update.error, canInstall: app.isPackaged && (process.platform === "win32" || !!process.env.APPIMAGE) });

async function checkUpdates() {
  try {
    const res = await fetch(`${SITE}/release.json`, { cache: "no-store" });
    if (!res.ok) throw new Error(`release list: HTTP ${res.status}`);
    const r = signedRelease(await res.text(), UPDATE_NAME);
    update.checkedAt = Date.now(); update.latest = r?.version || null; update.error = null;
    if (!r || !newer(r.version, app.getVersion()) || update.ready?.version === r.version) return updateStatus();
    if (!updateStatus().canInstall) {
      // (a .deb copy, or running from source: say so once per version)
      if (update.told !== r.version) { update.told = r.version; new Notification({ title: "Cellowalla update", body: `Cellowalla ${r.version} is out. Get it from ${SITE}/download/Cellowalla.deb (or the AppImage, which updates itself).`, icon: ICON }).show(); }
      return updateStatus();
    }
    const file = process.platform === "win32" ? path.join(app.getPath("temp"), `Cellowalla-Setup-${r.version}.exe`) : `${process.env.APPIMAGE}.new`;
    await saveVerified(await fetch(downloadUrl(r)), file, r);
    update.ready = { version: r.version, file };
    if (!win || !win.isVisible()) installUpdate(true);
    else new Notification({ title: "Cellowalla update ready", body: `Version ${r.version} goes in when you close the window, or choose "Restart to update" in the tray menu.`, icon: ICON }).show();
  } catch (e) {
    update.error = e.message;
  } finally { buildMenu(); }
  return updateStatus();
}

function installUpdate(hidden) {
  const u = update.ready;
  if (!u) return;
  quitting = true;
  if (process.platform === "win32") {
    const [cmd, args] = installCommand(u.file, process.execPath, hidden);
    spawn(cmd, args, { detached: true, stdio: "ignore", windowsVerbatimArguments: true, windowsHide: true }).unref();
  } else {
    fs.renameSync(u.file, process.env.APPIMAGE); // the AppImage replaces itself
    app.relaunch({ args: hidden ? ["--hidden"] : [] });
  }
  app.quit();
}

function setAutoUpdate(on) {
  config.autoUpdate = !!on; saveConfig(); buildMenu();
  if (on) checkUpdates();
  return updateStatus();
}

// The dashboard's Settings shows this app's own Updates switch too (through preload.js).
ipcMain.handle("cellowalla:updates", () => updateStatus());
ipcMain.handle("cellowalla:set-auto-update", (_e, on) => setAutoUpdate(on));
ipcMain.handle("cellowalla:check-updates", () => checkUpdates());
ipcMain.on("cellowalla:install-update", () => installUpdate(false));

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

// Problems in this app go to the box (it emails the owner); kept and sent later when the box can't be reached.
const pendingReports = () => path.join(app.getPath("userData"), "pending-reports.json");
async function reportProblem(kind, message, detail = "") {
  let list = [];
  try { list = JSON.parse(fs.readFileSync(pendingReports(), "utf8")); } catch { /* none */ }
  if (kind) list.push({ source: "desktop", kind, message: String(message).slice(0, 500), detail: String(detail).slice(0, 6000), device: `Cellowalla desktop · ${process.platform === "win32" ? "Windows" : "Linux"} ${os.release()}`, version: app.getVersion() });
  const left = [];
  for (const r of list.slice(-20)) { try { await api("POST", "/api/report", r); } catch (e) { if (!/HTTP 429/.test(e.message)) left.push(r); } }
  try { if (left.length) fs.writeFileSync(pendingReports(), JSON.stringify(left)); else fs.rmSync(pendingReports(), { force: true }); } catch { /* full disk */ }
}
process.on("uncaughtException", (e) => { reportProblem("app error", e.message, e.stack).catch(() => {}); });
process.on("unhandledRejection", (e) => { reportProblem("app error", e?.message || String(e), e?.stack || "").catch(() => {}); });

app.whenReady().then(() => {
  setTimeout(() => reportProblem(null).catch(() => {}), 30_000); // (any saved from last time)
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
  // Updates: a minute after starting, then every 6 hours, while the switch is on.
  const maybeUpdate = () => { if (autoUpdate() && app.isPackaged) checkUpdates(); };
  setTimeout(maybeUpdate, 60_000);
  setInterval(maybeUpdate, 6 * 3600_000);
});
app.on("window-all-closed", () => { /* stays in the tray */ });
app.on("before-quit", () => { quitting = true; });
