// Cellowalla for Windows and Linux: opens your box's dashboard in its own window, sits in the tray,
// shows Pings as desktop notifications, and pauses Shield from the tray menu.
//
// The box makes its own certificate (it's only reachable at home), so the first connection asks
// you to trust it, and from then on only that exact certificate is accepted.

const { app, BrowserWindow, Tray, Menu, Notification, dialog, ipcMain, session, shell, nativeImage, nativeTheme } = require("electron");
const path = require("node:path");
const fs = require("node:fs");

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
    if (isMain && code !== -3) win.loadFile(path.join(__dirname, "setup.html"), { query: { error: `Couldn't reach ${config.box} (${desc}).`, box: config.box } });
  });
  win.webContents.on("did-finish-load", () => pushTheme());
  if (config.box) win.loadURL(config.box); else win.loadFile(path.join(__dirname, "setup.html"));
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
    const fp = req.certificate.fingerprint; // "sha256/…"
    if (config.fingerprint && config.fingerprint === fp) return done(0);
    if (config.fingerprint && config.fingerprint !== fp) {
      dialog.showMessageBox({ type: "warning", title: "Cellowalla", message: "This box's certificate changed.",
        detail: `If you didn't reinstall Cellowalla, something may be pretending to be your box. Connection refused.\n\nExpected ${config.fingerprint}\nGot ${fp}\n\nTo trust the new one, use "Change box…" in the tray menu and connect again.` });
      return done(-2);
    }
    const choice = dialog.showMessageBoxSync({ type: "question", buttons: ["Trust this box", "Cancel"], defaultId: 0, cancelId: 1, title: "Cellowalla",
      message: `First connection to ${req.hostname}`,
      detail: `Your box made its own certificate, so your computer can't vouch for it. If this is your Cellowalla box, trust it once; after that only this exact certificate is accepted.\n\nFingerprint:\n${fp}` });
    if (choice !== 0) return done(-2);
    config.fingerprint = fp; saveConfig();
    done(0);
  });
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
    { label: "Change box…", click: () => { config.box = ""; config.fingerprint = ""; saveConfig(); show(); win.loadFile(path.join(__dirname, "setup.html")); } },
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

ipcMain.handle("cellowalla:connect", (_e, address) => {
  let url;
  try { url = new URL(/^https?:\/\//i.test(address) ? address : `https://${address}`); } catch { return { error: "That doesn't look like an address." }; }
  if (url.hostname !== boxHost()) config.fingerprint = "";
  config.box = url.origin; saveConfig();
  win.loadURL(config.box);
  return { ok: true };
});
ipcMain.handle("cellowalla:current", () => config.box);

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
