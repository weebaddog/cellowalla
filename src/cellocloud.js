// Sign in with CelloCloud. Cellowalla comes with CelloCloud's 700 GB plan, so the box signs in with
// the customer's CelloCloud account (one account per box) and asks cellosig.com, now and then, whether
// that account still includes Cellowalla. The CelloCloud server decides (plan, a payment that failed
// and wasn't fixed, the owner's switches); the box only follows the answer.
//
// When the answer is "no", the box STOPS PROTECTING (no blocking, House Rules, Clean Search, Lobby)
// but never stops the home's internet: Shield keeps answering every question, unfiltered, and in
// Gatekeeper mode the box keeps routing and handing out addresses. See policy.js (rulesFor).
//
// The password never leaves the box and is never kept: it's turned into the authKey (PBKDF2, the
// same as CelloCloud's own apps; APP-SIGNIN.md) and thrown away. Only the sign-in token (which can
// ask "may this app run?" and nothing else) and the last answer are kept, in <data>/cellocloud.json,
// readable by root only, like the box's other secrets. It's never put into a backup.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const CELLOCLOUD = "https://cellosig.com";
export const APP_ID = "cellowalla";
const H = 3600_000, DAY = 24 * H;
export const CHECK_EVERY = 6 * H;       // ask this often while running (and at start, and on "Check again")
export const OFFLINE_LIMIT = 14 * DAY;  // no answer at all for this long → lock
export const GRACE = 7 * DAY;           // boxes that were already running before sign-in existed
const USERNAME = /^[a-z0-9][a-z0-9._-]{2,31}$/;

export const TEXT = {
  signIn: "Sign in with your CelloCloud account to turn Cellowalla's protection on.",
  signedOut: "This box was signed out of CelloCloud (the password was changed, or it was signed out in CelloCloud's Settings). Sign in again to turn protection back on.",
  offline: "Connect to the internet so Cellowalla can check your CelloCloud plan.",
  payment: "Your CelloCloud payment didn't go through, so Cellowalla is locked. Update your card on cellosig.com, then press Check again.",
  notAllowed: "Your CelloCloud account doesn't include Cellowalla right now. See cellosig.com.",
};

/**
 * Where to ask: cellosig.com. The CI check of a real install points the box at a pretend CelloCloud
 * on the same machine (CELLOWALLA_CELLOCLOUD=http://127.0.0.1:port); nothing else is accepted.
 */
export function cloudSite(env = process.env) {
  const v = String(env.CELLOWALLA_CELLOCLOUD || "");
  return /^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?$/.test(v) ? v : CELLOCLOUD;
}

/**
 * The authKey CelloCloud checks: PBKDF2-HMAC-SHA256(NFKC password, 16-byte salt, 600 000) → 64 bytes;
 * bytes 32..63 as hex. Bytes 0..31 unlock the customer's files: wiped here, never sent or kept.
 * (Asynchronous: on a small box this takes a second or two, and Shield must keep answering meanwhile.)
 */
export function authKey(password, saltHex) {
  const salt = Buffer.from(String(saltHex || ""), "hex");
  if (salt.length !== 16) return Promise.reject(new Error("CelloCloud sent a strange salt"));
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(String(password).normalize("NFKC"), salt, 600_000, 64, "sha256", (err, bytes) => {
      if (err) return reject(err);
      const key = bytes.subarray(32).toString("hex");
      bytes.fill(0);
      resolve(key);
    });
  });
}

/** What the box should do now, from what it remembers (pure: the self-test drives it with times). */
export function decide(acct, now = Date.now()) {
  if (!acct.token) {
    if ((acct.graceUntil || 0) > now) return { locked: false, reason: "sign_in", message: null, graceUntil: acct.graceUntil };
    return { locked: true, reason: acct.signedOut ? "signed_out" : "sign_in", message: acct.signedOut ? TEXT.signedOut : TEXT.signIn };
  }
  const a = acct.answer || {};
  if (!acct.fetchedAt || now - acct.fetchedAt > OFFLINE_LIMIT) return { locked: true, reason: "offline", message: TEXT.offline };
  if (!a.allowed) return { locked: true, reason: a.reason || "not_in_plan", message: a.message || TEXT.notAllowed };
  if (a.lockAt && now >= a.lockAt) return { locked: true, reason: "payment_failed", message: TEXT.payment };
  return { locked: false, reason: "ok", message: null, lockAt: a.lockAt || null };
}

const ERRORS = {
  wrong_login: [403, "Wrong CelloCloud username or password"],
  totp_required: [403, "Type the 6-digit two-step code from your authenticator app"],
  wrong_code: [403, "That two-step code is wrong"],
  rate_limited: [429, "Too many tries; wait a few minutes and try again"],
  signins_paused: [429, "CelloCloud sign-ins are paused for a few minutes; try again soon"],
  paused_signins: [423, "CelloCloud sign-ins are paused right now; try again later"],
  bad_username: [400, "That isn't a CelloCloud username"],
};
const fail = (status, message, code) => Object.assign(new Error(message), { status, code });

export function createCelloCloud({ dataDir, fetchImpl = fetch, log = console.log, site = cloudSite(), device = "Cellowalla box", setUp = false, now = () => Date.now(), onChange = () => {} }) {
  const file = path.join(dataDir, "cellocloud.json");
  let acct = null;
  try { acct = JSON.parse(fs.readFileSync(file, "utf8")); } catch { /* never signed in */ }
  if (!acct || typeof acct !== "object") {
    // A box that was already set up before this version: it keeps protecting for a while, with a
    // banner asking to sign in, so an automatic update never drops a family's protection at once.
    // A new box asks for the sign-in during setup instead.
    acct = { graceUntil: setUp ? now() + GRACE : 0, graceGiven: setUp };
    save();
  }
  let busy = null, lastError = null, lastTry = 0;

  function save() {
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(acct), { mode: 0o600 });
    fs.renameSync(tmp, file);
    try { fs.chmodSync(file, 0o600); } catch { /* not on every system */ }
  }

  function status() {
    const d = decide(acct, now());
    const a = acct.answer || {};
    return { ...d, signedIn: !!acct.token, username: acct.username || null, device: acct.device || null,
      plan: acct.token ? a.plan || null : null, appName: a.appName || null, checkedAt: acct.fetchedAt || 0,
      lastTry, lastError, everSignedIn: !!acct.everSignedIn, graceGiven: !!acct.graceGiven };
  }

  async function ask(p, { method = "GET", body, token } = {}) {
    const headers = { accept: "application/json" };
    if (method !== "GET") { headers["x-cellocloud"] = "1"; headers["content-type"] = "application/json"; }
    if (token) headers.authorization = `Bearer ${token}`;
    const r = await fetchImpl(`${site}${p}`, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(20_000) });
    const data = await r.json().catch(() => ({}));
    return { status: r.status, data };
  }

  /** Signs the box in. The password is used for the authKey and dropped. */
  async function login({ username, password, totp } = {}) {
    const user = String(username || "").trim().toLowerCase();
    if (!USERNAME.test(user)) throw fail(400, ERRORS.bad_username[1], "bad_username");
    if (!password) throw fail(400, "Type your CelloCloud password", "no_password");
    const code = totp ? String(totp).replace(/\s+/g, "") : undefined;
    if (code !== undefined && !/^\d{6}$/.test(code)) throw fail(400, "The two-step code is 6 digits", "wrong_code");
    let salt, res;
    try {
      salt = await ask(`/api/salt?u=${encodeURIComponent(user)}`);
      if (salt.status !== 200) { const e = ERRORS[salt.data.error]; throw fail(e?.[0] || 502, e?.[1] || `CelloCloud said ${salt.data.error || salt.status}`, salt.data.error); }
      const key = await authKey(password, salt.data.salt);
      res = await ask("/api/apps/login", { method: "POST", body: { username: user, authKey: key, app: APP_ID, device: String(device).slice(0, 60), ...(code ? { totp: code } : {}) } });
    } catch (e) {
      if (e.status) throw e;
      throw fail(502, "Couldn't reach CelloCloud (cellosig.com). Check the box's internet connection and try again.", "offline");
    }
    if (res.status !== 200 || !res.data.token) {
      const err = res.data.error;
      const e = ERRORS[err];
      throw fail(e?.[0] || 502, e?.[1] || `CelloCloud said ${err || `HTTP ${res.status}`}`, err || "failed");
    }
    const { token, ...answer } = res.data;
    acct = { token, username: user, device: String(device).slice(0, 60), answer, fetchedAt: now(), everSignedIn: true, graceUntil: 0, graceGiven: acct.graceGiven };
    lastError = null; lastTry = now();
    save();
    log(`[cellocloud] signed in as ${user}: ${answer.allowed ? "Cellowalla is included" : answer.reason}`);
    onChange();
    return status();
  }

  /** Asks whether Cellowalla may run. Offline / unreachable: the last answer stands. */
  async function check() {
    if (!acct.token) return status();
    if (busy) return busy;
    busy = (async () => {
      lastTry = now();
      try {
        const r = await ask("/api/apps/access", { token: acct.token });
        if (r.status === 200 && typeof r.data.allowed === "boolean") {
          acct.answer = r.data; acct.fetchedAt = now(); lastError = null;
          save();
        } else if (r.status === 401) {
          log("[cellocloud] signed out by CelloCloud");
          acct = { signedOut: true, everSignedIn: true, username: acct.username, graceUntil: 0, graceGiven: acct.graceGiven };
          lastError = null;
          save();
        } else lastError = `CelloCloud answered ${r.data.error || `HTTP ${r.status}`}`;
      } catch (e) {
        lastError = "Couldn't reach CelloCloud";
        log(`[cellocloud] check: ${e.message}`);
      }
      onChange();
      return status();
    })().finally(() => { busy = null; });
    return busy;
  }

  /** Signs this box out (here and, if it can be reached, at CelloCloud). */
  async function logout() {
    const token = acct.token;
    acct = { everSignedIn: !!acct.everSignedIn, graceUntil: 0, graceGiven: acct.graceGiven };
    save();
    lastError = null;
    if (token) await ask("/api/apps/logout", { method: "POST", token }).catch(() => {});
    onChange();
    return status();
  }

  let timers = [];
  return {
    status,
    locked: () => decide(acct, now()).locked,
    login,
    check,
    logout,
    /** Asks now and every 6 hours; re-decides every minute (a lockAt or the 14 days can pass offline). */
    start() {
      check().catch(() => {});
      const t1 = setInterval(() => check().catch(() => {}), CHECK_EVERY); t1.unref?.();
      const t2 = setInterval(() => onChange(), 60_000); t2.unref?.();
      timers = [t1, t2];
      return () => { for (const t of timers) clearInterval(t); };
    },
  };
}
