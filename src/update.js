// Updates for the box: cellosig.com's signed release list (release.json, signed on the owner's PC with
// the release key) says which Cellowalla version is current and the fingerprint of its download. An
// update is put in only if the list's signature checks out with the key built in here AND the download
// matches the fingerprint, so a changed website or a tampered download can't install anything.
//
// Putting it in: the download is unpacked into <data>/update/ and its own installer is run again
// (the same as running it by hand), as a separate systemd job: this service can't change system files
// itself (ProtectSystem), and the installer restarts it.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// The same public key as cellosig.com's service worker (cellocloud/web/sw.js RELEASE_KEY).
export const RELEASE_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP9FLBRIG9RyIl+JFTBhVlyFz3QPoIvpVhU1iDmnfudQa+FhQ/9xj5F3741yOZUbZggvrxO7hrBkE+UPJUhrhAQ==";
export const SITE = "https://cellosig.com";
const DAY = 24 * 3600_000;

/** The `name` entry of a signed release list ({ payload, sig } JSON text), or null; throws if the signature is wrong. */
export function signedRelease(text, name, keyB64 = RELEASE_KEY) {
  const { payload, sig } = JSON.parse(text);
  const key = crypto.createPublicKey({ key: Buffer.from(keyB64, "base64"), format: "der", type: "spki" });
  if (typeof payload !== "string" || typeof sig !== "string" ||
      !crypto.verify("sha256", Buffer.from(payload), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sig, "base64"))) {
    throw new Error("the release list isn't signed with the release key");
  }
  const r = JSON.parse(payload).apps?.[name];
  if (!r || !/^\d+\.\d+\.\d+$/.test(r.version) || !/^[0-9a-f]{64}$/.test(r.sha256) || !Number.isSafeInteger(r.size) || r.size <= 0 ||
      !/^\/download\/[\w.-]+$/.test(r.path)) return null;
  return r;
}

/** Is version a newer than b ("1.10.0" > "1.9.3")? */
export function newer(a, b) {
  const x = String(a).split(".").map(Number), y = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return false;
}

// Updates come only from the owner: nothing on the box (settings, environment) can change the key.
// `site`/`key` are parameters for the self-test only.
export function createUpdater({ store, version, dataDir, sys, fetchImpl = fetch, log = console.log, pings, site = SITE, key = RELEASE_KEY }) {
  const dir = path.join(dataDir, "update");
  let state = { checkedAt: 0, latest: null, busy: null, error: null };

  const status = () => ({ auto: store.data.updates.auto, current: version, latest: state.latest?.version || null,
    available: !!state.latest && newer(state.latest.version, version), checkedAt: state.checkedAt, busy: state.busy, error: state.error });

  async function latest() {
    const res = await fetchImpl(`${site}/release.json`, { headers: { "cache-control": "no-cache" } });
    if (!res.ok) throw new Error(`release list: HTTP ${res.status}`);
    return signedRelease(await res.text(), "cellowallaBox", key);
  }

  /** Downloads r into <data>/update/, keeping it only if its size and SHA-256 are the signed ones. */
  async function download(r) {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = path.join(dir, "cellowalla.tar.gz");
    // (The fingerprint in the address: Cloudflare's cached copy of an older version is never handed out.)
    const res = await fetchImpl(`${site}${r.path}?v=${r.sha256.slice(0, 16)}`);
    if (!res.ok) throw new Error(`download: HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length !== r.size || crypto.createHash("sha256").update(buf).digest("hex") !== r.sha256) throw new Error("the download doesn't match the signed version");
    fs.writeFileSync(file, buf, { mode: 0o600 });
    return file;
  }

  /** Looks for a newer version; with install, puts it in. */
  async function check({ install = false } = {}) {
    if (state.busy) return status();
    state.busy = "checking"; state.error = null;
    let started = false;
    try {
      state.latest = await latest();
      state.checkedAt = Date.now();
      if (install && state.latest && newer(state.latest.version, version)) { await apply(state.latest); started = true; }
    } catch (e) {
      state.error = e.message;
      log(`[update] ${e.message}`);
    } finally { if (!started) state.busy = null; } // (once the installer runs, the box restarts)
    return status();
  }

  async function apply(r) {
    state.busy = "installing";
    log(`[update] installing Cellowalla ${r.version}`);
    const file = await download(r);
    await sys.run("tar", ["-xzf", file, "-C", dir], { timeout: 120_000 });
    const installer = path.join(dir, "cellowalla", "install", "install.sh");
    if (!sys.dry && !fs.existsSync(installer)) throw new Error("the download has no installer");
    const { mode, net } = store.data;
    pings?.send("system", `Updating Cellowalla to ${r.version}. The box restarts in a minute or two.`);
    store.flush();
    // Its own job, outside this service: the installer stops and restarts Cellowalla.
    await sys.run("systemd-run", ["--unit", `cellowalla-update-${Date.now()}`, "--collect", "--quiet",
      "--setenv=CW_YES=1", `--setenv=CW_MODE=${mode}`, `--setenv=CW_LAN=${net.lanIf}`, ...(mode === "gatekeeper" ? [`--setenv=CW_WAN=${net.wanIf}`] : []),
      "/bin/bash", installer]);
  }

  return {
    status,
    check,
    setAuto(on) { store.change("updates", (s) => { s.updates.auto = !!on; }); return status(); },
    /** Once a day (and a while after starting): when automatic updates are on, put in a newer version. */
    start() {
      const tick = () => check({ install: store.data.updates.auto }).catch(() => {});
      const first = setTimeout(tick, 10 * 60_000); first.unref?.();
      const t = setInterval(tick, DAY); t.unref?.();
      return () => { clearTimeout(first); clearInterval(t); };
    },
  };
}
