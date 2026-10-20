// Automatic updates: cellosig.com's signed release list (release.json, signed on the owner's PC with the
// release key: cellocloud/server/tools/sign-release.mjs) says which version of this app is current and
// the download's fingerprint. An update is put in only if the list's signature checks out with the key
// built in here AND the download matches: a changed website or a tampered download can't install anything.
// Updates come only from the owner: nothing outside this file can change the key.
const crypto = require("node:crypto");
const fs = require("node:fs");

// The same public key as cellosig.com's service worker (cellocloud/web/sw.js RELEASE_KEY).
const RELEASE_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP9FLBRIG9RyIl+JFTBhVlyFz3QPoIvpVhU1iDmnfudQa+FhQ/9xj5F3741yOZUbZggvrxO7hrBkE+UPJUhrhAQ==";
const SITE = "https://cellosig.com";

/** The `name` entry of a signed release list ({ payload, sig } JSON text), or null; throws if the signature is wrong. */
function signedRelease(text, name, keyB64 = RELEASE_KEY) {
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
function newer(a, b) {
  const x = String(a).split(".").map(Number), y = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return false;
}

/** Saves a download (a fetch Response) to `file`, keeping it only if its size and SHA-256 are the signed ones. */
async function saveVerified(res, file, { size, sha256 }) {
  if (!res.ok) throw new Error(`download failed (HTTP ${res.status})`);
  const hash = crypto.createHash("sha256");
  const out = fs.createWriteStream(file, { mode: 0o755 });
  let got = 0;
  try {
    for await (const chunk of res.body) {
      got += chunk.length;
      if (got > size) throw new Error("the download is bigger than the signed version");
      hash.update(chunk);
      if (!out.write(chunk)) await new Promise((ok) => out.once("drain", ok));
    }
    await new Promise((ok, bad) => out.end((e) => (e ? bad(e) : ok())));
    if (got !== size || hash.digest("hex") !== sha256) throw new Error("the download doesn't match the signed version");
  } catch (e) {
    out.destroy();
    fs.rmSync(file, { force: true });
    throw e;
  }
}

/** The download address: with the fingerprint in it, so Cloudflare's cached copy of an older version is never handed out. */
const downloadUrl = (r, site = SITE) => `${site}${r.path}?v=${r.sha256.slice(0, 16)}`;

/** Windows: cmd waits for the quiet installer (/S) to finish, then starts Cellowalla again (in the tray when hidden). */
function installCommand(installer, exe, hidden) {
  return ["cmd.exe", ["/d", "/s", "/c", `"start "" /wait "${installer}" /S & start "" "${exe}"${hidden ? " --hidden" : ""}"`]];
}

module.exports = { signedRelease, newer, saveVerified, downloadUrl, installCommand, RELEASE_KEY, SITE };
