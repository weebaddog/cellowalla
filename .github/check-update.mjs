// CI: a real box updates itself. Packs this checkout as version 9.9.9, signs a release list with a
// throwaway key, serves both locally, and runs the box's own updater (the installed copy's update.js,
// given the test key and site as parameters: the box itself only ever trusts the owner's key). Then
// waits for the installer's systemd job to put 9.9.9 in and for Cellowalla to come back.
//   sudo node .github/check-update.mjs

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const fail = (m) => { console.error(`FAIL: ${m}`); process.exit(1); };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cw-upd-"));
const stage = path.join(tmp, "cellowalla");
fs.mkdirSync(stage);
for (const f of ["LICENSE", "README.md", "HOW-TO-INSTALL.txt", "package.json", "src", "web", "install"]) fs.cpSync(f, path.join(stage, f), { recursive: true });
const pkg = JSON.parse(fs.readFileSync(path.join(stage, "package.json"), "utf8"));
pkg.version = "9.9.9";
fs.writeFileSync(path.join(stage, "package.json"), JSON.stringify(pkg, null, 2));
const tgz = path.join(tmp, "box.tar.gz");
execFileSync("tar", ["-czf", tgz, "-C", tmp, "cellowalla"]);
const bytes = fs.readFileSync(tgz);

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const payload = JSON.stringify({ v: 1, apps: { cellowallaBox: { version: "9.9.9", path: "/download/Cellowalla-Box.tar.gz", size: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") } } });
const list = JSON.stringify({ payload, sig: crypto.sign("sha256", Buffer.from(payload), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") });
const server = http.createServer((req, res) => {
  if (req.url.startsWith("/release.json")) return res.end(list);
  if (req.url.startsWith("/download/Cellowalla-Box.tar.gz")) return res.end(bytes);
  res.writeHead(404).end();
});
await new Promise((ok) => server.listen(18765, "127.0.0.1", ok));

const { createUpdater } = await import("/opt/cellowalla/src/update.js");
const { openState } = await import("/opt/cellowalla/src/state.js");
const { createSys } = await import("/opt/cellowalla/src/sys.js");
const dataDir = "/var/lib/cellowalla";
const store = openState(dataDir);
const up = createUpdater({ store, version: JSON.parse(fs.readFileSync("/opt/cellowalla/package.json", "utf8")).version, dataDir,
  sys: createSys({ dataDir, dry: false }), site: "http://127.0.0.1:18765", key: publicKey.export({ type: "spki", format: "der" }).toString("base64") });
const s = await up.check({ install: true });
console.log("updater:", JSON.stringify(s));
if (s.error || !s.available) fail("the updater didn't start the update");
server.close();

for (let i = 0; i < 150; i++) {
  const v = JSON.parse(fs.readFileSync("/opt/cellowalla/package.json", "utf8")).version;
  let active = false;
  try { active = execFileSync("systemctl", ["is-active", "cellowalla"], { encoding: "utf8" }).trim() === "active"; } catch { /* not yet */ }
  if (v === "9.9.9" && active) {
    const hello = await fetch("http://127.0.0.1/api/hello", { redirect: "manual" }).catch(() => null);
    console.log(`updated to ${v}; service active; dashboard answers ${hello?.status}`);
    process.exit(0);
  }
  await new Promise((r) => setTimeout(r, 2000));
}
try { console.log(execFileSync("journalctl", ["-u", "cellowalla-update-*", "--no-pager", "-n", "80"], { encoding: "utf8" })); } catch { /* none */ }
fail("the box didn't come back on 9.9.9 within 5 minutes");
