// Packs the box software for handing out:
//   dist/Cellowalla-Box.tar.gz     what boxes download to update themselves (cellosig.com/download/…)
//   dist/Cellowalla-Box-Software.zip  the same, for people installing by hand (HOW-TO-INSTALL.txt inside)
//   dist/box-build.json            its version and fingerprint (sign-release.mjs only signs a match)
//   node tools/pack-box.mjs

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const version = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).version;
const BOX = ["LICENSE", "README.md", "HOW-TO-INSTALL.txt", "package.json", "src", "web", "install"];

fs.rmSync(DIST, { recursive: true, force: true });
const stage = path.join(DIST, "stage", "cellowalla");
fs.mkdirSync(stage, { recursive: true });
for (const f of BOX) fs.cpSync(path.join(ROOT, f), path.join(stage, f), { recursive: true });
for (const f of fs.readdirSync(path.join(stage, "install"))) {
  const p = path.join(stage, "install", f);
  if (fs.readFileSync(p, "utf8").includes("\r")) throw new Error(`${f} has Windows line endings; bash would fail on the box`);
}

const tgz = path.join(DIST, "Cellowalla-Box.tar.gz");
execFileSync("tar", ["-czf", tgz, "-C", path.join(DIST, "stage"), "cellowalla"]);
execFileSync("tar", ["-a", "-cf", path.join(DIST, "Cellowalla-Box-Software.zip"), "-C", path.join(DIST, "stage"), "cellowalla"]);
fs.rmSync(path.join(DIST, "stage"), { recursive: true, force: true });

const bytes = fs.readFileSync(tgz);
const build = { version, file: "Cellowalla-Box.tar.gz", size: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
fs.writeFileSync(path.join(DIST, "box-build.json"), JSON.stringify(build, null, 1));
console.log(`Cellowalla box ${version}: ${tgz} (${bytes.length} bytes, ${build.sha256.slice(0, 12)}…)`);
