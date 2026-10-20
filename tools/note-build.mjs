// Writes a build's note next to it ({ version, file, size, sha256 }), which cellosig.com's release
// signing (cellocloud/server/tools/sign-release.mjs) needs before it offers that file as an update.
//   node tools/note-build.mjs <file> [version] [note.json]
//   (default version: package.json in the current folder; default note: build.json in the file's folder)

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [file, given, note2] = process.argv.slice(2);
const version = given || JSON.parse(fs.readFileSync("package.json", "utf8")).version;
const out = note2 || path.join(path.dirname(file || "."), "build.json");
if (!file || !/^\d+\.\d+\.\d+$/.test(version || "")) { console.error("usage: node tools/note-build.mjs <file> <x.y.z> [note.json]"); process.exit(1); }
const bytes = fs.readFileSync(file);
const note = { version, file: path.basename(file), size: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
fs.writeFileSync(out, JSON.stringify(note, null, 1));
console.log(`${note.file} ${version} ${note.sha256.slice(0, 12)}… → ${out}`);
