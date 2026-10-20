// The only place Cellowalla touches the operating system: running commands (nft, wg, ip) and
// writing system files. In "dry" mode (any non-Linux machine, or CELLOWALLA_DRY=1) nothing is run;
// commands are recorded and files land in <data>/dry/ instead, so everything can be tested on a PC.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export function createSys({ dataDir, dry = process.platform !== "linux" || process.env.CELLOWALLA_DRY === "1", log = console.log }) {
  const ran = [];          // dry mode: every command that would have run
  const dryDir = path.join(dataDir, "dry");
  const fakeOutput = new Map(); // dry mode: command name → canned stdout (tests)

  function run(cmd, args = [], { input, timeout = 15000 } = {}) {
    if (dry) {
      ran.push([cmd, ...args].join(" ") + (input ? `  <<< ${input.length} bytes` : ""));
      if (input) { fs.mkdirSync(dryDir, { recursive: true }); fs.writeFileSync(path.join(dryDir, `${cmd}.input`), input); }
      return Promise.resolve(fakeOutput.get([cmd, args[0]].join(" ")) ?? fakeOutput.get(cmd) ?? "");
    }
    return new Promise((resolve, reject) => {
      const child = execFile(cmd, args, { timeout, maxBuffer: 16 << 20 }, (err, stdout, stderr) => {
        if (err) { err.message = `${cmd} ${args.join(" ")}: ${String(stderr || err.message).trim()}`; reject(err); } else resolve(stdout);
      });
      if (input !== undefined) { child.stdin.end(input); }
    });
  }

  /** Writes a system file (only if it changed). Returns true if it changed. */
  function writeFile(file, text, mode = 0o644) {
    const target = dry ? path.join(dryDir, file.replace(/^[A-Za-z]:/, "").replace(/[\\/]+/g, "_")) : file;
    try { if (fs.readFileSync(target, "utf8") === text) return false; } catch { /* new */ }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const tmp = `${target}.tmp`;
    fs.writeFileSync(tmp, text, { mode });
    fs.renameSync(tmp, target);
    return true;
  }

  function readFile(file) {
    try { return fs.readFileSync(dry ? path.join(dryDir, file.replace(/^[A-Za-z]:/, "").replace(/[\\/]+/g, "_")) : file, "utf8"); } catch { return null; }
  }

  return { dry, run, writeFile, readFile, ran, fake: (cmd, out) => fakeOutput.set(cmd, out), log };
}
