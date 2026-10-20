// Used by install.sh: writes the mode and ports into Cellowalla's state, keeping everything else.
//   node configure.mjs --data /var/lib/cellowalla --mode lookout|gatekeeper --lan eth0 [--wan eth1]
//   node configure.mjs --data /var/lib/cellowalla --reset-password

import fs from "node:fs";
import path from "node:path";
import { openState } from "../src/state.js";

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => {
  if (a.startsWith("--")) acc.push([a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : true]);
  return acc;
}, []));
const dir = args.data || "/var/lib/cellowalla";
const store = openState(dir);
const IFACE = /^[A-Za-z0-9_.-]{1,15}$/;

if (args["reset-password"]) {
  store.change("admin", (s) => { s.admin = null; });
  store.flush();
  try { fs.unlinkSync(path.join(dir, "setup-code.txt")); } catch { /* none */ }
  console.log("Password cleared.");
  process.exit(0);
}

if (!["lookout", "gatekeeper"].includes(args.mode)) { console.error("--mode lookout|gatekeeper"); process.exit(2); }
if (!IFACE.test(args.lan || "")) { console.error("--lan <interface>"); process.exit(2); }
if (args.mode === "gatekeeper" && (!IFACE.test(args.wan || "") || args.wan === args.lan)) { console.error("--wan <a different interface>"); process.exit(2); }

store.change("net", (s) => {
  s.mode = args.mode;
  s.net.lanIf = args.lan;
  if (args.mode === "gatekeeper") {
    s.net.wanIf = args.wan;
    s.net.boxIp = "192.168.50.1";
    s.net.lanCidr = "192.168.50.0/24";
    s.net.dhcpFrom = "192.168.50.100";
    s.net.dhcpTo = "192.168.50.250";
    s.net.gateway = "";
  } else if (args.gateway) s.net.gateway = String(args.gateway);
});
store.flush();
console.log(`Cellowalla set to ${args.mode} mode (home port ${args.lan}${args.mode === "gatekeeper" ? `, internet port ${args.wan}` : ""}).`);
