// A demo box for trying the dashboard on any computer: dry mode (nothing on the system changes),
// real block lists and real DNS, a few made-up devices. Password: demo-password
//   node test/demo.js   →  http://localhost:8088   (DNS on port 5300)

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../src/main.js";
import { hashPassword } from "../src/web.js";
import { udpAsk } from "../src/shield.js";
import { makeQuery } from "../src/dnsproto.js";

const dir = path.join(os.tmpdir(), "cellowalla-demo");
fs.rmSync(dir, { recursive: true, force: true });
// Not signed in with CelloCloud: shown like a box from before the plan check (7 days of grace, banner).
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "cellocloud.json"), JSON.stringify({ graceUntil: Date.now() + 7 * 86400_000, graceGiven: true }));
const app = await createApp({ dataDir: dir, dry: true });
const now = Date.now();
const dev = (mac, ip, extra) => ({ mac, ip, name: null, host: null, vendor: null, firstSeen: now - 86400_000 * 9, lastSeen: now, crew: null, blocked: false, pausedUntil: 0, lobby: false, kind: "lan", ...extra });
app.store.change("seed", (s) => {
  s.admin = hashPassword("demo-password");
  s.crews.kids = { id: "kids", name: "Kids", lists: { adult: true, social: true }, cleanSearch: true, deny: [], bedtimes: [{ days: [0, 1, 2, 3, 4], from: "21:00", to: "07:00" }], pausedUntil: 0, graceUntil: 0 };
  s.devices = {
    "127.0.0.1": dev("127.0.0.1", "127.0.0.1", { name: "This computer", vendor: "Demo" }),
    "b8:27:eb:11:22:33": dev("b8:27:eb:11:22:33", "192.168.1.21", { name: "Living room TV", vendor: "Raspberry Pi Trading Ltd" }),
    "da:a1:19:44:55:66": dev("da:a1:19:44:55:66", "192.168.1.34", { name: "Sam's iPad", vendor: "Private address", crew: "kids" }),
    "3c:22:fb:77:88:99": dev("3c:22:fb:77:88:99", "192.168.1.40", { host: "nintendo-switch", vendor: "Nintendo Co.,Ltd", crew: "kids", lastSeen: now - 3 * 3600_000 }),
    "f4:f5:d8:aa:bb:cc": dev("f4:f5:d8:aa:bb:cc", "192.168.1.52", { vendor: "Google, Inc.", firstSeen: now - 600_000, lobby: true }),
  };
  s.lobby.on = true;
});
app.pings.send("newDevice", "Google, Inc. joined the network (192.168.1.52). It's waiting in the Lobby until you let it in.");
app.pings.send("malware", "Sam's iPad tried to reach bad-site.example, a known malware or scam site. Shield stopped it.");
await app.start({ dnsPort: 5300, webPort: 8088, host: "127.0.0.1" });
await app.refreshLists();
for (const n of ["example.com", "doubleclick.net", "www.google-analytics.com", "github.com", "ads.yahoo.com", "app-measurement.com", "wikipedia.org"]) await udpAsk("127.0.0.1", 5300, makeQuery(n, 1)).catch(() => {});
console.log("Demo dashboard: http://localhost:8088  (password: demo-password)");
