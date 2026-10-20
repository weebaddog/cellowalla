// Cellowalla self-test: runs the whole box in dry mode on any computer (nothing on the system is
// touched), with fake block lists and a fake upstream resolver, and checks every part.
//   node test/selftest.js

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { createApp } from "../src/main.js";
import * as P from "../src/dnsproto.js";
import { udpAsk } from "../src/shield.js";
import { parseList, underAny, cleanName } from "../src/lists.js";
import { bedtimeOn, rulesFor } from "../src/policy.js";
import { nftRules, dnsmasqConf, parseCounters, inCidr } from "../src/gate.js";
import { keyPair, parseDump, passConf } from "../src/tunnel.js";
import { parseLeases, hostsIn, randomMac } from "../src/roster.js";
import { DEFAULTS } from "../src/state.js";

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ok   ${name}`); }
  catch (e) { failed++; console.log(`  FAIL ${name}\n       ${e.stack.split("\n").slice(0, 3).join("\n       ")}`); }
}

// ---- unit tests ---------------------------------------------------------------------------------

console.log("units");
await test("parseList reads hosts, plain and adblock lists", () => {
  const s = parseList("# c\n0.0.0.0 ads.one.com\n127.0.0.1 two.net # x\n0.0.0.0 localhost\nthree.org\n||four.io^\n||bad^$third-party\n! adblock comment\nnot a name here\n::1 five.dev");
  assert.deepEqual([...s].sort(), ["ads.one.com", "five.dev", "four.io", "three.org", "two.net"]);
});
await test("underAny matches the name and everything under it", () => {
  const s = new Set(["ads.com"]);
  assert.equal(underAny(s, "x.y.ads.com"), "ads.com");
  assert.equal(underAny(s, "notads.com"), null);
  assert.equal(underAny(s, "com"), null);
});
await test("cleanName tidies what people type", () => {
  assert.equal(cleanName("https://WWW.Example.com/page?x=1"), "www.example.com");
  assert.equal(cleanName("*.tiktok.com"), "tiktok.com");
  assert.equal(cleanName("not a site"), null);
});
await test("bedtimes, including ones that run past midnight", () => {
  const at = (day, hh, mm = 0) => { const d = new Date(2026, 9, 18 + day, hh, mm); return d; }; // 2026-10-18 is a Sunday
  const b = { days: [0, 1, 2, 3, 4], from: "21:00", to: "07:00" };
  assert.equal(bedtimeOn(b, at(0, 22)), true);   // Sun 22:00
  assert.equal(bedtimeOn(b, at(1, 6, 59)), true); // Mon 06:59 (from Sunday)
  assert.equal(bedtimeOn(b, at(1, 7)), false);
  assert.equal(bedtimeOn(b, at(5, 22)), false);  // Fri night: not in days
  assert.equal(bedtimeOn(b, at(6, 3)), false);   // Sat 03:00: Friday's isn't on
  assert.equal(bedtimeOn({ days: [3], from: "13:00", to: "15:00" }, at(3, 14)), true);
});
await test("rulesFor: crew adds, cuts in the right order", () => {
  const s = DEFAULTS();
  s.crews.k = { id: "k", name: "Kids", lists: { adult: true }, cleanSearch: true, deny: ["x.com"], bedtimes: [], pausedUntil: 0, graceUntil: 0 };
  const d = { mac: "m", crew: "k", blocked: false, pausedUntil: 0, lobby: false };
  let r = rulesFor(s, d);
  assert.ok(r.lists.includes("adult") && r.lists.includes("ads"));
  assert.equal(r.cleanSearch, true);
  assert.deepEqual(r.deny, ["x.com"]);
  assert.equal(r.cut, null);
  s.crews.k.bedtimes = [{ days: [0, 1, 2, 3, 4, 5, 6], from: "00:00", to: "23:59" }];
  assert.equal(rulesFor(s, d, new Date(2026, 0, 1, 12)).cut, "bedtime");
  s.crews.k.graceUntil = Date.now() + 60_000;
  assert.equal(rulesFor(s, d).cut, null);
  d.pausedUntil = Date.now() + 60_000;
  assert.equal(rulesFor(s, d).cut, "paused");
  d.blocked = true;
  assert.equal(rulesFor(s, d).cut, "blocked");
});
await test("nftables rules: gatekeeper", () => {
  const s = DEFAULTS(); s.mode = "gatekeeper"; s.tunnel.on = true;
  const t = nftRules(s, { cut: ["192.168.50.7"], lobby: ["192.168.50.9"], counted: ["192.168.50.7"] });
  for (const want of ["delete table inet cellowalla", "elements = { 192.168.50.7 }", "elements = { 192.168.50.9 }", 'iifname "eth1" drop', 'oifname "eth1" masquerade',
    "counter u_192_168_50_7", "ip saddr 192.168.50.7 counter name u_192_168_50_7", "policy drop;", "th dport 853 reject", "udp dport 51820 accept", 'iifname { "eth0", "cw0" }', "meta nfproto ipv6 drop"])
    assert.ok(t.includes(want), `missing: ${want}`);
  assert.ok(t.indexOf("@cut4 reject") < t.indexOf("ct state established,related accept\n    ct state invalid drop\n    meta l4proto"), "cut must come before established");
});
await test("nftables rules: lookout only touches the Tunnel", () => {
  const s = DEFAULTS(); s.tunnel.on = true; s.net.lanCidr = "192.168.1.0/24";
  const t = nftRules(s, {});
  assert.ok(t.includes("policy accept;") && !t.includes("policy drop;"));
  assert.ok(t.includes('ip saddr 10.88.0.0/24 oifname "eth0" masquerade'));
  assert.ok(!t.includes('"eth1"'));
  assert.ok(!nftRules({ ...s, tunnel: { ...s.tunnel, on: false } }, {}).includes("redirect"));
});
await test("interface names can't inject rules", () => {
  const s = DEFAULTS(); s.mode = "gatekeeper"; s.net.wanIf = 'eth1" accept; drop #';
  const t = nftRules(s, {});
  assert.ok(t.includes('iifname "eth1acceptdrop" drop') && !t.includes("drop #"));
});
await test("dnsmasq keeps every known device's address", () => {
  const s = DEFAULTS();
  s.devices = { "aa:bb:cc:dd:ee:ff": { mac: "aa:bb:cc:dd:ee:ff", ip: "192.168.50.20", kind: "lan" }, "wg:1": { mac: "wg:1", ip: "10.88.0.2", kind: "tunnel" } };
  const c = dnsmasqConf(s);
  assert.ok(c.includes("port=0") && c.includes("dhcp-host=aa:bb:cc:dd:ee:ff,192.168.50.20") && !c.includes("10.88.0.2"));
});
await test("counters, leases, wg dump, addresses", () => {
  assert.deepEqual(parseCounters(JSON.stringify({ nftables: [{ metainfo: {} }, { counter: { name: "u_192_168_50_7", bytes: 10 } }, { counter: { name: "d_192_168_50_7", bytes: 99 } }] })), { "192.168.50.7": { up: 10, down: 99 } });
  assert.deepEqual(parseLeases("1700000000 aa:bb:cc:dd:ee:01 192.168.50.101 sams-phone *\n1700000000 aa:bb:cc:dd:ee:02 192.168.50.102 * *"),
    [{ mac: "aa:bb:cc:dd:ee:01", ip: "192.168.50.101", host: "sams-phone", expiry: 1700000000 }, { mac: "aa:bb:cc:dd:ee:02", ip: "192.168.50.102", host: null, expiry: 1700000000 }]);
  const d = parseDump("priv\tpub\t51820\toff\nPEER=\t(none)\t1.2.3.4:5555\t10.88.0.2/32\t1700000000\t100\t200\t25");
  assert.deepEqual(d["PEER="], { endpoint: "1.2.3.4:5555", handshake: 1700000000000, rx: 100, tx: 200 });
  assert.equal(hostsIn("192.168.50.0/24").length, 254);
  assert.equal(hostsIn("10.0.0.0/8").length, 0);
  assert.ok(inCidr("192.168.50.20", "192.168.50.0/24") && !inCidr("192.168.51.20", "192.168.50.0/24"));
  assert.ok(randomMac("da:a1:19:00:00:01") && !randomMac("b8:27:eb:00:00:01"));
});
await test("WireGuard keys and pass files", () => {
  const k = keyPair();
  assert.equal(Buffer.from(k.privateKey, "base64").length, 32);
  assert.equal(Buffer.from(k.publicKey, "base64").length, 32);
  const t = { ...DEFAULTS().tunnel, publicKey: k.publicKey, endpoint: "home.example.com" };
  const c = passConf(t, { ip: "10.88.0.2", privateKey: "PRIV", full: false }, "192.168.1.0/24");
  assert.ok(c.includes("Endpoint = home.example.com:51820") && c.includes("AllowedIPs = 10.88.0.0/24, 192.168.1.0/24") && c.includes("DNS = 10.88.0.1"));
  assert.ok(passConf({ ...t, endpoint: "2001:db8::1" }, { ip: "10.88.0.2", privateKey: "P", full: true }, "x").includes("Endpoint = [2001:db8::1]:51820"));
});

// ---- the whole box ------------------------------------------------------------------------------

console.log("box (dry run)");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cellowalla-"));
const filler = (prefix) => Array.from({ length: 60 }, (_, i) => `0.0.0.0 ${prefix}${i}.filler.test`).join("\n");
const LISTS = {
  "/hosts": `0.0.0.0 ads.example.com\n0.0.0.0 tracker.test\n${filler("a")}`,
  "/downloads/hostfile/": `127.0.0.1\tevil.example\n${filler("m")}`,
  "/alternates/porn-only/hosts": `0.0.0.0 adult.example\n${filler("p")}`,
  "/alternates/social-only/hosts": filler("s"),
  "/alternates/gambling-only/hosts": filler("g"),
  "/custom.txt": `||custom-blocked.test^\n${Array.from({ length: 60 }, (_, i) => `c${i}.filler.test`).join("\n")}`,
};
const ANSWERS = { "forcesafesearch.google.com": [216, 239, 38, 120], "rebind.example": [192, 168, 1, 5] };
const pushed = [];
async function fakeFetch(url, opts = {}) {
  const u = new URL(url);
  if (u.pathname === "/dns-query") {
    const msg = Buffer.from(opts.body);
    const q = P.question(msg);
    const ip = Buffer.from(ANSWERS[q.name] || [93, 184, 216, 34]);
    const reply = q.type === 1 ? Buffer.concat([P.blockedAnswer(msg, q, 120).subarray(0, -4), ip]) : P.blockedAnswer(msg, { ...q, type: 0 });
    return new Response(reply, { headers: { "content-type": "application/dns-message" } });
  }
  if (u.hostname === "ntfy.test") { pushed.push({ title: opts.headers.title, body: opts.body }); return new Response("ok"); }
  if (u.hostname === "api.ipify.org") return new Response("203.0.113.9");
  const text = LISTS[u.pathname.replace(/^\/StevenBlack\/hosts\/master/, "")];
  return text ? new Response(text) : new Response("nope", { status: 404 });
}

const logs = [];
const app = await createApp({ dataDir: dir, fetchImpl: fakeFetch, dry: true, log: (m) => logs.push(m) });
const DNS = 15353, WEB = 18080;
await app.start({ dnsPort: DNS, webPort: WEB, host: "127.0.0.1" });
await app.refreshLists();

const ask = async (name, type = 1) => {
  const r = await udpAsk("127.0.0.1", DNS, P.makeQuery(name, type));
  const a = P.answers(r);
  return { rcode: P.rcode(r), a: a.filter((x) => x.type === type).map((x) => [...x.rdata].join(".")), cname: a.some((x) => x.type === 5) };
};
let cookie = "";
const call = async (method, p, body, headers = {}) => {
  const r = await fetch(`http://127.0.0.1:${WEB}${p}`, { method, headers: { "content-type": "application/json", "x-cellowalla": "1", cookie, ...headers }, body: body ? JSON.stringify(body) : undefined, redirect: "manual" });
  const set = r.headers.get("set-cookie"); if (set) cookie = set.split(";")[0];
  return { status: r.status, body: await r.json().catch(() => null) };
};

await test("Shield answers normal names", async () => assert.deepEqual((await ask("example.com")).a, ["93.184.216.34"]));
await test("Shield blocks listed names and everything under them", async () => {
  assert.deepEqual((await ask("ads.example.com")).a, ["0.0.0.0"]);
  assert.deepEqual((await ask("x.tracker.test")).a, ["0.0.0.0"]);
  assert.deepEqual((await ask("evil.example")).a, ["0.0.0.0"]);
});
await test("categories that are off don't block", async () => assert.deepEqual((await ask("adult.example")).a, ["93.184.216.34"]));
await test("encrypted-DNS dodges are blocked; Firefox canary says no such name", async () => {
  assert.deepEqual((await ask("dns.google")).a, ["0.0.0.0"]);
  assert.equal((await ask("use-application-dns.net")).rcode, 3);
});
await test("home address guard stops rebinding", async () => assert.deepEqual((await ask("rebind.example")).a, ["0.0.0.0"]));
await test("the box answers its own name", async () => assert.deepEqual((await ask("cellowalla.lan")).a, ["127.0.0.1"].map(() => app.store.data.net.boxIp)));
await test("DNS over TCP works", async () => {
  const net = await import("node:net");
  const r = await new Promise((resolve, reject) => {
    const s = net.connect(DNS, "127.0.0.1"), m = P.makeQuery("ads.example.com", 1), len = Buffer.alloc(2);
    len.writeUInt16BE(m.length); s.write(Buffer.concat([len, m]));
    s.on("data", (d) => { s.end(); resolve(d.subarray(2)); }); s.on("error", reject);
  });
  assert.equal([...P.answers(r)[0].rdata].join("."), "0.0.0.0");
});
await test("a list that fails to download doesn't break the others", () => {
  assert.ok(app.lists.info().malware.size > 50);
  assert.match(app.lists.info().malware.error, /HTTP 404/); // (the fake has no HaGeZi list)
});

await test("first visit needs the setup code", async () => {
  assert.equal((await call("GET", "/api/hello")).body.setUp, false);
  assert.equal((await call("GET", "/api/status")).status, 401);
  assert.equal((await call("POST", "/api/setup", { code: "WRONG", password: "a long password" })).status, 403);
  const code = fs.readFileSync(path.join(dir, "setup-code.txt"), "utf8").trim();
  assert.equal((await call("POST", "/api/setup", { code: code.toLowerCase(), password: "short" })).status, 400);
  assert.equal((await call("POST", "/api/setup", { code, password: "a long password" })).status, 200);
  assert.equal((await call("POST", "/api/setup", { code, password: "another password" })).status, 409);
  assert.equal((await call("GET", "/api/status")).status, 200);
});
await test("changes need the dashboard's header (no cross-site requests)", async () => {
  assert.equal((await call("PUT", "/api/shield", { on: false }, { "x-cellowalla": "" })).status, 403);
  assert.equal(app.store.data.shield.on, true);
});
await test("sign out and back in; wrong passwords refused", async () => {
  await call("POST", "/api/logout"); cookie = "";
  assert.equal((await call("GET", "/api/status")).status, 401);
  assert.equal((await call("POST", "/api/login", { password: "nope" })).status, 403);
  assert.equal((await call("POST", "/api/login", { password: "a long password" })).status, 200);
});
await test("the dashboard is served, files outside it aren't", async () => {
  const r = await fetch(`http://127.0.0.1:${WEB}/`); assert.ok((await r.text()).includes("Cellowalla"));
  assert.ok(r.headers.get("content-security-policy").includes("script-src 'self'"));
  assert.equal((await fetch(`http://127.0.0.1:${WEB}/..%2fpackage.json`)).status, 404);
  assert.equal((await fetch(`http://127.0.0.1:${WEB}/guide.html`)).status, 200);
});
await test("Never-block and Always-block lists", async () => {
  await call("POST", "/api/shield/names", { list: "allow", name: "ads.example.com" });
  assert.deepEqual((await ask("ads.example.com")).a, ["93.184.216.34"]);
  await call("POST", "/api/shield/names", { list: "deny", name: "https://www.Annoying.test/x" });
  assert.deepEqual((await ask("www.annoying.test")).a, ["0.0.0.0"]);
  assert.deepEqual(app.store.data.shield.deny, ["www.annoying.test"]);
  await call("DELETE", "/api/shield/names", { name: "ads.example.com" });
  assert.deepEqual((await ask("ads.example.com")).a, ["0.0.0.0"]);
});
await test("Clean Search points Google at its safe address", async () => {
  await call("PUT", "/api/shield", { cleanSearch: true });
  const r = await ask("www.google.com");
  assert.ok(r.cname);
  assert.deepEqual(r.a, ["216.239.38.120"]);
  await call("PUT", "/api/shield", { cleanSearch: false });
});
await test("own lists download and block", async () => {
  const r = await call("POST", "/api/shield/custom", { name: "Mine", url: "https://lists.test/custom.txt" });
  assert.equal(r.status, 200);
  await call("POST", "/api/shield/refresh");
  assert.deepEqual((await ask("custom-blocked.test")).a, ["0.0.0.0"]);
  assert.equal((await call("POST", "/api/shield/custom", { url: "http://insecure.test/x" })).status, 400);
});
await test("pausing Shield lets everything through", async () => {
  await call("POST", "/api/shield/pause", { minutes: 5 });
  assert.deepEqual((await ask("evil.example")).a, ["93.184.216.34"]);
  await call("POST", "/api/shield/pause", { minutes: 0 });
  assert.deepEqual((await ask("evil.example")).a, ["0.0.0.0"]);
});

const MAC = "b8:27:eb:00:00:01";
await test("Roster: a device shows up, gets a Ping, can be renamed", async () => {
  app.roster.see(MAC, "127.0.0.1", "sams-tablet");
  const r = await call("GET", "/api/devices");
  const d = r.body.devices.find((x) => x.mac === MAC);
  assert.equal(d.label, "sams-tablet");
  assert.ok(app.pings.list().some((p) => p.kind === "newDevice" && p.text.includes("sams-tablet")));
  await call("PUT", "/api/devices", { mac: MAC, name: "Sam's tablet" });
  assert.equal(app.store.data.devices[MAC].name, "Sam's tablet");
});
await test("a malware look-up sends one Ping (not one per look-up)", async () => {
  await call("PUT", "/api/pings/settings", { ntfy: "https://ntfy.test/topic" });
  await ask("evil.example"); await ask("evil.example");
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(pushed.filter((p) => p.title === "Malware blocked").length, 1);
  assert.match(pushed.find((p) => p.title === "Malware blocked").body, /Sam's tablet/);
});
let crewId;
await test("House Rules: a crew adds categories and its own names", async () => {
  crewId = (await call("POST", "/api/crews", { name: "Kids" })).body.id;
  await call("PUT", "/api/crews", { id: crewId, members: [MAC], lists: { adult: true }, deny: ["roblox-clone.test"] });
  assert.deepEqual((await ask("adult.example")).a, ["0.0.0.0"]);
  assert.deepEqual((await ask("roblox-clone.test")).a, ["0.0.0.0"]);
});
await test("House Rules: bedtime cuts DNS and the firewall; 30 more minutes lifts it", async () => {
  await call("PUT", "/api/crews", { id: crewId, bedtimes: [{ days: [0, 1, 2, 3, 4, 5, 6], from: "00:00", to: "23:59" }] });
  const now = new Date(); const late = now.getHours() === 23 && now.getMinutes() === 59;
  if (!late) {
    assert.deepEqual((await ask("example.com")).a, ["0.0.0.0"]);
    assert.ok(fs.readFileSync(path.join(dir, "dry", "_etc_nftables.d_cellowalla.nft"), "utf8").match(/set cut4 \{\n\s+type ipv4_addr\n\s+elements = \{ 127\.0\.0\.1 \}/));
    assert.equal((await call("GET", "/api/crews")).body.crews[0].cutNow, true);
    await call("PUT", "/api/crews", { id: crewId, graceMinutes: 30 });
    assert.deepEqual((await ask("example.com")).a, ["93.184.216.34"]);
  }
  await call("PUT", "/api/crews", { id: crewId, bedtimes: [], graceMinutes: 0 });
});
await test("pause and block one device", async () => {
  await call("PUT", "/api/devices", { mac: MAC, pauseMinutes: 30 });
  assert.deepEqual((await ask("example.com")).a, ["0.0.0.0"]);
  assert.equal((await call("GET", "/api/devices")).body.devices.find((x) => x.mac === MAC).cut, "paused");
  await call("PUT", "/api/devices", { mac: MAC, pauseMinutes: 0 });
  assert.deepEqual((await ask("example.com")).a, ["93.184.216.34"]);
  await call("PUT", "/api/devices", { mac: MAC, blocked: true });
  assert.deepEqual((await ask("example.com")).a, ["0.0.0.0"]);
  await call("PUT", "/api/devices", { mac: MAC, blocked: false });
});
await test("Lobby: newcomers wait until let in", async () => {
  await call("PUT", "/api/lobby", { on: true });
  app.roster.see("b8:27:eb:00:00:02", "10.9.9.9");
  const d = (await call("GET", "/api/devices")).body.devices.find((x) => x.mac === "b8:27:eb:00:00:02");
  assert.equal(d.cut, "lobby");
  assert.ok(fs.readFileSync(path.join(dir, "dry", "_etc_nftables.d_cellowalla.nft"), "utf8").includes("elements = { 10.9.9.9 }"));
  await call("PUT", "/api/devices", { mac: d.mac, approve: true });
  assert.equal((await call("GET", "/api/devices")).body.devices.find((x) => x.mac === d.mac).cut, null);
  await call("PUT", "/api/lobby", { on: false });
});
await test("the look-up log shows what a device asked", async () => {
  const r = await call("GET", `/api/log?dev=${encodeURIComponent(MAC)}&only=blocked`);
  assert.ok(r.body.entries.length > 0 && r.body.entries.every((e) => e.dev === MAC));
});
await test("Tunnel: switch on, make a pass, the server config lists it", async () => {
  assert.equal((await call("POST", "/api/tunnel/passes", { name: "Phone" })).status, 409);
  const t = await call("PUT", "/api/tunnel", { on: true });
  assert.equal(t.body.endpoint, "203.0.113.9");
  const p = await call("POST", "/api/tunnel/passes", { name: "Ana's phone", full: true });
  assert.match(p.body.conf, /Endpoint = 203\.0\.113\.9:51820/);
  assert.match(p.body.conf, /AllowedIPs = 0\.0\.0\.0\/0, ::\/0/);
  const conf = fs.readFileSync(path.join(dir, "dry", "_etc_wireguard_cw0.conf"), "utf8");
  assert.ok(conf.includes("AllowedIPs = 10.88.0.2/32") && conf.includes("# Ana's phone"));
  assert.ok(app.sys.ran.some((c) => c.startsWith("systemctl enable --now wg-quick@cw0")));
  assert.equal((await call("GET", `/api/tunnel/pass?id=${p.body.id}`)).body.conf, p.body.conf);
  assert.ok(app.store.data.devices[`wg:${p.body.id}`], "pass is listed as a device");
  await call("DELETE", "/api/tunnel/passes", { id: p.body.id });
  assert.ok(!fs.readFileSync(path.join(dir, "dry", "_etc_wireguard_cw0.conf"), "utf8").includes("Ana"));
  assert.ok(!app.store.data.devices[`wg:${p.body.id}`]);
});
await test("bad input is refused politely", async () => {
  assert.equal((await call("PUT", "/api/tunnel", { endpoint: "http://x:1" })).status, 400);
  assert.equal((await call("PUT", "/api/shield", { upstream: "ftp://x" })).status, 400);
  assert.equal((await call("PUT", "/api/crews", { id: crewId, bedtimes: [{ from: "9pm", to: "7" }] })).status, 400);
  assert.equal((await call("PUT", "/api/devices", { mac: "nope" })).status, 404);
  assert.equal((await call("PUT", "/api/pings/settings", { ntfy: "javascript:alert(1)" })).status, 400);
});
await test("backup: download, change things, restore brings them back (and asks to sign in again)", async () => {
  assert.equal((await call("POST", "/api/backup", { passphrase: "short" })).status, 400);
  const sealed = (await call("POST", "/api/backup", { passphrase: "backup pass 1" })).body;
  assert.equal(sealed.kind, "cellowalla-backup-encrypted");
  assert.equal(JSON.stringify(sealed).includes("Sam's tablet"), false, "nothing readable in the file");
  assert.equal(JSON.stringify(sealed).includes(app.store.data.tunnel.privateKey || "Sam's tablet"), false, "no Tunnel key in the file");
  assert.equal((await call("POST", "/api/backup/restore", { backup: sealed, passphrase: "wrong one" })).status, 403);
  assert.equal((await call("POST", "/api/backup/restore", { backup: sealed })).status, 400);
  const { openBackup } = await import("../src/web.js");
  const b = JSON.parse(openBackup(sealed, "backup pass 1"));
  assert.equal(b.kind, "cellowalla-backup");
  assert.equal(b.state.devices[MAC].name, "Sam's tablet");
  await call("PUT", "/api/devices", { mac: MAC, name: "Renamed" });
  assert.equal((await call("POST", "/api/backup/restore", { backup: sealed, passphrase: "backup pass 1" })).status, 200, "the encrypted file restores");
  assert.equal(app.store.data.devices[MAC].name, "Sam's tablet");
  assert.equal((await call("POST", "/api/login", { password: "a long password" })).status, 200);
  await call("PUT", "/api/devices", { mac: MAC, name: "Renamed" });
  assert.equal(app.store.data.devices[MAC].name, "Renamed");
  assert.equal((await call("POST", "/api/backup/restore", { backup: { kind: "nope" } })).status, 400);
  assert.equal((await call("POST", "/api/backup/restore", { backup: { ...b, state: { ...b.state, devices: "x" } } })).status, 400);
  const mode = app.store.data.mode;
  const r = await call("POST", "/api/backup/restore", { backup: { ...b, state: { ...b.state, mode: "gatekeeper" } } });
  assert.equal(r.status, 200);
  assert.equal(app.store.data.devices[MAC].name, "Sam's tablet");
  assert.equal(app.store.data.mode, mode, "the box keeps its own mode");
  assert.equal((await call("GET", "/api/devices")).status, 401, "signed out after a restore");
  assert.equal((await call("POST", "/api/login", { password: "a long password" })).status, 200);
});

await test("updates: only a version signed with the release key, and only a matching download", async () => {
  const { createUpdater, signedRelease, newer } = await import("../src/update.js");
  const crypto = await import("node:crypto");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const key = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const tarball = Buffer.from("pretend this is cellowalla.tar.gz");
  const sha = crypto.createHash("sha256").update(tarball).digest("hex");
  const sign = (apps, k = privateKey) => { const payload = JSON.stringify({ v: 1, apps }); return JSON.stringify({ payload, sig: crypto.sign("sha256", Buffer.from(payload), { key: k, dsaEncoding: "ieee-p1363" }).toString("base64") }); };
  const entry = { version: "99.0.0", path: "/download/Cellowalla-Box.tar.gz", size: tarball.length, sha256: sha };
  assert.equal(signedRelease(sign({ cellowallaBox: entry }), "cellowallaBox", key).version, "99.0.0");
  assert.throws(() => signedRelease(sign({ cellowallaBox: entry }, crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey), "cellowallaBox", key), /isn't signed/);
  assert.equal(signedRelease(sign({ cellowallaBox: { ...entry, path: "https://evil/x" } }), "cellowallaBox", key), null);
  assert.ok(newer("1.10.0", "1.9.3") && !newer("1.0.0", "1.0.0") && !newer("0.9.9", "1.0.0"));

  let list = sign({ cellowallaBox: entry }), body = tarball;
  const fetchUpd = async (url) => new URL(url).pathname === "/release.json" ? new Response(list) : new Response(body);
  const ran = [];
  const sys = { dry: true, run: async (cmd, args) => { ran.push([cmd, ...args].join(" ")); return ""; } };
  const up = createUpdater({ store: app.store, version: "0.1.0", dataDir: dir, sys, fetchImpl: fetchUpd, log: () => {}, site: "https://updates.test", key });
  let s = await up.check();
  assert.ok(s.available && s.latest === "99.0.0" && ran.length === 0, "checking doesn't install");
  body = Buffer.from("tampered!");
  s = await up.check({ install: true });
  assert.match(s.error, /doesn't match/);
  assert.equal(ran.length, 0, "a tampered download is never run");
  body = tarball;
  s = await up.check({ install: true });
  assert.ok(ran.some((c) => c.startsWith("tar -xzf")) && ran.some((c) => c.startsWith("systemd-run") && c.includes("CW_YES=1") && c.endsWith("install.sh")), ran.join("\n"));
  assert.equal((await call("PUT", "/api/updates", { auto: false })).body.auto, false);
  assert.equal(app.store.data.updates.auto, false);
});

await test("problem reports: from any app, repeats counted, people's own emailed at once, password never shown", async () => {
  const sent = [];
  app.reports = (await import("../src/reports.js")).createReports({ store: app.store, dir, version: "test", log: () => {}, send: async (cfg, subject, text) => { sent.push({ cfg, subject, text }); } });
  const open = (b) => fetch(`http://127.0.0.1:${WEB}/api/report`, { method: "POST", headers: { "content-type": "application/json", "x-cellowalla": "1" }, body: JSON.stringify(b) });
  for (let i = 0; i < 2; i++) assert.equal((await open({ source: "android", kind: "crash", message: "NullPointerException" })).status, 200);
  let r = (await call("GET", "/api/reports")).body;
  assert.equal(r.reports.length, 1); assert.equal(r.reports[0].count, 2); assert.equal(r.mail.hasPass, false);
  assert.equal((await call("PUT", "/api/reports", { to: "not an email" })).status, 400);
  await call("PUT", "/api/reports", { to: "owner@test.dev", user: "me@test.dev", pass: "abcd efgh ijkl mnop" });
  await open({ source: "dashboard", kind: "user", message: "Shield blocked my bank" });
  for (let i = 0; i < 20 && !sent.length; i++) await new Promise((x) => setTimeout(x, 50));
  assert.equal(sent.length, 1);
  assert.equal(sent[0].cfg.pass, "abcdefghijklmnop");
  assert.match(sent[0].text, /Someone reported a problem in dashboard/); assert.match(sent[0].text, /NullPointerException \(2 times\)|crash in android \(2 times\)/);
  r = (await call("GET", "/api/reports")).body;
  assert.ok(r.reports.every((x) => x.sent)); assert.equal(JSON.stringify(r).includes("abcdefghijklmnop"), false);
  const { openBackup: openB } = await import("../src/web.js");
  const backup = JSON.parse(openB((await call("POST", "/api/backup", { passphrase: "backup pass 2" })).body, "backup pass 2"));
  assert.equal(JSON.stringify(backup).includes("abcdefghijklmnop"), false, "the App Password never goes into a backup");
});
await test("status adds it all up; state survives a restart", async () => {
  const s = (await call("GET", "/api/status")).body;
  assert.ok(s.shield.lookups > 10 && s.shield.blocked > 5 && s.devices.total >= 2);
  app.stop();
  const again = await createApp({ dataDir: dir, fetchImpl: fakeFetch, dry: true, log: () => {} });
  assert.equal(again.store.data.devices[MAC].name, "Sam's tablet");
  assert.equal(again.store.data.crews[crewId].name, "Kids");
  assert.ok(again.store.data.admin.hash);
  assert.ok(again.pings.list().length > 0);
});

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
