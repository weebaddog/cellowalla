// Roster: every device on the home network. Found from the box's neighbour table (ip neigh), the
// DHCP leases it hands out (gatekeeper mode), and anyone who asks Shield a question. A gentle sweep
// every few minutes (one tiny packet per address) makes quiet devices show up too.
//
// Devices are known by their hardware (MAC) address. Tunnel passes are listed as devices too
// ("wg:<id>") so House Rules work for them away from home.

import dgram from "node:dgram";
import fs from "node:fs";
import path from "node:path";

const ONLINE_MS = 10 * 60_000;

/** "192.168.50.0/24" → every host address in it (at most 1024). */
export function hostsIn(cidr) {
  const [base, bits] = cidr.split("/");
  const n = Number(bits);
  if (!(n >= 22 && n <= 30)) return [];
  const start = base.split(".").reduce((a, x) => a * 256 + Number(x), 0) >>> 0;
  const net = (start & ~((1 << (32 - n)) - 1)) >>> 0;
  const out = [];
  for (let i = 1; i < 2 ** (32 - n) - 1; i++) { const v = net + i; out.push([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(".")); }
  return out;
}

/** A phone's "private Wi-Fi address" (randomised MAC): the locally-administered bit is set. */
export const randomMac = (mac) => /^.[26ae]/i.test(mac);

export function parseLeases(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    const [expiry, mac, ip, host] = line.trim().split(/\s+/);
    if (mac && ip && /^[0-9a-f:]{17}$/i.test(mac)) out.push({ mac: mac.toLowerCase(), ip, host: host && host !== "*" ? host : null, expiry: Number(expiry) });
  }
  return out;
}

export function createRoster({ store, sys, dataDir, log = console.log, onNew = () => {} }) {
  const byIp = new Map();     // ip → mac
  const lastAsk = new Map();  // ip → time we last looked it up (don't run ip neigh per query)
  let vendors = null;

  function vendorOf(mac) {
    if (randomMac(mac)) return "Private address";
    if (!vendors) {
      vendors = new Map();
      try {
        // IEEE's oui.csv: Registry,Assignment,"Organization Name",Address
        for (const line of fs.readFileSync(path.join(dataDir, "oui.csv"), "utf8").split("\n")) {
          const m = line.match(/^MA-L,([0-9A-F]{6}),("([^"]*)"|[^,]*)/);
          if (m) vendors.set(m[1], (m[3] ?? m[2]).trim());
        }
      } catch { /* not downloaded: no vendor names */ }
    }
    return vendors.get(mac.replace(/:/g, "").slice(0, 6).toUpperCase()) || null;
  }

  /** Records that `mac` is at `ip` (seen just now). */
  function see(mac, ip, host = null, kind = "lan") {
    mac = mac.toLowerCase();
    const now = Date.now();
    const d = store.data.devices[mac];
    if (!d) {
      const dev = { mac, ip, name: null, host, vendor: kind === "lan" ? vendorOf(mac) : "Tunnel", firstSeen: now, lastSeen: now, crew: null, blocked: false, pausedUntil: 0, lobby: !!store.data.lobby.on, kind };
      store.change("devices", (s) => { s.devices[mac] = dev; });
      byIp.set(ip, mac);
      log(`[roster] new device ${mac} at ${ip}${host ? ` (${host})` : ""}`);
      onNew(dev);
      return;
    }
    if (d.ip !== ip || (host && d.host !== host)) {
      if (d.ip && byIp.get(d.ip) === mac) byIp.delete(d.ip);
      store.change("devices", () => { d.ip = ip; if (host) d.host = host; d.lastSeen = now; });
    } else d.lastSeen = now; // (saved with the next real change)
    byIp.set(ip, mac);
  }

  async function scan() {
    const data = store.data;
    // DHCP leases (gatekeeper mode hands out addresses itself).
    if (data.mode === "gatekeeper") {
      for (const l of parseLeases(sys.readFile("/var/lib/misc/cellowalla.leases"))) see(l.mac, l.ip, l.host);
    }
    try {
      const neigh = JSON.parse((await sys.run("ip", ["-j", "-4", "neigh", "show"])) || "[]");
      for (const n of neigh) {
        if (!n.lladdr || !n.dst || n.dev?.startsWith("cw")) continue;
        const st = n.state || [];
        if (st.includes("FAILED") || st.includes("INCOMPLETE")) continue;
        if (n.dst === data.net.boxIp || n.dst === data.net.gateway) continue;
        see(n.lladdr, n.dst);
      }
    } catch (e) { log(`[roster] ip neigh: ${e.message}`); }
    // Tunnel passes.
    for (const p of data.tunnel.passes) if (!store.data.devices[`wg:${p.id}`]) see(`wg:${p.id}`, p.ip, p.name, "tunnel");
  }

  /** One tiny UDP packet to every address: the kernel's ARP request makes quiet devices answer. */
  function sweep() {
    const cidr = store.data.net.lanCidr;
    const s = dgram.createSocket("udp4");
    s.on("error", () => {});
    const hosts = hostsIn(cidr);
    let i = 0;
    const tick = () => {
      for (let k = 0; k < 16 && i < hosts.length; k++, i++) s.send(Buffer.alloc(1), 9, hosts[i], () => {});
      if (i < hosts.length) setTimeout(tick, 50); else setTimeout(() => s.close(), 1000);
    };
    if (!sys.dry && hosts.length) tick(); else s.close();
  }

  function rebuild() {
    byIp.clear();
    for (const d of Object.values(store.data.devices)) if (d.ip) byIp.set(d.ip, d.mac);
  }
  rebuild();

  return {
    scan,
    sweep,
    see,
    rebuild,
    /** The device using `ip`, or null. An unknown address triggers a (rate-limited) look-up. */
    byIp(ip) {
      const mac = byIp.get(ip);
      if (mac) { const d = store.data.devices[mac]; if (d) { d.lastSeen = Date.now(); return d; } }
      const last = lastAsk.get(ip) || 0;
      if (Date.now() - last > 30_000 && ip !== "127.0.0.1") { lastAsk.set(ip, Date.now()); scan().catch(() => {}); }
      return null;
    },
    online: (d) => Date.now() - (d.lastSeen || 0) < ONLINE_MS,
    vendorOf,
  };
}
