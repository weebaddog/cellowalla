// Everything Cellowalla remembers lives in one JSON file (state.json in the data folder), written
// atomically (temp file + rename) so a power cut never leaves half a file. The query log and the
// Pings feed are kept apart (they change constantly and matter less).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const DEFAULTS = () => ({
  version: 1,
  admin: null,                    // { salt, hash } once the owner picks a password
  mode: "lookout",                // "lookout" (DNS only, plugged into the home router) | "gatekeeper" (two ports, it IS the router)
  net: {
    lanIf: "eth0",
    wanIf: "eth1",                // gatekeeper only
    boxIp: "192.168.50.1",        // gatekeeper: the box's address on the home side; lookout: filled in at start
    lanCidr: "192.168.50.0/24",
    dhcpFrom: "192.168.50.100",
    dhcpTo: "192.168.50.250",
    gateway: "",                  // lookout: the home router's address (never listed as a device)
    homeDns: "",                  // lookout: ask the home router about .lan/.local names (optional)
  },
  shield: {
    on: true,
    lists: { ads: true, malware: true, adult: false, social: false, gaming: false, gambling: false },
    custom: [],                   // [{ id, name, url, on }]
    allow: [],                    // names never blocked (and everything under them)
    deny: [],                     // names always blocked
    cleanSearch: false,
    rebinding: true,              // refuse public names that point into the home network
    upstream: "https://1.1.1.1/dns-query", // an address, not a name: the box never needs DNS to find its DNS
  },
  devices: {},                    // mac → { mac, ip, name, host, vendor, firstSeen, lastSeen, crew, blocked, pausedUntil, lobby, kind }
  crews: {},                      // id → { id, name, lists:{}, cleanSearch, deny:[], bedtimes:[{days,from,to}], pausedUntil, graceUntil }
  lobby: { on: false },           // new devices wait for approval
  tunnel: {
    on: false,
    port: 51820,
    net: "10.88.0.0/24",
    endpoint: "",                 // the address phones use from outside (a hostname or public IP)
    privateKey: "",
    publicKey: "",
    passes: [],                   // [{ id, name, ip, publicKey, privateKey, full, createdAt }]
  },
  reportsMail: {},               // problem reports: { to, user, pass (App Password), host, port, off, lastError }
  pings: {
    ntfy: "",                     // e.g. https://ntfy.sh/my-secret-topic
    webhook: "",
    events: { newDevice: true, tunnel: true, malware: true, bedtime: false, system: true },
  },
  traffic: {},                    // ip → { up, down } bytes counted so far (gatekeeper)
  updates: { auto: true },        // put in new versions (signed by the owner) by itself
});

/** Fills in anything a newer version added, keeping what's there. */
export function merge(base, saved) {
  if (Array.isArray(base) || typeof base !== "object" || base === null) return saved === undefined ? base : saved;
  const out = { ...base };
  for (const [k, v] of Object.entries(saved || {})) {
    out[k] = k in base && base[k] && typeof base[k] === "object" && !Array.isArray(base[k]) && Object.keys(base[k]).length
      ? merge(base[k], v) : v;
  }
  return out;
}

export function openState(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "state.json");
  let data = DEFAULTS();
  try { data = merge(DEFAULTS(), JSON.parse(fs.readFileSync(file, "utf8"))); } catch (e) { if (e.code !== "ENOENT") throw e; }
  const listeners = new Set();
  let timer = null;

  function writeNow() {
    clearTimeout(timer); timer = null;
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  return {
    get data() { return data; },
    /** Runs fn(data), then saves soon and tells everyone who's listening what changed. */
    change(what, fn) {
      const r = fn(data);
      if (!timer) timer = setTimeout(writeNow, 300);
      for (const l of listeners) { try { l(what); } catch (e) { console.error("[state] listener", e); } }
      return r;
    },
    onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    flush: writeNow,
    dir,
  };
}

/** A JSON file that is just a capped list (Pings feed). */
export function openFeed(dir, name, cap) {
  const file = path.join(dir, name);
  let items = [];
  try { items = JSON.parse(fs.readFileSync(file, "utf8")); } catch { /* new */ }
  let timer = null;
  const save = () => {
    timer = null;
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(items), { mode: 0o600 });
    fs.renameSync(tmp, file);
  };
  return {
    get items() { return items; },
    add(item) { items.unshift(item); if (items.length > cap) items.length = cap; if (!timer) timer = setTimeout(save, 1000); },
    update(fn) { fn(items); if (!timer) timer = setTimeout(save, 1000); },
    flush() { if (timer) { clearTimeout(timer); save(); } },
  };
}

export const newId = () => crypto.randomBytes(6).toString("hex");
