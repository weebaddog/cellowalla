// Cellowalla: starts every part and keeps them ticking.
//
//   CELLOWALLA_DATA   where it keeps its files (default /var/lib/cellowalla)
//   CELLOWALLA_DNS_PORT, CELLOWALLA_WEB_PORT, CELLOWALLA_TLS_PORT   (defaults 53, 80, 443)
//   CELLOWALLA_DRY=1  change nothing on the system (always on for non-Linux machines)

import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { openState } from "./state.js";
import { createSys } from "./sys.js";
import { createLists } from "./lists.js";
import { createRoster } from "./roster.js";
import { createShield } from "./shield.js";
import { createGate } from "./gate.js";
import { createTunnel } from "./tunnel.js";
import { createPings } from "./pings.js";
import { createWeb } from "./web.js";
import { createUpdater } from "./update.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).version;

/** The setup code the first visitor must type (made once, kept in <data>/setup-code.txt). */
function setupCode(dir) {
  const file = path.join(dir, "setup-code.txt");
  try { return fs.readFileSync(file, "utf8").trim(); } catch { /* make one */ }
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const code = Array.from(crypto.randomBytes(8), (b) => alphabet[b % 32]).join("");
  fs.writeFileSync(file, code + "\n", { mode: 0o600 });
  return code;
}

/** Lookout mode: the box's own address on the home network, and the network it's on. */
function lanAddress(ifname) {
  const list = os.networkInterfaces()[ifname] || [];
  const v4 = list.find((a) => a.family === "IPv4" && !a.internal);
  if (!v4) return null;
  const bits = v4.netmask.split(".").reduce((n, x) => n + (Number(x) >>> 0).toString(2).replace(/0/g, "").length, 0);
  const ipn = v4.address.split(".").map(Number), m = v4.netmask.split(".").map(Number);
  return { ip: v4.address, cidr: `${ipn.map((x, i) => x & m[i]).join(".")}/${bits}` };
}

export async function createApp({ dataDir, fetchImpl = fetch, log = console.log, dry, update = {} } = {}) {
  dataDir ||= process.env.CELLOWALLA_DATA || "/var/lib/cellowalla";
  const store = openState(dataDir);
  const sys = createSys({ dataDir, log, ...(dry !== undefined ? { dry } : {}) });
  const app = { version: VERSION, store, sys };

  if (store.data.mode === "lookout" && !sys.dry) {
    const a = lanAddress(store.data.net.lanIf);
    if (a) store.change("net", (s) => { s.net.boxIp = a.ip; s.net.lanCidr = a.cidr; });
    else log(`[main] no IPv4 address on ${store.data.net.lanIf} yet`);
  }

  const label = (d) => d?.name || d?.host || d?.vendor || d?.mac || "a device";
  app.pings = createPings({ store, dir: dataDir, fetchImpl, log });
  app.lists = createLists({ dir: dataDir, fetchImpl, log });
  app.roster = createRoster({ store, sys, dataDir, log, onNew: (d) => {
    if (d.kind !== "lan") return;
    app.pings.send("newDevice", `${label(d)} joined the network (${d.ip}).${d.lobby ? " It's waiting in the Lobby until you let it in." : ""}`, { ref: d.mac });
    app.gate?.apply().catch(() => {});
  } });
  app.shield = createShield({ store, lists: app.lists, roster: app.roster, fetchImpl, log,
    onMalware: (d, ip, name) => app.pings.send("malware", `${label(d) || ip} tried to reach ${name}, a known malware or scam site. Shield stopped it.`, { ref: d?.mac || ip, once: `mw:${d?.mac || ip}` }) });
  app.gate = createGate({ store, sys, log, onBedtime: (c, on) => app.pings.send("bedtime", on ? `Bedtime started for ${c.name}.` : `Bedtime is over for ${c.name}.`, { ref: c.id }) });
  app.tunnel = createTunnel({ store, sys, fetchImpl, log, onConnect: (p, l) => app.pings.send("tunnel", `${p.name} connected through the Tunnel${l?.endpoint ? ` from ${l.endpoint.replace(/:\d+$/, "")}` : ""}.`, { ref: p.id, once: `tn:${p.id}` }) });

  app.updater = createUpdater({ store, version: VERSION, dataDir, sys, fetchImpl, log, pings: app.pings, ...update });

  let refreshing = null;
  app.refreshLists = () => (refreshing ||= app.lists.refresh(store.data.shield.custom).finally(() => { refreshing = null; app.shield.clearCache(); }));

  const timers = [];
  app.start = async ({ dnsPort = Number(process.env.CELLOWALLA_DNS_PORT || 53), webPort = Number(process.env.CELLOWALLA_WEB_PORT || 80), tlsPort = Number(process.env.CELLOWALLA_TLS_PORT || 443), host = "0.0.0.0" } = {}) => {
    const code = setupCode(dataDir);
    if (!store.data.admin) log(`[main] not set up yet: open http://${store.data.net.boxIp}/ and use setup code ${code}`);
    app.web = createWeb({ store, app, webDir: path.join(ROOT, "web"), setupCode: code, log });
    await app.shield.listen({ port: dnsPort, host });
    await app.web.listen({ port: webPort, tlsPort, tlsDir: path.join(dataDir, "tls"), host });
    log(`[main] Cellowalla ${VERSION} (${store.data.mode} mode${sys.dry ? ", dry run" : ""}): DNS on ${dnsPort}, dashboard on ${webPort}`);

    app.refreshLists().catch((e) => log(`[lists] ${e.message}`));
    await app.roster.scan().catch(() => {});
    await app.tunnel.apply().catch((e) => log(`[tunnel] ${e.message}`));
    await app.gate.apply(true).catch((e) => log(`[gate] ${e.message}`));
    app.pings.send("system", `Cellowalla ${VERSION} started.`, { once: "start" });

    const every = (ms, fn) => timers.push(setInterval(() => fn().catch((e) => log(`[tick] ${e.message}`)), ms));
    every(30_000, async () => { await app.roster.scan(); await app.gate.apply(); await app.tunnel.poll(); });
    every(60_000, () => app.gate.readCounters());
    every(5 * 60_000, async () => app.roster.sweep());
    every(24 * 3600_000, () => app.refreshLists());
    setTimeout(() => app.roster.sweep(), 5000).unref();
    stopUpdates = app.updater.start();
  };
  let stopUpdates = () => {};
  app.stop = () => { for (const t of timers) clearInterval(t); stopUpdates(); app.shield.close(); app.web?.close(); store.flush(); app.pings.flush(); };
  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const app = await createApp();
  await app.start();
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { app.stop(); process.exit(0); });
}
