// The owner's dashboard: a small web app served by the box (https://cellowalla.lan), plus the JSON
// API it uses. Only reachable from home and through the Tunnel (the Gate drops it from outside).
//
// Sign-in: one owner password (scrypt). The very first visit needs the setup code the installer
// printed, so a stranger on the Wi-Fi can't claim the box first.

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { CATALOG, cleanName } from "./lists.js";
import { rulesFor } from "./policy.js";
import { newId } from "./state.js";

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json", ".webmanifest": "application/manifest+json", ".png": "image/png" };
const SESSION_DAYS = 30;

const fail = (status, message) => Object.assign(new Error(message), { status });

export function hashPassword(pw, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(String(pw), salt, 32, { N: 16384, r: 8, p: 1 }).toString("hex") };
}
function checkPassword(pw, admin) {
  if (!admin) return false;
  const h = Buffer.from(hashPassword(pw, admin.salt).hash, "hex");
  return crypto.timingSafeEqual(h, Buffer.from(admin.hash, "hex"));
}

export function createWeb({ store, app, webDir, setupCode, log = console.log }) {
  const sessions = new Map();     // token hash → expiry
  const failures = new Map();     // ip → [times]
  const tokenKey = (t) => crypto.createHash("sha256").update(t).digest("hex");

  function signedIn(req) {
    const m = String(req.headers.cookie || "").match(/(?:^|;\s*)cw=([A-Za-z0-9_-]{20,})/);
    if (!m) return false;
    const exp = sessions.get(tokenKey(m[1]));
    return exp && exp > Date.now();
  }
  function tooMany(ip) {
    const list = (failures.get(ip) || []).filter((t) => Date.now() - t < 15 * 60_000);
    failures.set(ip, list);
    return list.length >= 10;
  }
  function startSession(res, secure) {
    const t = crypto.randomBytes(24).toString("base64url");
    sessions.set(tokenKey(t), Date.now() + SESSION_DAYS * 86400_000);
    res.setHeader("set-cookie", `cw=${t}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}${secure ? "; Secure" : ""}`);
  }

  // ---- what the screens show -------------------------------------------------------------------

  function deviceView(d) {
    const r = rulesFor(store.data, d);
    const dns = app.shield.stats().devices[d.mac] || { q: 0, b: 0 };
    return { ...d, label: d.name || d.host || d.vendor || d.mac, online: app.roster.online(d), cut: r.cut, crewName: d.crew ? store.data.crews[d.crew]?.name || null : null,
      dns, traffic: d.ip ? app.gate.traffic(d.ip) : null };
  }

  const routes = {
    "GET /api/status": () => {
      const data = store.data;
      const devices = Object.values(data.devices);
      const st = app.shield.stats();
      const q = st.hours.reduce((a, h) => a + h.q, 0), b = st.hours.reduce((a, h) => a + h.b, 0);
      return {
        version: app.version, mode: data.mode, boxIp: data.net.boxIp, dry: app.sys.dry, uptime: Math.round(process.uptime()),
        shield: { on: data.shield.on, pausedUntil: app.shield.pausedUntil(), lookups: q, blocked: b, hours: st.hours, top: st.top.slice(0, 8) },
        devices: { total: devices.length, online: devices.filter((d) => app.roster.online(d)).length, waiting: devices.filter((d) => d.lobby && data.lobby.on).length,
          cut: devices.filter((d) => rulesFor(data, d).cut).length },
        tunnel: { on: data.tunnel.on, online: app.tunnel.status().filter((p) => p.online).length, passes: data.tunnel.passes.length },
        pings: { unread: app.pings.unread() },
      };
    },

    // Shield
    "GET /api/shield": () => {
      const s = store.data.shield, info = app.lists.info();
      return { ...s, pausedUntil: app.shield.pausedUntil(),
        catalog: Object.entries(CATALOG).map(([k, c]) => ({ key: k, title: c.title, about: c.about, on: !!s.lists[k], ...(info[k] || {}) })),
        customInfo: Object.fromEntries(s.custom.map((c) => [c.id, info[`custom:${c.id}`] || {}])) };
    },
    "PUT /api/shield": (b) => {
      store.change("shield", (s) => {
        const sh = s.shield;
        if ("on" in b) sh.on = !!b.on;
        if ("cleanSearch" in b) sh.cleanSearch = !!b.cleanSearch;
        if ("rebinding" in b) sh.rebinding = !!b.rebinding;
        if (b.lists) for (const k of Object.keys(CATALOG)) if (k in b.lists) sh.lists[k] = !!b.lists[k];
        if (typeof b.upstream === "string") {
          if (!/^(https:\/\/[^\s]+|udp:\/\/[0-9a-f.:]+)$/i.test(b.upstream)) throw fail(400, "Upstream must be an https:// DNS-over-HTTPS address or udp://ip");
          sh.upstream = b.upstream;
        }
      });
      app.shield.clearCache();
      return routes["GET /api/shield"]();
    },
    "POST /api/shield/pause": (b) => { app.shield.pause(Math.min(24 * 60, Math.max(0, Number(b.minutes) || 0))); return { pausedUntil: app.shield.pausedUntil() }; },
    "POST /api/shield/names": (b) => {
      const which = b.list === "allow" ? "allow" : "deny";
      const name = cleanName(b.name);
      if (!name) throw fail(400, "That isn't a web address");
      store.change("shield", (s) => {
        const other = which === "allow" ? "deny" : "allow";
        s.shield[other] = s.shield[other].filter((n) => n !== name);
        if (!s.shield[which].includes(name)) s.shield[which].push(name);
      });
      app.shield.clearCache();
      return { allow: store.data.shield.allow, deny: store.data.shield.deny };
    },
    "DELETE /api/shield/names": (b) => {
      store.change("shield", (s) => { s.shield.allow = s.shield.allow.filter((n) => n !== b.name); s.shield.deny = s.shield.deny.filter((n) => n !== b.name); });
      return { allow: store.data.shield.allow, deny: store.data.shield.deny };
    },
    "POST /api/shield/custom": (b) => {
      let url;
      try { url = new URL(String(b.url)); } catch { throw fail(400, "That isn't a web address"); }
      if (url.protocol !== "https:") throw fail(400, "Lists must be downloaded over https://");
      if (store.data.shield.custom.length >= 20) throw fail(409, "20 lists at most");
      store.change("shield", (s) => { s.shield.custom.push({ id: newId(), name: String(b.name || url.hostname).slice(0, 40), url: url.href, on: true }); });
      app.refreshLists();
      return store.data.shield.custom;
    },
    "PUT /api/shield/custom": (b) => { store.change("shield", (s) => { const c = s.shield.custom.find((x) => x.id === b.id); if (c) c.on = !!b.on; }); return store.data.shield.custom; },
    "DELETE /api/shield/custom": (b) => { store.change("shield", (s) => { s.shield.custom = s.shield.custom.filter((x) => x.id !== b.id); }); return store.data.shield.custom; },
    "POST /api/shield/refresh": async () => { await app.refreshLists(); return routes["GET /api/shield"](); },
    "GET /api/log": (b, url) => ({ entries: app.shield.recent({ dev: url.searchParams.get("dev") || null, q: url.searchParams.get("q") || null, only: url.searchParams.get("only") || null }) }),

    // Roster
    "GET /api/devices": () => ({ devices: Object.values(store.data.devices).map(deviceView).sort((a, b) => (b.online - a.online) || String(a.label).localeCompare(String(b.label))), lobby: store.data.lobby }),
    "PUT /api/devices": async (b) => {
      const d = store.data.devices[b.mac];
      if (!d) throw fail(404, "No such device");
      store.change("devices", () => {
        if ("name" in b) d.name = String(b.name || "").trim().slice(0, 40) || null;
        if ("crew" in b) { if (b.crew && !store.data.crews[b.crew]) throw fail(400, "No such crew"); d.crew = b.crew || null; }
        if ("blocked" in b) d.blocked = !!b.blocked;
        if ("pauseMinutes" in b) d.pausedUntil = Number(b.pauseMinutes) > 0 ? Date.now() + Math.min(7 * 1440, Number(b.pauseMinutes)) * 60_000 : 0;
        if ("approve" in b && b.approve) d.lobby = false;
      });
      await app.gate.apply().catch(() => {});
      return deviceView(d);
    },
    "DELETE /api/devices": async (b) => {
      if (String(b.mac).startsWith("wg:")) throw fail(400, "Remove the Tunnel pass instead");
      store.change("devices", (s) => { delete s.devices[b.mac]; });
      app.roster.rebuild();
      await app.gate.apply().catch(() => {});
      return { ok: true };
    },
    "PUT /api/lobby": async (b) => { store.change("lobby", (s) => { s.lobby.on = !!b.on; }); await app.gate.apply().catch(() => {}); return store.data.lobby; },

    // House Rules (crews)
    "GET /api/crews": () => ({ crews: Object.values(store.data.crews).map((c) => ({ ...c, members: Object.values(store.data.devices).filter((d) => d.crew === c.id).map((d) => d.mac),
      cutNow: Object.values(store.data.devices).some((d) => d.crew === c.id && rulesFor(store.data, d).cut === "bedtime") })),
      catalog: Object.entries(CATALOG).map(([k, c]) => ({ key: k, title: c.title, everyone: !!store.data.shield.lists[k] })) }),
    "POST /api/crews": (b) => {
      const id = newId();
      store.change("crews", (s) => { s.crews[id] = { id, name: String(b.name || "Crew").slice(0, 30), lists: {}, cleanSearch: false, deny: [], bedtimes: [], pausedUntil: 0, graceUntil: 0 }; });
      return store.data.crews[id];
    },
    "PUT /api/crews": async (b) => {
      const c = store.data.crews[b.id];
      if (!c) throw fail(404, "No such crew");
      store.change("crews", () => {
        if ("name" in b) c.name = String(b.name || "Crew").slice(0, 30);
        if (b.lists) for (const k of Object.keys(CATALOG)) if (k in b.lists) c.lists[k] = !!b.lists[k];
        if ("cleanSearch" in b) c.cleanSearch = !!b.cleanSearch;
        if (Array.isArray(b.deny)) c.deny = b.deny.map(cleanName).filter(Boolean).slice(0, 500);
        if (Array.isArray(b.bedtimes)) c.bedtimes = b.bedtimes.slice(0, 14).map((t) => {
          if (!/^\d{1,2}:\d{2}$/.test(t.from) || !/^\d{1,2}:\d{2}$/.test(t.to)) throw fail(400, "Times look like 21:30");
          return { days: (t.days || []).map(Number).filter((n) => n >= 0 && n <= 6), from: t.from, to: t.to };
        });
        if ("pauseMinutes" in b) c.pausedUntil = Number(b.pauseMinutes) > 0 ? Date.now() + Math.min(7 * 1440, Number(b.pauseMinutes)) * 60_000 : 0;
        if ("graceMinutes" in b) c.graceUntil = Number(b.graceMinutes) > 0 ? Date.now() + Math.min(600, Number(b.graceMinutes)) * 60_000 : 0;
        if (Array.isArray(b.members)) for (const d of Object.values(store.data.devices)) {
          if (b.members.includes(d.mac)) d.crew = c.id; else if (d.crew === c.id) d.crew = null;
        }
      });
      app.shield.clearCache();
      await app.gate.apply().catch(() => {});
      return c;
    },
    "DELETE /api/crews": async (b) => {
      store.change("crews", (s) => { delete s.crews[b.id]; for (const d of Object.values(s.devices)) if (d.crew === b.id) d.crew = null; });
      await app.gate.apply().catch(() => {});
      return { ok: true };
    },

    // Tunnel
    "GET /api/tunnel": () => { const t = store.data.tunnel; return { on: t.on, port: t.port, net: t.net, endpoint: t.endpoint, publicKey: t.publicKey, passes: app.tunnel.status() }; },
    "PUT /api/tunnel": async (b) => {
      store.change("tunnel", (s) => {
        if (typeof b.endpoint === "string") {
          const e = b.endpoint.trim();
          if (e && !/^[a-z0-9.-]+$|^[0-9a-f:]+$/i.test(e)) throw fail(400, "The address is a hostname or IP, without http:// or a port");
          s.tunnel.endpoint = e;
        }
        if ("port" in b) { const p = Number(b.port); if (!(p >= 1024 && p <= 65535)) throw fail(400, "Port 1024–65535"); s.tunnel.port = p; }
      });
      if ("on" in b) await app.tunnel.setOn(!!b.on); else await app.tunnel.apply();
      await app.gate.apply().catch(() => {});
      return routes["GET /api/tunnel"]();
    },
    "POST /api/tunnel/passes": async (b) => {
      if (!store.data.tunnel.on) throw fail(409, "Switch the Tunnel on first");
      const p = await app.tunnel.addPass(b.name, b.full !== false);
      await app.roster.scan().catch(() => {});
      await app.gate.apply().catch(() => {});
      return { id: p.id, conf: app.tunnel.conf(p) };
    },
    "GET /api/tunnel/pass": (b, url) => {
      const p = store.data.tunnel.passes.find((x) => x.id === url.searchParams.get("id"));
      if (!p) throw fail(404, "No such pass");
      return { id: p.id, name: p.name, conf: app.tunnel.conf(p) };
    },
    "DELETE /api/tunnel/passes": async (b) => { await app.tunnel.removePass(b.id); app.roster.rebuild(); await app.gate.apply().catch(() => {}); return { ok: true }; },

    // Pings
    "GET /api/pings": () => ({ pings: app.pings.list(), settings: store.data.pings }),
    "POST /api/pings/read": () => { app.pings.markRead(); return { ok: true }; },
    "DELETE /api/pings": () => { app.pings.clear(); return { ok: true }; },
    "PUT /api/pings/settings": (b) => {
      store.change("pings", (s) => {
        for (const k of ["ntfy", "webhook"]) if (typeof b[k] === "string") {
          const v = b[k].trim();
          if (v && !/^https:\/\/\S+$/.test(v)) throw fail(400, "Use an https:// address");
          s.pings[k] = v;
        }
        if (b.events) for (const k of Object.keys(s.pings.events)) if (k in b.events) s.pings.events[k] = !!b.events[k];
      });
      return store.data.pings;
    },
    "POST /api/pings/test": async () => { await app.pings.test(); return { ok: true }; },

    // Settings
    "GET /api/settings": () => ({ mode: store.data.mode, net: store.data.net, version: app.version, dry: app.sys.dry }),
    "PUT /api/settings": (b) => {
      store.change("net", (s) => { if (typeof b.homeDns === "string") { if (b.homeDns && !/^\d+\.\d+\.\d+\.\d+$/.test(b.homeDns)) throw fail(400, "An IPv4 address"); s.net.homeDns = b.homeDns; } });
      return { mode: store.data.mode, net: store.data.net };
    },
    "POST /api/password": (b) => {
      if (!checkPassword(b.current, store.data.admin)) throw fail(403, "The current password is wrong");
      if (String(b.password || "").length < 10) throw fail(400, "Use at least 10 characters");
      store.change("admin", (s) => { s.admin = hashPassword(b.password); });
      sessions.clear();
      return { ok: true };
    },
  };

  async function readJson(req) {
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > 65536) throw fail(413, "Too big"); chunks.push(c); }
    if (!n) return {};
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw fail(400, "Bad JSON"); }
  }

  function send(res, status, body) {
    const text = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(text);
  }

  function serveFile(res, rel) {
    const file = path.join(webDir, rel === "/" ? "index.html" : rel);
    if (!file.startsWith(webDir + path.sep) && file !== path.join(webDir, "index.html")) { res.writeHead(404); return res.end(); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404, { "content-type": "text/plain" }); return res.end("Not found"); }
      res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream", "cache-control": "no-cache" });
      res.end(buf);
    });
  }

  async function handle(req, res, secure) {
    res.setHeader("content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    const url = new URL(req.url, "http://box");
    const ip = req.socket.remoteAddress?.replace(/^::ffff:/, "") || "";
    try {
      if (!url.pathname.startsWith("/api/")) return serveFile(res, decodeURIComponent(url.pathname));
      if (req.method !== "GET" && req.headers["x-cellowalla"] !== "1") throw fail(403, "Missing header");

      if (url.pathname === "/api/hello") return send(res, 200, { setUp: !!store.data.admin, signedIn: !!signedIn(req) });
      if (url.pathname === "/api/setup" && req.method === "POST") {
        if (store.data.admin) throw fail(409, "Already set up");
        if (tooMany(ip)) throw fail(429, "Too many tries; wait 15 minutes");
        const b = await readJson(req);
        if (!setupCode || !crypto.timingSafeEqual(Buffer.from(String(b.code || "").trim().toUpperCase().padEnd(64)), Buffer.from(setupCode.padEnd(64)))) {
          failures.get(ip).push(Date.now()); throw fail(403, "That setup code is wrong");
        }
        if (String(b.password || "").length < 10) throw fail(400, "Use at least 10 characters");
        store.change("admin", (s) => { s.admin = hashPassword(b.password); });
        store.flush();
        startSession(res, secure);
        return send(res, 200, { ok: true });
      }
      if (url.pathname === "/api/login" && req.method === "POST") {
        if (tooMany(ip)) throw fail(429, "Too many tries; wait 15 minutes");
        const b = await readJson(req);
        if (!checkPassword(b.password, store.data.admin)) { failures.get(ip).push(Date.now()); throw fail(403, "Wrong password"); }
        startSession(res, secure);
        return send(res, 200, { ok: true });
      }
      if (url.pathname === "/api/logout" && req.method === "POST") {
        const m = String(req.headers.cookie || "").match(/(?:^|;\s*)cw=([A-Za-z0-9_-]+)/);
        if (m) sessions.delete(tokenKey(m[1]));
        res.setHeader("set-cookie", "cw=; Path=/; Max-Age=0");
        return send(res, 200, { ok: true });
      }

      if (!signedIn(req)) throw fail(401, "Sign in");
      const route = routes[`${req.method} ${url.pathname}`];
      if (!route) throw fail(404, "No such thing");
      const body = req.method === "GET" ? {} : await readJson(req);
      return send(res, 200, await route(body, url));
    } catch (e) {
      if (!e.status) log(`[web] ${req.method} ${url.pathname}: ${e.stack || e.message}`);
      return send(res, e.status || 500, { error: e.status ? e.message : "Something went wrong on the box" });
    }
  }

  const servers = [];
  return {
    async listen({ port = 80, tlsPort = 443, tlsDir = null, host = "0.0.0.0" } = {}) {
      const cert = tlsDir && path.join(tlsDir, "cert.pem"), key = tlsDir && path.join(tlsDir, "key.pem");
      if (cert && fs.existsSync(cert) && fs.existsSync(key)) {
        const s = https.createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(key) }, (req, res) => handle(req, res, true));
        await new Promise((ok, bad) => s.once("error", bad).listen(tlsPort, host, ok));
        servers.push(s);
        // Plain http just points at https.
        const r = http.createServer((req, res) => { res.writeHead(301, { location: `https://${String(req.headers.host || "cellowalla.lan").replace(/:\d+$/, "")}${tlsPort === 443 ? "" : `:${tlsPort}`}${req.url}` }); res.end(); });
        await new Promise((ok, bad) => r.once("error", bad).listen(port, host, ok));
        servers.push(r);
      } else {
        const s = http.createServer((req, res) => handle(req, res, false));
        await new Promise((ok, bad) => s.once("error", bad).listen(port, host, ok));
        servers.push(s);
      }
    },
    close() { for (const s of servers) s.close(); },
  };
}
