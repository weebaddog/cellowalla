// Shield: the box's DNS server. Every device asks it "where is example.com?"; Shield checks that
// device's House Rules and the block lists, answers "nowhere" (0.0.0.0) for blocked names, and
// passes the rest to an encrypted upstream (DNS-over-HTTPS) with a small cache.
//
// What was asked is kept only in memory (the last few thousand lookups, for the Log screen) and
// as counts. Nothing is sent anywhere but the upstream resolver.

import dgram from "node:dgram";
import net from "node:net";
import * as P from "./dnsproto.js";
import { BYPASS, CANARY, underAny } from "./lists.js";
import { rulesFor } from "./policy.js";

const CLEAN = [
  [/^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/, "forcesafesearch.google.com"],
  [/^(www\.|m\.)?youtube\.com$|^youtubei\.googleapis\.com$|^youtube\.googleapis\.com$|^www\.youtube-nocookie\.com$/, "restrictmoderate.youtube.com"],
  [/^(www\.)?bing\.com$/, "strict.bing.com"],
  [/^(www\.)?duckduckgo\.com$/, "safe.duckduckgo.com"],
  [/^search\.brave\.com$/, "forcesafe.search.brave.com"],
];
const cleanTarget = (name) => CLEAN.find(([re]) => re.test(name))?.[1] || null;

const LOCAL = /(^|\.)(lan|local|home|internal|localdomain|home\.arpa)$/;
const PRIVATE_PTR = /(^|\.)(10|127|168\.192|(1[6-9]|2[0-9]|3[01])\.172|254\.169)\.in-addr\.arpa$/;
const BYPASS_SET = new Set(BYPASS);
const LOG_SIZE = 5000;

export function createShield({ store, lists, roster, fetchImpl = fetch, log = console.log, onMalware = () => {} }) {
  const cache = new Map();   // "name/type" → { reply, at, ttl }
  const recent = [];         // the Log screen (newest last)
  const hours = [];          // [{ hour, q, b }] last 24 hours
  const topBlocked = new Map();
  const perDevice = new Map(); // key → { q, b }
  let paused = 0;             // whole-Shield pause (owner pressed "pause Shield for 15 min")

  function count(key, blocked) {
    const hour = Math.floor(Date.now() / 3600_000);
    if (!hours.length || hours.at(-1).hour !== hour) { hours.push({ hour, q: 0, b: 0 }); if (hours.length > 24) hours.shift(); }
    hours.at(-1).q++; if (blocked) hours.at(-1).b++;
    const d = perDevice.get(key) || { q: 0, b: 0 }; d.q++; if (blocked) d.b++; perDevice.set(key, d);
  }

  async function upstream(msg) {
    const url = store.data.shield.upstream;
    if (url.startsWith("udp://")) { const [host, port = "53"] = url.slice(6).split(":"); return udpAsk(host, Number(port), msg); }
    try {
      const r = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/dns-message", accept: "application/dns-message" }, body: msg, signal: AbortSignal.timeout(4000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return Buffer.from(await r.arrayBuffer());
    } catch (e) {
      // The encrypted resolver is unreachable: plain DNS rather than no internet.
      return udpAsk("9.9.9.9", 53, msg);
    }
  }

  async function resolve(msg, q) {
    const key = `${q.name}/${q.type}`;
    const hit = cache.get(key);
    const now = Date.now();
    if (hit && now - hit.at < hit.ttl * 1000) return P.forAsker(hit.reply, msg, Math.floor((now - hit.at) / 1000));
    const reply = await upstream(msg);
    const rc = P.rcode(reply);
    if (rc === 0 || rc === 3) {
      if (cache.size > 20000) cache.delete(cache.keys().next().value);
      cache.set(key, { reply, at: now, ttl: Math.min(3600, Math.max(rc === 3 ? 60 : 10, P.minTtl(reply, 60))) });
    }
    return reply;
  }

  /** The reply for one DNS message from `ip`. */
  async function answer(msg, ip) {
    const q = P.question(msg);
    if (!q) return null;
    const data = store.data;
    const device = roster.byIp(ip);
    const rules = rulesFor(data, device);
    if (!device && data.lobby.on && ip !== "127.0.0.1" && !rules.locked) rules.cut = "lobby"; // not met yet: waits like any newcomer
    const entry = { t: Date.now(), ip, dev: device?.mac || null, name: q.name, type: q.type, v: "ok" };
    const done = (reply, verdict) => {
      entry.v = verdict;
      if (q.type !== 12) { recent.push(entry); if (recent.length > LOG_SIZE) recent.splice(0, recent.length - LOG_SIZE); }
      count(device?.mac || ip, verdict.startsWith("blocked") || verdict === "cut");
      return reply;
    };

    // The box itself, and names that belong at home.
    if (q.name === "cellowalla.lan" || q.name === "cellowalla") {
      if (q.type === 1) return done(Buffer.concat([P.blockedAnswer(msg, q).subarray(0, -4), Buffer.from(data.net.boxIp.split(".").map(Number))]), "local");
      return done(P.blockedAnswer(msg, { ...q, type: 0 }), "local");
    }
    if (LOCAL.test(q.name) || PRIVATE_PTR.test(q.name)) {
      if (data.net.homeDns) { try { return done(await udpAsk(data.net.homeDns, 53, msg), "local"); } catch { /* fall through */ } }
      return done(P.nxAnswer(msg, q), "local");
    }

    const shieldOn = rules.shield && paused < Date.now();
    if (rules.cut) return done(P.blockedAnswer(msg, q), "cut");
    if (shieldOn) {
      if (q.name === CANARY) return done(P.nxAnswer(msg, q), "blocked:bypass");
      const allowed = underAny(new Set(rules.allow), q.name);
      if (!allowed) {
        let why = underAny(new Set(rules.deny), q.name) ? "yours" : null;
        if (!why && underAny(BYPASS_SET, q.name)) why = "bypass";
        if (!why) why = lists.match(rules.lists, q.name);
        if (why) {
          topBlocked.set(q.name, (topBlocked.get(q.name) || 0) + 1);
          if (topBlocked.size > 3000) for (const [k, n] of topBlocked) if (n < 3) topBlocked.delete(k);
          if (why === "malware") onMalware(device, ip, q.name);
          return done(P.blockedAnswer(msg, q), `blocked:${why}`);
        }
      }
      if (rules.cleanSearch && (q.type === 1 || q.type === 28)) {
        const target = cleanTarget(q.name);
        if (target) {
          try { return done(P.aliasAnswer(msg, q, target, await resolve(P.makeQuery(target, q.type), { name: target, type: q.type })), "clean"); }
          catch { return done(P.failAnswer(msg, q), "fail"); }
        }
      }
      if (rules.cleanSearch && q.type === 65 && cleanTarget(q.name)) return done(P.blockedAnswer(msg, q), "clean"); // no HTTPS records that skip the alias
    }

    let reply;
    try { reply = await resolve(msg, q); } catch { return done(P.failAnswer(msg, q), "fail"); }
    if (shieldOn && data.shield.rebinding && P.rebindAnswer(reply) && !underAny(new Set(rules.allow), q.name)) return done(P.blockedAnswer(msg, q), "blocked:rebinding");
    return done(reply, "ok");
  }

  let udp4 = null, tcp = null;

  return {
    answer,
    /** Starts listening (port 53 on the box; tests use another). */
    listen({ port = 53, host = "0.0.0.0" } = {}) {
      udp4 = dgram.createSocket({ type: "udp4", reuseAddr: true });
      udp4.on("message", (msg, from) => {
        answer(msg, from.address).then((r) => { if (r) udp4.send(r.length > 512 && !hasEdns(msg) ? truncate(r) : r, from.port, from.address); })
          .catch((e) => log(`[shield] ${e.message}`));
      });
      udp4.on("error", (e) => log(`[shield] udp: ${e.message}`));
      tcp = net.createServer((sock) => {
        sock.setTimeout(10_000, () => sock.destroy());
        let buf = Buffer.alloc(0);
        sock.on("data", (d) => {
          buf = Buffer.concat([buf, d]);
          while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
            const msg = buf.subarray(2, 2 + buf.readUInt16BE(0));
            buf = buf.subarray(2 + msg.length);
            answer(msg, sock.remoteAddress.replace(/^::ffff:/, "")).then((r) => {
              if (!r || sock.destroyed) return;
              const len = Buffer.alloc(2); len.writeUInt16BE(r.length); sock.write(Buffer.concat([len, r]));
            }).catch(() => sock.destroy());
          }
          if (buf.length > 70_000) sock.destroy();
        });
        sock.on("error", () => {});
      });
      return Promise.all([
        new Promise((ok, bad) => { udp4.once("error", bad); udp4.bind(port, host, () => { udp4.off("error", bad); ok(); }); }),
        new Promise((ok, bad) => { tcp.once("error", bad); tcp.listen(port, host, ok); }),
      ]);
    },
    close() { udp4?.close(); tcp?.close(); },
    pause(minutes) { paused = minutes > 0 ? Date.now() + minutes * 60_000 : 0; },
    pausedUntil: () => (paused > Date.now() ? paused : 0),
    clearCache: () => cache.clear(),
    /** The Log screen: newest first, filtered. */
    recent({ dev, q, only, limit = 300 } = {}) {
      const out = [];
      for (let i = recent.length - 1; i >= 0 && out.length < limit; i--) {
        const e = recent[i];
        if (dev && e.dev !== dev && e.ip !== dev) continue;
        if (only === "blocked" && !(e.v.startsWith("blocked") || e.v === "cut")) continue;
        if (q && !e.name.includes(q)) continue;
        out.push(e);
      }
      return out;
    },
    stats() {
      return {
        hours: hours.map((h) => ({ ...h })),
        top: [...topBlocked].sort((a, b) => b[1] - a[1]).slice(0, 20),
        devices: Object.fromEntries(perDevice),
        cached: cache.size,
      };
    },
  };
}

const hasEdns = (msg) => msg.length >= 12 && msg.readUInt16BE(10) > 0;

/** Over 512 bytes without EDNS: send just the header with "truncated" so the asker retries over TCP. */
function truncate(r) {
  const q = P.question(r);
  const out = Buffer.from(r.subarray(0, q ? q.end : 12));
  out[2] |= 0x02;
  out.writeUInt16BE(0, 6); out.writeUInt16BE(0, 8); out.writeUInt16BE(0, 10);
  return out;
}

/** Plain DNS over UDP to `host` (fallback resolver, the home router for local names). */
export function udpAsk(host, port, msg, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket(net.isIPv6(host) ? "udp6" : "udp4");
    const t = setTimeout(() => { s.close(); reject(new Error("timeout")); }, timeout);
    s.on("message", (r) => { if (r.length >= 2 && r[0] === msg[0] && r[1] === msg[1]) { clearTimeout(t); s.close(); resolve(r); } });
    s.on("error", (e) => { clearTimeout(t); s.close(); reject(e); });
    s.send(msg, port, host);
  });
}
