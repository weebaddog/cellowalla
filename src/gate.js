// Gate: the box's firewall (nftables table "cellowalla") and, in gatekeeper mode, its DHCP
// server (dnsmasq with DNS switched off; Shield answers DNS).
//
// Gatekeeper mode: the box sits between the modem and the home network and routes everything, so
// a paused or blocked device is really cut off, every device is counted, and DNS can't be dodged.
// Lookout mode: the box is just another device; the Gate only handles Tunnel traffic and House
// Rules work through DNS.

import { rulesFor } from "./policy.js";
import { tunnelNet } from "./tunnel.js";

const DNSMASQ = "/etc/dnsmasq.d/cellowalla.conf";
const q = (s) => `"${String(s).replace(/[^A-Za-z0-9_.:-]/g, "")}"`;
const cname = (ip) => ip.replace(/[.:]/g, "_");
const isIp4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s || "");

/** Is `ip` inside `cidr` (IPv4)? */
export function inCidr(ip, cidr) {
  const [base, bits] = String(cidr).split("/");
  if (!isIp4(ip) || !isIp4(base)) return false;
  const v = (s) => s.split(".").reduce((a, x) => a * 256 + Number(x), 0) >>> 0;
  const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return ((v(ip) & mask) >>> 0) === ((v(base) & mask) >>> 0);
}

/** The whole nftables ruleset, as one atomic `nft -f` file. */
export function nftRules({ mode, net, tunnel }, { cut = [], lobby = [], counted = [] }) {
  const gk = mode === "gatekeeper";
  const lan = q(net.lanIf), wan = q(net.wanIf);
  const tn = tunnel.on ? tunnelNet(tunnel.net) : null;
  const set = (name, ips) => [`  set ${name} {`, "    type ipv4_addr", ...(ips.length ? [`    elements = { ${ips.join(", ")} }`] : []), "  }"];
  const L = [];
  L.push("# Written by Cellowalla. Changes here are overwritten.");
  L.push("table inet cellowalla");
  L.push("delete table inet cellowalla");
  L.push("table inet cellowalla {");
  L.push(...set("cut4", cut), ...set("lobby4", lobby));
  for (const ip of counted) L.push(`  counter u_${cname(ip)} { }`, `  counter d_${cname(ip)} { }`);

  L.push("  chain input {", "    type filter hook input priority filter; policy accept;");
  L.push("    iif lo accept", "    ct state established,related accept", "    ct state invalid drop");
  if (tn) L.push(`    udp dport ${Number(tunnel.port)} accept`);
  if (gk) {
    L.push(`    iifname ${wan} icmp type echo-request limit rate 5/second accept`);
    L.push(`    iifname ${wan} meta nfproto ipv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept`);
    L.push(`    iifname ${wan} udp sport 67 udp dport 68 accept`);
    L.push(`    iifname ${wan} drop`);
    L.push(`    ip saddr @lobby4 udp dport { 53, 67 } accept`, "    ip saddr @lobby4 tcp dport 53 accept", "    ip saddr @lobby4 drop");
  }
  L.push("  }");

  L.push("  chain forward {", `    type filter hook forward priority filter; policy ${gk ? "drop" : "accept"};`);
  L.push("    ip saddr @cut4 reject with icmpx type admin-prohibited", "    ip daddr @cut4 drop");
  L.push("    ip saddr @lobby4 drop", "    ip daddr @lobby4 drop");
  for (const ip of counted) L.push(`    ip saddr ${ip} counter name u_${cname(ip)}`, `    ip daddr ${ip} counter name d_${cname(ip)}`);
  L.push("    ct state established,related accept", "    ct state invalid drop");
  // Private DNS (DNS-over-TLS) would skip Shield; refused so devices fall back to normal DNS.
  L.push(`    meta l4proto { tcp, udp } th dport 853 reject`);
  if (gk) {
    L.push("    meta nfproto ipv6 drop"); // the home side is IPv4-only; nothing slips past by IPv6
    L.push(`    iifname ${lan} oifname ${wan} accept`);
  }
  if (tn) {
    L.push(`    iifname "cw0" accept`);
    L.push(`    oifname "cw0" ct state new ${gk ? `iifname ${lan} ` : ""}accept`);
  }
  L.push("  }");

  // Every DNS question goes to Shield, even from devices set to use some other DNS server.
  const dnsFrom = [...(gk ? [q(net.lanIf)] : []), ...(tn ? ['"cw0"'] : [])];
  L.push("  chain pre {", "    type nat hook prerouting priority dstnat; policy accept;");
  if (dnsFrom.length) L.push(`    iifname { ${dnsFrom.join(", ")} } meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 redirect to :53`);
  L.push("  }");
  L.push("  chain post {", "    type nat hook postrouting priority srcnat; policy accept;");
  if (gk) L.push(`    oifname ${wan} masquerade`);
  else if (tn) L.push(`    ip saddr ${tn.cidr} oifname ${lan} masquerade`);
  L.push("  }");
  L.push("}");
  return L.join("\n") + "\n";
}

export function dnsmasqConf({ net, devices }) {
  const L = [
    "# Written by Cellowalla. Changes here are overwritten.",
    "port=0", // DNS is Shield's job
    `interface=${net.lanIf}`,
    "bind-interfaces",
    `dhcp-range=${net.dhcpFrom},${net.dhcpTo},12h`,
    `dhcp-option=option:router,${net.boxIp}`,
    `dhcp-option=option:dns-server,${net.boxIp}`,
    "dhcp-authoritative",
    "dhcp-leasefile=/var/lib/misc/cellowalla.leases",
    "domain=lan",
  ];
  // Every known device keeps its address (so House Rules and counters follow it).
  for (const d of Object.values(devices)) {
    if (d.kind === "lan" && /^[0-9a-f:]{17}$/.test(d.mac) && inCidr(d.ip, net.lanCidr) && d.ip !== net.boxIp) L.push(`dhcp-host=${d.mac},${d.ip}`);
  }
  return L.join("\n") + "\n";
}

/** `nft -j list counters` → { ip → { up, down } } bytes. */
export function parseCounters(json) {
  const out = {};
  let list = [];
  try { list = JSON.parse(json || "{}").nftables || []; } catch { return out; }
  for (const item of list) {
    const c = item.counter;
    const m = c?.name?.match(/^([ud])_(.+)$/);
    if (!m) continue;
    const ip = m[2].replace(/_/g, ".");
    out[ip] ||= { up: 0, down: 0 };
    out[ip][m[1] === "u" ? "up" : "down"] = Number(c.bytes) || 0;
  }
  return out;
}

export function createGate({ store, sys, log = console.log, onBedtime = () => {} }) {
  let applied = "";            // the ruleset last loaded
  let lastDhcp = "";
  let current = {};            // counters since the last reload
  let rate = {};               // ip → { up, down } bytes/s
  let lastRead = 0;
  const bedtimeNow = new Set();

  function plan() {
    const data = store.data, now = new Date();
    const cut = [], lobby = [], counted = [];
    for (const d of Object.values(data.devices)) {
      if (!isIp4(d.ip)) continue;
      const r = rulesFor(data, d, now);
      if (r.cut === "lobby") lobby.push(d.ip); else if (r.cut) cut.push(d.ip);
      if (data.mode === "gatekeeper" || d.kind === "tunnel") counted.push(d.ip);
    }
    // Bedtime starting/ending (for Pings).
    for (const c of Object.values(data.crews)) {
      const on = Object.values(data.devices).some((d) => d.crew === c.id && rulesFor(data, d, now).cut === "bedtime");
      if (on && !bedtimeNow.has(c.id)) { bedtimeNow.add(c.id); onBedtime(c, true); }
      if (!on && bedtimeNow.delete(c.id)) onBedtime(c, false);
    }
    return { cut: [...new Set(cut)].sort(), lobby: [...new Set(lobby)].sort(), counted: [...new Set(counted)].sort() };
  }

  async function readCounters() {
    let now;
    try { now = parseCounters(await sys.run("nft", ["-j", "list", "counters", "table", "inet", "cellowalla"])); } catch { return; }
    const t = Date.now(), secs = (t - lastRead) / 1000;
    if (lastRead && secs > 0) {
      rate = {};
      for (const [ip, c] of Object.entries(now)) {
        const p = current[ip] || { up: 0, down: 0 };
        rate[ip] = { up: Math.max(0, (c.up - p.up) / secs), down: Math.max(0, (c.down - p.down) / secs) };
      }
    }
    current = now; lastRead = t;
  }

  /** Writes and loads everything, if anything changed. */
  async function apply(force = false) {
    const data = store.data;
    const text = nftRules(data, plan());
    if (text !== applied || force) {
      // Reloading zeroes the counters: bank what they've counted first.
      await readCounters();
      store.change("traffic", (s) => {
        for (const [ip, c] of Object.entries(current)) { const t = (s.traffic[ip] ||= { up: 0, down: 0 }); t.up += c.up; t.down += c.down; }
      });
      current = {}; lastRead = 0;
      sys.writeFile("/etc/nftables.d/cellowalla.nft", text);
      try { await sys.run("nft", ["-f", "-"], { input: text }); applied = text; }
      catch (e) { log(`[gate] nft: ${e.message}`); throw e; }
    }
    if (data.mode === "gatekeeper") {
      const conf = dnsmasqConf(data);
      if (conf !== lastDhcp || force) {
        sys.writeFile(DNSMASQ, conf);
        await sys.run("systemctl", ["restart", "dnsmasq"]).catch((e) => log(`[gate] dnsmasq: ${e.message}`));
        lastDhcp = conf;
      }
    }
  }

  return {
    apply,
    plan,
    readCounters,
    /** Bytes counted so far and the current speed, per address. */
    traffic(ip) {
      const base = store.data.traffic[ip] || { up: 0, down: 0 }, c = current[ip] || { up: 0, down: 0 }, r = rate[ip] || { up: 0, down: 0 };
      return { up: base.up + c.up, down: base.down + c.down, upRate: r.up, downRate: r.down };
    },
  };
}
