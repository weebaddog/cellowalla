// Tunnel: a WireGuard server on the box, so phones and laptops away from home can come back in
// (reach home devices, and have Shield protect them on any Wi-Fi). Each phone gets a "pass": its
// own key pair and address, shown as a QR code for the WireGuard app.
//
// The interface is cw0; its config is /etc/wireguard/cw0.conf, run by wg-quick@cw0 (systemd).

import crypto from "node:crypto";
import { newId } from "./state.js";

const IFACE = "cw0";
const CONF = `/etc/wireguard/${IFACE}.conf`;

const b64 = (s) => Buffer.from(s, "base64url").toString("base64");

/** A fresh WireGuard key pair (Curve25519), base64 like `wg genkey` makes. */
export function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("x25519");
  return { privateKey: b64(privateKey.export({ format: "jwk" }).d), publicKey: b64(publicKey.export({ format: "jwk" }).x) };
}

/** "10.88.0.0/24" → { prefix: "10.88.0.", bits: 24, box: "10.88.0.1" } (only /24 networks). */
export function tunnelNet(cidr) {
  const m = String(cidr).match(/^(\d+\.\d+\.\d+\.)0\/24$/);
  if (!m) throw new Error("The tunnel network must look like 10.88.0.0/24");
  return { prefix: m[1], box: `${m[1]}1`, cidr };
}

export function serverConf(t) {
  const n = tunnelNet(t.net);
  return [
    "# Written by Cellowalla. Changes here are overwritten.",
    "[Interface]",
    `PrivateKey = ${t.privateKey}`,
    `Address = ${n.box}/24`,
    `ListenPort = ${t.port}`,
    "",
    ...t.passes.flatMap((p) => [`# ${p.name.replace(/[\r\n]/g, " ")}`, "[Peer]", `PublicKey = ${p.publicKey}`, `AllowedIPs = ${p.ip}/32`, ""]),
  ].join("\n");
}

export function passConf(t, p, lanCidr) {
  const n = tunnelNet(t.net);
  return [
    "[Interface]",
    `PrivateKey = ${p.privateKey}`,
    `Address = ${p.ip}/32`,
    `DNS = ${n.box}`,
    "",
    "[Peer]",
    `PublicKey = ${t.publicKey}`,
    `Endpoint = ${t.endpoint.includes(":") && !t.endpoint.startsWith("[") && t.endpoint.split(":").length > 2 ? `[${t.endpoint}]` : t.endpoint}:${t.port}`,
    `AllowedIPs = ${p.full ? "0.0.0.0/0, ::/0" : `${n.cidr}, ${lanCidr}`}`,
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
}

/** `wg show cw0 dump` → { publicKey → { endpoint, handshake (ms), rx, tx } }. */
export function parseDump(text) {
  const out = {};
  const lines = String(text || "").trim().split("\n").slice(1);
  for (const l of lines) {
    const [pub, , endpoint, , hs, rx, tx] = l.split("\t");
    if (pub) out[pub] = { endpoint: endpoint === "(none)" ? null : endpoint, handshake: Number(hs) * 1000, rx: Number(rx) || 0, tx: Number(tx) || 0 };
  }
  return out;
}

export function createTunnel({ store, sys, fetchImpl = fetch, log = console.log, onConnect = () => {} }) {
  let live = {};          // last `wg show` result
  const wasOnline = new Set();

  function ensureKeys() {
    if (store.data.tunnel.privateKey) return;
    const k = keyPair();
    store.change("tunnel", (s) => { s.tunnel.privateKey = k.privateKey; s.tunnel.publicKey = k.publicKey; });
  }

  async function guessEndpoint() {
    try {
      const r = await fetchImpl("https://api.ipify.org", { signal: AbortSignal.timeout(8000) });
      const ip = (await r.text()).trim();
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip;
    } catch { /* offline */ }
    return "";
  }

  async function apply() {
    const t = store.data.tunnel;
    if (!t.on) {
      await sys.run("systemctl", ["disable", "--now", `wg-quick@${IFACE}`]).catch(() => {});
      return;
    }
    ensureKeys();
    sys.writeFile(CONF, serverConf(store.data.tunnel), 0o600);
    const up = await sys.run("ip", ["link", "show", IFACE]).then(() => !sys.dry, () => false);
    if (up) await sys.run("bash", ["-c", `wg syncconf ${IFACE} <(wg-quick strip ${IFACE})`]);
    else await sys.run("systemctl", ["enable", "--now", `wg-quick@${IFACE}`]);
  }

  async function poll() {
    if (!store.data.tunnel.on) { live = {}; return; }
    try { live = parseDump(await sys.run("wg", ["show", IFACE, "dump"])); } catch { live = {}; }
    for (const p of store.data.tunnel.passes) {
      const on = Date.now() - (live[p.publicKey]?.handshake || 0) < 180_000;
      if (on && !wasOnline.has(p.id)) { wasOnline.add(p.id); onConnect(p, live[p.publicKey]); }
      if (!on) wasOnline.delete(p.id);
    }
  }

  return {
    apply,
    poll,
    async setOn(on) {
      if (on) { ensureKeys(); if (!store.data.tunnel.endpoint) { const e = await guessEndpoint(); store.change("tunnel", (s) => { s.tunnel.endpoint = e; }); } }
      store.change("tunnel", (s) => { s.tunnel.on = !!on; });
      await apply();
    },
    async addPass(name, full = true) {
      ensureKeys();
      const t = store.data.tunnel, n = tunnelNet(t.net);
      const used = new Set(t.passes.map((p) => p.ip));
      let ip = null;
      for (let i = 2; i < 255; i++) if (!used.has(`${n.prefix}${i}`)) { ip = `${n.prefix}${i}`; break; }
      if (!ip) throw Object.assign(new Error("No addresses left in the tunnel network"), { status: 409 });
      const k = keyPair();
      const pass = { id: newId(), name: String(name || "Phone").slice(0, 40), ip, publicKey: k.publicKey, privateKey: k.privateKey, full: !!full, createdAt: Date.now() };
      store.change("tunnel", (s) => { s.tunnel.passes.push(pass); });
      await apply();
      return pass;
    },
    async removePass(id) {
      store.change("tunnel", (s) => {
        s.tunnel.passes = s.tunnel.passes.filter((p) => p.id !== id);
        delete s.devices[`wg:${id}`];
      });
      await apply();
    },
    conf: (p) => passConf(store.data.tunnel, p, store.data.net.lanCidr),
    status: () => store.data.tunnel.passes.map((p) => {
      const l = live[p.publicKey];
      return { id: p.id, name: p.name, ip: p.ip, full: p.full, createdAt: p.createdAt, online: Date.now() - (l?.handshake || 0) < 180_000, lastHandshake: l?.handshake || 0, from: l?.endpoint || null, rx: l?.rx || 0, tx: l?.tx || 0 };
    }),
  };
}
