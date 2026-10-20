// Problem reports: errors and crashes from the box, its dashboard and the Cellowalla apps, plus
// "Report a problem" from people, kept on the box and emailed to the owner through their own mail
// account (e.g. Gmail with an App Password, set in the dashboard). Nothing is sent anywhere else.
//   - The same problem again within an hour is counted, not repeated.
//   - Automatic reports go out together every few minutes; ones people write go at once.

import tls from "node:tls";
import net from "node:net";
import os from "node:os";
import crypto from "node:crypto";
import { openFeed } from "./state.js";

const BATCH_MS = 5 * 60_000;
const SAME_FOR = 3600_000;
// ---- a tiny mail sender (SMTP) ---------------------------------------------------------------------

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const wrap = (s) => s.replace(/.{1,76}/g, "$&\r\n");
const header = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`);

/**
 * Sends one plain-text email. cfg: { host, port (465 = encrypted from the start), user, pass, from?, to, secure? }.
 * (`secure: false` is only for the self-test's pretend mail server.)
 */
export function sendMail(cfg, subject, text) {
  return new Promise((resolve, reject) => {
    const port = cfg.port || 465;
    const sock = cfg.secure === false ? net.connect(port, cfg.host) : tls.connect({ port, host: cfg.host, servername: cfg.host });
    sock.setEncoding("utf8");
    sock.setTimeout(30_000, () => { sock.destroy(); reject(new Error("The mail server didn't answer")); });
    const from = cfg.from || cfg.user;
    const msg = [
      `From: ${header("Cellowalla")} <${from}>`, `To: <${cfg.to}>`, `Subject: ${header(subject)}`, `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${crypto.randomBytes(12).toString("hex")}@cellowalla>`, "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: base64", "", wrap(b64(text)),
    ].join("\r\n");
    // Each step: what to send once the server answers with the expected code.
    const steps = [
      [220, `EHLO ${os.hostname().replace(/[^A-Za-z0-9.-]/g, "") || "cellowalla"}`], [250, "AUTH LOGIN"], [334, b64(cfg.user)], [334, b64(cfg.pass)],
      [235, `MAIL FROM:<${from}>`], [250, `RCPT TO:<${cfg.to}>`], [250, "DATA"], [354, `${msg}\r\n.`], [250, "QUIT"],
    ];
    let buf = "", step = 0;
    sock.on("data", (d) => {
      buf += d;
      // A reply is complete at a line "NNN text" (not "NNN-text", which continues).
      let m;
      while ((m = buf.match(/^(\d{3})([ -])(.*)\r?\n/m))) {
        const lineEnd = buf.indexOf("\n", m.index) + 1;
        const line = buf.slice(m.index, lineEnd);
        buf = buf.slice(lineEnd);
        if (m[2] === "-") continue;
        const code = +m[1];
        if (step >= steps.length) { sock.end(); resolve(); return; }
        const [want, send] = steps[step];
        if (code !== want) {
          sock.destroy();
          const hint = code === 535 ? " (wrong address or App Password)" : "";
          reject(new Error(`Mail server said: ${line.trim()}${hint}`));
          return;
        }
        step++;
        sock.write(`${send}\r\n`);
      }
    });
    sock.on("error", (e) => reject(new Error(`Couldn't reach the mail server: ${e.message}`)));
    sock.on("close", () => { if (step >= steps.length) resolve(); });
  });
}

const clip = (s, n) => (s === undefined || s === null ? null : String(s).slice(0, n));

export function createReports({ store, dir, version, log = console.log, send = sendMail }) {
  const feed = openFeed(dir, "reports.json", 500);
  let timer = null;
  const mail = () => store.data.reportsMail || {};
  const ready = () => { const c = mail(); return c.to && c.user && c.pass ? c : null; };

  function format(rows) {
    return rows.map((r) => [
      `• ${r.kind === "user" ? "Someone reported a problem" : r.kind} in ${r.source}${r.count > 1 ? ` (${r.count} times)` : ""}`,
      `  ${r.message}`,
      r.detail ? r.detail.split("\n").slice(0, 25).map((l) => `    ${l}`).join("\n") : null,
      `  ${[r.device, r.version ? `app ${r.version}` : null, new Date(r.last).toLocaleString()].filter(Boolean).join(" · ")}`,
    ].filter(Boolean).join("\n")).join("\n\n");
  }

  async function flush() {
    timer = null;
    const cfg = ready();
    if (!cfg) return { sent: 0, reason: "Email isn't set up" };
    const rows = feed.items.filter((r) => !r.sent).slice(0, 50);
    if (!rows.length) return { sent: 0 };
    const people = rows.filter((r) => r.kind === "user").length;
    const subject = people ? `Cellowalla: ${people === 1 ? "a problem was reported" : `${people} problems were reported`}` : `Cellowalla: ${rows.length} new ${rows.length === 1 ? "problem" : "problems"}`;
    try {
      await send(cfg, subject, `Your Cellowalla box (${os.hostname()}, Cellowalla ${version})\n\n${format(rows)}\n\n— Sent by your Cellowalla box. Turn these emails off in the dashboard → Settings → Problem reports.\n`);
      feed.update(() => { for (const r of rows) r.sent = true; });
      store.change("reportsMail", (s) => { s.reportsMail = { ...s.reportsMail, lastError: null }; });
      return { sent: rows.length };
    } catch (e) {
      log(`[reports] couldn't email: ${e.message}`);
      store.change("reportsMail", (s) => { s.reportsMail = { ...s.reportsMail, lastError: { at: Date.now(), message: e.message } }; });
      return { sent: 0, reason: e.message };
    }
  }

  return {
    add(r, now = false) {
      const row = { source: clip(r.source, 30) || "?", kind: clip(r.kind, 30) || "error", message: clip(r.message, 500) || "(no message)", detail: clip(r.detail, 6000), device: clip(r.device, 80), version: clip(r.version, 30) };
      const sig = crypto.createHash("sha1").update(`${row.source}|${row.kind}|${row.message}`).digest("hex");
      const same = row.kind !== "user" && feed.items.find((x) => x.sig === sig && x.last > Date.now() - SAME_FOR);
      if (same) feed.update(() => { same.count++; same.last = Date.now(); });
      else feed.add({ id: crypto.randomBytes(6).toString("hex"), first: Date.now(), last: Date.now(), count: 1, sig, sent: false, ...row });
      if (!ready() || mail().off) return;
      if (now) { clearTimeout(timer); timer = null; flush().catch(() => {}); }
      else if (!timer && !same) timer = setTimeout(() => flush().catch(() => {}), BATCH_MS);
    },
    flush,
    list: (n = 100) => feed.items.slice(0, n).map(({ sig, ...r }) => r),
    settings() { const c = mail(); return { to: c.to || "", user: c.user || "", host: c.host || "smtp.gmail.com", port: c.port || 465, hasPass: !!c.pass, off: !!c.off, lastError: c.lastError || null }; },
    save(b) {
      const next = { ...mail() };
      for (const k of ["to", "user", "host"]) if (typeof b[k] === "string") next[k] = b[k].trim().slice(0, 200);
      if (b.port) next.port = Math.max(1, Math.min(65535, +b.port || 465));
      if (typeof b.pass === "string" && b.pass) next.pass = b.pass.replace(/\s+/g, "");
      if ("off" in b) next.off = !!b.off;
      for (const k of ["to", "user"]) if (next[k] && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(next[k])) throw Object.assign(new Error(`That isn't an email address: ${next[k]}`), { status: 400 });
      next.lastError = null;
      store.change("reportsMail", (s) => { s.reportsMail = next; });
    },
    async test() {
      const cfg = ready();
      if (!cfg) throw Object.assign(new Error("Fill in your email address, the sending account and its App Password first"), { status: 400 });
      try { await send(cfg, "Cellowalla: test email", "It works: problem reports from your Cellowalla box will come to this address.\n"); }
      catch (e) { throw Object.assign(new Error(e.message), { status: 400 }); }
    },
    flushFeed: () => feed.flush(),
  };
}