// Pings: things the owner should know about (a new device, a phone connecting through the Tunnel,
// a device reaching for a malware site, bedtime starting). Kept in a feed on the box and, if the
// owner sets one up, pushed to their phone via ntfy (the free ntfy app) or any webhook.

import { openFeed, newId } from "./state.js";

const TITLES = { newDevice: "New device", tunnel: "Tunnel", malware: "Malware blocked", bedtime: "Bedtime", system: "Cellowalla" };

export function createPings({ store, dir, fetchImpl = fetch, log = console.log }) {
  const feed = openFeed(dir, "pings.json", 500);
  const quiet = new Map(); // key → time: don't repeat the same ping within the hour

  async function push(p) {
    const cfg = store.data.pings;
    const tasks = [];
    if (cfg.ntfy) tasks.push(fetchImpl(cfg.ntfy, { method: "POST", body: p.text, headers: { title: `${TITLES[p.kind] || "Cellowalla"}`, tags: p.kind === "malware" ? "warning" : "shield" }, signal: AbortSignal.timeout(10_000) }));
    if (cfg.webhook) tasks.push(fetchImpl(cfg.webhook, { method: "POST", body: JSON.stringify({ kind: p.kind, title: TITLES[p.kind], text: p.text, at: p.at, ref: p.ref }), headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(10_000) }));
    for (const r of await Promise.allSettled(tasks)) if (r.status === "rejected") log(`[pings] couldn't send: ${r.reason?.message}`);
  }

  /** Records (and maybe sends) a ping. `once` = a key that silences repeats for an hour. */
  function send(kind, text, { ref = null, once = null } = {}) {
    if (once) { const last = quiet.get(once) || 0; if (Date.now() - last < 3600_000) return; quiet.set(once, Date.now()); }
    const p = { id: newId(), kind, text, ref, at: Date.now(), read: false };
    feed.add(p);
    if (store.data.pings.events[kind] !== false) push(p).catch(() => {});
    return p;
  }

  return {
    send,
    test: () => push({ kind: "system", text: "Test from Cellowalla: Pings reach this phone.", at: Date.now() }),
    list: (limit = 100) => feed.items.slice(0, limit),
    unread: () => feed.items.filter((p) => !p.read).length,
    markRead: () => feed.update((items) => { for (const p of items) p.read = true; }),
    clear: () => feed.update((items) => { items.length = 0; }),
    flush: () => feed.flush(),
  };
}
