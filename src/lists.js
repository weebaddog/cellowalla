// Shield's block lists: which names belong to which category. Downloaded once a day from public,
// open-source lists (StevenBlack hosts: MIT; URLhaus: CC0; HaGeZi threat feed: GPL-3.0); the last good copy of each is kept so a box with no internet still blocks.
// A few short lists are built in (gaming, the DNS-bypass names) because no good public one exists.

import fs from "node:fs";
import path from "node:path";

const SB = "https://raw.githubusercontent.com/StevenBlack/hosts/master";

/** The categories Shield knows. `sources` are downloaded; `builtin` names are always included. */
export const CATALOG = {
  ads:      { title: "Ads & trackers",  about: "Advertising, tracking and analytics servers.", sources: [`${SB}/hosts`] },
  malware:  { title: "Malware & scams", about: "Servers spreading malware, phishing and scam sites.", sources: ["https://urlhaus.abuse.ch/downloads/hostfile/", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.mini.txt"] },
  adult:    { title: "Adult",           about: "Pornography and adult sites.", sources: [`${SB}/alternates/porn-only/hosts`] },
  social:   { title: "Social media",    about: "Facebook, Instagram, TikTok, Snapchat, X and similar.", sources: [`${SB}/alternates/social-only/hosts`],
              builtin: ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "snapchat.com", "snapkit.com", "sc-cdn.net", "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "x.com", "twitter.com", "twimg.com", "reddit.com", "redd.it", "pinterest.com", "tumblr.com", "threads.net", "discord.com", "discord.gg", "discordapp.com", "bereal.com"] },
  gaming:   { title: "Gaming",          about: "Online games and game stores.", sources: [],
              builtin: ["roblox.com", "rbxcdn.com", "roblox.cn", "epicgames.com", "epicgames.dev", "fortnite.com", "unrealengine.com", "minecraft.net", "minecraftservices.com", "mojang.com", "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamserver.net", "playstation.com", "playstation.net", "xboxlive.com", "xbox.com", "nintendo.net", "nintendo.com", "ea.com", "origin.com", "riotgames.com", "leagueoflegends.com", "valorant.com", "blizzard.com", "battle.net", "supercell.com", "clashofclans.com", "brawlstars.com", "king.com", "miniclip.com", "poki.com", "crazygames.com", "twitch.tv", "ttvnw.net", "jtvnw.net", "itch.io", "garena.com", "pubg.com", "hoyoverse.com", "mihoyo.com", "ubisoft.com", "ubi.com", "rockstargames.com", "activision.com", "callofduty.com"] },
  gambling: { title: "Gambling",        about: "Betting and casino sites.", sources: [`${SB}/alternates/gambling-only/hosts`] },
};

/**
 * Names that let a device dodge Shield by using its own encrypted DNS. Always blocked while Shield
 * is on (devices then fall back to normal DNS, which comes to us).
 */
export const BYPASS = ["dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
  "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "dns.adguard.com", "dns.adguard-dns.com", "dns-unfiltered.adguard.com",
  "doh.cleanbrowsing.org", "dns.nextdns.io", "chrome.cloudflare-dns.com", "doh.dns.sb", "dns.sb", "doh.mullvad.net", "dns.mullvad.net", "freedns.controld.com", "dns.controld.com"];

/** Firefox asks this name; "no such name" tells it not to switch on its own DNS-over-HTTPS. */
export const CANARY = "use-application-dns.net";

const IGNORE = new Set(["localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0", "ip6-localhost", "ip6-loopback"]);
const NAME = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

/** Hosts files ("0.0.0.0 name"), plain lists (one name per line) and adblock lists ("||name^"). */
export function parseList(text) {
  const names = new Set();
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/[#!].*$/, "").trim().toLowerCase();
    if (!line) continue;
    let name;
    const hosts = line.match(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(\S+)/);
    if (hosts) name = hosts[1];
    else if (line.startsWith("||")) { const m = line.match(/^\|\|([^\^\/$]+)\^?$/); if (!m) continue; name = m[1]; }
    else if (!/\s/.test(line)) name = line;
    else continue;
    name = name.replace(/\.$/, "");
    if (!IGNORE.has(name) && NAME.test(name)) names.add(name);
  }
  return names;
}

/** Cleans a name typed by a person ("https://www.Example.com/page" → "www.example.com"). */
export function cleanName(s) {
  let n = String(s || "").trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[\/?#:].*$/, "").replace(/^\*\./, "").replace(/\.$/, "");
  return NAME.test(n) ? n : null;
}

/** True if `name` or any domain it sits under is in `set`. */
export function underAny(set, name) {
  for (let n = name; ; ) {
    if (set.has(n)) return n;
    const dot = n.indexOf(".");
    if (dot < 0) return null;
    n = n.slice(dot + 1);
  }
}

export function createLists({ dir, fetchImpl = fetch, log = console.log, minSize = 50 }) {
  const cacheDir = path.join(dir, "lists");
  fs.mkdirSync(cacheDir, { recursive: true });
  const sets = new Map();     // category or "custom:<id>" → Set
  const info = new Map();     // → { size, updated, error }

  const file = (url) => path.join(cacheDir, Buffer.from(url).toString("base64url").slice(0, 120) + ".txt");

  async function fetchOne(url) {
    try {
      const r = await fetchImpl(url, { signal: AbortSignal.timeout(90_000), headers: { "user-agent": "cellowalla/0.1" } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      const names = parseList(text);
      if (names.size < minSize) throw new Error(`only ${names.size} names`);
      fs.writeFileSync(`${file(url)}.part`, text);
      fs.renameSync(`${file(url)}.part`, file(url));
      return { names, fresh: true };
    } catch (e) {
      try { return { names: parseList(fs.readFileSync(file(url), "utf8")), fresh: false, error: e.message }; }
      catch { return { names: new Set(), fresh: false, error: e.message }; }
    }
  }

  async function build(key, urls, builtin = []) {
    const set = new Set(builtin);
    let error = null, fresh = urls.length === 0;
    for (const url of urls) {
      const r = await fetchOne(url);
      for (const n of r.names) set.add(n);
      if (r.error) error = `${new URL(url).hostname}: ${r.error}`;
      if (r.fresh) fresh = true;
    }
    // Keep yesterday's list if every download failed and nothing was saved.
    if (set.size <= builtin.length && sets.get(key)?.size > set.size) { info.set(key, { ...info.get(key), error }); return; }
    sets.set(key, set);
    info.set(key, { size: set.size, updated: fresh ? Date.now() : info.get(key)?.updated || null, error });
  }

  /** Downloads every category (and the owner's own lists). Wanted = categories switched on anywhere. */
  async function refresh(custom = []) {
    for (const [key, c] of Object.entries(CATALOG)) await build(key, c.sources, c.builtin);
    for (const c of custom) await build(`custom:${c.id}`, [c.url]);
    for (const k of sets.keys()) if (k.startsWith("custom:") && !custom.some((c) => `custom:${c.id}` === k)) { sets.delete(k); info.delete(k); }
    log(`[lists] ${[...info].map(([k, v]) => `${k} ${v.size}`).join(", ")}`);
  }

  return {
    refresh,
    /** Which of `keys` contains `name` (or a domain above it): the key, or null. */
    match(keys, name) {
      for (const k of keys) { const s = sets.get(k); if (s && underAny(s, name)) return k; }
      return null;
    },
    info: () => Object.fromEntries(info),
    has: (key) => sets.has(key),
  };
}
