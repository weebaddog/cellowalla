// Just enough of the DNS wire format: read the question, make "nowhere" answers, point a name at
// another one (Clean Search), spot DNS rebinding, and find the shortest TTL for the cache.

/** The question in a DNS message: { name, type, end } (end = where the question stops), or null. */
export function question(msg) {
  if (msg.length < 12 || msg.readUInt16BE(4) !== 1) return null;
  const labels = [];
  let i = 12;
  while (i < msg.length) {
    const len = msg[i];
    if (len === 0) { i++; break; }
    if (len > 63 || i + 1 + len > msg.length) return null;
    labels.push(msg.subarray(i + 1, i + 1 + len).toString("latin1").toLowerCase());
    i += 1 + len;
  }
  if (i + 4 > msg.length) return null;
  return { name: labels.join("."), type: msg.readUInt16BE(i), end: i + 4 };
}

function header(msg, rcode, answers) {
  const head = Buffer.from(msg.subarray(0, 12));
  head.writeUInt16BE(0x8180 | (msg.readUInt16BE(2) & 0x0100) | rcode, 2); // response, recursion available, (RD copied)
  head.writeUInt16BE(1, 4);
  head.writeUInt16BE(answers, 6);
  head.writeUInt16BE(0, 8);
  head.writeUInt16BE(0, 10);
  return head;
}

function rr(type, ttl, rdata, nameBytes = null) {
  const name = nameBytes || Buffer.from([0xc0, 0x0c]); // default: the question's name
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(ttl, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([name, fixed, rdata]);
}

/** "Nowhere": 0.0.0.0 for A, :: for AAAA, an empty answer for anything else. */
export function blockedAnswer(msg, q, ttl = 60) {
  const rdata = q.type === 1 ? Buffer.alloc(4) : q.type === 28 ? Buffer.alloc(16) : null;
  return Buffer.concat([header(msg, 0, rdata ? 1 : 0), msg.subarray(12, q.end), ...(rdata ? [rr(q.type, ttl, rdata)] : [])]);
}

/** "No such name" (used for the browser DNS-over-HTTPS canary). */
export function nxAnswer(msg, q) {
  return Buffer.concat([header(msg, 3, 0), msg.subarray(12, q.end)]);
}

/** "Server failure": upstream couldn't be reached. */
export function failAnswer(msg, q) {
  return Buffer.concat([header(msg, 2, 0), msg.subarray(12, q.end)]);
}

export function encodeName(name) {
  const parts = name.split(".").filter(Boolean).map((l) => { const b = Buffer.from(l, "latin1"); return Buffer.concat([Buffer.from([b.length]), b]); });
  return Buffer.concat([...parts, Buffer.from([0])]);
}

/** A question for `name` of `type`, with a random id. */
export function makeQuery(name, type) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(Math.floor(Math.random() * 65536), 0);
  head.writeUInt16BE(0x0100, 2);
  head.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([head, encodeName(name), tail]);
}

/** Skips a (possibly compressed) name; returns where it ends, or -1. */
function skipName(msg, i) {
  while (i < msg.length) {
    const len = msg[i];
    if (len === 0) return i + 1;
    if ((len & 0xc0) === 0xc0) return i + 2;
    i += 1 + len;
  }
  return -1;
}

/** The answer records of a reply: [{ type, ttl, rdata, at }] (at = offset of the TTL field). */
export function answers(msg) {
  const out = [];
  if (msg.length < 12) return out;
  const qd = msg.readUInt16BE(4), an = msg.readUInt16BE(6);
  let i = 12;
  for (let k = 0; k < qd && i > 0; k++) { i = skipName(msg, i); if (i > 0) i += 4; }
  for (let k = 0; k < an && i > 0; k++) {
    i = skipName(msg, i);
    if (i < 0 || i + 10 > msg.length) break;
    const type = msg.readUInt16BE(i), ttl = msg.readUInt32BE(i + 4), len = msg.readUInt16BE(i + 8);
    if (i + 10 + len > msg.length) break;
    out.push({ type, ttl, rdata: msg.subarray(i + 10, i + 10 + len), at: i + 4 });
    i += 10 + len;
  }
  return out;
}

export const rcode = (msg) => (msg.length >= 4 ? msg[3] & 0x0f : 2);

/**
 * Clean Search: answers `q` as "this name is really <target>", using the addresses already looked
 * up for the target (`targetReply`). A CNAME then the target's A/AAAA records.
 */
export function aliasAnswer(msg, q, target, targetReply) {
  const tname = encodeName(target);
  const addrs = answers(targetReply).filter((a) => a.type === q.type && (a.type === 1 || a.type === 28));
  const recs = [rr(5, 300, tname), ...addrs.map((a) => rr(a.type, Math.min(a.ttl, 300), a.rdata, tname))];
  return Buffer.concat([header(msg, 0, recs.length), msg.subarray(12, q.end), ...recs]);
}

/** Home and private addresses: what a public name must never point at (DNS rebinding). */
export function isPrivateAddress(bytes) {
  if (bytes.length === 4) {
    const [a, b] = bytes;
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (bytes.length === 16) {
    if (bytes.every((x, i) => (i === 15 ? x === 1 : x === 0))) return true;
    if ((bytes[0] & 0xfe) === 0xfc) return true;
    if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
    if (bytes.slice(0, 10).every((x) => x === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return isPrivateAddress(bytes.subarray(12));
  }
  return false;
}

export const rebindAnswer = (msg) => answers(msg).some((a) => (a.type === 1 || a.type === 28) && isPrivateAddress(a.rdata));

/** Shortest TTL among the answers (for the cache), or `fallback`. */
export function minTtl(msg, fallback = 60) {
  const a = answers(msg);
  return a.length ? Math.min(...a.map((x) => x.ttl)) : fallback;
}

/** A copy of a cached reply with the asker's id, and TTLs counted down by `aged` seconds. */
export function forAsker(reply, askMsg, aged = 0) {
  const out = Buffer.from(reply);
  askMsg.copy(out, 0, 0, 2);
  if (aged > 0) for (const a of answers(out)) out.writeUInt32BE(Math.max(1, a.ttl - aged), a.at);
  return out;
}
