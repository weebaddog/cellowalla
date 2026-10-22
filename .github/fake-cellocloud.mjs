// CI: a pretend CelloCloud for the real-install check (the box only accepts one on 127.0.0.1, through
// CELLOWALLA_CELLOCLOUD; see src/cellocloud.js). Same API as cellosig.com's /api/salt and /api/apps/*.
// Account "cibox" / "ci-cloud-password-1" (CelloCloud usernames are 3-32 characters). POST /_ci with an access answer changes what it says.
//   node .github/fake-cellocloud.mjs &

import crypto from "node:crypto";
import http from "node:http";

const SALT = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const AUTH = crypto.pbkdf2Sync("ci-cloud-password-1", Buffer.from(SALT, "hex"), 600_000, 64, "sha256").subarray(32).toString("hex");
const tokens = new Set();
let access = { allowed: true, reason: "ok", message: null, lockAt: null };
const answer = () => ({ ...access, app: "cellowalla", appName: "Cellowalla", plan: "plus700", username: "cibox", checked: Date.now() });

http.createServer(async (req, res) => {
  const send = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
  const url = new URL(req.url, "http://x");
  let body = "";
  for await (const c of req) body += c;
  const b = body ? JSON.parse(body) : {};
  console.log(req.method, url.pathname);
  if (url.pathname === "/_ci" && req.method === "POST") { access = { allowed: true, reason: "ok", message: null, lockAt: null, ...b }; return send(200, answer()); }
  if (url.pathname === "/api/salt") return send(200, { salt: SALT });
  if (req.method === "POST" && req.headers["x-cellocloud"] !== "1") return send(403, { error: "forbidden" });
  if (url.pathname === "/api/apps/login" && req.method === "POST") {
    if (b.app !== "cellowalla") return send(400, { error: "bad_app" });
    if (b.username !== "cibox" || b.authKey !== AUTH) return send(401, { error: "wrong_login" });
    const token = `ca_${crypto.randomBytes(16).toString("hex")}`;
    tokens.add(token);
    console.log(`signed in: device ${b.device}`);
    return send(200, { token, ...answer() });
  }
  const tok = String(req.headers.authorization || "").replace(/^Bearer /, "");
  if (!tokens.has(tok)) return send(401, { error: "signed_out" });
  if (url.pathname === "/api/apps/access") return send(200, answer());
  if (url.pathname === "/api/apps/logout") { tokens.delete(tok); return send(200, { ok: true }); }
  send(404, { error: "not_found" });
}).listen(18790, "127.0.0.1", () => console.log("pretend CelloCloud on 127.0.0.1:18790"));
