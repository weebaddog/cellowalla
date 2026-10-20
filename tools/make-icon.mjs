// Draws the Cellowalla icon (same shapes as web/icon.svg) into a PNG, no image tools needed.
//   node tools/make-icon.mjs <out.png> [size=512]

import fs from "node:fs";
import zlib from "node:zlib";

const [out, sizeArg] = process.argv.slice(2);
const N = Number(sizeArg || 512), S = N / 64, SS = 4; // icon units are 64×64; 4×4 samples per pixel

// The shield outline, curves flattened to points.
function cubic(p0, p1, p2, p3, steps = 24) {
  const pts = [];
  for (let i = 1; i <= steps; i++) {
    const t = i / steps, u = 1 - t;
    pts.push([u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0], u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]]);
  }
  return pts;
}
const shield = [[32, 10], [50, 17], [50, 31], ...cubic([50, 31], [50, 43], [42, 51], [32, 55]), ...cubic([32, 55], [22, 51], [14, 43], [14, 31]), [14, 17]];
const lines = [[22, 26, 42, 26], [22, 33, 42, 33], [22, 40, 42, 40], [28, 26, 28, 33], [36, 33, 36, 40], [30, 40, 30, 47]];

function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
function nearSeg(x, y, [x1, y1, x2, y2], r) {
  const dx = x2 - x1, dy = y2 - y1, t = Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / (dx * dx + dy * dy)));
  return (x - x1 - t * dx) ** 2 + (y - y1 - t * dy) ** 2 <= r * r;
}
function inRoundRect(x, y, r = 14) {
  const cx = Math.max(r, Math.min(64 - r, x)), cy = Math.max(r, Math.min(64 - r, y));
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}
const GREEN = [15, 122, 90], WHITE = [255, 255, 255];
function sample(x, y) {
  if (!inRoundRect(x, y)) return null;
  if (inPoly(x, y, shield) && !lines.some((l) => nearSeg(x, y, l, 1.5))) return WHITE;
  return GREEN;
}

const rows = [];
for (let py = 0; py < N; py++) {
  const row = Buffer.alloc(1 + N * 4);
  for (let px = 0; px < N; px++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
      const c = sample((px + (sx + 0.5) / SS) / S, (py + (sy + 0.5) / SS) / S);
      if (c) { r += c[0]; g += c[1]; b += c[2]; a++; }
    }
    const o = 1 + px * 4;
    if (a) { row[o] = r / a; row[o + 1] = g / a; row[o + 2] = b / a; row[o + 3] = (a / (SS * SS)) * 255; }
  }
  rows.push(row);
}

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = (buf) => { let c = 0xffffffff; for (const x of buf) c = crcTable[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
  return Buffer.concat([len, td, c]);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6;
fs.writeFileSync(out, Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(Buffer.concat(rows), { level: 9 })), chunk("IEND", Buffer.alloc(0))]));
console.log(`${out} (${N}×${N})`);
