"use strict";

// Pay-per-GB v2 — the per-GB address tag (frozen interface I3), the agent's
// side: decode a per-GB source address back to its list.
//
// The interface id (low 64 bits) of every per-GB source address is a keyed
// 8-round Feistel permutation of a 64-bit plain block:
//   plain = L ‖ R, L = list_id (32 bits), R = r16 (16 bits) ‖ mac16 (16 bits)
//   mac16 = HMAC_SHA256(k, "netrun-pergb-mac" ‖ L(4, BE) ‖ r16(2, BE))[0:2]
//   round i = 0..7: (L, R) = (R, L XOR F(i, R)),
//   F(i, R) = HMAC_SHA256(k, "netrun-pergb-tag" ‖ byte(i) ‖ R(4, BE))[0:4] (BE)
//   iid = (L << 32) | R; r16 is redrawn while iid < 2^32.
// Decryption runs the rounds backwards; the tag is valid when the recomputed
// mac16 matches (a random interface id passes with probability 2^-16).
// Address = prefix48 | (subnet_id << 64) | iid.
//
// The reference is node_runtime/radius/tag.py; both are checked against
// node_runtime/radius/tests/feistel_vectors.json.
//
// Per-piece (amendment A13-I): a piece list's address is FIXED — its own /64
// (pieceNet) + the tag of its list id with r16 derived from the id:
//   r16 = HMAC_SHA256(k, "netrun-pergb-pick-r\0" ‖ "piece\0" ‖ L(4, BE) ‖ "\0\0" ‖ j(4, BE))[0:2]
// for the first j = 0, 1, ... whose iid is >= 2^32 (RADIUS alloc.piece_iid;
// vectors node_runtime/radius/tests/piece_vectors.json).

const crypto = require("crypto");
const net = require("net");

const MAC_LABEL = Buffer.from("netrun-pergb-mac");
const ROUND_LABEL = Buffer.from("netrun-pergb-tag");
const ROUNDS = 8;
const IID_MIN = 1n << 32n;
const MASK32 = 0xffffffff;

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

function mac16(key, listId, r16) {
  const b = Buffer.alloc(MAC_LABEL.length + 6);
  MAC_LABEL.copy(b, 0);
  b.writeUInt32BE(listId >>> 0, MAC_LABEL.length);
  b.writeUInt16BE(r16 & 0xffff, MAC_LABEL.length + 4);
  const d = hmac(key, b);
  return (d[0] << 8) | d[1];
}

function roundF(key, i, r) {
  const b = Buffer.alloc(ROUND_LABEL.length + 5);
  ROUND_LABEL.copy(b, 0);
  b[ROUND_LABEL.length] = i;
  b.writeUInt32BE(r >>> 0, ROUND_LABEL.length + 1);
  return hmac(key, b).readUInt32BE(0);
}

function checkKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError("address key must be 32 bytes");
}

// Raw Feistel output (BigInt) for (listId, r16); may be < 2^32 (callers redraw).
function encrypt(key, listId, r16) {
  checkKey(key);
  if (!Number.isInteger(listId) || listId < 0 || listId > MASK32) throw new RangeError("listId out of range");
  if (!Number.isInteger(r16) || r16 < 0 || r16 > 0xffff) throw new RangeError("r16 out of range");
  let left = listId >>> 0;
  let right = (((r16 << 16) >>> 0) | mac16(key, listId, r16)) >>> 0;
  for (let i = 0; i < ROUNDS; i += 1) {
    const next = (left ^ roundF(key, i, right)) >>> 0;
    left = right;
    right = next;
  }
  return (BigInt(left) << 32n) | BigInt(right);
}

// iid (BigInt, 0..2^64-1) -> { listId, r16, valid }.
function decrypt(key, iid) {
  checkKey(key);
  const v = BigInt(iid);
  if (v < 0n || v >= 1n << 64n) throw new RangeError("iid out of range");
  let left = Number(v >> 32n) >>> 0;
  let right = Number(v & 0xffffffffn) >>> 0;
  for (let i = ROUNDS - 1; i >= 0; i -= 1) {
    // forward step: left' = right, right' = left ^ F(i, right)
    const prevRight = left;
    const prevLeft = (right ^ roundF(key, i, prevRight)) >>> 0;
    left = prevLeft;
    right = prevRight;
  }
  const listId = left >>> 0;
  const r16 = right >>> 16;
  return { listId, r16, valid: (right & 0xffff) === mac16(key, listId, r16) };
}

const PIECE_SEED = Buffer.from("netrun-pergb-pick-r\0piece\0", "latin1");

// The fixed interface id (BigInt) of piece list listId (A13-I).
function pieceIid(key, listId) {
  checkKey(key);
  if (!Number.isInteger(listId) || listId < 0 || listId > MASK32) throw new RangeError("listId out of range");
  const b = Buffer.alloc(PIECE_SEED.length + 10);
  PIECE_SEED.copy(b, 0);
  b.writeUInt32BE(listId >>> 0, PIECE_SEED.length);
  // two zero bytes (the empty slot and extra), then j
  for (let j = 0; j < 64; j += 1) {
    b.writeUInt32BE(j, PIECE_SEED.length + 6);
    const d = hmac(key, b);
    const iid = encrypt(key, listId, (d[0] << 8) | d[1]);
    if (iid >= IID_MIN) return iid;
  }
  throw new Error("no piece interface id >= 2^32 in 64 draws");
}

// "2602:f2dc:a9:12:..." -> BigInt, or null (zone ids and IPv4 refused).
function ipv6ToBig(text) {
  let s = String(text == null ? "" : text).trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!s || s.includes("%") || net.isIPv6(s) !== true) return null;
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const o = tail.split(".").map(Number);
    s = `${s.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (part) => (part === "" ? [] : part.split(":").map((h) => parseInt(h, 16)));
  const left = parse(halves[0]);
  const right = halves.length === 2 ? parse(halves[1]) : [];
  const fill = 8 - left.length - right.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  const groups = halves.length === 2 ? [...left, ...new Array(fill).fill(0), ...right] : left;
  if (groups.length !== 8 || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

// BigInt -> RFC 5952 text.
function bigToIpv6(big) {
  const groups = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((BigInt(big) >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLen).join(":")}`;
}

// "2602:f2dc:a9::/48" -> { text, base (BigInt, the /48 as a 128-bit value) } or null.
function parsePrefix48(text) {
  const m = /^([^/\s]+)\/48$/.exec(String(text || "").trim());
  if (!m) return null;
  const big = ipv6ToBig(m[1]);
  if (big === null) return null;
  const base = (big >> 80n) << 80n;
  return { text: `${bigToIpv6(base)}/48`, base };
}

// A tagger bound to one key and one /48:
//   decodeAddress(text) -> null (not an IPv6 of the prefix) or
//     { subnetId, iid (BigInt), listId, r16, valid }
//   address(subnetId, listId, r16) -> text (tests, attribution checks)
function createTagger({ key, prefix }) {
  const k = Buffer.isBuffer(key) ? key : Buffer.from(String(key || ""), "base64");
  checkKey(k);
  const p = typeof prefix === "string" ? parsePrefix48(prefix) : prefix;
  if (!p) throw new TypeError("tagger needs the node's /48");
  const cache = new Map(); // iid hex -> decode result (sockets repeat across ticks)
  function decodeIid(iid) {
    const keyHex = iid.toString(16);
    const hit = cache.get(keyHex);
    if (hit) return hit;
    const out = decrypt(k, iid);
    if (cache.size >= 100000) cache.clear();
    cache.set(keyHex, out);
    return out;
  }
  return {
    prefix: p.text,
    prefixBase: p.base,
    decodeAddress(text) {
      const big = typeof text === "bigint" ? text : ipv6ToBig(text);
      if (big === null || big >> 80n !== p.base >> 80n) return null;
      const subnetId = Number((big >> 64n) & 0xffffn);
      const iid = big & ((1n << 64n) - 1n);
      const d = decodeIid(iid);
      return { subnetId, iid, listId: d.listId, r16: d.r16, valid: d.valid && iid >= IID_MIN };
    },
    address(subnetId, listId, r16) {
      const iid = encrypt(k, listId, r16);
      return bigToIpv6(p.base | (BigInt(subnetId) << 64n) | iid);
    },
    // A13-I: the fixed address of piece list listId in its /64 pieceNet
    pieceAddress(pieceNet, listId) {
      return bigToIpv6(p.base | (BigInt(pieceNet) << 64n) | pieceIid(k, listId));
    },
  };
}

module.exports = {
  ROUNDS,
  IID_MIN,
  mac16,
  encrypt,
  decrypt,
  pieceIid,
  ipv6ToBig,
  bigToIpv6,
  parsePrefix48,
  createTagger,
};
