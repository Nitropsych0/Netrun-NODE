"use strict";

// Pay-per-GB v2 — a direct RADIUS Access-Request for the service probe login
// `netrun-svcprobe` (plan §3.4: the agent probes netrun-radius every 5 s).
// The packet is laid out like 3proxy 0.9.3's radsend(auth=1) (node_runtime/
// radius/proto.py build_3proxy_request): Service-Type, Acct-Session-Id,
// NAS-Port-Type, NAS-Port, NAS-IP-Address, NAS-Identifier, Framed-IP-Address
// (the client), Login-Service and Login-TCP-Port with 3proxy's length-4
// attributes, Login-IP(v6)-Host (a canary destination), User-Name,
// User-Password (PAP). The reply must carry a valid Response Authenticator;
// an Access-Accept with one Framed address = RADIUS is alive and answers.

const crypto = require("crypto");
const dgram = require("dgram");
const net = require("net");

const ACCESS_REQUEST = 1;
const ACCESS_ACCEPT = 2;
const ACCESS_REJECT = 3;

function md5(buf) {
  return crypto.createHash("md5").update(buf).digest();
}

function attr(type, value) {
  if (value.length > 253) throw new RangeError("attribute too long");
  return Buffer.concat([Buffer.from([type, value.length + 2]), value]);
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
}

// RFC 2865 §5.2 PAP.
function encodePassword(password, secret, authenticator) {
  let p = Buffer.from(password).subarray(0, 128);
  if (p.length === 0) return Buffer.alloc(0);
  const pad = (16 - (p.length % 16)) % 16;
  p = Buffer.concat([p, Buffer.alloc(pad)]);
  const out = [];
  let last = authenticator;
  for (let i = 0; i < p.length; i += 16) {
    const b = md5(Buffer.concat([secret, last]));
    const c = Buffer.alloc(16);
    for (let j = 0; j < 16; j += 1) c[j] = p[i + j] ^ b[j];
    out.push(c);
    last = c;
  }
  return Buffer.concat(out);
}

function ipBytes(ip) {
  if (net.isIPv4(ip)) return Buffer.from(ip.split(".").map(Number));
  if (net.isIPv6(ip)) {
    const tag = require("./pergb_tag.js");
    const big = tag.ipv6ToBig(ip);
    const b = Buffer.alloc(16);
    for (let i = 0; i < 16; i += 1) b[i] = Number((big >> BigInt((15 - i) * 8)) & 0xffn);
    return b;
  }
  throw new TypeError(`not an IP: ${ip}`);
}

// An Access-Request shaped like 3proxy's.
function buildRequest({ ident, authenticator, secret, username, password, nasPort, dst, dstPort, hostname = null }) {
  const sec = Buffer.from(secret);
  const parts = [];
  parts.push(Buffer.concat([Buffer.from([6, 6]), u32(8)])); // Service-Type = Authenticate-Only
  parts.push(attr(44, Buffer.from(`${Math.floor(Date.now() / 1000)}.probe`)));
  parts.push(Buffer.concat([Buffer.from([61, 6]), u32(5)])); // NAS-Port-Type = Virtual
  parts.push(Buffer.concat([Buffer.from([5, 6]), u32(nasPort)]));
  parts.push(Buffer.concat([Buffer.from([4, 6]), Buffer.from([127, 0, 0, 4])]));
  parts.push(attr(32, Buffer.from("SOCKS")));
  parts.push(Buffer.concat([Buffer.from([8, 6]), Buffer.from([127, 0, 0, 1])]));
  if (hostname) parts.push(attr(30, Buffer.from(hostname)));
  parts.push(Buffer.concat([Buffer.from([15, 4]), u16(1001)]));
  parts.push(Buffer.concat([Buffer.from([16, 4]), u16(dstPort)]));
  const d = ipBytes(dst);
  parts.push(d.length === 16 ? Buffer.concat([Buffer.from([98, 18]), d]) : Buffer.concat([Buffer.from([14, 6]), d]));
  parts.push(attr(1, Buffer.from(username)));
  parts.push(attr(2, encodePassword(password, sec, authenticator)));
  const body = Buffer.concat(parts);
  const hdr = Buffer.alloc(4);
  hdr[0] = ACCESS_REQUEST;
  hdr[1] = ident & 0xff;
  hdr.writeUInt16BE(20 + body.length, 2);
  return Buffer.concat([hdr, authenticator, body]);
}

function verifyReply(reply, reqAuth, secret) {
  if (!Buffer.isBuffer(reply) || reply.length < 20) return false;
  const length = reply.readUInt16BE(2);
  if (length !== reply.length) return false;
  const want = md5(Buffer.concat([reply.subarray(0, 4), reqAuth, reply.subarray(20, length), Buffer.from(secret)]));
  return crypto.timingSafeEqual(want, reply.subarray(4, 20));
}

function replyAttrs(reply) {
  const out = [];
  const length = reply.readUInt16BE(2);
  let pos = 20;
  while (pos + 2 <= length) {
    const t = reply[pos];
    const l = reply[pos + 1];
    if (l < 2) break;
    out.push({ type: t, value: reply.subarray(pos + 2, pos + l) });
    pos += l;
  }
  return out;
}

// The Framed address of an Accept as text (IPv4 for type 8, IPv6 for 168), or null.
function framedText(attr) {
  const v = attr && attr.value;
  if (attr.type === 8 && v.length === 4) return [...v].join(".");
  if (attr.type === 168 && v.length === 16) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(v.readUInt16BE(i));
    return require("./pergb_tag.js").bigToIpv6(groups.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n));
  }
  return null;
}

// One probe. -> { ok, verdict: "accept"|"reject"|"timeout"|"bad_reply"|"error", ms, framed, framedAddr }
function probeOnce({ server = "127.0.0.1", port = 1812, secret, username = "netrun-svcprobe", password, nasPort, dst, dstPort, timeoutMs = 2000, socketFactory = () => dgram.createSocket("udp4") }) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const ms = () => Number(process.hrtime.bigint() - t0) / 1e6;
    const authenticator = crypto.randomBytes(16);
    const ident = crypto.randomBytes(1)[0];
    let pkt;
    try {
      pkt = buildRequest({ ident, authenticator, secret, username, password, nasPort, dst, dstPort });
    } catch (e) {
      resolve({ ok: false, verdict: "error", error: e.message, ms: 0 });
      return;
    }
    const sock = socketFactory();
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        sock.close();
      } catch {}
      resolve({ ...r, ms: Math.round(ms() * 1000) / 1000 });
    };
    const timer = setTimeout(() => finish({ ok: false, verdict: "timeout" }), timeoutMs);
    sock.on("error", (e) => finish({ ok: false, verdict: "error", error: e.code || e.message }));
    sock.on("message", (msg) => {
      if (msg.length < 20 || msg[1] !== ident) return;
      if (!verifyReply(msg, authenticator, secret)) {
        finish({ ok: false, verdict: "bad_reply" });
        return;
      }
      if (msg[0] === ACCESS_ACCEPT) {
        const framed = replyAttrs(msg).filter((a) => a.type === 8 || a.type === 168);
        finish({ ok: framed.length === 1, verdict: "accept", framed: framed.length, framedAddr: framed.length === 1 ? framedText(framed[0]) : null });
      } else if (msg[0] === ACCESS_REJECT) finish({ ok: false, verdict: "reject" });
      else finish({ ok: false, verdict: "bad_reply" });
    });
    sock.send(pkt, port, server, (err) => {
      if (err) finish({ ok: false, verdict: "error", error: err.code || err.message });
    });
  });
}

module.exports = {
  ACCESS_REQUEST,
  ACCESS_ACCEPT,
  ACCESS_REJECT,
  encodePassword,
  buildRequest,
  verifyReply,
  replyAttrs,
  probeOnce,
};
