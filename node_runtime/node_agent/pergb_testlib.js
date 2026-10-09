"use strict";

// Pay-per-GB v2 — shared fakes for the per-GB agent tests: a node "world"
// of live sockets behind a fake `ss` (listing per cgroup, -K kills by exact
// 4-tuple), a fake systemctl / ip, and a fake RADIUS ctl.

const tagLib = require("./pergb_tag.js");

const KEY_B64 = Buffer.alloc(32, 7).toString("base64");
const PREFIX = "2001:db8:aa::/48";
const UNIT_A = "netrun-pergb-3proxy@31000.service";
const UNIT_B = "netrun-pergb-3proxy@31500.service";
const CG = (u) => `/netrun.slice/netrun-pergb.slice/${u}`;

function tagger() {
  return tagLib.createTagger({ key: Buffer.from(KEY_B64, "base64"), prefix: PREFIX });
}

// A random interface id that is NOT a valid tag of any list (MAC check fails).
function untaggedAddress(subnet, seed) {
  const t = tagger();
  let x = BigInt(seed) * 0x9e3779b97f4a7c15n;
  for (;;) {
    x = (x * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    const iid = x | (1n << 40n);
    const addr = tagLib.bigToIpv6(t.prefixBase | (BigInt(subnet) << 64n) | iid);
    const d = t.decodeAddress(addr);
    if (!d.valid) return addr;
  }
}

function bracket(ip) {
  return ip.includes(":") ? `[${ip}]` : ip;
}

function ssLine(s) {
  return `0      0      ${bracket(s.local)}:${s.lport}     ${bracket(s.peer)}:${s.pport}\n\t cubic wscale:7,7 rto:204 bytes_sent:${s.sent || 0} bytes_acked:${s.sent || 0} bytes_received:${s.received || 0} segs_out:3\n`;
}

// world: { sockets: [{ local, lport, peer, pport, sent, received, cgroup }], cgroupSupport }
function fakeRun(world, extra = {}) {
  const calls = [];
  const run = async (cmd, args) => {
    calls.push([cmd, ...args]);
    if (extra[cmd]) {
      const r = await extra[cmd](args, world);
      if (r) return r;
    }
    if (cmd === "ss") {
      const kill = args.includes("-K");
      const cgi = args.indexOf("cgroup");
      if (cgi >= 0 && world.cgroupSupport === false) return { code: 255, stdout: "", stderr: 'Error: an inet prefix is expected rather than "cgroup".' };
      const cg = cgi >= 0 ? args[cgi + 1] : null;
      let pool = world.sockets.filter((s) => (cg === null || cg === "/" ? true : s.cgroup === cg));
      if (cg === "/") pool = [];
      if (kill) {
        // exact tuples from "( src A:p and dst B:q ) or ..."
        const tuples = [];
        for (let i = 0; i < args.length; i += 1) {
          if (args[i] === "src" && args[i + 2] === "and" && args[i + 3] === "dst") tuples.push(`${args[i + 1]}|${args[i + 4]}`);
        }
        const hit = pool.filter((s) => tuples.includes(`${bracket(s.local)}:${s.lport}|${bracket(s.peer)}:${s.pport}`));
        world.sockets = world.sockets.filter((s) => !hit.includes(s));
        world.killed = (world.killed || []).concat(hit);
        return { code: 0, stdout: hit.map(ssLine).join(""), stderr: "" };
      }
      if (cgi < 0 && args.includes("src")) {
        // fallback listing: the pool prefix and the loopback listeners
        pool = world.sockets.filter((s) => s.local.startsWith("2001:db8:aa:") || s.local === "127.0.0.3" || s.local === "127.0.0.4");
      }
      return { code: 0, stdout: pool.map(ssLine).join(""), stderr: "" };
    }
    if (cmd === "systemctl" || cmd === "timedatectl") return { code: 0, stdout: cmd === "timedatectl" ? "yes\n" : "", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  run.calls = calls;
  return run;
}

// A fake RADIUS ctl: { call(op, body) } recording calls; handlers per op.
function fakeCtl(handlers = {}) {
  const calls = [];
  const ctl = {
    calls,
    async call(op, body = {}) {
      calls.push({ op, body });
      const h = handlers[op];
      if (typeof h === "function") return h(body);
      if (h !== undefined) return h;
      return { ok: true };
    },
  };
  return ctl;
}

module.exports = { KEY_B64, PREFIX, UNIT_A, UNIT_B, CG, tagger, untaggedAddress, ssLine, fakeRun, fakeCtl };
