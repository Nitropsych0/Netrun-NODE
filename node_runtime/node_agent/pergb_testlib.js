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

// ── the real netrun-radius (node_runtime/radius) for integration tests ─────

const fs = require("fs");
const path = require("path");
const dgram = require("dgram");
const { spawn, spawnSync } = require("child_process");

const RADIUS_DIR = path.resolve(__dirname, "../radius");
const SECRET = "T3stSecretT3stSecretT3stSecretT3stSecre1";

function havePython() {
  const r = spawnSync("python3", ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"]);
  return r.status === 0;
}

function freeUdpPort() {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket("udp4");
    s.on("error", reject);
    s.bind(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

// -> { ctlPath, udpPort, secretPath, stop() }
async function startRadius(dir) {
  fs.mkdirSync(path.join(dir, "radius"), { recursive: true });
  const secretPath = path.join(dir, "radius.secret");
  if (!fs.existsSync(secretPath)) fs.writeFileSync(secretPath, SECRET, { mode: 0o600 });
  const ctlPath = path.join(dir, "c.sock");
  const udpPort = await freeUdpPort();
  const proc = spawn(
    "python3",
    ["-I", path.join(RADIUS_DIR, "netrun_radius.py"), "--listen", `127.0.0.1:${udpPort}`, "--state-dir", path.join(dir, "radius"), "--secret-file", secretPath, "--ctl-socket", ctlPath, "--no-watchdog"],
    { stdio: ["ignore", "ignore", "pipe"] }
  );
  let stderr = "";
  proc.stderr.on("data", (d) => {
    stderr += d.toString();
    if (stderr.length > 20000) stderr = stderr.slice(-10000);
  });
  const deadline = Date.now() + 15000;
  while (!fs.existsSync(ctlPath)) {
    if (Date.now() > deadline || proc.exitCode !== null) throw new Error(`netrun-radius did not start: ${stderr}`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return {
    ctlPath,
    udpPort,
    secretPath,
    proc,
    stderr: () => stderr,
    stop: () =>
      new Promise((resolve) => {
        if (proc.exitCode !== null) return resolve();
        proc.once("exit", () => resolve());
        proc.kill("SIGTERM");
      }),
  };
}

// A pergb_runtime stand-in: apply() writes enable.json the way L2's does
// (version 1, the proc layout, params = the raw body), status() reports the
// units active; nothing touches systemd. Records its calls.
function fakeRuntime(rtSettings) {
  const rt = require("./pergb_runtime.js");
  const calls = [];
  const fake = {
    ...rt,
    calls,
    readSettings: () => rtSettings,
    readEnable: () => rt.readEnable(rtSettings),
    sharedRange: () => rt.sharedRange(rtSettings),
    detectPrimaryIpv4: async () => "203.0.113.10",
    async apply(raw) {
      calls.push(["apply", raw]);
      const n = rt.normalizeParams(raw);
      if (!n.ok) return n;
      const p = n.params;
      const layout = rt.procRanges(p.base, p.count, p.procs);
      const prev = rt.readEnable(rtSettings);
      const body = {
        version: 1,
        enabled: true,
        base: p.base,
        count: p.count,
        last: p.last,
        egressIpv4: p.egressIpv4,
        dedicatedIpv4: p.dedicatedIpv4,
        family: p.family,
        maxConns: p.maxConns,
        logdumpBytes: p.logdumpBytes,
        denyPorts: p.denyPorts,
        sliceMemMax: p.sliceMemMax,
        cpuWeight: p.cpuWeight,
        procs: layout.map((r) => ({ sp: r.sp, first: r.first, last: r.last, unit: r.unit, cfg: `/x/pergb_${r.sp}.cfg` })),
        params: raw,
      };
      const text = `${JSON.stringify(body, null, 2)}\n`;
      const changed = [];
      const cur = fs.existsSync(rtSettings.enablePath) ? fs.readFileSync(rtSettings.enablePath, "utf-8") : null;
      if (cur !== text) {
        fs.mkdirSync(path.dirname(rtSettings.enablePath), { recursive: true });
        fs.writeFileSync(rtSettings.enablePath, text);
        changed.push(rtSettings.enablePath);
      }
      return { ok: true, changed, restarted: prev && prev.family !== p.family ? layout.map((r) => r.unit) : [], started: [], stopped: [], reloaded: [], procs: layout, secretCreated: false };
    },
    async disable(opts) {
      calls.push(["disable", opts]);
      const e = rt.readEnable(rtSettings);
      if (e) fs.writeFileSync(rtSettings.enablePath, `${JSON.stringify({ ...e, enabled: false }, null, 2)}\n`);
      return { ok: true, stopped: e ? [...e.procs.map((x) => x.unit), rt.HAPROXY_UNIT, rt.TARGET] : [] };
    },
    async status() {
      const e = rt.readEnable(rtSettings);
      const procs = e ? e.procs.map((x, i) => ({ unit: x.unit, first: x.first, last: x.last, active: e.enabled, pid: e.enabled ? 1000 + i : null })) : [];
      return { enabled: Boolean(e && e.enabled), procs, haproxy: { active: Boolean(e && e.enabled), pid: 999 }, target: { active: Boolean(e && e.enabled), enabled: Boolean(e && e.enabled) } };
    },
  };
  return fake;
}

module.exports = {
  KEY_B64,
  PREFIX,
  UNIT_A,
  UNIT_B,
  CG,
  SECRET,
  tagger,
  untaggedAddress,
  ssLine,
  fakeRun,
  fakeCtl,
  havePython,
  startRadius,
  fakeRuntime,
};
