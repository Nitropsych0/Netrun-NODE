"use strict";

// Pay-per-GB v2, AMENDMENT A1 — pergb_pool.js: the pool file, the /64 wire
// forms, the RADIUS ctl client (a real unix socket), reserve / release
// validation (fail closed), the per-piece /64 scan and releaseUnusedNets.
// Run with: node --test node_runtime/node_agent/pergb_pool.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");

const pp = require(path.resolve(__dirname, "pergb_pool.js"));

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-pergb-pool-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));
const quiet = { log() {}, error() {} };
const R48 = "2602:f2dc:a9::/48";
const BASE = pp.net64Of("2602:f2dc:a9::");
const sub = (k) => Number(k - BASE);

test("parsePoolConf: PREFIX / POOL / ENABLED; the node's own /64 never in the pool; garbage is an error (fail closed)", () => {
  let r = pp.parsePoolConf(`# written by /pergb/enable\nPREFIX=${R48}\nPOOL=0000-fffe\nENABLED=1\n`);
  assert.strictEqual(r.state, "on");
  assert.strictEqual(r.pool.prefix, R48);
  assert.deepStrictEqual([sub(r.pool.lo), sub(r.pool.hi)], [0, 0xfffe]);
  r = pp.parsePoolConf(`PREFIX="2602:F2DC:A9:0::5/48"\n`);
  assert.deepStrictEqual([r.pool.prefix, sub(r.pool.lo), sub(r.pool.hi)], [R48, 0, 0xfffe], "default POOL = all but ffff");
  r = pp.parsePoolConf(`PREFIX=${R48}\nPOOL=8000-ffff\n`);
  assert.deepStrictEqual([sub(r.pool.lo), sub(r.pool.hi)], [0x8000, 0xfffe], "ffff clipped");
  for (const v of ["0", "false", "no", "OFF"]) assert.strictEqual(pp.parsePoolConf(`PREFIX=${R48}\nENABLED=${v}\n`).state, "off");
  for (const bad of ["", "PREFIX=bogus", `PREFIX=2602:f2dc:a9::/64`, `PREFIX=2602::/8`, `PREFIX=${R48}\nPOOL=9-1`, `PREFIX=${R48}\nPOOL=0-10000`, `PREFIX=${R48}\nPOOL=x`, `PREFIX=${R48}\nPOOL=ffff-ffff`]) {
    assert.strictEqual(pp.parsePoolConf(bad).state, "error", bad);
  }
});

test("createPoolReader: absent = off; cached by inode/size/mtime; a change is picked up; an unreadable file is an error", () => {
  const file = path.join(TMP, "reader.conf");
  const read = pp.createPoolReader({ env: { NETRUN_PERGB_POOL_FILE: file } });
  assert.strictEqual(read().state, "off");
  fs.writeFileSync(file, `PREFIX=${R48}\n`);
  assert.strictEqual(read().state, "on");
  assert.strictEqual(read(), read(), "cached");
  fs.writeFileSync(file, `PREFIX=${R48}\nENABLED=0\n`);
  assert.strictEqual(read().state, "off");
  if (process.getuid && process.getuid() !== 0) {
    fs.writeFileSync(file, `PREFIX=${R48}\nPOOL=1-2\n`);
    fs.chmodSync(file, 0o000);
    assert.strictEqual(read().state, "error");
    fs.chmodSync(file, 0o600);
  }
  fs.rmSync(file);
  assert.strictEqual(read().state, "off");
});

test("netFromWire / netToWire / poolOverlaps / inPool", () => {
  const { pool } = pp.parsePoolConf(`PREFIX=${R48}\nPOOL=8000-fffe\n`);
  assert.strictEqual(sub(pp.netFromWire(pool, 0x8a3f)), 0x8a3f, "a JSON number = a subnet id");
  assert.strictEqual(sub(pp.netFromWire(pool, "8a3f")), 0x8a3f, "a string id is hex");
  assert.strictEqual(sub(pp.netFromWire(pool, "1234")), 0x1234, "all-digit strings are hex too");
  assert.strictEqual(sub(pp.netFromWire(pool, "0x8A3F")), 0x8a3f);
  assert.strictEqual(sub(pp.netFromWire(pool, "2602:f2dc:a9:8a3f::/64")), 0x8a3f);
  assert.strictEqual(sub(pp.netFromWire(pool, "2602:f2dc:a9:8a3f::77")), 0x8a3f);
  for (const bad of [-1, 0x10000, "2602:f2dc:b0::/64", "nope", null, 1.5, true]) assert.strictEqual(pp.netFromWire(pool, bad), null, String(bad));
  assert.strictEqual(pp.netToWire(pool, BASE + 0x8a3fn), 0x8a3f);
  assert.ok(pp.inPool(pool, BASE + 0x8000n) && !pp.inPool(pool, BASE + 0x7fffn) && !pp.inPool(pool, BASE + 0xffffn));
  assert.ok(pp.poolOverlaps(pool, R48));
  assert.ok(pp.poolOverlaps(pool, "2602:f2dc:a9:8000::/49"));
  assert.ok(!pp.poolOverlaps(pool, "2602:f2dc:a9::/49"), "the per-piece half only");
  assert.ok(!pp.poolOverlaps(pool, "2602:f2dc:b0::/48"));
});

// A fake netrun-radius ctl socket: one JSON line in, one out (I5).
function ctlServer(handler) {
  const sock = path.join(TMP, `ctl-${process.pid}-${Math.random().toString(16).slice(2)}.sock`);
  const seen = [];
  const server = net.createServer((c) => {
    let buf = "";
    c.setEncoding("utf-8");
    c.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const req = JSON.parse(buf.slice(0, nl));
      seen.push(req);
      const reply = handler(req);
      if (reply === undefined) return; // hang
      c.end(`${JSON.stringify(reply)}\n`);
    });
  });
  return new Promise((resolve) => server.listen(sock, () => resolve({ sock, seen, close: () => new Promise((r) => server.close(r)) })));
}

test("ctlRequest + createPoolAccess: reserve_nets / release_nets over the ctl socket (I5), replies validated", async () => {
  const file = path.join(TMP, "access.conf");
  fs.writeFileSync(file, `PREFIX=${R48}\nPOOL=0000-fffe\n`);
  const srv = await ctlServer((req) => {
    if (req.op === "reserve_nets") return { nets: Array.from({ length: req.count }, (_, i) => 0x100 + i), ref: req.ref };
    if (req.op === "release_nets") return { released: req.nets.length, coolDownUntil: "2026-10-10T12:00:00Z" };
    return { error: "bad_op" };
  });
  try {
    const access = pp.createPoolAccess({ env: { NETRUN_PERGB_POOL_FILE: file, NETRUN_RADIUS_CTL_SOCKET: srv.sock }, log: quiet });
    const got = await access.reserve({ count: 3, ref: "gen:18100:job-1" });
    assert.deepStrictEqual(got.nets.map(sub), [0x100, 0x101, 0x102]);
    assert.deepStrictEqual(srv.seen[0], { op: "reserve_nets", count: 3, owner: "perpiece", ref: "gen:18100:job-1" });
    await access.reserve({ count: 1, ref: "egress:aa", force: true });
    assert.strictEqual(srv.seen[1].force, true);
    const rel = await access.release({ nets: [BASE + 0x100n, BASE + 0x101n, BASE + 0x100n], ref: "deprovision:1" });
    assert.deepStrictEqual(srv.seen[2], { op: "release_nets", nets: [0x100, 0x101], ref: "deprovision:1" }, "subnet ids, deduplicated");
    assert.strictEqual(rel.released, 2);
    await assert.rejects(access.reserve({ count: 0, ref: "x" }), { code: "bad_request" });
    await assert.rejects(access.reserve({ count: 5001, ref: "x" }), { code: "bad_request" });
    await assert.rejects(access.reserve({ count: 1, ref: "bad ref" }), { code: "bad_request" });
  } finally {
    await srv.close();
  }
});

test("createPoolAccess: every bad reply or transport failure rejects (the caller fails closed)", async () => {
  const file = path.join(TMP, "access-bad.conf");
  fs.writeFileSync(file, `PREFIX=${R48}\n`);
  const env = { NETRUN_PERGB_POOL_FILE: file };
  const with_ = (reply) => pp.createPoolAccess({ env, log: quiet, request: async () => reply });
  await assert.rejects(with_({}).reserve({ count: 1, ref: "r" }), { code: "bad_reply" });
  await assert.rejects(with_({ nets: [1, 2] }).reserve({ count: 1, ref: "r" }), { code: "bad_reply" }, "count mismatch");
  await assert.rejects(with_({ nets: [1, 1] }).reserve({ count: 2, ref: "r" }), { code: "bad_reply" }, "duplicate");
  await assert.rejects(with_({ nets: [0xffff] }).reserve({ count: 1, ref: "r" }), { code: "bad_reply" }, "the node's own /64");
  await assert.rejects(with_({ nets: ["2602:f2dc:b0::/64"] }).reserve({ count: 1, ref: "r" }), { code: "bad_reply" }, "outside PREFIX");
  const failing = pp.createPoolAccess({ env, log: quiet, request: async () => { throw Object.assign(new Error("x"), { code: "capacity" }); } });
  await assert.rejects(failing.reserve({ count: 1, ref: "r" }), { code: "capacity" });
  // the real socket: missing, an {error} reply, a hang (timeout)
  const missing = pp.createPoolAccess({ env: { ...env, NETRUN_RADIUS_CTL_SOCKET: path.join(TMP, "none.sock") }, log: quiet });
  await assert.rejects(missing.reserve({ count: 1, ref: "r" }), { code: "radius_unavailable" });
  const srv = await ctlServer((req) => (req.op === "reserve_nets" ? { error: "capacity" } : undefined));
  try {
    const access = pp.createPoolAccess({ env: { ...env, NETRUN_RADIUS_CTL_SOCKET: srv.sock }, log: quiet });
    await assert.rejects(access.reserve({ count: 1, ref: "r" }), { code: "capacity" });
    await assert.rejects(pp.ctlRequest({ op: "release_nets", nets: [], ref: "r" }, { socketPath: srv.sock, timeoutMs: 100 }), { code: "radius_unavailable" });
  } finally {
    await srv.close();
  }
  // per-GB off: nothing is asked at all
  const off = pp.createPoolAccess({ env: { NETRUN_PERGB_POOL_FILE: path.join(TMP, "absent.conf") }, log: quiet, request: async () => assert.fail("called") });
  await assert.rejects(off.reserve({ count: 1, ref: "r" }), { code: "pergb_off" });
});

test("setTransport: the agent's own ctl client can take over the default access", async () => {
  const file = path.join(TMP, "transport.conf");
  fs.writeFileSync(file, `PREFIX=${R48}\n`);
  const calls = [];
  pp.setTransport(async (op, body) => {
    calls.push([op, body]);
    return { nets: ["2602:f2dc:a9:42::/64"] };
  });
  try {
    const access = pp.createPoolAccess({ env: { NETRUN_PERGB_POOL_FILE: file }, log: quiet });
    const got = await access.reserve({ count: 1, ref: "r" });
    assert.deepStrictEqual(got.nets.map(sub), [0x42]);
    assert.deepStrictEqual(calls, [["reserve_nets", { count: 1, owner: "perpiece", ref: "r" }]]);
  } finally {
    pp.setTransport(null);
  }
});

function proxyRoot(name) {
  const root = path.join(TMP, name);
  fs.mkdirSync(path.join(root, "3proxy"), { recursive: true });
  const cfg = (port, addr) => `flush\nusers u${port}:CL:p\nallow u${port} *\ndeny *\nsocks -6 -a -p${port} -i1.2.3.4 -e${addr}\nproxy -6 -n -a -p${port - 10000} -i1.2.3.4 -e${addr}\n`;
  fs.writeFileSync(path.join(root, "3proxy", "3proxy_30000.cfg"), `daemon\n${cfg(30000, "2602:f2dc:a9:10::1")}${cfg(30001, "2602:f2dc:a9:11::1")}`);
  fs.writeFileSync(path.join(root, "3proxy", "3proxy_31000.cfg.disabled"), cfg(31000, "2602:f2dc:a9:12::1"));
  fs.writeFileSync(path.join(root, "3proxy", "3proxy_32000.cfg.failed"), cfg(32000, "2602:f2dc:a9:13::1"));
  fs.writeFileSync(path.join(root, "ipv6_33000.list"), "2602:f2dc:a9:14::1\n2602:f2dc:a9:15::1\n");
  fs.writeFileSync(path.join(root, "ipv6_34000.list.tmp"), "2602:f2dc:a9:16::1\n");
  fs.writeFileSync(path.join(root, "egress_state.json"), JSON.stringify({
    version: 1,
    ports: { 30000: { anchor: "2602:f2dc:a9:10::1", current: "2602:f2dc:a9:17::5", mode: "static" } },
    pool: ["2602:f2dc:a9:18::5"],
    draining: [{ addr: "2602:f2dc:a9:19::5", until: "2026-10-09T00:00:00Z" }],
    pergb_held: [{ net: "2602:f2dc:a9:1a::/64", ref: "egress:x" }],
  }));
  return root;
}

test("scanPerPieceNets: every cfg variant, lists and .tmp lists, the egress state (incl. holds); complete flag", () => {
  const root = proxyRoot("scan");
  const scan = pp.scanPerPieceNets({ proxyRoot: root });
  assert.strictEqual(scan.complete, true, scan.errors.join());
  assert.deepStrictEqual([...scan.nets].map(sub).sort((a, b) => a - b), [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a]);
  const skipped = pp.scanPerPieceNets({ proxyRoot: root, skip: [path.join(root, "ipv6_33000.list")] });
  assert.ok(!skipped.nets.has(BASE + 0x14n));
  if (process.getuid && process.getuid() !== 0) {
    fs.chmodSync(path.join(root, "3proxy", "3proxy_30000.cfg"), 0o000);
    assert.strictEqual(pp.scanPerPieceNets({ proxyRoot: root }).complete, false);
    fs.chmodSync(path.join(root, "3proxy", "3proxy_30000.cfg"), 0o600);
  }
  assert.strictEqual(pp.scanPerPieceNets({ proxyRoot: path.join(TMP, "no-such-root") }).complete, true, "nothing there = nothing used");
});

test("releaseUnusedNets: hands back only pool /64s nothing per-piece names; never on an incomplete scan; a no-op without per-GB", async () => {
  const root = proxyRoot("release");
  const file = path.join(TMP, "release.conf");
  fs.writeFileSync(file, `PREFIX=${R48}\nPOOL=0000-fffe\n`);
  const calls = [];
  const access = pp.createPoolAccess({ env: { NETRUN_PERGB_POOL_FILE: file }, log: quiet, request: async (op, body) => { calls.push([op, body]); return { released: body.nets.length }; } });
  const cand = new Set([BASE + 0x14n, BASE + 0x50n, BASE + 0x51n, BASE + 0xffffn, pp.net64Of("2001:db8::")]);
  const out = await pp.releaseUnusedNets(cand, { access, proxyRoot: root, ref: "deprovision:33000:aa", log: quiet });
  assert.deepStrictEqual(calls, [["release_nets", { nets: [0x50, 0x51], ref: "deprovision:33000:aa" }]],
    "0x14 is still in a list, ffff and foreign /64s are no pool /64s");
  assert.deepStrictEqual(out, { requested: 3, released: 2, kept: 1 });
  // in use by the caller's own bookkeeping
  calls.length = 0;
  await pp.releaseUnusedNets(new Set([BASE + 0x50n]), { access, proxyRoot: root, inUse: new Set([BASE + 0x50n]), log: quiet });
  assert.deepStrictEqual(calls, []);
  // an incomplete scan hands nothing back
  if (process.getuid && process.getuid() !== 0) {
    fs.chmodSync(path.join(root, "ipv6_33000.list"), 0o000);
    const r = await pp.releaseUnusedNets(new Set([BASE + 0x50n]), { access, proxyRoot: root, log: quiet });
    assert.strictEqual(r.error, "scan_incomplete");
    assert.deepStrictEqual(calls, []);
    fs.chmodSync(path.join(root, "ipv6_33000.list"), 0o600);
  }
  // RADIUS failing: reported, never thrown
  const failing = pp.createPoolAccess({ env: { NETRUN_PERGB_POOL_FILE: file }, log: quiet, request: async () => { throw Object.assign(new Error("down"), { code: "radius_unavailable" }); } });
  const r2 = await pp.releaseUnusedNets(new Set([BASE + 0x50n]), { access: failing, proxyRoot: root, log: quiet });
  assert.strictEqual(r2.error, "radius_unavailable");
  // per-GB off: skipped
  fs.rmSync(file);
  const r3 = await pp.releaseUnusedNets(new Set([BASE + 0x50n]), { access, proxyRoot: root, log: quiet });
  assert.strictEqual(r3.skipped, "pergb_off");
});

test("collectFileNets: cfg anchors and list lines of the given files; missing files add nothing", () => {
  const root = proxyRoot("collect");
  const got = pp.collectFileNets([path.join(root, "3proxy", "3proxy_30000.cfg"), path.join(root, "ipv6_33000.list"), path.join(root, "absent")]);
  assert.deepStrictEqual([...got].map(sub).sort((a, b) => a - b), [0x10, 0x11, 0x14, 0x15]);
});

test("newRef: <kind>:<what>:<random>, valid for reserve / release", () => {
  const r = pp.newRef("gen", "18100/../x");
  assert.match(r, /^gen:18100\.\.x:[0-9a-f]{12}$/, "only [A-Za-z0-9._-] kept");
  assert.notStrictEqual(pp.newRef("egress"), pp.newRef("egress"));
  assert.match(pp.newRef("egress"), /^egress:[0-9a-f]{12}$/);
});
