"use strict";

// Pay-per-GB v2 — the per-GB agent end to end (pergb_state.js +
// pergb_tls_server.js) against the REAL netrun-radius (node_runtime/radius,
// python3, --listen + its own ctl socket) and a fake node (ss / systemctl /
// ip; pergb_runtime stand-in that writes enable.json like L2's):
// enable (checks, facts, excluded, the pool file, idempotence, refusals),
// TLS-only routing and certificate reload, snapshot paging and its 409s,
// deltas and seq_mismatch, kills from `transitions` on snapshot AND delta,
// usage (meter + RADIUS bindings + rejects), attribution, port_check,
// reserve / release (A1), the RADIUS probe packet, disable.
// Run with: node --test node_runtime/node_agent/pergb_state.test.js

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const stateLib = require("./pergb_state.js");
const tlsLib = require("./pergb_tls_server.js");
const radprobe = require("./pergb_radprobe.js");
const rtLib = require("./pergb_runtime.js");
const T = require("./pergb_testlib.js");

const QUIET = { log() {}, error() {} };
const API_KEY = "state-test-key";
const PREFIX = T.PREFIX;
const EGRESS = "203.0.113.10";

const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
const skip = !T.havePython() ? "python3 >= 3.9 is needed (the real netrun-radius)" : !haveOpenssl ? "openssl is needed (test certificates)" : false;

function certPair(dir, name) {
  const crt = path.join(dir, `${name}.crt`);
  const key = path.join(dir, `${name}.key`);
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", `/CN=${name}`, "-addext", "subjectAltName=IP:127.0.0.1"], { encoding: "utf-8" });
  if (r.status !== 0) throw new Error(r.stderr);
  return { crt, key, pem: fs.readFileSync(crt, "utf-8") };
}

function pw(salt, password) {
  return crypto.createHash("sha256").update(Buffer.concat([Buffer.from(salt, "hex"), Buffer.from(password)])).digest("hex");
}

const SALT = "00112233445566778899aabbccddeeff";
const LIST = (id, login, accountId, extra = {}) => ({ id, login, accountId, pwSalt: SALT, pwHash: pw(SALT, `pass-${id}`), pwRev: 1, status: "active", mode: "rotate", ttlSec: null, ...extra });
const ACCOUNT = (id, extra = {}) => ({ id, state: "active", expiresAt: Math.floor(Date.now() / 1000) + 86400, limit: { epoch: 1, bytes: 1e15, allowance: 1e15, full: true }, trial: false, ...extra });

function hourName(sp, t = Date.now()) {
  const d = new Date(t);
  const z = (n) => String(n).padStart(2, "0");
  return `p${sp}.log.${d.getUTCFullYear()}.${z(d.getUTCMonth() + 1)}.${z(d.getUTCDate())}-${z(d.getUTCHours())}`;
}

function logTime(t = Date.now()) {
  const d = new Date(t);
  const z = (n, w = 2) => String(n).padStart(w, "0");
  return `${d.getUTCFullYear()}${z(d.getUTCMonth() + 1)}${z(d.getUTCDate())}${z(d.getUTCHours())}${z(d.getUTCMinutes())}${z(d.getUTCSeconds())}.${z(d.getUTCMilliseconds(), 3)}`;
}

function rec({ user, bound, cport = 40000, i = 1000, o = 100, dst = "2606:4700::1", lip = "127.0.0.4", port = 31000, code = 0 }) {
  return [logTime(), "SOCKS", port, code, user, "127.0.0.1", cport, lip, bound, dst, 443, i, o, "example.com"].join(" ");
}

function request(port, method, p, { body, key = API_KEY, ca, raw } = {}) {
  return new Promise((resolve, reject) => {
    const data = raw !== undefined ? raw : body === undefined ? null : JSON.stringify(body);
    const req = https.request(
      { host: "127.0.0.1", port, method, path: p, ca, agent: false, headers: { ...(key === null ? {} : { "X-API-KEY": key }), ...(data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}) } },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {}
          resolve({ status: res.statusCode, json, cert: res.socket && res.socket.getPeerCertificate ? res.socket.getPeerCertificate() : null });
        });
      }
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

test("per-GB agent end to end against the real netrun-radius", { skip, timeout: 120000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgs-"));
  const radius = await T.startRadius(dir);
  t.after(async () => {
    await radius.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const etc = path.join(dir, "etc");
  const logDir = path.join(dir, "log");
  const proxyRoot = path.join(dir, "proxy");
  fs.mkdirSync(etc, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });
  fs.mkdirSync(path.join(proxyRoot, "3proxy"), { recursive: true });
  fs.copyFileSync(radius.secretPath, path.join(etc, "radius.secret"));
  const crtList = path.join(dir, "crt-list");
  fs.writeFileSync(crtList, `${path.join(dir, "node.pem")} 127.0.0.1\n`);
  // per-piece on this node: two /64s of the /48 (and one outside it)
  fs.writeFileSync(path.join(proxyRoot, "3proxy", "3proxy_20000.cfg"), "socks -6 -a -p20000 -i203.0.113.10 -e2001:db8:aa:1::5\nsocks -6 -a -p20001 -i203.0.113.10 -e2001:db8:bb::1\n");
  fs.writeFileSync(path.join(proxyRoot, "ipv6_20000.list"), "2001:db8:aa:2::9\n");
  const rtSettings = { ...rtLib.readSettings({ NETRUN_PERGB_ETC_DIR: etc, NETRUN_PERGB_LOG_DIR: logDir, NETRUN_PERGB_CRT_LIST: crtList, NETRUN_PERGB_RUN_DIR: path.join(dir, "run") }) };
  const runtime = T.fakeRuntime(rtSettings);
  const world = { sockets: [], cgroupSupport: true, listeners: [] };
  const run = T.fakeRun(world, {
    ip: async (args) => (args[0] === "-6" ? { code: 0, stdout: "local 2001:db8:aa::/48 dev lo proto kernel metric 0 pref medium\nlocal ::1 dev lo proto kernel metric 0 pref medium\n", stderr: "" } : { code: 0, stdout: `1.1.1.1 via 203.0.113.1 dev eth0 src ${EGRESS} uid 0\n`, stderr: "" }),
    ss: async (args) => {
      if (args[0] !== "-Hltnp") return null;
      const lo = Number(args[3].slice(1));
      const hi = Number(args[7].slice(1));
      const lines = world.listeners.filter((l) => l.port >= lo && l.port <= hi).map((l) => `LISTEN 0 4096 ${l.ip}:${l.port} 0.0.0.0:* users:(("${l.proc}",pid=${l.pid},fd=7))`);
      return { code: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
    },
  });
  const cgroups = { 999: "0::/netrun.slice/netrun-pergb.slice/netrun-pergb-haproxy.service\n", 4242: "0::/system.slice/netrun-3proxy-20000.scope\n" };
  let clockOffset = 0;
  const now = () => Date.now() + clockOffset;
  const env = { NETRUN_RADIUS_CTL_SOCKET: radius.ctlPath, NETRUN_RADIUS_ADDR: `127.0.0.1:${radius.udpPort}` };
  const pergb = stateLib.createPergb({
    env,
    now,
    log: QUIET,
    run,
    runtime,
    runtimeSettings: rtSettings,
    settings: { poolFile: path.join(dir, "pergb-pool.conf"), stateDir: path.join(dir, "state"), proxyRoot, loops: false, haproxyLog: path.join(logDir, "haproxy.log") },
    readCgroupOf: (pid) => cgroups[pid] || "",
    radiusWaitMs: 5000,
    statfs: () => ({ blocks: 1000, bavail: 500, bsize: 4096 }),
    readFile: (p) => {
      if (p.endsWith("ip_local_port_range")) return "1024 8000\n";
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
  });
  const c1 = certPair(dir, "one");
  const srv = tlsLib.createTlsServer({ pergb, apiKeyMatches: (k) => k === API_KEY, log: QUIET, settings: { port: 0, host: "127.0.0.1", certPath: c1.crt, keyPath: c1.key, enabled: true, requireInstalled: false, requireFirewall: false } });
  t.after(() => srv.stop());
  await srv.start();
  const port = srv.port;
  const ca = c1.pem;
  const call = (method, p, opts = {}) => request(port, method, p, { ca, ...opts });

  const ENABLE = {
    base: 31000,
    count: 1000,
    procs: 2,
    subnets: "0000-fffe",
    prefix: PREFIX,
    geo: "us",
    egressIpv4: null,
    ipv4s: [],
    family: "dualstack",
    maxConns: 8000,
    logdumpBytes: 262144,
    denyPorts: [25, 465, 587],
    sliceMemMax: 1610612736,
    cpuWeight: 50,
    canaryHosts: [],
    addrKey: T.KEY_B64,
    probe: { password: "probe-password-1", canary: [["2606:4700::1", 443]] },
  };

  await t.test("TLS only: the key is required; per-GB is off before enable (404 pergb_off)", async () => {
    assert.strictEqual((await call("GET", "/pergb/status", { key: null })).status, 401);
    assert.strictEqual((await call("GET", "/pergb/status", { key: "wrong" })).status, 401);
    const st = await call("GET", "/pergb/status");
    assert.strictEqual(st.status, 200);
    assert.strictEqual(st.json.enabled, false);
    assert.strictEqual((await call("POST", "/pergb/reserve_nets", { body: { count: 1, ref: "r0" } })).json.error, "pergb_off");
    assert.strictEqual((await call("PATCH", "/pergb/state", { body: { baseSeq: 0, seq: 1 } })).json.error, "pergb_off");
  });

  await t.test("enable refusals: ports_in_use (not our own listeners), no_ip_cert, no_routed_prefix, bad params", async () => {
    world.listeners = [
      { ip: EGRESS, port: 31005, proc: "3proxy", pid: 4242 },
      { ip: EGRESS, port: 31000, proc: "haproxy", pid: 999 }, // the per-GB haproxy itself
    ];
    let r = await call("POST", "/pergb/enable", { body: ENABLE });
    assert.strictEqual(r.status, 409);
    assert.strictEqual(r.json.error, "ports_in_use");
    assert.deepStrictEqual(r.json.conflicts.map((c) => [c.port, c.pid, c.unit]), [[31005, 4242, "netrun-3proxy-20000.scope"]]);
    world.listeners = [{ ip: EGRESS, port: 31000, proc: "haproxy", pid: 999 }];
    r = await call("POST", "/pergb/enable", { body: { ...ENABLE, prefix: "2001:db8:cc::/48" } });
    assert.strictEqual(r.json.error, "no_routed_prefix");
    r = await call("POST", "/pergb/enable", { body: { ...ENABLE, addrKey: "c2hvcnQ=" } });
    assert.strictEqual(r.status, 400);
    fs.renameSync(crtList, `${crtList}.x`);
    r = await call("POST", "/pergb/enable", { body: ENABLE });
    assert.strictEqual(r.json.error, "no_ip_cert");
    fs.renameSync(`${crtList}.x`, crtList);
    assert.ok(!fs.existsSync(path.join(dir, "pergb-pool.conf")), "no refusal writes the pool file");
  });

  let firstPoolStat;
  await t.test("enable: runtime applied, RADIUS facts + excluded, the pool file last; the same params change nothing", async () => {
    const r = await call("POST", "/pergb/enable", { body: ENABLE });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.strictEqual(r.json.enabled, true);
    assert.strictEqual(r.json.prefix, PREFIX);
    assert.strictEqual(r.json.subnets, "0000-fffe");
    assert.strictEqual(r.json.egressIpv4, EGRESS, "option A: the primary IPv4");
    assert.strictEqual(r.json.radius.ready, true);
    assert.deepStrictEqual(r.json.excludedPush, { ok: true, excluded: 2, scanned: 2, complete: true });
    const pool = fs.readFileSync(path.join(dir, "pergb-pool.conf"), "utf-8");
    assert.match(pool, /^PREFIX=2001:db8:aa::\/48$/m);
    assert.match(pool, /^POOL=0000-fffe$/m);
    assert.match(pool, /^ENABLED=1$/m);
    assert.strictEqual(fs.statSync(path.join(dir, "pergb-pool.conf")).mode & 0o777, 0o644);
    firstPoolStat = fs.statSync(path.join(dir, "pergb-pool.conf"));
    const st = await pergb.ctl.call("status", {});
    assert.strictEqual(st.facts.prefix, PREFIX);
    assert.strictEqual(st.facts.base, 31000);
    assert.strictEqual(st.alloc.scanExcluded === undefined ? 2 : st.alloc.scanExcluded, 2);
    const again = await call("POST", "/pergb/enable", { body: ENABLE });
    assert.strictEqual(again.status, 200);
    assert.deepStrictEqual(again.json.applied.changed, [], "idempotent: nothing rewritten");
    assert.deepStrictEqual(again.json.applied.restarted, []);
    assert.strictEqual(fs.statSync(path.join(dir, "pergb-pool.conf")).mtimeMs, firstPoolStat.mtimeMs);
    const mismatch = await call("POST", "/pergb/enable", { body: { ...ENABLE, subnets: "8000-fffe" } });
    assert.strictEqual(mismatch.status, 409);
    assert.strictEqual(mismatch.json.error, "slice_mismatch");
  });

  await t.test("guards push admission and IPv4 admission (with the per-address map) to the real RADIUS", async () => {
    await pergb.guardTick();
    const g = pergb.guards.status();
    assert.strictEqual(g.pushed.error, null, JSON.stringify(g.pushed));
    assert.strictEqual(g.pushed.admission, true);
    const st = await pergb.ctl.call("status", {});
    assert.strictEqual(st.admission.open, true);
    assert.strictEqual(st.ipv4AdmissionOpen, true);
  });

  await t.test("smart rotation: the real RADIUS takes the ctl op avoid and reports smartRotation (A12)", async () => {
    const until = Math.floor(Date.now() / 1000) + 600;
    await pergb.ctl.call("avoid", { full: true, entries: [{ net: 5, site: "example.com", until }], removed: [] });
    const st = await pergb.ctl.call("status", {});
    assert.strictEqual(st.smartRotation.avoidedPairs, 1);
    assert.strictEqual(typeof st.smartRotation.picksAvoided1h, "number");
    const r = await pergb.smart.push();
    assert.ok(!r.error, JSON.stringify(r));
    assert.strictEqual(pergb.smart.status(st.smartRotation).radiusSupport, true);
  });

  await t.test("the RADIUS probe (a 3proxy-shaped Access-Request from JS) is accepted; a wrong password is not", async () => {
    await pergb.guards.probeTick();
    assert.strictEqual(pergb.guards.status().radiusAlive, true, JSON.stringify(pergb.guards.status().probe));
    const bad = await radprobe.probeOnce({ port: radius.udpPort, secret: T.SECRET, password: "wrong-password", nasPort: 31000, dst: "2606:4700::1", dstPort: 443 });
    assert.strictEqual(bad.verdict, "reject");
    const off = await radprobe.probeOnce({ port: radius.udpPort, secret: T.SECRET, password: "probe-password-1", nasPort: 31000, dst: "2606:4700::99", dstPort: 443 });
    assert.strictEqual(off.verdict, "reject", "only towards the canary");
  });

  await t.test("snapshot paging: 202 per page, 200 {epoch, seq} on the last; 409 snapshot_mismatch; staging expires", async () => {
    const accounts = [ACCOUNT(10), ACCOUNT(20)];
    const lists = [LIST(1, "netrun-aaaa1", 10), LIST(2, "netrun-aaaa2", 10), LIST(3, "netrun-bbbb3", 20)];
    let r = await call("PUT", "/pergb/state?snapshotId=s1&page=1&pages=2&seq=5", { body: { accounts, lists: lists.slice(0, 2), static: [] } });
    assert.strictEqual(r.status, 202);
    assert.deepStrictEqual([r.json.received, r.json.pages], [1, 2]);
    r = await call("PUT", "/pergb/state?snapshotId=s1&page=2&pages=2&seq=5", { body: { accounts: [], lists: lists.slice(2), static: [] } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.strictEqual(r.json.seq, 5);
    assert.ok(Number.isSafeInteger(r.json.epoch));
    // a page of the same snapshot with another seq
    await call("PUT", "/pergb/state?snapshotId=s2&page=1&pages=2&seq=6", { body: { accounts, lists, static: [] } });
    r = await call("PUT", "/pergb/state?snapshotId=s2&page=2&pages=2&seq=7", { body: {} });
    assert.strictEqual(r.status, 409);
    assert.strictEqual(r.json.error, "snapshot_mismatch");
    // the last page without the others
    r = await call("PUT", "/pergb/state?snapshotId=s3&page=3&pages=3&seq=6", { body: {} });
    assert.strictEqual(r.json.error, "snapshot_mismatch");
    assert.deepStrictEqual(r.json.missing, [1, 2]);
    // staging expires after 120 s
    await call("PUT", "/pergb/state?snapshotId=s4&page=1&pages=2&seq=6", { body: { accounts, lists, static: [] } });
    assert.ok(pergb._staging.has("s4"));
    clockOffset += 121000;
    r = await call("PUT", "/pergb/state?snapshotId=s4&page=2&pages=2&seq=6", { body: {} });
    assert.strictEqual(r.json.error, "snapshot_mismatch", "page 1 expired");
    clockOffset -= 121000;
    r = await call("PUT", "/pergb/state?snapshotId=bad%20id&page=1&pages=1&seq=6", { body: {} });
    assert.strictEqual(r.status, 400);
    // the logins reached the meter and the enforcer
    assert.strictEqual(pergb.meter.loginInfo("netrun-bbbb3").accountId, 20);
  });

  const tg = T.tagger();
  const addr1 = tg.address(0x31, 1, 11);
  const addr2 = tg.address(0x32, 2, 22);
  const addr3 = tg.address(0x33, 3, 33);
  await t.test("transitions kill: a blocked account in a snapshot, a password change in a delta", async () => {
    world.sockets = [
      { local: addr1, lport: 40001, peer: "2606:4700::1", pport: 443, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) },
      { local: addr2, lport: 40002, peer: "2606:4700::1", pport: 443, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) },
      { local: addr3, lport: 40003, peer: "2606:4700::1", pport: 443, sent: 1, received: 1, cgroup: T.CG(T.UNIT_B) },
    ];
    world.killed = [];
    const lists = [LIST(1, "netrun-aaaa1", 10), LIST(2, "netrun-aaaa2", 10), LIST(3, "netrun-bbbb3", 20)];
    let r = await call("PUT", "/pergb/state?snapshotId=s5&page=1&pages=1&seq=10", { body: { accounts: [ACCOUNT(10), ACCOUNT(20, { state: "blocked" })], lists, static: [] } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.deepStrictEqual(r.json.transitions.accounts, [{ id: 20, why: "blocked" }]);
    assert.deepStrictEqual(world.killed.map((s) => s.local), [addr3], "only account 20's socket");
    // a delta: list 1's password changed
    r = await call("PATCH", "/pergb/state", { body: { baseSeq: 9, seq: 11, accounts: [], lists: [LIST(1, "netrun-aaaa1", 10, { pwRev: 2 })] } });
    assert.strictEqual(r.status, 409);
    assert.deepStrictEqual([r.json.error, r.json.seq], ["seq_mismatch", 10]);
    assert.ok(Number.isSafeInteger(r.json.epoch));
    r = await call("PATCH", "/pergb/state", { body: { baseSeq: 10, seq: 11, accounts: [], lists: [LIST(1, "netrun-aaaa1", 10, { pwRev: 2 })] } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.deepStrictEqual(r.json.transitions.lists, [{ id: 1, why: "pw" }]);
    assert.deepStrictEqual(world.killed.map((s) => s.local), [addr3, addr1], "then list 1's socket, not list 2's");
    // unblock account 20 again (a delta)
    r = await call("PATCH", "/pergb/state", { body: { baseSeq: 11, seq: 12, accounts: [ACCOUNT(20)], lists: [] } });
    assert.strictEqual(r.status, 200);
  });

  let staticAddr;
  await t.test("usage: meter counters since a seq, RADIUS binding events and rejects, the status", async () => {
    await pergb.mainTick(); // fresh meter state: no logs yet
    // traffic: a static line (a binding event in RADIUS) and a wrong password (a reject)
    const ok = await radprobe.probeOnce({ port: radius.udpPort, secret: T.SECRET, username: "netrun-aaaa2-static", password: "pass-2", nasPort: 31005, dst: "2606:4700::1", dstPort: 443 });
    assert.strictEqual(ok.verdict, "accept");
    const bad = await radprobe.probeOnce({ port: radius.udpPort, secret: T.SECRET, username: "netrun-aaaa2", password: "nope", nasPort: 31005, dst: "2606:4700::1", dstPort: 443 });
    assert.strictEqual(bad.verdict, "reject");
    const b = await pergb.ctl.call("bindings", { after: 0, limit: 10 });
    staticAddr = b.items[0].addr;
    fs.writeFileSync(path.join(logDir, hourName(31000)), `${rec({ user: "netrun-aaaa2-static", bound: staticAddr, i: 5000, o: 300, cport: 41111 })}\n${rec({ user: "netrun-aaaa1", bound: addr1, i: 7, o: 3 })}\n`);
    fs.writeFileSync(path.join(logDir, "haproxy.log"), `Oct  9 14:00:00 node netrun-pergb-haproxy[1]: 198.51.100.77:55555 31000 127.0.0.1:41111 1200 5300 3\n`);
    await pergb.mainTick();
    const u = await call("GET", "/pergb/usage?since=0&bindingsAfter=0");
    assert.strictEqual(u.status, 200);
    assert.deepStrictEqual(u.json.logins["netrun-aaaa2"], { up: 300, down: 5000, conns: 1 });
    assert.deepStrictEqual(u.json.logins["netrun-aaaa1"], { up: 3, down: 7, conns: 1 });
    assert.strictEqual(u.json.bindings.items.length, 1);
    assert.strictEqual(u.json.bindings.items[0].op, "add");
    assert.strictEqual(u.json.rejects["2"].reason, "bad_login");
    assert.strictEqual(u.json.status.enabled, true);
    assert.ok(Array.isArray(u.json.localBlocks));
    const u2 = await call("GET", `/pergb/usage?since=${u.json.seq}&bindingsAfter=${u.json.bindings.last}`);
    assert.deepStrictEqual(u2.json.logins, {}, "nothing changed since");
    assert.deepStrictEqual(u2.json.bindings.items, []);
  });

  await t.test("attribution: the tag decodes to the list; records and the client from the haproxy log", async () => {
    const r = await call("GET", `/pergb/attribution?addr=${encodeURIComponent(staticAddr)}`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.listId, 2);
    assert.strictEqual(r.json.tagValid, true);
    assert.strictEqual(r.json.records.length, 1);
    assert.strictEqual(r.json.records[0].user, "netrun-aaaa2-static");
    assert.deepStrictEqual(r.json.clients, ["198.51.100.77:55555"]);
    assert.strictEqual(r.json.clientsDetail[0].backend, "127.0.0.1:41111");
    const per = await call("GET", "/pergb/attribution?addr=2001:db8:aa:1::5");
    assert.strictEqual(per.json.listId, null, "a per-piece /64 is never decoded");
  });

  await t.test("kill route; port_check (shadow range in option A); reserve / release through RADIUS (A1)", async () => {
    world.sockets.push({ local: addr2, lport: 40009, peer: "2606:4700::1", pport: 443, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) });
    let r = await call("POST", "/pergb/kill", { body: { accountId: 10 } });
    assert.deepStrictEqual([r.json.killed6, r.json.killed4], [2, 0]);
    world.listeners = [
      { ip: EGRESS, port: 31000, proc: "haproxy", pid: 999 },
      { ip: "0.0.0.0", port: 31700, proc: "3proxy", pid: 4242 },
      { ip: EGRESS, port: 41010, proc: "3proxy", pid: 4242 },
    ];
    r = await call("GET", `/pergb/port_check?base=31000&count=1000&ipv4=${EGRESS}`);
    assert.strictEqual(r.json.free, false);
    assert.deepStrictEqual(r.json.conflicts.map((c) => [c.port, Boolean(c.shadow)]), [[31700, false], [41010, true]]);
    r = await call("GET", "/pergb/port_check?base=50000&count=10&ipv4=198.51.100.9");
    assert.strictEqual(r.json.free, true);
    r = await call("POST", "/pergb/reserve_nets", { body: { count: 3, owner: "perpiece", ref: "gen:20000:abc" } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.strictEqual(r.json.nets.length, 3);
    for (const n of r.json.nets) assert.match(n, /^2001:db8:aa:[0-9a-f]{1,4}::\/64$/);
    const again = await call("POST", "/pergb/reserve_nets", { body: { count: 3, ref: "gen:20000:abc" } });
    assert.deepStrictEqual(again.json.nets, r.json.nets, "idempotent per ref");
    for (const id of r.json.subnetIds) assert.ok(pergb._excluded().has(id), "kills and attribution skip them at once");
    const rel = await call("POST", "/pergb/release_nets", { body: { nets: [r.json.nets[0], r.json.subnetIds[1], `0x${r.json.subnetIds[2].toString(16)}`], ref: "rel:1" } });
    assert.strictEqual(rel.status, 200, JSON.stringify(rel.json));
    assert.strictEqual(rel.json.released, 3);
    const badNet = await call("POST", "/pergb/release_nets", { body: { nets: ["2001:db8:bb:1::/64"], ref: "rel:2" } });
    assert.strictEqual(badNet.status, 400);
  });

  await t.test("a RADIUS restart with a lost DB: the next watch pushes facts and excluded again", async () => {
    await radius.stop();
    fs.rmSync(path.join(dir, "radius"), { recursive: true, force: true });
    const r2 = await T.startRadius(dir);
    t.after(() => r2.stop());
    // same ctl path and secret; a new UDP port does not matter for ctl
    const st0 = await pergb.ctl.call("status", {});
    assert.strictEqual(st0.ready, false);
    await pergb.radiusWatch(false);
    const st1 = await pergb.ctl.call("status", {});
    assert.strictEqual(st1.ready, true);
    assert.strictEqual(st1.facts.prefix, PREFIX);
    const status = await call("GET", "/pergb/status");
    assert.strictEqual(status.json.radius.epoch, st1.epoch);
    assert.ok(status.json.events.some((e) => e.type === "pergb_radius_epoch_changed"));
  });

  await t.test("body limit 2 MiB → 413; certificate renewal picked up without a restart", async () => {
    const big = JSON.stringify({ accounts: [], lists: [], static: [], pad: "x".repeat(2 * 1024 * 1024) });
    const r = await call("PUT", "/pergb/state?snapshotId=big&page=1&pages=1&seq=1", { raw: big });
    assert.strictEqual(r.status, 413);
    const c2 = certPair(dir, "two");
    fs.copyFileSync(c2.crt, c1.crt);
    fs.copyFileSync(c2.key, c1.key);
    assert.strictEqual(await srv.checkCertificate(), true);
    assert.strictEqual(srv.status().reloads, 1);
    const ok = await request(port, "GET", "/pergb/status", { ca: c2.pem });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(ok.cert.subject.CN, "two");
    await assert.rejects(request(port, "GET", "/pergb/status", { ca: c1.pem }), "the old certificate is gone");
  });

  await t.test("disable: the pool file first, then the runtime; reserve answers pergb_off", async () => {
    const r = await request(port, "POST", "/pergb/disable", { body: { stopRadius: false }, ca: fs.readFileSync(c1.crt, "utf-8") });
    assert.strictEqual(r.status, 200);
    assert.ok(Array.isArray(r.json.stopped) && r.json.stopped.length >= 2);
    assert.ok(!fs.existsSync(path.join(dir, "pergb-pool.conf")));
    const res = await request(port, "POST", "/pergb/reserve_nets", { body: { count: 1, ref: "r9" }, ca: fs.readFileSync(c1.crt, "utf-8") });
    assert.strictEqual(res.status, 404);
    assert.strictEqual(res.json.error, "pergb_off");
    assert.deepStrictEqual(runtime.calls.at(-1), ["disable", { stopRadius: false }]);
  });
});

test("generateConflict (option A): the shared range and its +10000 shadow refuse a batch; option B does not", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgg-"));
  const rtSettings = rtLib.readSettings({ NETRUN_PERGB_ETC_DIR: dir });
  const runtime = T.fakeRuntime(rtSettings);
  const pergb = stateLib.createPergb({ runtime, runtimeSettings: rtSettings, log: QUIET, settings: { poolFile: path.join(dir, "pool"), stateDir: dir, loops: false } });
  assert.strictEqual(pergb.generateConflict(31000, 100), null, "no per-GB here");
  const write = (dedicated) =>
    fs.writeFileSync(rtSettings.enablePath, JSON.stringify({ version: 1, enabled: true, base: 31000, count: 1000, egressIpv4: "203.0.113.10", dedicatedIpv4: dedicated, procs: [] }));
  write(null);
  assert.strictEqual(pergb.generateConflict(30000, 1000), null, "below the range");
  assert.strictEqual(pergb.generateConflict(30500, 1000).error, "ports_reserved_pergb", "overlaps the range");
  assert.strictEqual(pergb.generateConflict(41500, 100).via, "shadow", "its http mirror would sit on the range");
  assert.strictEqual(pergb.generateConflict(42000, 1000), null, "after the shadow");
  assert.strictEqual(pergb.generateConflict(20000, 1000), null);
  write("198.51.100.20");
  assert.strictEqual(pergb.generateConflict(31000, 10), null, "option B: per-GB is on its own IPv4");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("pool file text and parsing; /64 wire forms", () => {
  const text = stateLib.poolText("2001:db8:aa::/48", "0000-fffe");
  const p = stateLib.parsePoolText(text);
  assert.strictEqual(p.state, "on");
  assert.strictEqual(p.prefix, "2001:db8:aa::/48");
  assert.deepStrictEqual([p.lo, p.hi], [0, 0xfffe]);
  assert.strictEqual(stateLib.parsePoolText("PREFIX=2001:db8:aa::/48\nENABLED=0\n").state, "off");
  assert.strictEqual(stateLib.normalizePool("8000-ffff").text, "8000-fffe", "never the node's own /64");
  assert.strictEqual(stateLib.normalizePool("fffe-0001"), null);
  const base = p.prefixBase;
  assert.strictEqual(stateLib.netText(base, 0x12), "2001:db8:aa:12::/64");
  for (const v of [0x12, "0x12", "12", "2001:db8:aa:12::/64", "2001:db8:aa:12::1"]) assert.strictEqual(stateLib.subnetIdOf(base, v), 0x12, String(v));
  assert.strictEqual(stateLib.subnetIdOf(base, 18), 0x12, "a number is the id itself");
  assert.strictEqual(stateLib.subnetIdOf(base, "12345"), null);
  assert.strictEqual(stateLib.subnetIdOf(base, "2001:db8:bb:12::/64"), null);
  const listeners = stateLib.parseListeners('LISTEN 0 4096 203.0.113.10:31000 0.0.0.0:* users:(("haproxy",pid=999,fd=7),("haproxy",pid=1000,fd=7))\nLISTEN 0 128 *:8085 *:*\n');
  assert.deepStrictEqual(listeners[0], { ip: "203.0.113.10", port: 31000, pids: [999, 1000], procs: ["haproxy", "haproxy"] });
  assert.strictEqual(listeners[1].ip, "*");
});

test("the per-piece /64 scan (excluded): cfg variants, lists and their temps, the egress state; only the /48; complete flag", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgx-"));
  fs.mkdirSync(path.join(dir, "3proxy"));
  fs.writeFileSync(path.join(dir, "3proxy", "3proxy_20000.cfg"), "socks -6 -a -p20000 -i1.2.3.4 -e2001:db8:aa:1::5\n");
  fs.writeFileSync(path.join(dir, "3proxy", "3proxy_21000.cfg.disabled"), "socks -6 -a -p21000 -i1.2.3.4 -e2001:db8:aa:2::5\n");
  fs.writeFileSync(path.join(dir, "3proxy", "3proxy_22000.cfg.failed"), "socks -6 -a -p22000 -i1.2.3.4 -e2001:db8:aa:3::5\n");
  fs.writeFileSync(path.join(dir, "ipv6_23000.list"), "2001:db8:aa:4::1\n2001:db8:bb:4::1\n");
  fs.writeFileSync(path.join(dir, "ipv6_24000.list.tmp"), "2001:db8:aa:5::1\n");
  fs.writeFileSync(
    path.join(dir, "egress_state.json"),
    JSON.stringify({ ports: { 20000: { anchor: "2001:db8:aa:6::1", current: "2001:db8:aa:7::1" } }, pool: ["2001:db8:aa:8::1"], draining: [{ addr: "2001:db8:aa:9::1" }], pergb_held: [{ net: "2001:db8:aa:a::/64" }] })
  );
  const base = require("./pergb_tag.js").parsePrefix48(PREFIX).base;
  const r = stateLib.scanPerPieceNets({ proxyRoot: dir, prefixBase: base });
  assert.deepStrictEqual([...r.nets].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.strictEqual(r.complete, true);
  fs.writeFileSync(path.join(dir, "egress_state.json"), "{broken");
  assert.strictEqual(stateLib.scanPerPieceNets({ proxyRoot: dir, prefixBase: base }).complete, false, "an unreadable source makes the scan incomplete (add-only in RADIUS)");
  fs.rmSync(dir, { recursive: true, force: true });
});
