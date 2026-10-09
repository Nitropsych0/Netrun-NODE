"use strict";

// Pay-per-GB v2 (lane L3) — the per-GB contracts of the plain :8085 agent
// (server.js): /health's pergb block (no secrets), /describe's
// supports.pergb_radius / pergb_tls_port, /pergb/* answering 404
// pergb_tls_only except the amendment-A1 reserve_nets / release_nets (served
// for node-local callers through RADIUS, 404 pergb_off without the pool
// file), and the /generate refusal on the shared per-GB range (option A).
// Run with: node --test node_runtime/node_agent/server.pergb.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "spg-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const JOBS_ROOT = path.join(TMP, "jobs");
const BIN = path.join(TMP, "bin");
const ETC = path.join(TMP, "etc");
const POOL = path.join(TMP, "pergb-pool.conf");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
fs.mkdirSync(ETC, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NODE_AGENT_JOBS_ROOT = JOBS_ROOT;
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.NETRUN_ENV_FILE = path.join(TMP, "no-netrun.env");
process.env.PATH = `${BIN}:${process.env.PATH}`;
process.env.NETRUN_PERGB_ETC_DIR = ETC;
process.env.NETRUN_PERGB_POOL_FILE = POOL;
process.env.NETRUN_PERGB_STATE_DIR = path.join(TMP, "state");
process.env.NETRUN_PERGB_LOG_DIR = path.join(TMP, "log");
process.env.NETRUN_RADIUS_CTL_SOCKET = path.join(TMP, "c.sock");
delete process.env.NETRUN_IPV6_ROUTED_PREFIX;
fs.writeFileSync(path.join(BIN, "ss"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });

const FAKE_GEN = path.join(TMP, "fake_generator.sh");
fs.writeFileSync(FAKE_GEN, "#!/bin/bash\n# --random --skip-self-check --proxies-type\nexit 3\n", { mode: 0o755 });

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const T = require("./pergb_testlib.js");
const srv = require("./server.js");

function req(port, method, p, { body, key = "test-key" } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const r = http.request(
      { host: "127.0.0.1", port, path: p, method, headers: { ...(key ? { "X-API-KEY": key } : {}), ...(data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}) } },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode, json: text ? JSON.parse(text) : null }));
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

let PORT = 0;
test.before(async () => {
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  PORT = srv.server.address().port;
});
test.after(async () => {
  await new Promise((r) => srv.server.close(r));
  fs.rmSync(TMP, { recursive: true, force: true });
});

test("/describe: supports.pergb_radius = 1 and supports.pergb_tls_port = 8086", { timeout: 30000 }, async () => {
  const d = await req(PORT, "GET", "/describe");
  assert.strictEqual(d.status, 200);
  assert.strictEqual(d.json.supports.pergb_radius, 1);
  assert.strictEqual(d.json.supports.pergb_tls_port, 8086);
});

test("/health: an additive pergb block without secrets; the liveness answer stays {ok:true}", { timeout: 30000 }, async () => {
  const h = await req(PORT, "GET", "/health");
  assert.strictEqual(h.status, 200);
  const p = h.json.pergb;
  assert.ok(p, "pergb block present");
  assert.strictEqual(p.enabled, false);
  for (const k of ["radiusAlive", "live", "guards", "tls"]) assert.ok(k in p, k);
  for (const k of ["admissionOpen", "ipv4AdmissionOpen", "memPct", "ipv4PortsPct", "logFsFreePct", "meterLagSec", "clockSynced"]) assert.ok(k in p.guards, k);
  assert.doesNotMatch(JSON.stringify(p), /addrKey|password|secret/i);
  assert.deepStrictEqual((await req(PORT, "GET", "/health", { key: null })).json, { ok: true });
});

test("plain /pergb/*: 401 without the key, 404 pergb_tls_only with it", async () => {
  assert.strictEqual((await req(PORT, "GET", "/pergb/status", { key: null })).status, 401);
  for (const [m, p] of [["GET", "/pergb/status"], ["POST", "/pergb/enable"], ["PUT", "/pergb/state"], ["GET", "/pergb/usage"], ["POST", "/pergb/kill"]]) {
    const r = await req(PORT, m, p, { body: m === "GET" ? undefined : {} });
    assert.strictEqual(r.status, 404, `${m} ${p}`);
    assert.strictEqual(r.json.error, "pergb_tls_only");
    assert.strictEqual(r.json.tlsPort, 8086);
  }
});

test("plain reserve_nets / release_nets: 404 pergb_off without the pool file; through RADIUS with it", { skip: T.havePython() ? false : "python3 needed", timeout: 60000 }, async (t) => {
  let r = await req(PORT, "POST", "/pergb/reserve_nets", { body: { count: 1, owner: "perpiece", ref: "gen:1" } });
  assert.strictEqual(r.status, 404);
  assert.strictEqual(r.json.error, "pergb_off");
  fs.writeFileSync(POOL, "PREFIX=2001:db8:aa::/48\nPOOL=0000-fffe\nENABLED=1\n");
  // RADIUS down: the generator must fail closed
  r = await req(PORT, "POST", "/pergb/reserve_nets", { body: { count: 1, ref: "gen:1" } });
  assert.strictEqual(r.status, 503);
  assert.strictEqual(r.json.error, "radius_unavailable");
  const radius = await T.startRadius(TMP);
  t.after(() => radius.stop());
  await srv.pergb.ctl.call("facts", {
    facts: { base: 31000, count: 1000, family: "dualstack", egressIpv4: "203.0.113.10", prefix: "2001:db8:aa::/48", subnets: "0000-fffe", addrKey: T.KEY_B64 },
  });
  r = await req(PORT, "POST", "/pergb/reserve_nets", { body: { count: 2, ref: "gen:1" } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.strictEqual(r.json.nets.length, 2);
  assert.match(r.json.nets[0], /^2001:db8:aa:/);
  r = await req(PORT, "POST", "/pergb/release_nets", { body: { nets: r.json.nets, ref: "dep:1" } });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.released, 2);
  r = await req(PORT, "POST", "/pergb/reserve_nets", { body: { count: 0, ref: "gen:2" } });
  assert.strictEqual(r.status, 400);
  fs.unlinkSync(POOL);
});

test("/generate: 409 ports_reserved_pergb on the shared range or its shadow (option A); other ranges pass the check", async () => {
  fs.writeFileSync(path.join(ETC, "enable.json"), JSON.stringify({ version: 1, enabled: true, base: 31000, count: 1000, egressIpv4: "203.0.113.10", dedicatedIpv4: null, procs: [] }));
  const body = (jobId, startPort) => ({
    jobId,
    generatorScript: FAKE_GEN,
    startPort,
    proxyCount: 100,
    proxiesType: "dual",
    networkProfile: "high_compatibility",
    fingerprintProfileVersion: "v2_android_ipv6_only_dns_custom",
    intendedClientOsProfile: "android_mobile",
    clientOsProfileEnforcement: "not_controlled_by_proxy",
    timeoutSec: 30,
  });
  let r = await req(PORT, "POST", "/generate", { body: body("pg-1", 31500) });
  assert.strictEqual(r.status, 409);
  assert.strictEqual(r.json.error, "ports_reserved_pergb");
  assert.deepStrictEqual([r.json.base, r.json.last], [31000, 31999]);
  r = await req(PORT, "POST", "/generate", { body: body("pg-2", 41950) });
  assert.strictEqual(r.status, 409, "socks 41950.. would put its http mirror on 31950..");
  assert.strictEqual(r.json.via, "shadow");
  assert.ok(!fs.existsSync(path.join(JOBS_ROOT, "pg-1")), "refused before any job state");
  r = await req(PORT, "POST", "/generate", { body: body("pg-3", 20000) });
  assert.notStrictEqual(r.json.error, "ports_reserved_pergb");
  // option B: per-GB on its own IPv4 — no refusal
  fs.writeFileSync(path.join(ETC, "enable.json"), JSON.stringify({ version: 1, enabled: true, base: 31000, count: 1000, egressIpv4: "198.51.100.20", dedicatedIpv4: "198.51.100.20", procs: [] }));
  for (let i = 0; i < 200 && fs.existsSync(path.join(JOBS_ROOT, ".generation.lock")); i += 1) await new Promise((res) => setTimeout(res, 10));
  r = await req(PORT, "POST", "/generate", { body: body("pg-4", 31500) });
  assert.notStrictEqual(r.json.error, "ports_reserved_pergb");
  fs.unlinkSync(path.join(ETC, "enable.json"));
});
