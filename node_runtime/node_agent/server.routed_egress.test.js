"use strict";

// Audit 2026-10-08 — /health ipv6EgressRouted: the egress self-check FROM the
// node's own /64 of the routed prefix (<last /64>::1), so a dead /48 (BGP
// session down, local route gone) shows although ipv6Egress (primary address)
// is fine. Cached (one request per TTL), single-flight, null without a prefix.
// Run with: node --test node_runtime/node_agent/server.routed_egress.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-routed-egress-"));
fs.mkdirSync(path.join(TMP, "proxyserver", "3proxy"), { recursive: true });
fs.mkdirSync(path.join(TMP, "bin"), { recursive: true });
fs.writeFileSync(path.join(TMP, "bin", "ss"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
process.env.NODE_AGENT_PROXY_ROOT = path.join(TMP, "proxyserver");
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NETRUN_ENV_FILE = path.join(TMP, "no-netrun.env");
process.env.NETRUN_IPV6_ROUTED_PREFIX = "2602:f2dc:a9::/48";
process.env.PATH = `${path.join(TMP, "bin")}:${process.env.PATH}`;

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const srv = require("./server.js");

const T = { prefix: "2602:f2dc:a9::/48", address: "2602:f2dc:a9:ffff::1" };

test("routedEgressTarget: NETRUN_IPV6_ROUTED_PREFIX, else EGRESS_ROTATE_PREFIX; off / unset = null; a /64 uses <prefix>::1", () => {
  const none = { NETRUN_ENV_FILE: path.join(TMP, "none.env") };
  assert.deepStrictEqual(srv.routedEgressTarget({ ...none, NETRUN_IPV6_ROUTED_PREFIX: "2602:F2DC:A9:0::7/48" }), T);
  assert.strictEqual(srv.routedEgressTarget(none), null);
  assert.strictEqual(srv.routedEgressTarget({ ...none, NETRUN_IPV6_ROUTED_PREFIX: "off", EGRESS_ROTATE_PREFIX: "off" }), null);
  assert.deepStrictEqual(srv.routedEgressTarget({ ...none, EGRESS_ROTATE_PREFIX: "2602:f2dc:b0::/48" }), {
    prefix: "2602:f2dc:b0::/48",
    address: "2602:f2dc:b0:ffff::1",
  });
  assert.deepStrictEqual(srv.routedEgressTarget({ ...none, NETRUN_IPV6_ROUTED_PREFIX: "2602:f2dc:a9:5::/64" }), {
    prefix: "2602:f2dc:a9:5::/64",
    address: "2602:f2dc:a9:5::1",
  });
  assert.deepStrictEqual(srv.routedEgressTarget({ ...none, NETRUN_IPV6_ROUTED_PREFIX: "junk" }), { prefix: "junk", address: null });
  // netrun.env is read too (the generator's file)
  const env = path.join(TMP, "netrun.env");
  fs.writeFileSync(env, 'NETRUN_IPV6_ROUTED_PREFIX="2602:f2dc:a9::/48"\n');
  assert.deepStrictEqual(srv.routedEgressTarget({ NETRUN_ENV_FILE: env }), T);
});

test("routedEgressVerdict: ok only for a 2xx answering with the bound address", () => {
  const at = "2026-10-09T00:00:00.000Z";
  assert.deepStrictEqual(srv.routedEgressVerdict(T, { ok: true, statusCode: 200, body: "2602:f2dc:a9:ffff:0:0:0:1\n" }, at), {
    ok: true, prefix: T.prefix, address: T.address, error: null, statusCode: 200, observed: "2602:f2dc:a9:ffff:0:0:0:1", checkedAt: at,
  });
  const mism = srv.routedEgressVerdict(T, { ok: true, statusCode: 200, body: "2001:19f0:5c01:cdf:5400:6ff:febe:b5cf" }, at);
  assert.strictEqual(mism.ok, false);
  assert.strictEqual(mism.error, "egress_address_mismatch");
  const dead = srv.routedEgressVerdict(T, { ok: false, statusCode: 0, body: "", error: "ipv6_error:timeout" }, at);
  assert.deepStrictEqual([dead.ok, dead.error, dead.observed], [false, "ipv6_error:timeout", null]);
  assert.strictEqual(srv.routedEgressVerdict({ prefix: "junk", address: null }, {}, at).error, "bad_routed_prefix");
});

test("createRoutedEgressProbe: null without a prefix; cached per TTL; single-flight; a new prefix rechecks", async () => {
  let t = null;
  let calls = 0;
  let clock = 0;
  let release;
  const gate = new Promise((r) => (release = r));
  const probe = srv.createRoutedEgressProbe({
    ttlMs: 60_000,
    target: () => t,
    now: () => clock,
    check: async (tg) => {
      calls += 1;
      await gate;
      return { ok: true, statusCode: 200, body: tg.address };
    },
  });
  assert.strictEqual(await probe.get(), null);
  assert.strictEqual(calls, 0, "no prefix: no request");
  t = T;
  const [a, b] = [probe.get(), probe.get()];
  release();
  const [ra, rb] = await Promise.all([a, b]);
  assert.strictEqual(calls, 1, "concurrent /health calls share one request");
  assert.strictEqual(ra.ok, true);
  assert.strictEqual(rb, ra);
  clock = 59_000;
  await probe.get();
  assert.strictEqual(calls, 1, "within the TTL: cached");
  clock = 61_000;
  await probe.get();
  assert.strictEqual(calls, 2, "after the TTL: one new request");
  t = { prefix: "2602:f2dc:b0::/48", address: "2602:f2dc:b0:ffff::1" };
  assert.strictEqual((await probe.get()).address, "2602:f2dc:b0:ffff::1");
  assert.strictEqual(calls, 3, "another prefix: checked at once");
  const failing = srv.createRoutedEgressProbe({ target: () => T, check: async () => { throw new Error("EADDRNOTAVAIL"); } });
  const f = await failing.get();
  assert.deepStrictEqual([f.ok, f.error], [false, "ipv6_error:EADDRNOTAVAIL"]);
});

test("GET /health (with the key): ipv6EgressRouted from the node's own /64; the canary is fetched bound to it", { timeout: 30_000 }, async () => {
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  try {
    const json = await new Promise((resolve, reject) => {
      http
        .get({ host: "127.0.0.1", port: srv.server.address().port, path: "/health", headers: { "X-API-KEY": "test-key" } }, (res) => {
          let body = "";
          res.on("data", (c) => (body += c));
          res.on("end", () => resolve(JSON.parse(body)));
        })
        .on("error", reject);
    });
    const r = json.ipv6EgressRouted;
    assert.ok(r && typeof r === "object", "present with a routed prefix");
    assert.strictEqual(r.prefix, "2602:f2dc:a9::/48");
    assert.strictEqual(r.address, "2602:f2dc:a9:ffff::1");
    assert.strictEqual(r.ok, false, "this box cannot egress from the /48");
    assert.ok(typeof r.error === "string" && r.error.length > 0);
    assert.strictEqual(r.ttlSec, 60);
    assert.ok("ipv6Egress" in json, "the primary check is still there");
  } finally {
    await new Promise((r) => srv.server.close(r));
    fs.rmSync(TMP, { recursive: true, force: true });
  }
});
