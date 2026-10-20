"use strict";

// Audit P-N4 — proc_snapshot.js: one ps / ss scan shared inside a TTL.
// Run with: node --test node_runtime/node_agent/proc_snapshot.test.js

const test = require("node:test");
const assert = require("node:assert");
const snap = require("./proc_snapshot.js");

function fake({ psOut = "10 5 /x/3proxy /y/3proxy_18100.cfg\n", fail = false, delayMs = 0 } = {}) {
  const calls = [];
  const state = { psOut, fail };
  const run = async (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    if (state.fail) return { code: 1, stdout: "", stderr: "boom\n" };
    if (cmd === "ps") return { code: 0, stdout: state.psOut, stderr: "" };
    const m = /sport = :(\d+)/.exec(args[1]);
    return { code: 0, stdout: `LISTEN 0 4096 0.0.0.0:${m ? m[1] : 0} 0.0.0.0:*\n`, stderr: "" };
  };
  let t = 1_000_000;
  const s = snap.createProcSnapshot({ run, now: () => t, ttlMs: 10000, etimes: true });
  return { s, calls, state, advance: (ms) => (t += ms), make: (opts) => snap.createProcSnapshot({ run, now: () => t, etimes: true, ...opts }) };
}

test("ps: two calls inside the TTL run ps once; after the TTL it runs again", async () => {
  const f = fake();
  const a = await f.s.ps();
  const b = await f.s.ps();
  assert.deepStrictEqual(f.calls, ["ps -eo pid=,etimes=,args="]);
  assert.strictEqual(a, b);
  assert.strictEqual(a.stdout, "10 5 /x/3proxy /y/3proxy_18100.cfg\n");
  f.advance(9999);
  await f.s.ps();
  assert.strictEqual(f.calls.length, 1, "9.999 s is still inside the TTL");
  f.advance(2);
  await f.s.ps();
  assert.strictEqual(f.calls.length, 2);
  assert.deepStrictEqual(
    { hits: f.s.stats().hits, misses: f.s.stats().misses, ttlMs: f.s.stats().ttlMs },
    { hits: 2, misses: 2, ttlMs: 10000 }
  );
  assert.ok(f.s.stats().lastRefreshAt);
});

test("concurrent calls coalesce into one in-flight scan", async () => {
  const f = fake({ delayMs: 30 });
  const [a, b, c] = await Promise.all([f.s.ps(), f.s.ps(), f.s.ps()]);
  assert.strictEqual(f.calls.length, 1);
  assert.ok(a === b && b === c);
  assert.strictEqual(f.s.stats().coalesced, 2);
});

test("fresh:true bypasses the cache and writes through to it", async () => {
  const f = fake();
  await f.s.ps();
  f.state.psOut = "11 1 /x/3proxy /y/3proxy_18100.cfg\n";
  const stale = await f.s.ps();
  assert.match(stale.stdout, /^10 /, "cached view");
  const fresh = await f.s.ps({ fresh: true });
  assert.match(fresh.stdout, /^11 /);
  assert.strictEqual(f.calls.length, 2);
  const after = await f.s.ps();
  assert.match(after.stdout, /^11 /, "the fresh read refreshed the cache for everyone");
  assert.strictEqual(f.calls.length, 2);
});

test("a failed scan is never cached", async () => {
  const f = fake({ fail: true });
  const bad = await f.s.ps();
  assert.deepStrictEqual([bad.ok, bad.error], [false, "boom"]);
  f.state.fail = false;
  const good = await f.s.ps();
  assert.strictEqual(good.ok, true);
  assert.strictEqual(f.calls.length, 2, "the failure did not stick");
  const ssBad = fake({ fail: true });
  assert.strictEqual((await ssBad.s.ss([1, 2])).ok, false);
  assert.strictEqual((await ssBad.s.ss([1, 2])).ok, false);
  assert.strictEqual(ssBad.calls.length, 2);
});

test("ss: keyed by the sorted port set; argv in the caller's order, 256 ports per ss", async () => {
  const f = fake();
  const a = await f.s.ss([18101, 18100, 18100]);
  assert.deepStrictEqual(f.calls, ["ss -ltnH sport = :18101 or sport = :18100"]);
  assert.match(a.stdout, /:18101/);
  await f.s.ss([18100, 18101]);
  assert.strictEqual(f.calls.length, 1, "same set, other order: cached");
  await f.s.ss([18100]);
  assert.strictEqual(f.calls.length, 2, "another set is another scan");
  const many = Array.from({ length: 600 }, (_, i) => 20000 + i);
  const m = await f.s.ss(many);
  assert.strictEqual(f.calls.length, 5, "600 ports = 3 chunks (256 + 256 + 88)");
  assert.strictEqual(m.stdout.split("\n").filter((l) => l.includes("LISTEN")).length, 3);
  assert.deepStrictEqual(await f.s.ss([]), { ok: true, error: null, stdout: "" });
  assert.strictEqual(f.calls.length, 5, "no ports: nothing runs");
});

test("TTL 0 = the old behaviour: every call runs, nothing is shared", async () => {
  const f = fake({ delayMs: 10 });
  const s0 = f.make({ ttlMs: 0 });
  await Promise.all([s0.ps(), s0.ps()]);
  await s0.ps();
  await s0.ss([5]);
  await s0.ss([5]);
  assert.strictEqual(f.calls.length, 5);
  assert.strictEqual(s0.stats().entries, 0);
});

test("invalidate() drops entries and discards a scan that started before it", async () => {
  const f = fake({ delayMs: 20 });
  const first = f.s.ps();
  f.s.invalidate();
  await first;
  assert.strictEqual(f.s.stats().entries, 0, "the pre-invalidate scan is not stored");
  await f.s.ps();
  assert.strictEqual(f.s.stats().entries, 1);
  f.s.invalidate();
  assert.strictEqual(f.s.stats().entries, 0);
  await f.s.ps();
  assert.strictEqual(f.calls.length, 3);
});

test("ps without an etimes column (BSD ps) is normalised to the pid etimes args layout", async () => {
  const calls = [];
  const run = async (cmd, args) => (calls.push(args.join(" ")), { code: 0, stdout: "  101 /x/3proxy /y/3proxy_1.cfg\n  7 sshd\n", stderr: "" });
  const s = snap.createProcSnapshot({ run, ttlMs: 1000, etimes: false });
  const r = await s.ps();
  assert.deepStrictEqual(calls, ["-eo pid=,args="]);
  assert.strictEqual(r.stdout, "  101 0 /x/3proxy /y/3proxy_1.cfg\n  7 0 sshd\n");
});

test("etimes 'auto': a ps that does not know etimes is retried once without it, for good", async () => {
  const calls = [];
  const run = async (cmd, args) => {
    calls.push(args.join(" "));
    if (args[1].includes("etimes")) return { code: 1, stdout: "  1 launchd\n", stderr: "ps: etimes: keyword not found\n" };
    return { code: 0, stdout: "  1 launchd\n", stderr: "" };
  };
  const s = snap.createProcSnapshot({ run, ttlMs: 0 });
  assert.strictEqual((await s.ps()).stdout, "  1 0 launchd\n");
  await s.ps();
  assert.deepStrictEqual(calls, ["-eo pid=,etimes=,args=", "-eo pid=,args=", "-eo pid=,args="]);
  // any other failure is a failure (no retry)
  const bad = snap.createProcSnapshot({ run: async () => ({ code: 1, stdout: "", stderr: "fork failed" }), ttlMs: 0 });
  assert.deepStrictEqual(await bad.ps(), { ok: false, error: "fork failed", stdout: "" });
});

test("ttlFromEnv: unset = 10 s, 0 = off, junk = default", () => {
  assert.strictEqual(snap.ttlFromEnv({}), 10000);
  assert.strictEqual(snap.ttlFromEnv({ NODE_AGENT_SNAPSHOT_TTL_MS: "0" }), 0);
  assert.strictEqual(snap.ttlFromEnv({ NODE_AGENT_SNAPSHOT_TTL_MS: "2500" }), 2500);
  assert.strictEqual(snap.ttlFromEnv({ NODE_AGENT_SNAPSHOT_TTL_MS: "abc" }), 10000);
  assert.strictEqual(snap.ttlFromEnv({ NODE_AGENT_SNAPSHOT_TTL_MS: "-5" }), 10000);
});
