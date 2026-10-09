"use strict";

// Pay-per-GB v2, amendment A12 — smart rotation, the agent's half
// (pergb_smart.js, pergb_psl.js): record classification, the 5-minute window
// and its thresholds, the doubling avoid period, the ctl `avoid` deltas and
// the full push after a RADIUS epoch change, PSL site keys (the shared
// vectors), the pair cap.
// Run with: node --test node_runtime/node_agent/pergb_smart.test.js

const test = require("node:test");
const assert = require("node:assert");
const smartLib = require("./pergb_smart.js");
const psl = require("./pergb_psl.js");
const T = require("./pergb_testlib.js");
const vectors = require("../radius/tests/psl_vectors.json");

const QUIET = { log() {}, error() {} };

test("PSL: the shared site-key vectors (co.uk, github.io, IDN, wildcards, exceptions, IP fallbacks)", () => {
  const data = psl.loadDefault();
  assert.ok(data.size > 5000, "the vendored list is loaded");
  for (const v of vectors.vectors) assert.strictEqual(psl.siteKey(v.host, v.dst, data), v.site, `${v.host} / ${v.dst}`);
});

test("classifyRecord: code 13 and 0-byte replies fail; ≥ 1 KiB succeeds; 11/12/15 are our side", () => {
  const r = (o) => ({ code: 0, inBytes: 0, outBytes: 0, interim: false, ...o });
  assert.strictEqual(smartLib.classifyRecord(r({ code: 13 })), "fail");
  assert.strictEqual(smartLib.classifyRecord(r({ inBytes: 0, outBytes: 517 })), "fail", "reset after the ClientHello");
  assert.strictEqual(smartLib.classifyRecord(r({ inBytes: 0, outBytes: 517 }), true), null, "a session that had interim records");
  assert.strictEqual(smartLib.classifyRecord(r({ inBytes: 2048, outBytes: 517 })), "ok");
  assert.strictEqual(smartLib.classifyRecord(r({ inBytes: 500, outBytes: 517 })), null, "neutral");
  for (const c of [11, 12, 15]) assert.strictEqual(smartLib.classifyRecord(r({ code: c })), "own");
});

function setup() {
  let t = 1_790_000_000_000;
  const now = () => t;
  const ctl = T.fakeCtl({});
  const tagger = T.tagger();
  const s = smartLib.createSmart({ now, ctl, log: QUIET, tagger: () => tagger, excluded: () => new Set([0x99]) });
  let port = 40000;
  const rec = (net, o = {}) => ({
    t: now(),
    code: 0,
    inBytes: 0,
    outBytes: 517,
    interim: false,
    host: "shop.example.co.uk",
    dstIp: "93.184.216.34",
    localIp: "127.0.0.3",
    port: 31000,
    clientIp: "127.0.0.1",
    clientPort: port++,
    bound: tagger.address(net, 7, port % 65536),
    ...o,
  });
  return { s, ctl, rec, advance: (ms) => (t += ms), now };
}

test("verdict: ≥ 3 failures and ≥ 50 % in 5 min → avoid the /64 for that site 30 min; others untouched", async () => {
  const { s, ctl, rec } = setup();
  s.observe([rec(0x10), rec(0x10, { inBytes: 5000 }), rec(0x10, { code: 13 })]);
  assert.strictEqual(s._active.size, 0, "2 failures of 3: not yet");
  s.observe([rec(0x10)]);
  assert.strictEqual(s._active.size, 1);
  const ok = () => rec(0x11, { inBytes: 5000 });
  s.observe([ok(), ok(), rec(0x11), rec(0x11), ok(), ok(), rec(0x11)]);
  assert.strictEqual(s._active.size, 1, "3 failures of 7 < 50 %");
  s.observe([rec(0x11)]);
  assert.strictEqual(s._active.size, 2, "4 of 8 = 50 %");
  // a per-piece /64 and our-side errors never count
  s.observe([rec(0x99), rec(0x99), rec(0x99), rec(0x12, { code: 12 }), rec(0x12, { code: 12 }), rec(0x12, { code: 15 })]);
  assert.strictEqual(s._active.size, 2);
  assert.strictEqual(s.status().bindErrors, 3);
  const r = await s.push();
  assert.strictEqual(r.full, true, "the first push is the full set");
  const call = ctl.calls.find((c) => c.op === "avoid");
  assert.deepStrictEqual(call.body.entries.map((e) => [e.net, e.site]).sort(), [[0x10, "example.co.uk"], [0x11, "example.co.uk"]]);
  assert.ok(call.body.entries.every((e) => e.until > 0));
  const st = s.status();
  assert.strictEqual(st.avoidedPairs, 2);
  assert.strictEqual(st.sites, 1);
  assert.deepStrictEqual(st.top[0].site, "example.co.uk");
});

test("window: failures older than 5 min drop out; the avoid period doubles on a repeat within 24 h (cap 12 h); a success after it clears", async () => {
  const { s, ctl, rec, advance, now } = setup();
  s.observe([rec(0x20), rec(0x20)]);
  advance(6 * 60 * 1000);
  s.observe([rec(0x20)]);
  assert.strictEqual(s._active.size, 0, "only 1 failure left in the window");
  s.observe([rec(0x20), rec(0x20)]);
  const until1 = s._active.get(`${0x20}|example.co.uk`);
  assert.strictEqual(until1 - now(), smartLib.BASE_AVOID_MS);
  await s.push();
  // expiry → removed delta
  advance(smartLib.BASE_AVOID_MS + 1000);
  const r = await s.push();
  assert.deepStrictEqual(r, { pushed: 0, removed: 1, full: false });
  assert.deepStrictEqual(ctl.calls.at(-1).body.removed, [{ net: 0x20, site: "example.co.uk" }]);
  // repeat within 24 h: 1 h
  s.observe([rec(0x20), rec(0x20), rec(0x20)]);
  assert.strictEqual(s._active.get(`${0x20}|example.co.uk`) - now(), 2 * smartLib.BASE_AVOID_MS);
  for (let i = 0; i < 6; i += 1) {
    advance(s._active.get(`${0x20}|example.co.uk`) - now() + 1000); // past the period, still within 24 h of it
    s.maintain();
    s.observe([rec(0x20), rec(0x20), rec(0x20)]);
  }
  assert.strictEqual(s._active.get(`${0x20}|example.co.uk`) - now(), smartLib.MAX_AVOID_MS, "capped at 12 h");
  // after expiry one success clears the history: the next verdict is 30 min again
  advance(smartLib.MAX_AVOID_MS + 1000);
  s.maintain();
  s.observe([rec(0x20, { inBytes: 4096 })]);
  s.observe([rec(0x20), rec(0x20), rec(0x20)]);
  assert.strictEqual(s._active.get(`${0x20}|example.co.uk`) - now(), smartLib.BASE_AVOID_MS);
});

test("delivery: deltas, the full set after a RADIUS epoch change, retry when RADIUS lacks the op", async () => {
  const { s, ctl, rec, advance } = setup();
  s.observe([rec(0x30), rec(0x30), rec(0x30)]);
  await s.push();
  s.observe([rec(0x31, { host: "other.org" }), rec(0x31, { host: "other.org" }), rec(0x31, { host: "other.org" })]);
  let r = await s.push();
  assert.deepStrictEqual(r, { pushed: 1, removed: 0, full: false });
  r = await s.push();
  assert.strictEqual(r.skipped, "nothing");
  s.onRadiusEpoch();
  r = await s.push();
  assert.strictEqual(r.full, true);
  assert.strictEqual(r.pushed, 2);
  // a RADIUS without `avoid`
  ctl.call = async (op) => {
    ctl.calls.push({ op });
    const e = new Error("unknown_op");
    e.code = "unknown_op";
    throw e;
  };
  s.onRadiusEpoch();
  r = await s.push();
  assert.strictEqual(r.error, "unknown_op");
  r = await s.push();
  assert.strictEqual(r.skipped, "unsupported");
  advance(5 * 60 * 1000 + 1);
  r = await s.push();
  assert.strictEqual(r.error, "unknown_op", "retried after 5 min");
  assert.strictEqual(s.status().radiusSupport, false);
});

test("memory: tracked pairs stay capped", () => {
  const { s, rec } = setup();
  for (let i = 0; i < 1000; i += 1) s.observe([rec(0x40 + (i % 50), { host: `site${i}.com`, inBytes: 4096 })]);
  assert.ok(s.status().trackedPairs <= 1000);
});
