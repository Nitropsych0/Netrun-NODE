"use strict";

// Audit P-N3 — the nft counter dump grows with every port: its timeout scales with the
// counter count of the last dump, a slow or failed dump is logged (rate-limited), and the
// last duration / count are readable. The dump itself is faked (_setDumpExec).
// Run with: node --test node_runtime/node_agent/accounting.dump_cost.test.js
delete process.env.NODE_AGENT_NFT_DUMP_TIMEOUT_MS;
delete process.env.NODE_AGENT_NFT_DUMP_TIMEOUT_MAX_MS;
process.env.NODE_AGENT_NFT_DUMP_WARN_MS = "30";

const test = require("node:test");
const assert = require("node:assert");
const accounting = require("./accounting");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const itemsJson = (n) => JSON.stringify({ nftables: Array.from({ length: n }, (_, i) => ({ counter: { family: "inet", table: "proxy_accounting", name: `proxy_${30000 + (i >> 1)}_${i & 1 ? "out" : "in"}`, bytes: i } })) });

function capture() {
  const out = { warn: [], error: [] };
  const w = console.warn;
  const e = console.error;
  console.warn = (m) => out.warn.push(String(m));
  console.error = (m) => out.error.push(String(m));
  out.restore = () => {
    console.warn = w;
    console.error = e;
  };
  return out;
}

test("the dump timeout scales with the last counter count: 20 s floor, 6 x the expected time, 60 s ceiling", async () => {
  accounting._resetDumpState();
  assert.strictEqual(accounting.NFT_DUMP_TIMEOUT_MS, 20000, "the base default is unchanged");
  assert.strictEqual(accounting._dumpTimeoutMs(), 20000, "nothing dumped yet: the floor");
  const asked = [];
  for (const n of [1000, 55000, 200000]) {
    accounting._setDumpExec(async (cmd, args, opts) => (asked.push(opts.timeoutMs), { code: 0, stdout: itemsJson(n), stderr: "" }));
    await accounting._fetchAllCounterItems();
  }
  accounting._setDumpExec(null);
  // asked: the timeout used BY each dump = what the previous dump's size called for
  assert.deepStrictEqual(asked, [20000, 20000, Math.ceil((55000 / 12000) * 1100 * 6)]);
  assert.strictEqual(accounting._dumpTimeoutMs(), 60000, "200k counters: capped");
  assert.strictEqual(accounting.NFT_DUMP_TIMEOUT_MAX_MS, 60000);
  assert.strictEqual(accounting.getCounterDumpStats().lastCount, 200000);
});

test("a dump slower than the threshold is logged once per interval, with duration and item count", async () => {
  accounting._resetDumpState();
  const log = capture();
  try {
    accounting._setDumpExec(async () => (await sleep(60), { code: 0, stdout: itemsJson(10), stderr: "" }));
    await accounting._fetchAllCounterItems();
    await accounting._fetchAllCounterItems();
  } finally {
    accounting._setDumpExec(null);
    log.restore();
  }
  assert.strictEqual(log.warn.length, 1, log.warn.join("\n"));
  assert.match(log.warn[0], /slow nft counter dump: \d+ ms for 10 items/);
  const st = accounting.getCounterDumpStats();
  assert.strictEqual(st.slowCount, 2, "both are counted, one is logged");
  assert.ok(st.lastMs >= 50);
  // a fast dump is silent
  accounting._resetDumpState();
  const quiet = capture();
  try {
    accounting._setDumpExec(async () => ({ code: 0, stdout: itemsJson(10), stderr: "" }));
    await accounting._fetchAllCounterItems();
  } finally {
    accounting._setDumpExec(null);
    quiet.restore();
  }
  assert.deepStrictEqual(quiet.warn, []);
});

test("a failed dump logs the duration, timeout and last count once, and still throws NftablesError", async () => {
  accounting._resetDumpState();
  const log = capture();
  let err1;
  let err2;
  try {
    accounting._setDumpExec(async () => ({ code: -1, stdout: "", stderr: "timeout" }));
    await accounting._fetchAllCounterItems().catch((e) => (err1 = e));
    await accounting._fetchAllCounterItems().catch((e) => (err2 = e));
  } finally {
    accounting._setDumpExec(null);
    log.restore();
  }
  for (const e of [err1, err2]) {
    assert.ok(e instanceof accounting.NftablesError);
    assert.strictEqual(e.message, "nft_list_counters_failed");
  }
  assert.strictEqual(log.error.length, 1);
  assert.match(log.error[0], /nft counter dump failed after \d+ ms \(timeout 20000 ms, 0 counters at the last dump\): timeout/);
  assert.strictEqual(accounting.getCounterDumpStats().failCount, 2);
});
