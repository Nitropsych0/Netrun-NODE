"use strict";

// Wave FLEET-HEALTH (SPD-05) — the counter dump is parsed ONCE per poll cycle
// into Map(port -> {in, out, in6}) and every chunk is served from it; the nft
// dump runs with a 20 s timeout instead of execCapture's 5 s SIGKILL default.
process.env.NODE_AGENT_COUNTERS_CACHE_GAP_MS = "50";
process.env.NODE_AGENT_COUNTERS_CACHE_MAX_MS = "5000";
delete process.env.NODE_AGENT_NFT_DUMP_TIMEOUT_MS;

const test = require("node:test");
const assert = require("node:assert");
const accounting = require("./accounting");

const ctr = (name, bytes, table = "proxy_accounting") => ({ counter: { family: "inet", table, name, bytes } });

test("parseCounterItems builds port -> {in, out, in6} in one pass, ignoring noise", () => {
  const map = accounting.parseCounterItems([
    { metainfo: { version: "1.0.9" } },
    ctr("proxy_18100_in", 10),
    ctr("proxy_18100_out", 20),
    ctr("proxy_18100_in6", 3),
    ctr("proxy_18101_out", 7),
    ctr("proxy_18102_in", 99, "other_table"),
    ctr("garbage", 1),
    null,
  ]);
  assert.ok(map instanceof Map);
  assert.deepStrictEqual(map.get(18100), { in: 10, out: 20, in6: 3 });
  assert.deepStrictEqual(map.get(18101), { in: 0, out: 7, in6: 0 });
  assert.strictEqual(map.has(18102), false, "foreign table ignored");
  assert.strictEqual(map.size, 2);
});

test("a whole poll cycle of 100-port chunks parses the dump exactly once", async () => {
  accounting._resetCountersCache();
  const items = [];
  for (let p = 18100; p < 18100 + 3000; p += 1) items.push(ctr(`proxy_${p}_in`, p), ctr(`proxy_${p}_out`, p * 2));
  let dumps = 0;
  accounting._setCounterItemsFetcher(async () => {
    dumps += 1;
    return items;
  });
  for (let start = 18100; start < 18100 + 3000; start += 100) {
    const chunk = Array.from({ length: 100 }, (_, i) => start + i);
    const out = await accounting.getCountersForPorts(chunk);
    assert.strictEqual(Object.keys(out).length, 100);
    assert.deepStrictEqual(out[String(start)], { bytes_in: start, bytes_out: start * 2 });
  }
  assert.strictEqual(dumps, 1, "one nft dump per cycle");
  assert.strictEqual(accounting._counterParses(), 1, "one parse per dump (not one per chunk)");
  accounting._setCounterItemsFetcher(null);
});

test("unknown ports are omitted; billing shape unchanged (in6 not summed)", async () => {
  accounting._resetCountersCache();
  accounting._setCounterItemsFetcher(async () => [ctr("proxy_30000_in", 5), ctr("proxy_30000_out", 6), ctr("proxy_30000_in6", 50)]);
  const out = await accounting.getCountersForPorts([30000, 30001]);
  assert.deepStrictEqual(out, { 30000: { bytes_in: 5, bytes_out: 6 } });
  accounting._setCounterItemsFetcher(null);
});

test("the nft dump is run with a 20 s timeout (not the 5 s execCapture default)", async () => {
  assert.strictEqual(accounting.NFT_DUMP_TIMEOUT_MS, 20000);
  let seen = null;
  accounting._setDumpExec(async (cmd, args, opts) => {
    seen = { cmd, args, opts };
    return { code: 0, stdout: JSON.stringify({ nftables: [ctr("proxy_18100_out", 42)] }), stderr: "" };
  });
  const items = await accounting._fetchAllCounterItems();
  assert.strictEqual(seen.cmd, "nft");
  assert.deepStrictEqual(seen.args, ["-j", "list", "counters", "table", "inet", "proxy_accounting"]);
  assert.strictEqual(seen.opts.timeoutMs, 20000);
  assert.strictEqual(items.length, 1);
  accounting._setDumpExec(null);
});

test("a killed / failed dump still raises nft_list_counters_failed", async () => {
  accounting._setDumpExec(async () => ({ code: -1, stdout: "", stderr: "" }));
  await assert.rejects(() => accounting._fetchAllCounterItems(), /nft_list_counters_failed/);
  accounting._setDumpExec(null);
});
