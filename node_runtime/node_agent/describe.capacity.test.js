"use strict";

// Wave CAPACITY-18K — /describe capacity model (describe.js).
// Run with: node --test node_runtime/node_agent/describe.capacity.test.js

const test = require("node:test");
const assert = require("node:assert");
const https = require("https");
const path = require("path");

// buildDescribe() geolocates via https.get — keep the test offline.
https.get = () => {
  const { EventEmitter } = require("events");
  const req = new EventEmitter();
  req.destroy = () => {};
  process.nextTick(() => req.emit("error", new Error("offline test")));
  return req;
};

const describe = require(path.resolve(__dirname, "describe.js"));
const { estimateCapacity, capacityFromMemTotalMb, parseMemTotalMb, CAPACITY_MODEL } = describe;

const meminfo = (totalKb, availKb = 100000) =>
  `MemTotal:       ${totalKb} kB\nMemFree:          50000 kB\nMemAvailable:   ${availKb} kB\n`;

// Vultr MemTotal per plan (report §3: ~3.8 / 7.7 / 15.6 GiB).
const GIB_KB = 1024 * 1024;
const PLAN_2C_4GB = Math.round(3.8 * GIB_KB);
const PLAN_4C_8GB = Math.round(7.7 * GIB_KB);
const PLAN_8C_16GB = Math.round(15.6 * GIB_KB);

test("2c/4GB box: capacity allows the 18k target (was clamped to 5000)", () => {
  const cap = estimateCapacity({ meminfoText: meminfo(PLAN_2C_4GB) });
  assert.ok(cap >= 18000, `4 GB capacity ${cap} < 18000`);
  assert.ok(cap <= CAPACITY_MODEL.portCeiling, `4 GB capacity ${cap} above the port ceiling`);
  // ~0.1 MB per proxy + per-process overhead, NOT 0.5 MB: the old model gave
  // (MemAvailable - 200) / 0.5 -> at most ~7000 before the 5000 clamp.
  assert.ok(cap > 3 * 5000, "capacity still behaves like the 0.5 MB/proxy model");
});

test("per-proxy cost is ~0.1 MB plus per-process overhead", () => {
  const perProxyMb = CAPACITY_MODEL.perProxyKb / 1024 + CAPACITY_MODEL.perProcessMb / CAPACITY_MODEL.avgBatchSize;
  assert.ok(perProxyMb > 0.09 && perProxyMb < 0.12, `per-proxy budget ${perProxyMb} MB`);
  // +1 GB of RAM -> ~0.85 GB usable -> roughly 8000 more proxies (below the ceiling).
  const a = capacityFromMemTotalMb(3000);
  const b = capacityFromMemTotalMb(4000);
  assert.ok(b - a > 7000 && b - a < 9000, `delta per GB = ${b - a}`);
});

test("bigger plans are capped by the single-IPv4 dual port ceiling (27 436)", () => {
  assert.strictEqual(estimateCapacity({ meminfoText: meminfo(PLAN_4C_8GB) }), 27436);
  assert.strictEqual(estimateCapacity({ meminfoText: meminfo(PLAN_8C_16GB) }), 27436);
  assert.strictEqual(CAPACITY_MODEL.portCeiling, 27436);
});

test("capacity is a property of the box (MemTotal), not of how full it is (MemAvailable)", () => {
  const empty = estimateCapacity({ meminfoText: meminfo(PLAN_2C_4GB, PLAN_2C_4GB - 300000) });
  const full = estimateCapacity({ meminfoText: meminfo(PLAN_2C_4GB, 200000) });
  assert.strictEqual(empty, full);
});

test("tiny box floors at minCapacity; unreadable meminfo falls back to 5000", () => {
  assert.strictEqual(estimateCapacity({ meminfoText: meminfo(512 * 1024) }), CAPACITY_MODEL.minCapacity);
  assert.strictEqual(estimateCapacity({ meminfoText: "garbage" }), 5000);
  assert.strictEqual(estimateCapacity({ meminfoText: "" }), 5000);
  assert.strictEqual(parseMemTotalMb("MemTotal: 2048 kB"), 2);
  assert.strictEqual(parseMemTotalMb("nope"), null);
});

test("buildDescribe keeps max_batch_size 1500 / max_parallel_jobs 1 and exposes the model", async () => {
  const d = await describe.buildDescribe({});
  assert.strictEqual(d.max_batch_size, 1500);
  assert.strictEqual(d.max_parallel_jobs, 1);
  assert.ok(Number.isInteger(d.capacity) && d.capacity >= 100, `capacity ${d.capacity}`);
  assert.strictEqual(d.capacity_model.perProxyKb, 100);
  assert.strictEqual(d.capacity_model.portCeiling, 27436);
});
