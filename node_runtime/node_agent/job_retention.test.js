"use strict";

// Wave FLEET-HEALTH — bounded retention of /opt/netrun/jobs: keep the newest
// N job directories plus every directory something still needs (the live
// lock's job, a generation in progress, the newest ready job of every batch
// that still has a cfg). Run with:
//   node --test node_runtime/node_agent/job_retention.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");

const r = require("./job_retention.js");

const NOW = Date.parse("2026-10-07T03:00:00.000Z");
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const entry = (name, minAgo, extra = {}) => ({
  name,
  mtimeMs: NOW - minAgo * 60_000,
  meta: { jobId: name, status: "ready", updatedAt: iso(minAgo), params: { startPort: 0 }, ...extra },
});

test("keepFromEnv: default 200, 0/negative/garbage disable", () => {
  assert.strictEqual(r.keepFromEnv(undefined), 200);
  assert.strictEqual(r.keepFromEnv(""), 200);
  assert.strictEqual(r.keepFromEnv("50"), 50);
  assert.strictEqual(r.keepFromEnv("0"), 0);
  assert.strictEqual(r.keepFromEnv("-3"), 0);
  assert.strictEqual(r.keepFromEnv("abc"), 0);
});

test("planJobPrune keeps the newest N, removes the rest oldest-first", () => {
  const entries = [];
  for (let i = 0; i < 10; i += 1) entries.push(entry(`job-${i}`, i * 10)); // job-0 newest
  const plan = r.planJobPrune(entries, { keep: 4, nowMs: NOW });
  assert.deepStrictEqual(plan.keep, ["job-0", "job-1", "job-2", "job-3"]);
  assert.deepStrictEqual(plan.remove, ["job-9", "job-8", "job-7", "job-6", "job-5", "job-4"]);
});

test("protected beyond N: lock job, fresh running job, newest ready job of a live cfg", () => {
  const entries = [
    entry("new-1", 1),
    entry("new-2", 2),
    entry("locked", 500, { status: "running" }), // the lock names it (even if stale-looking)
    entry("running-fresh", 600, { status: "running", updatedAt: iso(10) }),
    entry("running-stale", 700, { status: "running", updatedAt: iso(700) }),
    entry("cfg-18100-newest", 800, { params: { startPort: 18100 } }),
    entry("cfg-18100-older", 900, { params: { startPort: 18100 } }),
    entry("deprovisioned-20000", 950, { params: { startPort: 20000 } }),
    entry("failed-old", 1000, { status: "failed", params: { startPort: 18100 } }),
  ];
  // running-fresh's sort key is its updatedAt (10 min ago) -> it is the 3rd
  // newest; keep=2 still keeps it as an in-progress generation.
  const plan = r.planJobPrune(entries, {
    keep: 2,
    nowMs: NOW,
    staleMs: 30 * 60_000,
    lockJobId: "locked",
    cfgStartPorts: new Set([18100]),
  });
  assert.deepStrictEqual(new Set(plan.keep), new Set(["new-1", "new-2", "locked", "running-fresh", "cfg-18100-newest"]));
  assert.deepStrictEqual(plan.remove, ["failed-old", "deprovisioned-20000", "cfg-18100-older", "running-stale"]);
});

test("names outside the job-id alphabet are never planned; keep 0 = off", () => {
  const entries = [entry(".hidden", 1), entry("../escape", 2), entry("ok-1", 3), entry("ok-2", 4)];
  const plan = r.planJobPrune(entries, { keep: 1, nowMs: NOW });
  assert.deepStrictEqual(plan.keep, ["ok-1"]);
  assert.deepStrictEqual(plan.remove, ["ok-2"]);
  assert.deepStrictEqual(r.planJobPrune(entries, { keep: 0 }).remove, []);
});

test("pruneJobDirs on disk: 250 jobs -> 200 newest + protected kept, lock file untouched", async () => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "netrun-jobs-"));
  const cfgDir = await fsp.mkdtemp(path.join(os.tmpdir(), "netrun-cfg-"));
  try {
    for (let i = 0; i < 250; i += 1) {
      const name = `job-${String(i).padStart(3, "0")}`; // job-000 oldest
      await fsp.mkdir(path.join(root, name));
      const meta = { jobId: name, status: "ready", updatedAt: new Date(NOW - (250 - i) * 60_000).toISOString(), params: { startPort: 30000 + i } };
      await fsp.writeFile(path.join(root, name, "job.json"), JSON.stringify(meta));
      await fsp.writeFile(path.join(root, name, "proxies.list"), "x\n");
    }
    await fsp.mkdir(path.join(root, "no-meta-old"));
    await fsp.utimes(path.join(root, "no-meta-old"), new Date(NOW - 10 * 86400_000), new Date(NOW - 10 * 86400_000));
    await fsp.writeFile(path.join(root, ".generation.lock"), "{}");
    await fsp.writeFile(path.join(cfgDir, "3proxy_30003.cfg"), "socks\n"); // job-003 is a live batch's job
    await fsp.writeFile(path.join(cfgDir, "3proxy_30004.cfg.disabled"), "socks\n"); // so is job-004 (disabled cfg)

    const res = await r.pruneJobDirs({ jobsRoot: root, cfgDir, keep: 200, lockJobId: "job-010", nowMs: NOW });
    assert.strictEqual(res.ok, true);
    assert.strictEqual(res.scanned, 251);
    const left = new Set(fs.readdirSync(root));
    assert.ok(left.has(".generation.lock"), "lock file never touched");
    assert.ok(left.has("job-249") && left.has("job-050"), "200 newest kept");
    assert.ok(!left.has("job-049"), "201st newest removed");
    assert.ok(left.has("job-003") && left.has("job-004"), "newest ready job of a cfg on disk kept");
    assert.ok(left.has("job-010"), "the lock's job kept");
    assert.ok(!left.has("job-000") && !left.has("no-meta-old"), "old dirs removed");
    assert.strictEqual(res.removed.length, 251 - 203);

    const again = await r.pruneJobDirs({ jobsRoot: root, cfgDir, keep: 200, lockJobId: "job-010", nowMs: NOW });
    assert.deepStrictEqual(again.removed, [], "idempotent");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(cfgDir, { recursive: true, force: true });
  }
});

test("pruneJobDirs: missing root is reported, never thrown; keep 0 is a no-op", async () => {
  const res = await r.pruneJobDirs({ jobsRoot: path.join(os.tmpdir(), "netrun-no-such-dir-xyz"), keep: 5 });
  assert.strictEqual(res.ok, false);
  const off = await r.pruneJobDirs({ jobsRoot: os.tmpdir(), keep: 0 });
  assert.deepStrictEqual(off, { ok: true, scanned: 0, removed: [], kept: 0 });
});
