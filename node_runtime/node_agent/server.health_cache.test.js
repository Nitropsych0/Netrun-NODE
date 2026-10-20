"use strict";

// Audit P-N4 — GET /health scans ps / ss once per snapshot TTL, not once per call.
// `ps` and `ss` are PATH stubs that log every spawn; the TTL is 2.5 s so the
// "second batch after the TTL" part needs no fake clock. The mutating callers'
// invalidation (process lock, generation lock) is checked on the same server.
// Run with: node --test node_runtime/node_agent/server.health_cache.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-health-cache-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const BIN = path.join(TMP, "bin");
const SPAWNS = path.join(TMP, "spawns.log");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.PATH = `${BIN}:${process.env.PATH}`;
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NETRUN_ENV_FILE = path.join(TMP, "no-netrun.env");
process.env.NODE_AGENT_SNAPSHOT_TTL_MS = "2500";
delete process.env.NETRUN_IPV6_ROUTED_PREFIX;
fs.writeFileSync(path.join(BIN, "ss"), `#!/bin/sh\necho "ss $*" >> ${SPAWNS}\necho 'LISTEN 0 13 45.32.10.20:18100 0.0.0.0:*'\n`, { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "ps"), `#!/bin/sh\necho "ps $*" >> ${SPAWNS}\necho '  41 1 /opt/3proxy/bin/3proxy ${PROXY_ROOT}/3proxy/3proxy_18100.cfg'\n`, { mode: 0o755 });
fs.writeFileSync(path.join(PROXY_ROOT, "3proxy", "3proxy_18100.cfg"), "daemon\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::a\n");

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const { server, procSnapshot } = require("./server.js");
const { withProcessLock } = require("./process_lock.js");

const get = (port, p) =>
  new Promise((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port, path: p, headers: { "X-API-KEY": "test-key" } }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve(JSON.parse(body)));
      })
      .on("error", reject);
  });
const spawns = (re) => (fs.existsSync(SPAWNS) ? fs.readFileSync(SPAWNS, "utf8").split("\n").filter((l) => re.test(l)).length : 0);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test("P-N4: N consecutive /health calls spawn ps and ss once inside the TTL; again after it; a locked change invalidates", { timeout: 30_000 }, async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const port = server.address().port;
    procSnapshot.invalidate();
    fs.rmSync(SPAWNS, { force: true });
    const first = await get(port, "/health");
    for (let i = 0; i < 5; i += 1) await get(port, "/health");
    // other callers (hygiene, supervisor timers) may have scanned too: they are fresh reads, never fewer
    assert.strictEqual(spawns(/^ps /), 1, fs.readFileSync(SPAWNS, "utf8") + JSON.stringify(first.scanCache));
    assert.strictEqual(spawns(/^ss /), 1);
    assert.strictEqual(first.instances.count, 1, "the cached view still answers: one 3proxy");
    assert.deepStrictEqual(first.cfgs, [{ startPort: 18100, count: 1, listening: true, pid: 41 }]);
    assert.ok(first.scanCache && first.scanCache.ttlMs === 2500, JSON.stringify(first.scanCache));
    const last = await get(port, "/health");
    assert.ok(last.scanCache.hits >= 2 && last.scanCache.misses >= 1, JSON.stringify(last.scanCache));

    await wait(2600); // past the TTL
    await get(port, "/health");
    assert.strictEqual(spawns(/^ps /), 2, "the second batch scans again");
    assert.strictEqual(spawns(/^ss /), 2);

    // a change of the process table (any locked section) drops the snapshot at once
    await withProcessLock(async () => {});
    await get(port, "/health");
    assert.strictEqual(spawns(/^ps /), 3);
    assert.strictEqual(spawns(/^ss /), 3);
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(TMP, { recursive: true, force: true });
  }
});
