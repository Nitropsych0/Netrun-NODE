"use strict";

// Wave FLEET-HEALTH (RES-12) — kill-on-rebind: strict mode refuses a stale
// 3proxy whose start port the orchestrator did not list (ports_in_use, nothing
// killed); a listed (or, for legacy callers, any) one is killed and ALL six
// per-start-port files are removed, so the next batch at that start port can
// never reuse the old IPv6 list or the old credentials.
// `ss` and `ps` are PATH stubs; the "3proxy" is a real `sleep` child.
// Run with: node --test node_runtime/node_agent/server.rebind_reclaim.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-rebind-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const BIN = path.join(TMP, "bin");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.PATH = `${BIN}:${process.env.PATH}`;
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const srv = require("./server.js");

const CFG = (p) => path.join(PROXY_ROOT, "3proxy", `3proxy_${p}.cfg`);

function writeStubs(pid, startPort) {
  fs.writeFileSync(
    path.join(BIN, "ss"),
    `#!/bin/sh\necho 'LISTEN 0 13 45.32.10.20:${startPort} 0.0.0.0:* users:(("3proxy",pid=${pid},fd=5))'\n` +
      `echo 'LISTEN 0 13 127.0.0.1:${startPort - 10000} 0.0.0.0:* users:(("3proxy",pid=${pid},fd=6))'\n` +
      `echo 'LISTEN 0 4096 45.32.10.20:${startPort - 10000} 0.0.0.0:* users:(("haproxy",pid=1,fd=9))'\n`,
    { mode: 0o755 }
  );
  fs.writeFileSync(
    path.join(BIN, "ps"),
    `#!/bin/sh\necho '  PID ARGS'\necho '${pid} ${PROXY_ROOT}/3proxy/bin/3proxy ${CFG(startPort)}'\n`,
    { mode: 0o755 }
  );
}

function seedBatchFiles(startPort) {
  const files = srv.perStartPortFiles(startPort);
  fs.writeFileSync(CFG(startPort), `daemon\nflush\nsocks -6 -a -p${startPort} -i45.32.10.20 -e2001:db8::1\nflush\nsocks -6 -a -p${startPort + 1} -i45.32.10.20 -e2001:db8::2\n`);
  for (const f of files.slice(1)) fs.writeFileSync(f, "stale\n");
  return files;
}

function startDummy() {
  const child = spawn("sleep", ["30"], { stdio: "ignore" });
  return child;
}

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

test("perStartPortFiles: the six generator files of a start port", () => {
  const f = srv.perStartPortFiles(18100).map((p) => path.relative(PROXY_ROOT, p));
  assert.deepStrictEqual(f, [
    "3proxy/3proxy_18100.cfg",
    "3proxy/3proxy_18100.cfg.disabled",
    "proxy-startup_18100.sh",
    "ipv6_18100.list",
    "random_users_18100.list",
    "running_server_18100.info",
  ]);
});

test("planRebindKills: strict refuses unlisted, kills listed; legacy kills all", () => {
  const instances = [
    { pid: 11, startPort: 18100, cfgPath: CFG(18100) },
    { pid: 12, startPort: 19600, cfgPath: CFG(19600) },
  ];
  const strictNone = srv.planRebindKills({ pids: [11, 12], instances, reclaimStartPorts: [], strict: true });
  assert.deepStrictEqual(strictNone.kill, []);
  assert.deepStrictEqual(strictNone.conflicts, [
    { startPort: 18100, pid: 11, cfg: CFG(18100) },
    { startPort: 19600, pid: 12, cfg: CFG(19600) },
  ]);
  const strictOne = srv.planRebindKills({ pids: [11, 12], instances, reclaimStartPorts: [18100], strict: true });
  assert.deepStrictEqual(strictOne.kill.map((k) => k.pid), [11]);
  assert.deepStrictEqual(strictOne.conflicts.map((c) => c.startPort), [19600]);
  const legacy = srv.planRebindKills({ pids: [11, 12, 13], instances, reclaimStartPorts: null, strict: false });
  assert.deepStrictEqual(legacy.kill.map((k) => k.pid), [11, 12, 13]);
  assert.deepStrictEqual(legacy.conflicts, []);
  // A 3proxy whose cfg is unknown can never be reclaimed in strict mode.
  const unknown = srv.planRebindKills({ pids: [99], instances, reclaimStartPorts: [18100], strict: true });
  assert.deepStrictEqual(unknown.conflicts, [{ startPort: null, pid: 99, cfg: null }]);
});

test("parseReclaimStartPorts: absent / list / invalid", () => {
  assert.deepStrictEqual(srv.parseReclaimStartPorts(undefined), { ok: true, provided: false, ports: [] });
  assert.deepStrictEqual(srv.parseReclaimStartPorts([]), { ok: true, provided: true, ports: [] });
  assert.deepStrictEqual(srv.parseReclaimStartPorts([18100, "18100", 19600]), { ok: true, provided: true, ports: [18100, 19600] });
  assert.strictEqual(srv.parseReclaimStartPorts("18100").ok, false);
  assert.strictEqual(srv.parseReclaimStartPorts([0]).ok, false);
  assert.strictEqual(srv.parseReclaimStartPorts([70000]).ok, false);
});

test("strict + not listed: refuse with ports_in_use, kill nothing, keep every file", async () => {
  const child = startDummy();
  try {
    writeStubs(child.pid, 18100);
    const files = seedBatchFiles(18100);
    const r = await srv.killOverlappingListeners({ newStart: 18100, newCount: 1500, reclaimStartPorts: [], strict: true });
    assert.strictEqual(r.refused, true);
    assert.strictEqual(r.error, "ports_in_use");
    assert.deepStrictEqual(r.killedPids, []);
    assert.deepStrictEqual(r.conflicts, [{ startPort: 18100, pid: child.pid, cfg: CFG(18100) }]);
    assert.ok(alive(child.pid), "the listed-nowhere batch must survive");
    for (const f of files) assert.ok(fs.existsSync(f), `kept ${path.basename(f)}`);
  } finally {
    child.kill("SIGKILL");
  }
});

test("strict + listed: kill and remove all six per-start-port files", { timeout: 15_000 }, async () => {
  const child = startDummy();
  const exited = new Promise((r) => child.once("exit", r));
  writeStubs(child.pid, 18100);
  const files = seedBatchFiles(18100);
  fs.writeFileSync(CFG(20000), "socks -6 -a -p20000 -i45.32.10.20 -e2001:db8::9\n"); // another batch
  const r = await srv.killOverlappingListeners({ newStart: 18100, newCount: 1500, reclaimStartPorts: [18100], strict: true });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.killedPids, [child.pid]);
  assert.deepStrictEqual(r.cleanedStartPorts, [18100]);
  await exited;
  for (const f of files) assert.ok(!fs.existsSync(f), `removed ${path.basename(f)}`);
  assert.ok(fs.existsSync(CFG(20000)), "an unrelated batch is untouched");
});

test("legacy caller (no reclaimStartPorts): kills as before, now also cleans the files", { timeout: 15_000 }, async () => {
  const child = startDummy();
  const exited = new Promise((r) => child.once("exit", r));
  writeStubs(child.pid, 18100);
  const files = seedBatchFiles(18100);
  const r = await srv.killOverlappingListeners({ newStart: 18100, newCount: 1500 });
  assert.deepStrictEqual(r.killedPids, [child.pid]);
  await exited;
  for (const f of files) assert.ok(!fs.existsSync(f), `removed ${path.basename(f)}`);
});

test("haproxy on the paired http port is never a conflict", async () => {
  fs.writeFileSync(
    path.join(BIN, "ss"),
    `#!/bin/sh\necho 'LISTEN 0 4096 45.32.10.20:8100 0.0.0.0:* users:(("haproxy",pid=1,fd=9))'\n`,
    { mode: 0o755 }
  );
  const r = await srv.killOverlappingListeners({ newStart: 18100, newCount: 1500, reclaimStartPorts: [], strict: true });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.conflicts, []);
  assert.deepStrictEqual(r.killedPids, []);
});

test("POST /generate with reclaimStartPorts [] over a live batch -> 200 ports_in_use, lock released", { timeout: 15_000 }, async () => {
  const child = startDummy();
  const gen = path.join(TMP, "gen.sh");
  fs.writeFileSync(gen, "#!/bin/bash\ntouch \"$JOB_DIR/ran\"\nexit 3\n", { mode: 0o755 });
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  try {
    writeStubs(child.pid, 18100);
    seedBatchFiles(18100);
    const body = JSON.stringify({
      jobId: "rebind-refused",
      generatorScript: gen,
      startPort: 18100,
      proxyCount: 1500,
      proxiesType: "dual",
      networkProfile: "high_compatibility",
      fingerprintProfileVersion: "v2_android_ipv6_only_dns_custom",
      intendedClientOsProfile: "android_mobile",
      clientOsProfileEnforcement: "not_controlled_by_proxy",
      reclaimStartPorts: [],
    });
    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port: srv.server.address().port, path: "/generate", method: "POST", headers: { "Content-Type": "application/json" } },
        (r) => {
          let t = "";
          r.on("data", (c) => (t += c));
          r.on("end", () => resolve({ status: r.statusCode, json: JSON.parse(t) }));
        }
      );
      req.on("error", reject);
      req.end(body);
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, false);
    assert.strictEqual(res.json.error, "ports_in_use");
    assert.deepStrictEqual(res.json.detail, [{ startPort: 18100, pid: child.pid, cfg: CFG(18100) }]);
    assert.ok(alive(child.pid));
    assert.ok(fs.existsSync(CFG(18100)));
    assert.ok(!fs.existsSync(path.join(process.env.NODE_AGENT_JOBS_ROOT, ".generation.lock")), "lock released");
    assert.ok(!fs.existsSync(path.join(process.env.NODE_AGENT_JOBS_ROOT, "rebind-refused", "ran")), "generator never ran");
  } finally {
    child.kill("SIGKILL");
    await new Promise((r) => srv.server.close(r));
  }
});
