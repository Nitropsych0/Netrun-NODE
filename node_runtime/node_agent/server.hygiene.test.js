"use strict";

// Incident 2026-10-07 — the agent's hygiene wiring end to end: the generation
// lock (generationBusy) stops everything, PROXY_ROOT is the copy kept, the
// /root/proxyserver symlink resolves to the same cfg, and the post-/generate
// cron cleanup now matches the generator's /root/... line. `ps`, `ss`,
// `crontab` and `systemctl` are PATH stubs (checked to resolve before
// anything runs); the two "3proxy" processes are this test's own `sleep`
// children, so nothing else can ever be signalled.
// Run with: node --test node_runtime/node_agent/server.hygiene.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execFileSync } = require("child_process");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-hygiene-"));
const PROXY_ROOT = path.join(TMP, "opt", "netrun", "proxyserver");
const LEGACY_ROOT = path.join(TMP, "root", "proxyserver"); // the /root/proxyserver symlink
const JOBS_ROOT = path.join(TMP, "jobs");
const BIN = path.join(TMP, "bin");
const CALLS = path.join(TMP, "calls.log");
const PROCS = path.join(TMP, "procs.txt");
const CRONTAB = path.join(TMP, "crontab.txt");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(path.dirname(LEGACY_ROOT), { recursive: true });
fs.symlinkSync(PROXY_ROOT, LEGACY_ROOT);
fs.mkdirSync(JOBS_ROOT, { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
fs.writeFileSync(path.join(PROXY_ROOT, "3proxy", "3proxy_18100.cfg"), "daemon\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::a\n");
fs.writeFileSync(PROCS, "");
const stub = (name, body) => fs.writeFileSync(path.join(BIN, name), `#!/bin/sh\necho "${name} $*" >> '${CALLS}'\n${body}\n`, { mode: 0o755 });
// Only the listed pids that are still alive, like the real ps.
stub("ps", `while read -r pid age args; do kill -0 "$pid" 2>/dev/null && echo "$pid $age $args"; done < '${PROCS}'; exit 0`);
stub("ss", "echo 'LISTEN 0 4096 45.32.10.20:18100 0.0.0.0:*'");
stub("crontab", `if [ "$1" = "-l" ]; then cat '${CRONTAB}'; exit 0; fi\ncp "$1" '${CRONTAB}'`);
stub("systemctl", "echo enabled; echo enabled");
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_JOBS_ROOT = JOBS_ROOT;
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.PATH = `${BIN}:${process.env.PATH}`;
for (const name of ["ps", "ss", "crontab", "systemctl"]) {
  const resolved = execFileSync("/bin/sh", ["-c", `command -v ${name}`], { env: process.env }).toString().trim();
  if (resolved !== path.join(BIN, name)) throw new Error(`${name} resolves to ${resolved}, not the stub; refusing to run`);
}

const test = require("node:test");
const assert = require("node:assert");
const srv = require("./server.js");

const LOCK = path.join(JOBS_ROOT, ".generation.lock");
const calls = () => (fs.existsSync(CALLS) ? fs.readFileSync(CALLS, "utf-8").trim().split("\n").filter(Boolean) : []);
const writeLock = (pid) =>
  fs.writeFileSync(LOCK, JSON.stringify({ jobId: "job-1", ownerToken: "t", pid, acquiredAt: new Date().toISOString() }));

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

test("generationBusy: a live lock is busy; none / a dead pid is not", async () => {
  fs.rmSync(LOCK, { force: true });
  assert.strictEqual(await srv.generationBusy(), false);
  writeLock(process.pid);
  assert.strictEqual(await srv.generationBusy(), true);
  writeLock(2147483646);
  assert.strictEqual(await srv.generationBusy(), false);
  fs.rmSync(LOCK, { force: true });
});

test("post-/generate cron cleanup removes the generator's /root line for this start port only", async () => {
  fs.writeFileSync(
    CRONTAB,
    [
      `@reboot /usr/bin/bash ${LEGACY_ROOT}/proxy-startup_18100.sh`,
      `@reboot /usr/bin/bash ${LEGACY_ROOT}/proxy-startup_19600.sh`,
      "*/5 * * * * /opt/netrun/scripts/trend_monitor.sh",
      "",
    ].join("\n")
  );
  const res = await srv.cleanupCronStartup(path.join(PROXY_ROOT, "proxy-startup_18100.sh"));
  assert.deepStrictEqual(
    { ok: res.ok, skipped: res.skipped, outcome: res.outcome, removed: res.removed },
    { ok: true, skipped: false, outcome: "removed", removed: 1 }
  );
  assert.strictEqual(
    fs.readFileSync(CRONTAB, "utf-8"),
    `@reboot /usr/bin/bash ${LEGACY_ROOT}/proxy-startup_19600.sh\n*/5 * * * * /opt/netrun/scripts/trend_monitor.sh\n`
  );
});

test("tick: nothing while a /generate holds the lock; then the /root duplicate is reaped and the /opt one kept", { timeout: 30_000 }, async () => {
  const children = [];
  const sleeper = () => {
    const child = spawn("/bin/sleep", ["60"], { stdio: "ignore" });
    child.exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve(signal || code)));
    children.push(child);
    return child;
  };
  const cron = sleeper(); // what `@reboot bash /root/proxyserver/proxy-startup_18100.sh` started
  const restore = sleeper(); // what netrun-3proxy-restore started
  try {
    fs.writeFileSync(
      PROCS,
      [
        `${cron.pid} 500 ${LEGACY_ROOT}/3proxy/bin/3proxy ${LEGACY_ROOT}/3proxy/3proxy_18100.cfg`,
        `${restore.pid} 400 ${PROXY_ROOT}/3proxy/bin/3proxy ${PROXY_ROOT}/3proxy/3proxy_18100.cfg`,
        "",
      ].join("\n")
    );
    fs.writeFileSync(CRONTAB, `@reboot /usr/bin/bash ${LEGACY_ROOT}/proxy-startup_19600.sh\nSHELL=/bin/bash\n`);
    fs.rmSync(CALLS, { force: true });

    writeLock(process.pid);
    await srv.hygiene.tick();
    assert.deepStrictEqual(calls(), [], "lock held: crontab not read, ps not run");
    assert.strictEqual(cron.exitCode, null);
    assert.strictEqual(restore.exitCode, null);

    fs.rmSync(LOCK, { force: true });
    await srv.hygiene.tick();
    assert.strictEqual(await cron.exited, "SIGTERM", "the /root copy got SIGTERM");
    assert.strictEqual(restore.exitCode, null);
    assert.strictEqual(restore.signalCode, null, "the /opt copy keeps running");
    assert.strictEqual(fs.readFileSync(CRONTAB, "utf-8"), "SHELL=/bin/bash\n");
    const log = calls();
    assert.ok(log.includes("ps -eo pid=,etimes=,args="), log.join("\n"));
    assert.ok(log.includes("ss -ltnH sport = :18100"), log.join("\n"));
    const st = srv.hygiene.status();
    assert.strictEqual(st.duplicatesReaped, 1);
    assert.ok(st.lastReapAt);
    assert.strictEqual(st.cronLinesRemoved, 2, "1 by the post-/generate cleanup + 1 by the sweep");
  } finally {
    fs.rmSync(LOCK, { force: true });
    for (const c of children) {
      try {
        c.kill("SIGKILL");
      } catch {}
    }
  }
});
