"use strict";

// Pay-per-GB v2 — pergb_guards.js: admission thresholds and hysteresis
// (slice memory / pids), the log filesystem and meter-lag closes, the IPv4
// local-port guard, the RADIUS probe and its recovery calls.
// Run with: node --test node_runtime/node_agent/pergb_guards.test.js

const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const guardsLib = require("./pergb_guards.js");
const T = require("./pergb_testlib.js");

const QUIET = { log() {}, error() {} };
const SLICE = "/netrun.slice/netrun-pergb.slice";

test("admission level: soft at 90 %, hard at 100 %, back to soft under 90 %, open under 80 %", () => {
  const seq = [[50, "open"], [89.9, "open"], [90, "soft"], [85, "soft"], [100, "hard"], [95, "hard"], [89, "soft"], [81, "soft"], [79.9, "open"], [101, "hard"], [70, "open"]];
  let lvl = "open";
  for (const [pct, want] of seq) {
    lvl = guardsLib.nextLevel(lvl, pct);
    assert.strictEqual(lvl, want, `at ${pct} %`);
  }
  assert.strictEqual(guardsLib.nextLevel("soft", null), "soft", "no reading: unchanged");
});

test("IPv4 admission: closes at 60 %, reopens at 50 %", () => {
  let open = true;
  for (const [pct, want] of [[59, true], [60, false], [55, false], [50.1, false], [50, true], [70, false], [null, false]]) {
    open = guardsLib.nextIpv4Open(open, pct);
    assert.strictEqual(open, want, `at ${pct} %`);
  }
});

test("countLocalPorts: distinct local ports of the address inside the range, any state", () => {
  const text = [
    "ESTAB 0 0 203.0.113.5:2000 93.184.216.34:443",
    "TIME-WAIT 0 0 203.0.113.5:2000 93.184.216.35:443",
    "ESTAB 0 0 203.0.113.5:9000 93.184.216.34:443",
    "SYN-SENT 0 1 203.0.113.5:3000 93.184.216.34:80",
    "ESTAB 0 0 203.0.113.6:2001 93.184.216.34:443",
    "LISTEN 0 4096 203.0.113.5:8100 0.0.0.0:*",
  ].join("\n");
  assert.strictEqual(guardsLib.countLocalPorts(text, "203.0.113.5", 1024, 8000), 2);
});

function env({ mem = 50, pids = 10, freePct = 50, lag = 0, portsUsed = 0, sessions = new Map(), probe = null } = {}) {
  const files = {};
  const set = (m, p) => {
    files[path.join("/cg", SLICE, "memory.current")] = String(Math.round(m * 10 * 1024 * 1024));
    files[path.join("/cg", SLICE, "memory.high")] = String(1000 * 1024 * 1024);
    files[path.join("/cg", SLICE, "memory.max")] = String(1200 * 1024 * 1024);
    files[path.join("/cg", SLICE, "pids.current")] = String(p * 100);
    files[path.join("/cg", SLICE, "pids.max")] = "10000";
  };
  set(mem, pids);
  files["/proc/range"] = "1024\t8000\n";
  const st = { freePct, lag, portsUsed };
  const ctl = T.fakeCtl({ status: { epoch: 1, seq: 0 } });
  const runCalls = [];
  const run = async (cmd, args) => {
    runCalls.push([cmd, ...args]);
    if (cmd === "ss") {
      const ip = args[args.indexOf("src") + 1];
      let out = "";
      for (let i = 0; i < st.portsUsed; i += 1) out += `ESTAB 0 0 ${ip}:${1024 + i} 93.184.216.34:443\n`;
      return { code: 0, stdout: out, stderr: "" };
    }
    if (cmd === "timedatectl") return { code: 0, stdout: "yes\n", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  let t = 1_790_000_000_000;
  const now = () => t;
  const g = guardsLib.createGuards({
    ctl,
    run,
    now,
    log: QUIET,
    readFile: (p) => {
      if (p in files) return files[p];
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
    statfs: () => ({ blocks: 1000, bavail: Math.round(st.freePct * 10), bsize: 4096 }),
    settings: { cgroupRoot: "/cg", sliceCgroup: SLICE, logDir: "/logs", portRangeFile: "/proc/range" },
    enable: () => ({ sliceMemMax: 1200 * 1024 * 1024 }),
    egressIpv4s: () => ["203.0.113.5"],
    meterLagSec: () => st.lag,
    liveSessions: async () => sessions,
    probe,
  });
  return { g, ctl, run, runCalls, set, st, advance: (ms) => (t += ms) };
}

test("tick: admission pushed every tick with the soft accounts (> 20 % of live sessions)", async () => {
  const sessions = new Map([
    [10, 50],
    [20, 30],
    [30, 15],
    [40, 5],
  ]);
  const e = env({ mem: 50, sessions });
  let s = await e.g.tick();
  assert.strictEqual(s.admissionOpen, true);
  assert.deepStrictEqual(s.softAccounts, []);
  e.set(93, 10); // memory 93 % of memory.high
  s = await e.g.tick();
  assert.strictEqual(s.level, "soft");
  assert.deepStrictEqual(s.softAccounts, [10, 20]);
  e.set(30, 101); // pids over the max
  s = await e.g.tick();
  assert.strictEqual(s.admissionOpen, false);
  assert.deepStrictEqual(s.closedBy, ["memory"]);
  e.set(30, 50);
  s = await e.g.tick();
  assert.strictEqual(s.admissionOpen, true);
  assert.strictEqual(s.level, "open");
  const adm = e.ctl.calls.filter((c) => c.op === "admission").map((c) => [c.body.open, c.body.softAccounts.length]);
  assert.deepStrictEqual(adm, [[true, 0], [true, 2], [false, 0], [true, 0]]);
  assert.strictEqual(e.ctl.calls.filter((c) => c.op === "ipv4_admission").length, 4);
  assert.strictEqual(s.clockSynced, true);
});

test("tick: log filesystem < 10 % free or meter lag > 30 s close admission for everyone", async () => {
  const e = env();
  e.st.freePct = 9;
  let s = await e.g.tick();
  assert.strictEqual(s.admissionOpen, false);
  assert.deepStrictEqual(s.closedBy, ["log_fs"]);
  e.st.freePct = 40;
  e.st.lag = 31;
  s = await e.g.tick();
  assert.deepStrictEqual(s.closedBy, ["meter_lag"]);
  e.st.lag = 1;
  s = await e.g.tick();
  assert.strictEqual(s.admissionOpen, true);
});

test("tick: IPv4 local ports on the egress IPv4 drive ipv4_admission with hysteresis", async () => {
  const e = env();
  const size = 8000 - 1024 + 1;
  e.st.portsUsed = Math.ceil(size * 0.61);
  let s = await e.g.tick();
  assert.strictEqual(s.ipv4AdmissionOpen, false);
  assert.ok(s.ipv4PortsPct >= 60);
  e.st.portsUsed = Math.ceil(size * 0.55);
  s = await e.g.tick();
  assert.strictEqual(s.ipv4AdmissionOpen, false, "still closed above 50 %");
  e.st.portsUsed = Math.floor(size * 0.49);
  s = await e.g.tick();
  assert.strictEqual(s.ipv4AdmissionOpen, true);
  const pushed = e.ctl.calls.filter((c) => c.op === "ipv4_admission").map((c) => c.body.open);
  assert.deepStrictEqual(pushed, [false, false, true]);
});

test("probe: 2 failures in a row → reset-failed + socket restart (at most every 30 s), alive=false; a success → alive", async () => {
  const verdicts = ["accept", "timeout", "timeout", "timeout", "accept"];
  const e = env({ probe: async () => {
    const v = verdicts.shift();
    return { ok: v === "accept", verdict: v, ms: 1 };
  } });
  assert.strictEqual(await e.g.probeTick(), true);
  assert.strictEqual(e.g.status().radiusAlive, true);
  await e.g.probeTick();
  assert.strictEqual(e.g.status().radiusAlive, true, "one failure is not enough");
  await e.g.probeTick();
  assert.strictEqual(e.g.status().radiusAlive, false);
  const sys = e.runCalls.filter((c) => c[0] === "systemctl");
  assert.deepStrictEqual(sys, [
    ["systemctl", "reset-failed", "netrun-radius.socket", "netrun-radius.service"],
    ["systemctl", "restart", "netrun-radius.socket"],
  ]);
  await e.g.probeTick();
  assert.strictEqual(e.runCalls.filter((c) => c[0] === "systemctl").length, 2, "throttled");
  e.advance(31000);
  await e.g.probeTick();
  assert.strictEqual(e.g.status().radiusAlive, true);
  assert.strictEqual(e.g.status().probe.recoveries, 1);
});

test("probe not configured: liveness from the ctl socket", async () => {
  const e = env({ probe: async () => null });
  assert.strictEqual(await e.g.probeTick(), true);
  assert.strictEqual(e.g.status().probe.last.verdict, "not_configured");
});
