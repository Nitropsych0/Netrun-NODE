"use strict";

// Incident 2026-10-07 — duplicate 3proxy reaper (hygiene.js). After a reboot
// every batch ran twice: netrun-3proxy-restore (/opt/netrun/proxyserver/...)
// plus a leftover generator @reboot line (/root/proxyserver/..., a symlink to
// the same directory). The fake host below serves `ps` / `ss` from a process
// table that kill() really changes, so the real planning + signalling code
// runs end to end. Run with:
//   node --test node_runtime/node_agent/hygiene.dedupe.test.js

const test = require("node:test");
const assert = require("node:assert");

const h = require("./hygiene.js");

const NOW = Date.parse("2026-10-07T12:00:00.000Z");
const OPT = "/opt/netrun/proxyserver";
const ROOT = "/root/proxyserver";
const viaRoot = (sp) => `${ROOT}/3proxy/bin/3proxy ${ROOT}/3proxy/3proxy_${sp}.cfg`;
const viaOpt = (sp) => `${OPT}/3proxy/bin/3proxy ${OPT}/3proxy/3proxy_${sp}.cfg`;
// Never 3proxy processes, although their command lines name a 3proxy cfg.
const NOISE = [
  { pid: 900, age: 2, args: `bash -c setsid "${OPT}/3proxy/bin/3proxy" "${OPT}/3proxy/3proxy_18100.cfg" </dev/null` },
  { pid: 901, age: 3000, args: "/usr/bin/node /opt/netrun/node_runtime/node_agent/server.js" },
  { pid: 902, age: 1, args: "pgrep -f 3proxy_18100\\.cfg" },
  { pid: 903, age: 50, args: "[3proxy] <defunct>" },
];

function fakeHost({ procs, listening = [], busy = false, cfgs = {}, env = {}, psFails = false, ssFails = false, onPs = null } = {}) {
  const state = {
    procs: [...procs, ...NOISE].map((p) => ({ ...p })),
    calls: [],
    kills: [],
    logs: [],
    busy,
    psCount: 0,
  };
  const run = async (cmd, args) => {
    state.calls.push([cmd, ...args].join(" "));
    if (cmd === "ps") {
      state.psCount += 1;
      if (onPs) onPs(state.psCount, state);
      if (psFails) return { code: 1, stdout: "", stderr: "ps: boom" };
      const text = state.procs.map((p) => `${String(p.pid).padStart(7)} ${String(p.age).padStart(7)} ${p.args}`).join("\n");
      return { code: 0, stdout: `${text}\n`, stderr: "" };
    }
    if (cmd === "ss") {
      if (ssFails) return { code: 1, stdout: "", stderr: "ss: boom" };
      const asked = [...String(args[1]).matchAll(/:(\d+)/g)].map((m) => Number(m[1]));
      const rows = asked.filter((p) => listening.includes(p)).map((p) => `LISTEN 0 4096 45.32.10.20:${p} 0.0.0.0:*`);
      return { code: 0, stdout: rows.join("\n"), stderr: "" };
    }
    return { code: 127, stdout: "", stderr: `unexpected ${cmd}` };
  };
  const kill = (pid, signal) => {
    state.kills.push([pid, signal]);
    const i = state.procs.findIndex((p) => p.pid === pid);
    if (i < 0) {
      const err = new Error("kill ESRCH");
      err.code = "ESRCH";
      throw err;
    }
    if (signal === "SIGKILL" || !state.procs[i].stubborn) state.procs.splice(i, 1);
  };
  const realpath = async (dir) => (dir.startsWith(`${ROOT}/`) || dir === ROOT ? OPT + dir.slice(ROOT.length) : dir);
  const readFile = async (p) => {
    if (Object.prototype.hasOwnProperty.call(cfgs, p)) return cfgs[p];
    const err = new Error(`ENOENT ${p}`);
    err.code = "ENOENT";
    throw err;
  };
  const sink = (level) => (msg) => state.logs.push(`${level} ${msg}`);
  const hygiene = h.createHygiene({
    env,
    run,
    kill,
    realpath,
    readFile,
    sleep: async () => {},
    now: () => NOW,
    isGenerationBusy: async () => (typeof state.busy === "function" ? state.busy() : state.busy),
    preferRoot: OPT,
    log: { log: sink("log"), warn: sink("warn"), error: sink("error") },
  });
  return { hygiene, state };
}

const signals = (state, sig) => state.kills.filter(([, s]) => s === sig).map(([pid]) => pid);

test("one cfg via /root and /opt: the /root copy is killed, even though it is older", async () => {
  const { hygiene, state } = fakeHost({
    procs: [
      { pid: 101, age: 50, args: viaRoot(18100) }, // cron @reboot, started first
      { pid: 202, age: 40, args: viaOpt(18100) }, // netrun-3proxy-restore
      { pid: 303, age: 60, args: viaRoot(19600) }, // a batch that runs once
    ],
    listening: [18100, 19600],
  });
  const res = await hygiene.dedupe();
  assert.strictEqual(res.outcome, "ok");
  assert.deepStrictEqual(state.kills, [[101, "SIGTERM"]]);
  assert.deepStrictEqual(res.reaped, [{ pid: 101, cfg: `${ROOT}/3proxy/3proxy_18100.cfg`, startPort: 18100, keptPid: 202 }]);
  assert.deepStrictEqual(state.procs.filter((p) => p.pid < 900).map((p) => p.pid), [202, 303]);
  assert.ok(state.logs.includes(
    `log [hygiene] dedupe: ${OPT}/3proxy/3proxy_18100.cfg (start port 18100) runs 2 times; keeping pid 202 (${OPT}/3proxy/3proxy_18100.cfg, up 40s)`
  ), state.logs.join("\n"));
  assert.ok(state.logs.includes(`log [hygiene] dedupe: SIGTERM pid 101 (${ROOT}/3proxy/3proxy_18100.cfg, up 50s), duplicate of pid 202`));
  assert.ok(state.logs.includes("log [hygiene] dedupe: reaped 1 duplicate 3proxy process(es); 1 since agent start"));
  const st = hygiene.status();
  assert.strictEqual(st.duplicatesReaped, 1);
  assert.strictEqual(st.lastReapAt, new Date(NOW).toISOString());
  assert.strictEqual(st.lastDedupeOutcome, "ok");

  // Converged: the next round finds one process per cfg and asks nothing more.
  state.calls.length = 0;
  const again = await hygiene.dedupe();
  assert.deepStrictEqual(again.reaped, []);
  assert.deepStrictEqual(state.calls, ["ps -eo pid=,etimes=,args="]);
  assert.strictEqual(state.kills.length, 1);
  assert.strictEqual(hygiene.status().duplicatesReaped, 1);
});

test("two /opt processes: the older is kept; a SIGTERM survivor is SIGKILLed; no /opt copy -> oldest kept", async () => {
  const { hygiene, state } = fakeHost({
    procs: [
      { pid: 300, age: 100, args: viaOpt(18100), stubborn: true },
      { pid: 301, age: 900, args: viaOpt(18100) },
      { pid: 401, age: 10, args: viaRoot(21100) },
      { pid: 402, age: 20, args: viaRoot(21100) },
      { pid: 403, age: 5, args: viaRoot(21100) },
    ],
    listening: [18100, 21100],
  });
  const res = await hygiene.dedupe();
  assert.deepStrictEqual(signals(state, "SIGTERM").sort(), [300, 401, 403]);
  assert.deepStrictEqual(signals(state, "SIGKILL"), [300], "only the stubborn one");
  assert.deepStrictEqual(state.procs.filter((p) => p.pid < 900).map((p) => p.pid), [301, 402]);
  assert.deepStrictEqual(res.reaped.map((r) => [r.pid, r.keptPid]).sort(), [[300, 301], [401, 402], [403, 402]]);
  assert.ok(state.logs.includes("log [hygiene] dedupe: SIGKILL pid 300: still alive 3000 ms after SIGTERM"));
  assert.strictEqual(hygiene.status().duplicatesReaped, 3);
});

test("a cfg with a single process is never killed (no ss probe either)", async () => {
  const { hygiene, state } = fakeHost({
    procs: [
      { pid: 101, age: 50, args: viaRoot(18100) },
      { pid: 202, age: 40, args: viaOpt(19600) },
      { pid: 203, age: 40, args: `/tmp/other/3proxy /tmp/other/3proxy_21100.cfg` },
      { pid: 204, age: 40, args: `${OPT}/3proxy/bin/3proxy 3proxy_21100.cfg` }, // relative: unknown file
    ],
    listening: [18100, 19600, 21100],
  });
  const res = await hygiene.dedupe();
  assert.deepStrictEqual(res.reaped, []);
  assert.deepStrictEqual(state.kills, []);
  assert.deepStrictEqual(state.calls, ["ps -eo pid=,etimes=,args="]);
  assert.strictEqual(hygiene.status().duplicatesReaped, 0);
  assert.strictEqual(hygiene.status().lastReapAt, null);
});

test("generation lock held: no ps, no kill; a lock taken before the kill stops it too", async () => {
  const procs = [
    { pid: 101, age: 50, args: viaRoot(18100) },
    { pid: 202, age: 40, args: viaOpt(18100) },
  ];
  const held = fakeHost({ procs, listening: [18100], busy: true });
  const res = await held.hygiene.dedupe();
  assert.strictEqual(res.outcome, "generation_in_progress");
  assert.strictEqual(res.skipped, true);
  assert.deepStrictEqual(held.state.calls, []);
  assert.deepStrictEqual(held.state.kills, []);
  assert.strictEqual(held.hygiene.status().lastDedupeOutcome, "generation_in_progress");

  let asked = 0;
  const racing = fakeHost({ procs, listening: [18100], busy: () => (asked += 1) > 1 });
  const late = await racing.hygiene.dedupe();
  assert.strictEqual(late.outcome, "generation_in_progress");
  assert.deepStrictEqual(racing.state.kills, []);

  const unknown = h.createHygiene({
    env: {},
    run: async () => assert.fail("must not run anything"),
    kill: () => assert.fail("must not kill"),
    isGenerationBusy: async () => {
      throw new Error("lock unreadable");
    },
    log: { log() {}, warn() {}, error() {} },
  });
  assert.strictEqual((await unknown.dedupe()).outcome, "generation_in_progress", "an unknown lock counts as held");
});

test("a cfg none of whose probe ports listens is left alone; the cfg's first socks port counts", async () => {
  const procs = [
    { pid: 101, age: 50, args: viaRoot(18100) },
    { pid: 202, age: 40, args: viaOpt(18100) },
  ];
  const booting = fakeHost({ procs, listening: [] });
  const res = await booting.hygiene.dedupe();
  assert.deepStrictEqual(res.reaped, []);
  assert.deepStrictEqual(booting.state.kills, []);
  assert.ok(booting.state.logs.includes(
    `warn [hygiene] dedupe: ${OPT}/3proxy/3proxy_18100.cfg runs 2 times but none of port(s) 18100 listens; left alone`
  ), booting.state.logs.join("\n"));

  // /deprovision dropped the start port's block; the batch serves from 18105.
  const cfg = "daemon\nflush\nsocks -6 -a -p18105 -i45.32.10.20 -e2001:db8::5\nproxy -6 -n -a -p8105 -i45.32.10.20 -e2001:db8::5\n";
  const rewritten = fakeHost({ procs, listening: [18105], cfgs: { [`${OPT}/3proxy/3proxy_18100.cfg`]: cfg } });
  const ok = await rewritten.hygiene.dedupe();
  assert.deepStrictEqual(rewritten.state.kills, [[101, "SIGTERM"]]);
  assert.strictEqual(ok.reaped.length, 1);
  assert.ok(rewritten.state.calls.includes("ss -ltnH sport = :18100 or sport = :18105"), rewritten.state.calls.join("\n"));
});

test("ps / ss failures and a keeper that vanished: nothing is killed", async () => {
  const procs = [
    { pid: 101, age: 50, args: viaRoot(18100) },
    { pid: 202, age: 40, args: viaOpt(18100) },
  ];
  const noPs = fakeHost({ procs, listening: [18100], psFails: true });
  assert.strictEqual((await noPs.hygiene.dedupe()).outcome, "ps_failed");
  assert.deepStrictEqual(noPs.state.kills, []);

  const noSs = fakeHost({ procs, listening: [18100], ssFails: true });
  const r2 = await noSs.hygiene.dedupe();
  assert.strictEqual(r2.outcome, "ss_failed");
  assert.strictEqual(r2.ok, false);
  assert.deepStrictEqual(noSs.state.kills, []);
  assert.ok(noSs.state.logs.some((l) => l.startsWith("error [hygiene] dedupe: ss failed")));

  // The process to keep exits between the first snapshot and the kill: the
  // remaining one is now the cfg's LAST process.
  const gone = fakeHost({
    procs,
    listening: [18100],
    onPs: (n, st) => {
      if (n === 2) st.procs = st.procs.filter((p) => p.pid !== 202);
    },
  });
  const r3 = await gone.hygiene.dedupe();
  assert.deepStrictEqual(r3.reaped, []);
  assert.deepStrictEqual(gone.state.kills, []);
  assert.ok(gone.state.logs.some((l) => l.includes("pid 202 to keep is gone; left alone this round")));

  // A duplicate whose pid now runs something else is not touched.
  const recycled = fakeHost({
    procs,
    listening: [18100],
    onPs: (n, st) => {
      if (n === 2) st.procs = st.procs.map((p) => (p.pid === 101 ? { ...p, args: "/usr/sbin/sshd -D" } : p));
    },
  });
  await recycled.hygiene.dedupe();
  assert.deepStrictEqual(recycled.state.kills, []);
});

test("NODE_AGENT_DEDUPE_3PROXY=0: no ps, no kill", async () => {
  const { hygiene, state } = fakeHost({
    procs: [
      { pid: 101, age: 50, args: viaRoot(18100) },
      { pid: 202, age: 40, args: viaOpt(18100) },
    ],
    listening: [18100],
    env: { NODE_AGENT_DEDUPE_3PROXY: "0" },
  });
  const res = await hygiene.dedupe();
  assert.strictEqual(res.outcome, "disabled");
  assert.deepStrictEqual(state.calls, []);
  assert.strictEqual(hygiene.status().dedupe3proxy, false);
});

test("settings: switches default on, interval default 600 s and at least 60 s", () => {
  assert.deepStrictEqual(h.readSettings({}), { dedupe: true, cronHygiene: "on", intervalSec: 600 });
  assert.deepStrictEqual(
    h.readSettings({ NODE_AGENT_DEDUPE_3PROXY: "off", NODE_AGENT_CRON_HYGIENE: "0", NODE_AGENT_HYGIENE_INTERVAL_SEC: "900" }),
    { dedupe: false, cronHygiene: "off", intervalSec: 900 }
  );
  assert.strictEqual(h.readSettings({ NODE_AGENT_CRON_HYGIENE: "FORCE" }).cronHygiene, "force");
  assert.strictEqual(h.readSettings({ NODE_AGENT_CRON_HYGIENE: "1" }).cronHygiene, "on");
  assert.strictEqual(h.readSettings({ NODE_AGENT_DEDUPE_3PROXY: "no" }).dedupe, false);
  assert.strictEqual(h.readSettings({ NODE_AGENT_DEDUPE_3PROXY: "" }).dedupe, true);
  assert.strictEqual(h.readSettings({ NODE_AGENT_HYGIENE_INTERVAL_SEC: "5" }).intervalSec, 60);
  assert.strictEqual(h.readSettings({ NODE_AGENT_HYGIENE_INTERVAL_SEC: "abc" }).intervalSec, 600);
  assert.strictEqual(h.readSettings({ NODE_AGENT_HYGIENE_INTERVAL_SEC: "0" }).intervalSec, 600);
});

test("parsePsProcesses / planDedupe: only real 3proxy with an absolute 3proxy_<p>.cfg", () => {
  const text = [
    `    101      50 ${viaRoot(18100)}`,
    `    202      40 ${viaOpt(18100)}`,
    ...NOISE.map((p) => `${p.pid} ${p.age} ${p.args}`),
    `    205      40 3proxy /etc/3proxy/3proxy.cfg`,
    "garbage line",
    "",
  ].join("\n");
  const procs = h.parsePsProcesses(text);
  assert.deepStrictEqual(procs.map((p) => [p.pid, p.ageSec, p.startPort]), [[101, 50, 18100], [202, 40, 18100]]);
  const plans = h.planDedupe(
    procs.map((p) => ({ ...p, key: `${OPT}/3proxy/3proxy_18100.cfg` })),
    { preferRoot: `${OPT}/` }
  );
  assert.strictEqual(plans.length, 1);
  assert.strictEqual(plans[0].keep.pid, 202);
  assert.deepStrictEqual(plans[0].kill.map((p) => p.pid), [101]);
  // Equal age: the lower pid is the older one.
  const tie = h.planDedupe([
    { pid: 7, ageSec: 5, cfgArg: "/x/3proxy_1.cfg", startPort: 1, key: "k" },
    { pid: 6, ageSec: 5, cfgArg: "/x/3proxy_1.cfg", startPort: 1, key: "k" },
  ]);
  assert.strictEqual(tie[0].keep.pid, 6);
  assert.deepStrictEqual(h.planDedupe([{ pid: 7, ageSec: 5, cfgArg: "/x/3proxy_1.cfg", startPort: 1, key: "k" }]), []);
});

test("start(): cron at once, first dedupe after 60 s, both every interval; stop() clears", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const calls = [];
  const hyg = h.createHygiene({
    env: { NODE_AGENT_HYGIENE_INTERVAL_SEC: "600" },
    run: async (cmd, args) => {
      calls.push(`${cmd} ${args[0]}`);
      if (cmd === "crontab") return { code: 0, stdout: "*/5 * * * * /opt/netrun/scripts/trend_monitor.sh\n", stderr: "" };
      return { code: 0, stdout: "", stderr: "" };
    },
    kill: () => assert.fail("nothing to kill"),
    log: { log() {}, warn() {}, error() {} },
  });
  const flush = async () => {
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
  };
  hyg.start();
  await flush();
  assert.deepStrictEqual(calls, ["crontab -l"], "cron hygiene runs at start, dedupe does not");
  t.mock.timers.tick(59_000);
  await flush();
  assert.deepStrictEqual(calls, ["crontab -l"]);
  t.mock.timers.tick(1_000);
  await flush();
  assert.deepStrictEqual(calls, ["crontab -l", "ps -eo"], "first dedupe one minute after start");
  t.mock.timers.tick(540_000);
  await flush();
  assert.deepStrictEqual(calls, ["crontab -l", "ps -eo", "crontab -l", "ps -eo"], "both on the 600 s tick");
  hyg.stop();
  t.mock.timers.tick(600_000);
  await flush();
  assert.strictEqual(calls.length, 4, "stopped");
});
