"use strict";

// Audit RES-11 — the 3proxy supervisor (supervisor.js) against a fake host:
// ps / ss / systemctl / ip are a fake `run`, the cfg inventory is the real
// cfg_status.createCfgInventory over a temp dir (so *.cfg.disabled is
// excluded exactly as on a node), spawnCfg is a recorder. Nothing here can
// signal or start a real process.
// Run with: node --test node_runtime/node_agent/supervisor.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert");
const sup = require("./supervisor.js");
const cfgStatus = require("./cfg_status.js");
const { withProcessLock } = require("./process_lock.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-supervisor-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const quietLog = { log() {}, warn() {}, error() {} };

// /proc/net/if_inet6 line: 32 hex, ifindex, plen, scope, flags, ifname.
function inet6Line(addr, { plen = 0x80, scope = 0, flags = 0x82, ifname = "enp1s0" } = {}) {
  const hex = cfgStatus.ipv6ToHex(addr);
  const h2 = (n) => n.toString(16).padStart(2, "0");
  return `${hex} 02 ${h2(plen)} ${h2(scope)} ${h2(flags)} ${ifname}`;
}

test("planRespawns: a batch is respawned only when dead on two ticks, outside the settle window, under the hourly cap", () => {
  const state = { downSince: new Map(), history: new Map(), failed: new Map() };
  const cfgs = [
    { startPort: 18100, probePort: 18100, mtimeMs: 0, cfgPath: "/c/3proxy_18100.cfg" },
    { startPort: 20000, probePort: 20001, mtimeMs: 0, cfgPath: "/c/3proxy_20000.cfg" },
    { startPort: 30000, probePort: 30000, mtimeMs: 0, cfgPath: "/c/3proxy_30000.cfg" },
  ];
  const keyOf = (c) => c.cfgPath;
  const base = { keyOf, settleMs: 120_000, maxPerHour: 2, state, bootMs: 500 }; // cfgs written before the boot
  // 18100 runs; 20000 listens on its first socks port (no ps match); 30000 is dead.
  let plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(["/c/3proxy_18100.cfg"]), listening: new Set([20001]), nowMs: 1_000_000 });
  assert.deepStrictEqual(plan.respawn, []);
  assert.deepStrictEqual(plan.pending, [30000], "first sighting is only remembered");
  plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(["/c/3proxy_18100.cfg"]), listening: new Set([20001]), nowMs: 1_060_000 });
  assert.deepStrictEqual(plan.respawn.map((c) => c.startPort), [30000], "second sighting -> respawn");
  // Hourly cap: two respawns recorded -> failed, logged once.
  state.history.set(30000, [1_000_000, 1_060_000]);
  plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(), listening: new Set([20001, 18100]), nowMs: 1_120_000 });
  assert.deepStrictEqual(plan.respawn, []);
  assert.deepStrictEqual(plan.failedNew, [{ startPort: 30000, respawns: 2 }]);
  plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(), listening: new Set([20001, 18100]), nowMs: 1_180_000 });
  assert.deepStrictEqual(plan.failedNew, [], "failed is reported once");
  assert.deepStrictEqual(plan.respawn, []);
  // It listens again -> recovered; a rewritten cfg is tried again.
  plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(), listening: new Set([20001, 18100, 30000]), nowMs: 1_200_000 });
  assert.deepStrictEqual(plan.recovered, [30000]);
  // Settle: a cfg written 30 s ago is never touched.
  const fresh = [{ startPort: 40000, probePort: 40000, mtimeMs: 1_290_000, cfgPath: "/c/3proxy_40000.cfg" }];
  plan = sup.planRespawns(fresh, { ...base, bootMs: 1_300_000, runningKeys: new Set(), listening: new Set(), nowMs: 1_320_000 });
  assert.deepStrictEqual(plan.settling, [40000]);
  assert.deepStrictEqual(plan.pending, []);
  // A cfg that disappeared is forgotten.
  assert.ok(!state.history.has(30000) && !state.failed.has(30000), "state pruned for cfgs no longer on disk");
});

test("planRespawns: only a batch that DIED (seen serving) or was due since boot (cfg older than the boot) is respawned", () => {
  const state = { downSince: new Map(), history: new Map(), failed: new Map(), seen: new Set() };
  const keyOf = (c) => c.cfgPath;
  const base = { keyOf, settleMs: 0, maxPerHour: 5, state, bootMs: 1_000_000 };
  const cfgs = [
    { startPort: 18100, probePort: 18100, mtimeMs: 2_000_000, cfgPath: "/c/18100" }, // generated after boot, served
    { startPort: 20000, probePort: 20000, mtimeMs: 2_000_000, cfgPath: "/c/20000" }, // failed generation: never served
    { startPort: 30000, probePort: 30000, mtimeMs: 500_000, cfgPath: "/c/30000" }, // from before the boot, never started
  ];
  let plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(), listening: new Set([18100]), nowMs: 3_000_000 });
  assert.deepStrictEqual(plan.unsupervised, [20000]);
  assert.deepStrictEqual(plan.pending, [30000]);
  assert.ok(state.seen.has(18100));
  // 18100 dies: it was seen serving -> supervised.
  plan = sup.planRespawns(cfgs, { ...base, runningKeys: new Set(), listening: new Set(), nowMs: 3_060_000 });
  assert.deepStrictEqual(plan.pending, [18100]);
  assert.deepStrictEqual(plan.respawn.map((c) => c.startPort), [30000]);
  assert.deepStrictEqual(plan.unsupervised, [20000], "a never-served post-boot cfg is never started");
});

test("planAnchors: re-add only addresses of a /64 the node has; deprecate only nodad anchors not yet deprecated", () => {
  const rows = sup.parseIfInet6Rows(
    [
      inet6Line("2001:db8:0:1:5400:6ff:febe:b5cf", { plen: 64, flags: 0x00 }), // primary (SLAAC, no nodad)
      inet6Line("2001:db8:0:1::a", { flags: 0x82 }), // anchor, preferred
      inet6Line("2001:db8:0:1::b", { flags: 0xa2 }), // anchor, already deprecated
      inet6Line("2001:db8:0:1::c", { plen: 64, flags: 0x80 }), // a cfg address WITHOUT nodad (never deprecated)
      inet6Line("fe80::1", { plen: 64, scope: 0x20, flags: 0x80 }),
    ].join("\n")
  );
  const cfgs = [
    { egress: ["2001:db8:0:1::a", "2001:db8:0:1::b", "2001:db8:0:1::d"] },
    { egress: ["2001:db8:0:1::c", "2001:db8:9:9::1", "2001:db8:0:1:0:0:0:a"] },
  ];
  const plan = sup.planAnchors(cfgs, rows, { iface: "enp1s0" });
  assert.strictEqual(plan.expected, 5, "duplicates collapse (::a twice)");
  assert.deepStrictEqual(plan.missing, ["2001:db8:0:1::d"], "a lost prefix (2001:db8:9:9) is not re-added");
  assert.deepStrictEqual(plan.pendingDeprecate, [{ addr: "2001:db8:0:1:0:0:0:a", plen: 128, ifname: "enp1s0" }]);
  assert.strictEqual(
    sup.readdBatchText(["2001:db8:0:1::d"], "enp1s0"),
    "address add 2001:db8:0:1::d/128 dev enp1s0 nodad preferred_lft 0\n"
  );
  assert.strictEqual(sup.readdBatchText(["2001:db8:0:1::d"], "enp1s0", { deprecate: false }), "address add 2001:db8:0:1::d/128 dev enp1s0 nodad\n");
  assert.strictEqual(
    sup.deprecateBatchText(plan.pendingDeprecate),
    "address change 2001:db8:0:1:0:0:0:a/128 dev enp1s0 nodad valid_lft forever preferred_lft 0\n"
  );
});

// A fake node: cfg dir on disk, ps / ss / systemctl / ip answered from state.
function fakeNode(name, { cfgs = {}, env = {}, nowMs = 10_000_000, bootTimeMs = () => Date.now() } = {}) {
  const dir = path.join(TMP, name, "3proxy");
  fs.mkdirSync(dir, { recursive: true });
  for (const [file, text] of Object.entries(cfgs)) {
    fs.writeFileSync(path.join(dir, file), text);
    fs.utimesSync(path.join(dir, file), new Date(0), new Date(0)); // long settled
  }
  const host = {
    procs: [], // "pid etimes args"
    listening: new Set(),
    restoreState: "active",
    ifInet6: "",
    calls: [],
    batches: [],
    busy: false,
    spawned: [],
    nowMs,
    onPs: null,
  };
  const run = async (cmd, args) => {
    host.calls.push(`${cmd} ${args.join(" ")}`);
    if (cmd === "ps") {
      if (host.onPs) host.onPs();
      return { code: 0, stdout: host.procs.join("\n"), stderr: "" };
    }
    if (cmd === "ss") {
      const ports = [...String(args[1]).matchAll(/:(\d+)/g)].map((m) => Number(m[1]));
      return { code: 0, stdout: ports.filter((p) => host.listening.has(p)).map((p) => `LISTEN 0 13 1.2.3.4:${p} 0.0.0.0:*`).join("\n"), stderr: "" };
    }
    if (cmd === "systemctl") return { code: 0, stdout: `${host.restoreState}\n`, stderr: "" };
    if (cmd === "ip" && args[0] === "-6" && args[1] === "route") return { code: 0, stdout: "default via fe80::1 dev enp1s0 proto ra metric 100\n", stderr: "" };
    if (cmd === "ip" && args.includes("-batch")) {
      host.batches.push(fs.readFileSync(args[args.length - 1], "utf-8"));
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: `unexpected ${cmd}` };
  };
  const inventory = cfgStatus.createCfgInventory({ cfgDir: dir });
  const statusPath = path.join(TMP, name, "supervisor.json");
  const supervisor = sup.createSupervisor({
    env: { NODE_AGENT_SUPERVISOR_STATUS_FILE: statusPath, NETRUN_ENV_FILE: path.join(TMP, "none.env"), ...env },
    readCfgs: () => inventory.read(),
    spawnCfg: async (cfgPath) => {
      host.spawned.push(cfgPath);
      host.procs.push(`${4000 + host.spawned.length} 1 /opt/netrun/proxyserver/3proxy/bin/3proxy ${cfgPath}`);
      return { ok: true, outcome: "spawned", pid: 4000 + host.spawned.length, via: "helper" };
    },
    run,
    readFile: async () => host.ifInet6,
    isGenerationBusy: async () => host.busy,
    processLock: withProcessLock,
    now: () => host.nowMs,
    log: quietLog,
    bootTimeMs, // default: every fixture cfg (mtime 1970) predates the boot
  });
  return { dir, host, supervisor, statusPath };
}

const CFG = (sp, addr) => `daemon\nnserver 127.0.0.1\nflush\nsocks -6 -a -p${sp} -i1.2.3.4 -e${addr}\nproxy -6 -n -a -p${sp - 10000} -i127.0.0.1 -e${addr}\n`;

test("tick: a dead batch is respawned on the second tick through spawnCfg; *.cfg.disabled never; running/listening never", async () => {
  const { dir, host, supervisor, statusPath } = fakeNode("respawn", {
    cfgs: {
      "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a"),
      "3proxy_20000.cfg": CFG(20000, "2001:db8:0:1::b"),
      "3proxy_30000.cfg.disabled": CFG(30000, "2001:db8:0:1::c"),
      "3proxy_40000.cfg": CFG(40000, "2001:db8:0:1::d"),
    },
  });
  // 18100 runs through the /root symlink path (its realpath is the same dir in the
  // fake: realpath of a nonexistent dir falls back to the path itself), 40000 listens.
  host.procs = [`77 500 /opt/netrun/proxyserver/3proxy/bin/3proxy ${path.join(dir, "3proxy_18100.cfg")}`];
  host.listening = new Set([40000]);
  let r = await supervisor.tick();
  assert.strictEqual(r.outcome, "ok");
  assert.deepStrictEqual(host.spawned, [], "first sighting: nothing started");
  assert.deepStrictEqual(supervisor.status().pendingDown, [20000]);
  host.nowMs += 60_000;
  r = await supervisor.tick();
  assert.deepStrictEqual(host.spawned, [path.join(dir, "3proxy_20000.cfg")]);
  const st = supervisor.status();
  assert.strictEqual(st.cfgsRespawned, 1);
  assert.strictEqual(st.lastRespawns[0].startPort, 20000);
  assert.deepStrictEqual(st.pendingDown, []);
  const file = JSON.parse(fs.readFileSync(statusPath, "utf-8"));
  assert.strictEqual(file.cfgsRespawned, 1, "status file written");
  // It now runs (the fake spawn added a process): the next ticks leave it alone.
  host.nowMs += 60_000;
  await supervisor.tick();
  host.nowMs += 60_000;
  await supervisor.tick();
  assert.strictEqual(host.spawned.length, 1);
  assert.ok(!host.spawned.some((p) => p.includes("30000")), "a .cfg.disabled is never started");
});

test("tick: nothing while a generation holds the lock or the boot restore runs; the lock is re-checked right before a spawn", async () => {
  const { host, supervisor } = fakeNode("busy", { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") } });
  host.busy = true;
  assert.strictEqual((await supervisor.tick()).outcome, "generation_in_progress");
  assert.ok(!host.calls.some((c) => c.startsWith("ps")), "no process scan under the generation lock");
  host.busy = false;
  host.restoreState = "activating";
  assert.strictEqual((await supervisor.tick()).outcome, "boot_restore_running");
  host.restoreState = "active";
  await supervisor.tick(); // first sighting
  host.nowMs += 60_000;
  // A /generate takes the lock between the plan and the spawn.
  const realCalls = host.calls.length;
  let psCount = 0;
  const origProcs = host.procs;
  Object.defineProperty(host, "procs", {
    get() {
      psCount += 1;
      if (psCount === 1) host.busy = true; // after the planning ps, the lock appears
      return origProcs;
    },
    set() {},
    configurable: true,
  });
  const r = await supervisor.tick();
  assert.strictEqual(r.outcome, "generation_in_progress");
  assert.deepStrictEqual(host.spawned, [], "no spawn once the generation lock is held");
  assert.ok(host.calls.length > realCalls);
});

test("tick: the shared process lock serialises the supervisor behind a running reap (hygiene)", async () => {
  const { host, supervisor } = fakeNode("lock", { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") } });
  await supervisor.tick();
  host.nowMs += 60_000;
  const order = [];
  let release;
  const reap = withProcessLock(async () => {
    order.push("reap:start");
    await new Promise((r) => { release = r; });
    order.push("reap:end");
  });
  const tick = supervisor.tick().then(() => order.push("supervisor:done"));
  await new Promise((r) => setTimeout(r, 30));
  assert.deepStrictEqual(host.spawned, [], "the respawn waits for the lock");
  release();
  await reap;
  await tick;
  assert.deepStrictEqual(order, ["reap:start", "reap:end", "supervisor:done"]);
  assert.strictEqual(host.spawned.length, 1);
});

test("tick: past NODE_AGENT_SUPERVISOR_MAX_RESPAWNS_PER_HOUR the batch is marked failed and left alone", async () => {
  const { host, supervisor } = fakeNode("ratelimit", {
    cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") },
    env: { NODE_AGENT_SUPERVISOR_MAX_RESPAWNS_PER_HOUR: "2" },
  });
  for (let i = 0; i < 8; i += 1) {
    host.procs = []; // every respawned 3proxy dies at once (a crash loop)
    await supervisor.tick();
    host.nowMs += 60_000;
  }
  assert.strictEqual(host.spawned.length, 2, "two respawns, then it gives up");
  const st = supervisor.status();
  assert.deepStrictEqual(st.failedCfgs.map((f) => [f.startPort, f.reason]), [[18100, "rate_limited"]]);
});

test("tick: missing anchors re-added in ONE ip -batch (/128 nodad deprecated); anchors deprecated in batches; switches", async () => {
  const { host, supervisor } = fakeNode("anchors", {
    cfgs: {
      "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a"),
      "3proxy_20000.cfg": CFG(20000, "2001:db8:0:1::b"),
      "3proxy_30000.cfg": CFG(30000, "2001:db8:0:1::c"),
    },
    env: { NODE_AGENT_ANCHOR_DEPRECATE_BATCH: "1" },
  });
  host.listening = new Set([18100, 20000, 30000]);
  host.ifInet6 = [
    inet6Line("2001:db8:0:1:5400:6ff:febe:b5cf", { plen: 64, flags: 0x00 }),
    inet6Line("2001:db8:0:1::a", { flags: 0x82 }),
    inet6Line("2001:db8:0:1::b", { flags: 0x82 }),
  ].join("\n");
  await supervisor.tick();
  assert.strictEqual(host.batches.length, 2);
  assert.strictEqual(host.batches[0], "address add 2001:db8:0:1::c/128 dev enp1s0 nodad preferred_lft 0\n");
  assert.strictEqual(host.batches[1], "address change 2001:db8:0:1:0:0:0:a/128 dev enp1s0 nodad valid_lft forever preferred_lft 0\n");
  const st = supervisor.status();
  assert.strictEqual(st.addressesReadded, 1);
  assert.strictEqual(st.addressesMissing, 1);
  assert.strictEqual(st.anchorsDeprecated, 1);
  assert.strictEqual(st.anchorsPendingDeprecate, 1, "batch of 1: one left for the next tick");

  const off = fakeNode("anchors-off", {
    cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a"), "3proxy_20000.cfg": CFG(20000, "2001:db8:0:1::b") },
    env: { NETRUN_ANCHOR_DEPRECATE: "0" },
  });
  off.host.listening = new Set([18100, 20000]);
  off.host.ifInet6 = [inet6Line("2001:db8:0:1:5400:6ff:febe:b5cf", { plen: 64, flags: 0 }), inet6Line("2001:db8:0:1::a")].join("\n");
  await off.supervisor.tick();
  assert.deepStrictEqual(off.host.batches, ["address add 2001:db8:0:1::b/128 dev enp1s0 nodad\n"], "NETRUN_ANCHOR_DEPRECATE=0: preferred re-add, no deprecation");

  const none = fakeNode("anchors-none", {
    cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") },
    env: { NETRUN_ANCHOR_DEPRECATE: "0", NETRUN_ANCHOR_READD: "0" },
  });
  none.host.listening = new Set([18100]);
  await none.supervisor.tick();
  assert.deepStrictEqual(none.host.batches, []);
  assert.ok(!none.host.calls.some((c) => c.startsWith("ip ")), "both anchor switches off: no ip call");
});

test("NODE_AGENT_SUPERVISOR=0: tick does nothing", async () => {
  const { host, supervisor } = fakeNode("off", { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") }, env: { NODE_AGENT_SUPERVISOR: "0" } });
  const r = await supervisor.tick();
  assert.deepStrictEqual(r, { skipped: true, outcome: "disabled" });
  assert.deepStrictEqual(host.calls, []);
  assert.strictEqual(supervisor.status().enabled, false);
});

test("the batches seen serving survive an agent restart (status file on /run); a post-boot batch that died is still respawned", async () => {
  const name = "restart";
  const first = fakeNode(name, { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") } });
  first.host.listening = new Set([18100]);
  await first.supervisor.tick();
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(first.statusPath, "utf-8")).seenServing, [18100]);
  // New agent process, same /run file; the boot was AFTER the cfg's mtime here
  // is irrelevant: the batch is known to have served, so its death is handled.
  const statusPath = first.statusPath;
  const inventory = cfgStatus.createCfgInventory({ cfgDir: first.dir });
  const spawned = [];
  const second = sup.createSupervisor({
    env: { NODE_AGENT_SUPERVISOR_STATUS_FILE: statusPath, NETRUN_ENV_FILE: path.join(TMP, "none.env"), NETRUN_ANCHOR_DEPRECATE: "0", NETRUN_ANCHOR_READD: "0" },
    readCfgs: () => inventory.read(),
    spawnCfg: async (p) => { spawned.push(p); return { ok: true, outcome: "spawned", pid: 1, via: "helper" }; },
    run: async (cmd) => (cmd === "systemctl" ? { code: 0, stdout: "active\n" } : { code: 0, stdout: "" }),
    readFile: async () => "",
    log: quietLog,
    bootTimeMs: () => 0, // every cfg is "post-boot": only seenServing makes it eligible
  });
  assert.deepStrictEqual(second.status().seenServing, [18100]);
  await second.tick();
  await second.tick();
  assert.deepStrictEqual(spawned, [path.join(first.dir, "3proxy_18100.cfg")]);
});

test("forget: a start port regenerated after serving is a NEW batch — a failed attempt's leftover stays unsupervised, also after an agent restart", async () => {
  const boot = Date.now() - 3600_000;
  const { dir, host, supervisor, statusPath } = fakeNode("forget", {
    cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") },
    bootTimeMs: () => boot,
  });
  host.listening = new Set([18100]);
  await supervisor.tick();
  assert.deepStrictEqual(supervisor.status().seenServing, [18100]);
  // /generate at 18100: kill-on-rebind removed the old batch, forget() under
  // the lock, the new attempt wrote its cfg and failed before 3proxy came up.
  assert.strictEqual(supervisor.forget([18100, "x", -1]), 1);
  fs.writeFileSync(path.join(dir, "3proxy_18100.cfg"), CFG(18100, "2001:db8:0:1::f")); // written after the boot
  host.listening = new Set();
  host.procs = [];
  host.nowMs = Date.now() + 10 * 60_000; // past the settle window
  for (let i = 0; i < 3; i += 1) {
    await supervisor.tick();
    host.nowMs += 60_000;
  }
  assert.deepStrictEqual(host.spawned, [], "never respawned");
  assert.deepStrictEqual(supervisor.status().unsupervised, [18100]);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(statusPath, "utf-8")).seenServing, []);
  // Agent restart: the status file does not bring the old "seen" back.
  const inventory = cfgStatus.createCfgInventory({ cfgDir: dir });
  const spawned = [];
  const second = sup.createSupervisor({
    env: { NODE_AGENT_SUPERVISOR_STATUS_FILE: statusPath, NETRUN_ENV_FILE: path.join(TMP, "none.env"), NETRUN_ANCHOR_DEPRECATE: "0", NETRUN_ANCHOR_READD: "0" },
    readCfgs: () => inventory.read(),
    spawnCfg: async (p) => { spawned.push(p); return { ok: true, outcome: "spawned", pid: 1, via: "helper" }; },
    run: async (cmd) => (cmd === "systemctl" ? { code: 0, stdout: "active\n" } : { code: 0, stdout: "" }),
    readFile: async () => "",
    now: () => host.nowMs,
    log: quietLog,
    bootTimeMs: () => boot,
  });
  await second.tick();
  await second.tick();
  assert.deepStrictEqual(spawned, []);
  assert.deepStrictEqual(second.status().unsupervised, [18100]);
});

test("without forget a rewrite of a served batch (deprovision rewrite / egress_mode) keeps it supervised", async () => {
  const boot = Date.now() - 3600_000;
  const { dir, host, supervisor } = fakeNode("rewrite-kept", {
    cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") },
    bootTimeMs: () => boot,
  });
  host.listening = new Set([18100]);
  await supervisor.tick();
  fs.writeFileSync(path.join(dir, "3proxy_18100.cfg"), CFG(18100, "2001:db8:0:1::a")); // rewritten after the boot
  host.listening = new Set();
  host.procs = [];
  host.nowMs = Date.now() + 10 * 60_000;
  await supervisor.tick();
  assert.deepStrictEqual(supervisor.status().pendingDown, [18100]);
  host.nowMs += 60_000;
  await supervisor.tick();
  assert.deepStrictEqual(host.spawned, [path.join(dir, "3proxy_18100.cfg")]);
});

test("forget during a tick: the tick's older ps / ss snapshot does not mark the port seen again", async () => {
  const { host, supervisor } = fakeNode("forget-race", { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") } });
  host.listening = new Set([18100]);
  let once = true;
  host.onPs = () => {
    if (once) {
      once = false;
      supervisor.forget([18100]); // /generate takes the lock while this tick reads ps / ss
    }
  };
  await supervisor.tick();
  assert.deepStrictEqual(supervisor.status().seenServing, [], "not re-added from the stale snapshot");
  host.nowMs += 60_000;
  await supervisor.tick(); // a later tick sees the (new) batch listening
  assert.deepStrictEqual(supervisor.status().seenServing, [18100]);
});

test("the hourly respawn cap and the failed mark survive an agent restart; a changed cfg is tried again once the hour is over", async () => {
  const name = "cap-restart";
  const env = { NODE_AGENT_SUPERVISOR_MAX_RESPAWNS_PER_HOUR: "2", NETRUN_ANCHOR_DEPRECATE: "0", NETRUN_ANCHOR_READD: "0" };
  const first = fakeNode(name, { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") }, env });
  for (let i = 0; i < 6; i += 1) {
    first.host.procs = []; // a crash loop
    await first.supervisor.tick();
    first.host.nowMs += 60_000;
  }
  assert.strictEqual(first.host.spawned.length, 2);
  const file = JSON.parse(fs.readFileSync(first.statusPath, "utf-8"));
  assert.deepStrictEqual(file.failedCfgs.map((f) => [f.startPort, f.reason, f.mtimeMs]), [[18100, "rate_limited", 0]]);
  assert.strictEqual(file.respawnHistory["18100"].length, 2);
  // OOM / watchdog restart of the agent: a NEW supervisor on the same /run file.
  const second = fakeNode(name, { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") }, env, nowMs: first.host.nowMs });
  assert.deepStrictEqual(second.supervisor.status().failedCfgs.map((f) => f.startPort), [18100], "failed mark restored");
  assert.strictEqual(second.supervisor.status().respawnHistory["18100"].length, 2, "history restored");
  await second.supervisor.tick();
  second.host.nowMs += 60_000;
  await second.supervisor.tick();
  assert.deepStrictEqual(second.host.spawned, [], "no fresh 5/h after a restart");
  // The cfg changes; the cap still counts the last hour, then it is tried again.
  fs.utimesSync(path.join(second.dir, "3proxy_18100.cfg"), new Date(1000), new Date(1000));
  second.host.nowMs += 3600_000;
  await second.supervisor.tick();
  second.host.nowMs += 60_000;
  await second.supervisor.tick();
  assert.strictEqual(second.host.spawned.length, 1, "respawned after the change, outside the hour");
  // A status file of the previous agent version (no history / mtimes) restores nothing.
  const oldDir = path.join(TMP, "cap-old");
  fs.mkdirSync(oldDir, { recursive: true });
  fs.writeFileSync(path.join(oldDir, "s.json"), JSON.stringify({ seenServing: [1], failedCfgs: [{ startPort: 1, at: "x", reason: "rate_limited", respawns: 5 }] }));
  const old = sup.createSupervisor({ env: { NODE_AGENT_SUPERVISOR_STATUS_FILE: path.join(oldDir, "s.json") }, readCfgs: async () => ({ ok: true, cfgs: [] }), spawnCfg: async () => ({}), log: quietLog });
  assert.deepStrictEqual(old.status().failedCfgs, []);
  assert.deepStrictEqual(old.status().respawnHistory, {});
});

test("http-only cfg behind the HTTPS front: haproxy's frontend on the same port is not the batch — a dead batch is respawned", async () => {
  const { dir, host, supervisor } = fakeNode("http-only", {
    cfgs: { "3proxy_8100.cfg": "daemon\nflush\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8:0:1::a\nproxy -6 -n -a -p8101 -i127.0.0.1 -e2001:db8:0:1::b\n" },
    env: { NETRUN_ANCHOR_DEPRECATE: "0", NETRUN_ANCHOR_READD: "0" },
  });
  host.listening = new Set([8100]); // the fake ss answers 1.2.3.4:8100 — haproxy's public frontend
  await supervisor.tick();
  assert.deepStrictEqual(supervisor.status().pendingDown, [8100], "not 'up' on haproxy's listener");
  host.nowMs += 60_000;
  await supervisor.tick();
  assert.deepStrictEqual(host.spawned, [path.join(dir, "3proxy_8100.cfg")]);
  // planRespawns with the 3proxy listener present on 127.0.0.1: up.
  const state = { downSince: new Map(), history: new Map(), failed: new Map(), seen: new Set() };
  const c = { startPort: 8100, probePort: 8100, probeAddr: "127.0.0.1", httpOnly: true, mtimeMs: 0, cfgPath: "/c/8100" };
  const plan = sup.planRespawns([c], {
    runningKeys: new Set(), listening: new Set([8100]), listeningKeys: new Set(["45.32.10.20:8100", "127.0.0.1:8100"]),
    keyOf: (x) => x.cfgPath, nowMs: 1, settleMs: 0, maxPerHour: 5, state, bootMs: 10,
  });
  assert.deepStrictEqual(plan.pending, []);
  assert.ok(state.seen.has(8100));
});

test("planAnchors: preferred nodad addresses no active cfg lists (deprovisioned batch, *.cfg.disabled, old /64 restore) are deprecated too; the primary never", () => {
  const rows = sup.parseIfInet6Rows(
    [
      inet6Line("2001:db8:0:1:5400:6ff:febe:b5cf", { plen: 64, flags: 0x00 }), // primary (SLAAC)
      inet6Line("2001:db8:0:1::a", { flags: 0x82 }), // active cfg anchor, preferred
      inet6Line("2001:db8:0:1::e", { flags: 0x82 }), // deprovisioned batch's anchor, still on the NIC
      inet6Line("2001:db8:0:1::d", { plen: 64, flags: 0x82 }), // a .cfg.disabled anchor the old restore re-added as /64
      inet6Line("2001:db8:0:1::f", { flags: 0xa2 }), // already deprecated
      inet6Line("2001:db8:0:1::7", { flags: 0xc2 }), // tentative
      inet6Line("2001:db8:0:2::1", { flags: 0x82, ifname: "wg0" }), // another interface: not ours
    ].join("\n")
  );
  const plan = sup.planAnchors([{ egress: ["2001:db8:0:1::a"] }], rows, { iface: "enp1s0" });
  assert.deepStrictEqual(
    plan.pendingDeprecate.map((p) => [p.addr, p.plen, Boolean(p.orphan)]),
    [["2001:db8:0:1:0:0:0:a", 128, false], ["2001:db8:0:1:0:0:0:e", 128, true], ["2001:db8:0:1:0:0:0:d", 64, true]]
  );
  assert.strictEqual(plan.orphans, 2);
  assert.strictEqual(plan.preferredNodad, 3);
  assert.strictEqual(plan.preferredNonNodad, 1, "the primary");
  const noIface = sup.planAnchors([{ egress: ["2001:db8:0:1::a"] }], rows, { iface: null });
  assert.strictEqual(noIface.orphans, 0, "no egress interface known: only cfg anchors");
  assert.strictEqual(noIface.preferredNodad, null);
  // A primary that itself carries nodad (hand-added, DAD off): no preferred
  // address without nodad is left, so no orphan is deprecated (cfg anchors still are).
  const nodadPrimary = sup.parseIfInet6Rows(
    [
      inet6Line("2001:db8:0:1:5400:6ff:febe:b5cf", { plen: 64, flags: 0x02 }), // primary, nodad
      inet6Line("2001:db8:0:1::a", { flags: 0x82 }),
      inet6Line("2001:db8:0:1::e", { flags: 0x82 }),
    ].join("\n")
  );
  const held = sup.planAnchors([{ egress: ["2001:db8:0:1::a"] }], nodadPrimary, { iface: "enp1s0" });
  assert.deepStrictEqual(held.pendingDeprecate.map((p) => p.addr), ["2001:db8:0:1:0:0:0:a"]);
  assert.strictEqual(held.orphans, 0);
  assert.strictEqual(held.orphansHeld, 2, "the primary and the old anchor are held back");
  assert.strictEqual(held.preferredNonNodad, 0);
});

test("tick: orphan anchors deprecated in the same batch; /health preferredNodad reaches 0", async () => {
  const { host, supervisor } = fakeNode("orphans", { cfgs: { "3proxy_18100.cfg": CFG(18100, "2001:db8:0:1::a") } });
  host.listening = new Set([18100]);
  host.ifInet6 = [
    inet6Line("2001:db8:0:1:5400:6ff:febe:b5cf", { plen: 64, flags: 0x00 }),
    inet6Line("2001:db8:0:1::a", { flags: 0xa2 }), // the cfg anchor: deprecated already
    inet6Line("2001:db8:0:1::e", { flags: 0x82 }), // orphan
  ].join("\n");
  await supervisor.tick();
  assert.deepStrictEqual(host.batches, ["address change 2001:db8:0:1:0:0:0:e/128 dev enp1s0 nodad valid_lft forever preferred_lft 0\n"]);
  const st = supervisor.status();
  assert.strictEqual(st.orphanAnchorsDeprecated, 1);
  assert.strictEqual(st.preferredNodad, 0);
  assert.strictEqual(st.preferredNonNodad, 1);
});
