"use strict";

// Pay-per-GB v2 — pergb_enforcer.js: the local limit rule (same epoch →
// absolute, else cum at receipt + allowance), full vs split, near-limit mode
// (the per-socket upper bound against a simulated 1000-socket mix; the
// unrecorded IPv4 accepts), the heartbeat, unblocking, expiry kills.
// Run with: node --test node_runtime/node_agent/pergb_enforcer.test.js

const test = require("node:test");
const assert = require("node:assert");
const enforcerLib = require("./pergb_enforcer.js");
const killLib = require("./pergb_kill.js");
const T = require("./pergb_testlib.js");

const QUIET = { log() {}, error() {} };
const MiB = 1024 * 1024;
const LOGDUMP = 262144;
const LP = LOGDUMP + 65536;

function fakeMeter(epoch = 5000000001) {
  const m = {
    epoch,
    c: {},
    sess: [],
    counters: () => m.c,
    sessions: ({ logins } = {}) => m.sess.filter((s) => !logins || logins.has(s.login)),
    add(login, up, down) {
      const o = m.c[login] || { up: 0, down: 0, conns: 0 };
      m.c[login] = { up: o.up + up, down: o.down + down, conns: o.conns };
    },
  };
  return m;
}

function fakeKiller(view = { v6: [], v4: [], loopUnknown: 0 }) {
  const k = {
    view,
    kills: [],
    async snapshot() {
      return k.view;
    },
    async kill(target) {
      k.kills.push(target);
      return { killed6: 1, killed4: 0, pending4: 0, matched6: 1, matched4: 0 };
    },
  };
  return k;
}

function clock(t0 = 1_790_000_000_000) {
  let t = t0;
  const now = () => t;
  now.advance = (ms) => (t += ms);
  return now;
}

const LISTS = [
  { id: 1, login: "netrun-aaaa1", accountId: 10, status: "active", pwRev: 1 },
  { id: 2, login: "netrun-aaaa2", accountId: 10, status: "active", pwRev: 1 },
  { id: 3, login: "netrun-bbbb3", accountId: 20, status: "active", pwRev: 1 },
];

function setup({ accounts, meter = fakeMeter(), killer = fakeKiller(), ctlHandlers = {}, now = clock() } = {}) {
  const ctl = T.fakeCtl({ near_stats: { accounts: {} }, ...ctlHandlers });
  const e = enforcerLib.createEnforcer({ ctl, meter, killer, now, log: QUIET, logdumpBytes: () => LOGDUMP });
  e.setLists(LISTS);
  e.setAccounts(accounts);
  return { e, ctl, meter, killer, now };
}

test("localLimit: same epoch → absolute bytes; another epoch → cum at receipt + allowance", () => {
  assert.strictEqual(enforcerLib.localLimit({ limit: { epoch: 7, bytes: 1000, allowance: 50 }, cumAtReceipt: 900 }, 7), 1000);
  assert.strictEqual(enforcerLib.localLimit({ limit: { epoch: 7, bytes: 1000, allowance: 50 }, cumAtReceipt: 900 }, 8), 950);
  assert.strictEqual(enforcerLib.localLimit({ limit: { epoch: "7", bytes: 1000, allowance: 50 }, cumAtReceipt: 0 }, 7), 1000, "epochs compare as text");
  assert.strictEqual(enforcerLib.localLimit({ limit: null }, 7), null);
  // and through the enforcer: the allowance counts from the cum when the limit arrived
  const meter = fakeMeter(42);
  meter.add("netrun-aaaa1", 0, 500 * MiB);
  const { e } = setup({ meter, accounts: [{ id: 10, state: "active", limit: { epoch: 41, bytes: 1, allowance: 100 * MiB, full: true } }] });
  assert.strictEqual(e._accounts.get(10).cumAtReceipt, 500 * MiB);
});

test("full=true: blocked locally AND killed, every tick while blocked; full=false: refused only", async () => {
  const meter = fakeMeter();
  const killer = fakeKiller();
  const { e, ctl } = setup({
    meter,
    killer,
    accounts: [
      { id: 10, state: "active", limit: { epoch: meter.epoch, bytes: 1000 * MiB, allowance: 0, full: true } },
      { id: 20, state: "active", limit: { epoch: meter.epoch, bytes: 1000 * MiB, allowance: 0, full: false } },
    ],
  });
  meter.add("netrun-aaaa1", 600 * MiB, 0);
  meter.add("netrun-aaaa2", 0, 400 * MiB);
  meter.add("netrun-bbbb3", 0, 1001 * MiB);
  const r1 = await e.tick();
  assert.deepStrictEqual(r1.blocked.sort(), [10, 20]);
  const blocks = ctl.calls.filter((c) => c.op === "local_block");
  assert.deepStrictEqual(blocks.map((c) => [c.body.accountId, c.body.blocked]).sort(), [[10, true], [20, true]]);
  assert.deepStrictEqual(killer.kills, [{ accountId: 10 }], "split account not killed");
  await e.tick();
  assert.strictEqual(killer.kills.length, 2, "the kill repeats while blocked (sessions without a record yet)");
  assert.strictEqual(ctl.calls.filter((c) => c.op === "local_block").length, 2, "no second block call");
  const lb = e.localBlocks();
  assert.deepStrictEqual(lb.map((x) => x.accountId).sort(), [10, 20]);
  assert.ok(lb.every((x) => x.blocked === true && x.cum >= x.limit));
  // a raised budget unblocks
  e.setAccounts([
    { id: 10, state: "active", localBlocked: true, limit: { epoch: meter.epoch, bytes: 5000 * MiB, allowance: 0, full: true } },
    { id: 20, state: "active", localBlocked: true, limit: { epoch: meter.epoch, bytes: 5000 * MiB, allowance: 0, full: false } },
  ]);
  const r3 = await e.tick();
  assert.deepStrictEqual(r3.unblocked.sort(), [10, 20]);
  assert.ok(e.localBlocks().every((x) => x.blocked === false));
});

test("heartbeat every tick: near map only for accounts within H of their limit; H = max(256 MiB, 30 s × rate)", async () => {
  const meter = fakeMeter();
  const now = clock();
  const { e, ctl } = setup({
    meter,
    now,
    accounts: [
      { id: 10, state: "active", limit: { epoch: meter.epoch, bytes: 10000 * MiB, allowance: 0, full: true } },
      { id: 20, state: "active", limit: { epoch: meter.epoch, bytes: 1000 * MiB, allowance: 0, full: true } },
    ],
  });
  meter.add("netrun-bbbb3", 0, 800 * MiB); // 200 MiB left < 256 MiB
  await e.tick();
  let hb = ctl.calls.filter((c) => c.op === "heartbeat").pop();
  assert.deepStrictEqual(Object.keys(hb.body.near), ["20"]);
  assert.strictEqual(hb.body.near["20"], 200 * MiB);
  // account 10 runs at 100 MiB/s: H = 3000 MiB; with 2600 MiB left it is near
  for (let i = 0; i < 15; i += 1) {
    now.advance(1000);
    meter.add("netrun-aaaa1", 0, 100 * MiB);
    if (i === 0) meter.add("netrun-aaaa1", 0, 5800 * MiB);
    await e.tick();
  }
  hb = ctl.calls.filter((c) => c.op === "heartbeat").pop();
  assert.ok("10" in hb.body.near, "fast account near well before 256 MiB");
  assert.ok(ctl.calls.filter((c) => c.op === "heartbeat").length >= 16, "one heartbeat per tick");
});

test("near-limit: the per-socket bound is never below the true unlogged bytes (simulated 1000-socket mix)", async () => {
  let seed = 99;
  const rand = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  const t = T.tagger();
  const meter = fakeMeter();
  const world = { sockets: [], cgroupSupport: true };
  const truth = new Map([
    [10, 0],
    [20, 0],
  ]);
  const listAcc = { 1: 10, 2: 10, 3: 20 };
  const loginOf = { 1: "netrun-aaaa1", 2: "netrun-aaaa2", 3: "netrun-bbbb3" };
  const TUP = new Map();
  for (let i = 0; i < 1000; i += 1) {
    const list = 1 + Math.floor(rand() * 3);
    // one direction at a time: chunks ≤ 64 KiB, a record whenever ≥ logdump
    const dir = () => {
      let total = 0;
      let counter = 0;
      let logged = 0;
      const chunks = Math.floor(rand() * 40);
      for (let c = 0; c < chunks; c += 1) {
        const n = 1 + Math.floor(rand() * 65536);
        total += n;
        counter += n;
        if (counter >= LOGDUMP) {
          logged += counter;
          counter = 0;
        }
      }
      return { total, logged, unlogged: counter };
    };
    const up = dir();
    const down = dir();
    meter.add(loginOf[list], up.logged, down.logged);
    truth.set(listAcc[list], truth.get(listAcc[list]) + up.unlogged + down.unlogged);
    const ipv4 = rand() < 0.3;
    if (ipv4) {
      // IPv4 session: the loopback accepted socket (sent = to the client = down)
      const key = `127.0.0.4:${31000 + (i % 500)}<127.0.0.1:${20000 + i}`;
      TUP.set(key, loginOf[list]);
      world.sockets.push({ local: "127.0.0.4", lport: 31000 + (i % 500), peer: "127.0.0.1", pport: 20000 + i, sent: down.total, received: up.total, cgroup: T.CG(T.UNIT_A) });
    } else {
      world.sockets.push({ local: t.address(0x30 + (i % 50), list, i), lport: 30000 + i, peer: "2606:4700::1", pport: 443, sent: up.total, received: down.total, cgroup: T.CG(T.UNIT_A) });
    }
  }
  const lists = new Map(LISTS.map((l) => [l.id, l]));
  const killer = killLib.createKiller({
    run: T.fakeRun(world),
    log: QUIET,
    units: () => [{ unit: T.UNIT_A, cgroup: T.CG(T.UNIT_A) }],
    ctx: () => ({
      tagger: t,
      excluded: new Set(),
      tupleLogin: (k) => TUP.get(k) || null,
      listAccount: (id) => (lists.get(id) || {}).accountId ?? null,
      loginAccount: (login) => (LISTS.find((l) => l.login === login) || {}).accountId ?? null,
    }),
  });
  const cum = (acc) => LISTS.filter((l) => l.accountId === acc).reduce((s, l) => s + (meter.c[l.login] ? meter.c[l.login].up + meter.c[l.login].down : 0), 0);
  const limits = { 10: cum(10) + 200 * MiB, 20: cum(20) + 250 * MiB };
  const { e, ctl } = setup({
    meter,
    killer,
    accounts: [
      { id: 10, state: "active", limit: { epoch: meter.epoch, bytes: limits[10], allowance: 0, full: true } },
      { id: 20, state: "active", limit: { epoch: meter.epoch, bytes: limits[20], allowance: 0, full: true } },
    ],
  });
  await e.tick();
  const hb = ctl.calls.filter((c) => c.op === "heartbeat").pop().body.near;
  for (const acc of [10, 20]) {
    const v = e.accountView(acc);
    assert.ok(v.near);
    assert.ok(v.unlogged >= truth.get(acc), `account ${acc}: bound ${v.unlogged} >= true unlogged ${truth.get(acc)}`);
    assert.ok(hb[String(acc)] <= Math.max(0, limits[acc] - cum(acc) - truth.get(acc)), "the headroom RADIUS gets is never more than the real one");
    // the bound is the per-socket min(bytes, L') sum: never more than the sockets' traffic
    assert.ok(v.unlogged <= v.sockets * 2 * LP);
  }
});

test("near-limit reservations: IPv4 accepts RADIUS counted without a record yet add 2·L' each", async () => {
  const meter = fakeMeter();
  const now = clock();
  const since = now() / 1000 - 10;
  meter.sess = [
    { login: "netrun-aaaa1", first: now() - 5000 }, // seen since near mode started
    { login: "netrun-aaaa2", first: now() - 2000 },
    { login: "netrun-aaaa1", first: now() - 60000 }, // before: not counted
  ];
  const { e } = setup({
    meter,
    now,
    ctlHandlers: { near_stats: { accounts: { 10: { reserved: 0, ipv4Accepts: 5, since, headroom: 1 } } } },
    accounts: [{ id: 10, state: "active", limit: { epoch: meter.epoch, bytes: 100 * MiB, allowance: 0, full: true } }],
  });
  await e.tick();
  const v = e.accountView(10);
  assert.strictEqual(v.unrecorded4, 3);
  assert.strictEqual(v.unlogged, 3 * 2 * LP);
});

test("expiry: an account whose expiresAt passed is killed once; RADIUS failures are retried", async () => {
  const meter = fakeMeter();
  const killer = fakeKiller();
  const now = clock();
  let failBlock = true;
  const { e, ctl } = setup({
    meter,
    killer,
    now,
    ctlHandlers: {
      local_block: () => {
        if (failBlock) {
          const err = new Error("down");
          err.code = "radius_unavailable";
          throw err;
        }
        return { ok: true };
      },
    },
    accounts: [
      { id: 10, state: "active", expiresAt: now() / 1000 - 1, limit: { epoch: meter.epoch, bytes: 1e15, allowance: 0, full: true } },
      { id: 20, state: "active", limit: { epoch: meter.epoch, bytes: 10, allowance: 0, full: false } },
    ],
  });
  meter.add("netrun-bbbb3", 100, 0);
  await e.tick();
  await e.tick();
  assert.deepStrictEqual(killer.kills, [{ accountId: 10 }], "expiry kill once");
  assert.ok(!e._accounts.get(20).localBlocked, "block failed: not recorded as blocked");
  failBlock = false;
  await e.tick();
  assert.ok(e._accounts.get(20).localBlocked, "retried and recorded on the next tick");
  assert.strictEqual(ctl.calls.filter((c) => c.op === "local_block").length, 3);
});

test("an account the orchestrator blocked: its sessions are killed on every tick (late first records), no local block", async () => {
  const meter = fakeMeter();
  const killer = fakeKiller({ v6: [], v4: [], loopUnknown: 0 });
  killer.kill = async (target) => {
    killer.kills.push(target);
    return { killed6: 0, killed4: 1, pending4: 0, matched6: 0, matched4: 1 };
  };
  const { e, ctl } = setup({ meter, killer, accounts: [{ id: 20, state: "blocked", limit: { epoch: meter.epoch, bytes: 10, allowance: 0, full: true } }] });
  meter.add("netrun-bbbb3", 100, 0);
  await e.tick();
  await e.tick();
  assert.deepStrictEqual(killer.kills, [{ accountId: 20 }, { accountId: 20 }]);
  assert.strictEqual(ctl.calls.filter((c) => c.op === "local_block").length, 0);
});

test("A13-I: a piece account has no limit — never near, never blocked; expiry and its state still kill", async () => {
  const meter = fakeMeter();
  const killer = fakeKiller();
  const now = clock();
  const ctl = T.fakeCtl({ near_stats: { accounts: {} } });
  const e = enforcerLib.createEnforcer({ ctl, meter, killer, now, log: QUIET, logdumpBytes: () => LOGDUMP });
  e.setLists([...LISTS, { id: 7, login: "netrun-piece7", accountId: 70, status: "active", pwRev: 1, kind: "piece" }]);
  // a limit sent with a piece account (it should not be) is ignored here as in RADIUS
  e.setAccounts([{ id: 70, kind: "piece", state: "active", expiresAt: now() / 1000 + 5, limit: { epoch: meter.epoch, bytes: 1, allowance: 0, full: true } }]);
  meter.add("netrun-piece7", 50 * 1024 * MiB, 50 * 1024 * MiB);
  let r = await e.tick();
  assert.deepStrictEqual([r.near, r.blocked], [[], []]);
  assert.ok(!ctl.calls.some((c) => c.op === "local_block"));
  assert.deepStrictEqual(r.heartbeat, {}, "never in the heartbeat's near map");
  assert.strictEqual(e._accounts.get(70).limit, null);
  assert.strictEqual(e.accountView(70).limit, null);
  // expiry: killed once
  now.advance(6000);
  r = await e.tick();
  assert.deepStrictEqual(r.killed.map((k) => [k.accountId, k.why]), [[70, "expired"]]);
  await e.tick();
  assert.strictEqual(killer.kills.length, 1);
  // refund / end of order: the state kills every tick
  e.setAccounts([{ id: 70, kind: "piece", state: "released", expiresAt: null }]);
  await e.tick();
  await e.tick();
  assert.strictEqual(killer.kills.length, 3);
});
