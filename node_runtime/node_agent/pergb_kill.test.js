"use strict";

// Pay-per-GB v2 — pergb_kill.js: ss parsing, attribution of live per-GB
// sockets (tag + excluded skip for IPv6, the loopback tuple for IPv4) and
// exact chunked kills, with and without the ss cgroup filter.
// Run with: node --test node_runtime/node_agent/pergb_kill.test.js

const test = require("node:test");
const assert = require("node:assert");
const killLib = require("./pergb_kill.js");
const T = require("./pergb_testlib.js");

const QUIET = { log() {}, error() {} };

test("parseSs: state-less established listing with tcp_info lines; bracketed IPv6, %iface, mapped IPv4", () => {
  const text = [
    "0      0      [2001:db8:aa:12:4301:2de4:e935:4ca7]:41000     [2606:4700::1]:443",
    "\t cubic wscale:7,7 rto:204 bytes_sent:1200 bytes_acked:1201 bytes_received:99000 segs_out:10",
    "0      0      127.0.0.4%lo:31000     127.0.0.1:52000",
    "\t cubic bytes_acked:77 bytes_received:5",
    "0      0      [::ffff:127.0.0.3]:31001     [::ffff:127.0.0.1]:52001",
    "garbage",
    "",
  ].join("\n");
  const s = killLib.parseSs(text);
  assert.strictEqual(s.length, 3);
  assert.deepStrictEqual(s[0], { local: "2001:db8:aa:12:4301:2de4:e935:4ca7", lport: 41000, peer: "2606:4700::1", pport: 443, sent: 1200, received: 99000 });
  assert.deepStrictEqual(s[1], { local: "127.0.0.4", lport: 31000, peer: "127.0.0.1", pport: 52000, sent: 77, received: 5 });
  assert.strictEqual(s[2].local, "127.0.0.3");
  assert.strictEqual(s[2].peer, "127.0.0.1");
});

// A mixed node: per-GB sockets of two accounts in two units, a per-piece-like
// socket in an excluded /64 carrying even a VALID tag, an untagged address in
// the pool, IPv4 egress sockets, loopback sessions known and unknown.
function world() {
  const t = T.tagger();
  const A1 = t.address(0x12, 1, 100); // list 1, account 10
  const A2 = t.address(0x13, 2, 200); // list 2, account 10
  const B3 = t.address(0x14, 3, 300); // list 3, account 20
  const EXCL = t.address(0x99, 1, 400); // list 1's tag, but in a per-piece /64
  const RAND = T.untaggedAddress(0x15, 5);
  const s = [
    { local: A1, lport: 40001, peer: "2606:4700::1", pport: 443, sent: 10, received: 20, cgroup: T.CG(T.UNIT_A) },
    { local: A2, lport: 40002, peer: "2606:4700::2", pport: 443, sent: 10, received: 20, cgroup: T.CG(T.UNIT_B) },
    { local: B3, lport: 40003, peer: "2606:4700::1", pport: 443, sent: 10, received: 20, cgroup: T.CG(T.UNIT_A) },
    { local: EXCL, lport: 40004, peer: "2606:4700::1", pport: 443, sent: 10, received: 20, cgroup: T.CG(T.UNIT_A) },
    { local: RAND, lport: 40005, peer: "2606:4700::1", pport: 443, sent: 10, received: 20, cgroup: T.CG(T.UNIT_A) },
    { local: "203.0.113.5", lport: 40006, peer: "93.184.216.34", pport: 443, sent: 10, received: 20, cgroup: T.CG(T.UNIT_A) },
    { local: "127.0.0.4", lport: 31000, peer: "127.0.0.1", pport: 50001, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) }, // account 10 IPv4
    { local: "127.0.0.3", lport: 31600, peer: "127.0.0.1", pport: 50002, sent: 1, received: 1, cgroup: T.CG(T.UNIT_B) }, // account 20 IPv4
    { local: "127.0.0.4", lport: 31001, peer: "127.0.0.1", pport: 50003, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) }, // unknown tuple
    // per-piece sockets outside the per-GB cgroup (only seen in fallback mode when in the pool)
    { local: t.address(0x99, 1, 401), lport: 40007, peer: "2606:4700::1", pport: 443, sent: 1, received: 1, cgroup: "/system.slice/netrun-3proxy-20000.scope" },
    { local: "127.0.0.1", lport: 10000, peer: "127.0.0.1", pport: 50009, sent: 1, received: 1, cgroup: "/system.slice/netrun-3proxy-20000.scope" },
  ];
  return { sockets: s, cgroupSupport: true, addrs: { A1, A2, B3, EXCL, RAND } };
}

const LISTS = new Map([
  [1, { accountId: 10, login: "netrun-aaaa1" }],
  [2, { accountId: 10, login: "netrun-aaaa2" }],
  [3, { accountId: 20, login: "netrun-bbbb3" }],
]);
const TUPLES = new Map([
  ["127.0.0.4:31000<127.0.0.1:50001", "netrun-aaaa1"],
  ["127.0.0.3:31600<127.0.0.1:50002", "netrun-bbbb3"],
]);

function killer(w) {
  const run = T.fakeRun(w);
  const k = killLib.createKiller({
    run,
    log: QUIET,
    units: () => [T.UNIT_A, T.UNIT_B].map((u) => ({ unit: u, cgroup: T.CG(u) })),
    fallbackFilter: () => ["(", "src", T.PREFIX, "or", "src", "127.0.0.3", "or", "src", "127.0.0.4", ")"],
    ctx: () => ({
      tagger: T.tagger(),
      excluded: new Set([0x99]),
      tupleLogin: (key) => TUPLES.get(key) || null,
      listAccount: (id) => (LISTS.get(id) || {}).accountId ?? null,
      loginAccount: (login) => {
        for (const l of LISTS.values()) if (l.login === login) return l.accountId;
        return null;
      },
    }),
  });
  return { k, run };
}

for (const mode of ["cgroup", "fallback"]) {
  test(`kill(account) [${mode}]: only the account's tagged sockets and its IPv4 tuples; never excluded /64s, untagged, egress IPv4 or per-piece`, async () => {
    const w = world();
    w.cgroupSupport = mode === "cgroup";
    const { k, run } = killer(w);
    const r = await k.kill({ accountId: 10 });
    const killedLocals = w.killed.map((s) => `${s.local}:${s.lport}`).sort();
    assert.deepStrictEqual(killedLocals, [`${w.addrs.A1}:40001`, `${w.addrs.A2}:40002`, "127.0.0.4:31000"].sort());
    assert.strictEqual(r.killed6, 2);
    assert.strictEqual(r.killed4, 1);
    assert.strictEqual(r.pending4, 1, "the session without a record yet");
    for (const s of w.killed) assert.ok(!s.cgroup.startsWith("/system.slice"), "never a per-piece socket");
    // every kill is an exact 4-tuple filter (and inside the unit's cgroup when supported)
    const kills = run.calls.filter((c) => c.includes("-K"));
    assert.ok(kills.length >= 1);
    for (const c of kills) {
      assert.ok(c.includes("src") && c.includes("dst"));
      if (mode === "cgroup") assert.ok(c.includes("cgroup"));
      else assert.ok(!c.includes("cgroup"));
    }
    assert.strictEqual(k.status().cgroupFilter, mode === "cgroup");
  });
}

test("kill(list): the list's IPv6 sockets and the IPv4 tuples of its login only", async () => {
  const w = world();
  const { k } = killer(w);
  const r = await k.kill({ listId: 3, logins: new Set(["netrun-bbbb3"]) });
  assert.deepStrictEqual(w.killed.map((s) => s.local).sort(), [w.addrs.B3, "127.0.0.3"].sort());
  assert.deepStrictEqual([r.killed6, r.killed4], [1, 1]);
  // the IPv4 kill selects only the target's loopback tuple
  const w2 = world();
  const { k: k2 } = killer(w2);
  await k2.kill({ listId: 1, logins: new Set(["netrun-aaaa1"]) });
  assert.deepStrictEqual(w2.killed.map((s) => `${s.local}:${s.lport}<${s.peer}:${s.pport}`).sort(), [`${w2.addrs.A1}:40001<2606:4700::1:443`, "127.0.0.4:31000<127.0.0.1:50001"].sort());
});

test("kills go in chunks of 256 tuples", async () => {
  const t = T.tagger();
  const w = { sockets: [], cgroupSupport: true };
  for (let i = 0; i < 600; i += 1) {
    w.sockets.push({ local: t.address(0x20 + (i % 7), 1, i), lport: 30000 + i, peer: "2606:4700::1", pport: 443, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) });
  }
  const { k, run } = killer(w);
  const r = await k.kill({ accountId: 10 });
  assert.strictEqual(r.killed6, 600);
  const kills = run.calls.filter((c) => c.includes("-K"));
  assert.strictEqual(kills.length, 3);
  for (const c of kills) assert.ok(c.filter((x) => x === "src").length <= killLib.KILL_CHUNK);
  assert.strictEqual(w.sockets.length, 0);
});

test("classify: the sockets view the enforcer and guards share", () => {
  const w = world();
  const ctx = {
    tagger: T.tagger(),
    excluded: new Set([0x99]),
    tupleLogin: (key) => TUPLES.get(key) || null,
    listAccount: (id) => (LISTS.get(id) || {}).accountId ?? null,
    loginAccount: (login) => (login === "netrun-aaaa1" ? 10 : login === "netrun-bbbb3" ? 20 : null),
  };
  const v = killLib.classify(w.sockets, ctx);
  assert.deepStrictEqual(v.v6.map((s) => s.listId).sort(), [1, 2, 3]);
  assert.deepStrictEqual(v.v4.map((s) => s.accountId).sort(), [10, 20]);
  assert.strictEqual(v.loopUnknown, 1);
});

// A13-I: per-piece proxies on RADIUS — list 7 (account 70) owns /64 0x77.
function pieceWorld() {
  const t = T.tagger();
  const w = world();
  const PIECE = t.pieceAddress(0x77, 7);
  const FOREIGN = t.address(0x77, 1, 500); // list 1's tag inside the piece's /64: not the piece's
  w.sockets.push(
    { local: PIECE, lport: 40100, peer: "2606:4700::1", pport: 443, sent: 5, received: 5, cgroup: T.CG(T.UNIT_A) },
    { local: PIECE, lport: 40101, peer: "2606:4700::2", pport: 443, sent: 5, received: 5, cgroup: T.CG(T.UNIT_B) },
    { local: FOREIGN, lport: 40102, peer: "2606:4700::1", pport: 443, sent: 5, received: 5, cgroup: T.CG(T.UNIT_A) },
    { local: "127.0.0.4", lport: 31007, peer: "127.0.0.1", pport: 50070, sent: 1, received: 1, cgroup: T.CG(T.UNIT_A) } // the piece's IPv4 session
  );
  w.addrs.PIECE = PIECE;
  w.addrs.FOREIGN = FOREIGN;
  return w;
}

function pieceKiller(w) {
  const lists = new Map([...LISTS, [7, { accountId: 70, login: "netrun-piece7" }]]);
  const tuples = new Map([...TUPLES, ["127.0.0.4:31007<127.0.0.1:50070", "netrun-piece7"]]);
  return killLib.createKiller({
    run: T.fakeRun(w),
    log: QUIET,
    units: () => [T.UNIT_A, T.UNIT_B].map((u) => ({ unit: u, cgroup: T.CG(u) })),
    fallbackFilter: () => ["(", "src", T.PREFIX, "or", "src", "127.0.0.3", "or", "src", "127.0.0.4", ")"],
    ctx: () => ({
      tagger: T.tagger(),
      excluded: new Set([0x99, 0x77]), // piece /64s are in the excluded set as well
      pieceOf: (net) => (net === 0x77 ? { listId: 7, accountId: 70 } : null),
      tupleLogin: (key) => tuples.get(key) || null,
      listAccount: (id) => (lists.get(id) || {}).accountId ?? null,
      loginAccount: (login) => {
        for (const l of lists.values()) if (l.login === login) return l.accountId;
        return null;
      },
    }),
  });
}

for (const mode of ["cgroup", "fallback"]) {
  test(`A13-I [${mode}]: a piece's sockets are its own — killed by its account or list, never by another kill`, async () => {
    let w = pieceWorld();
    w.cgroupSupport = mode === "cgroup";
    let k = pieceKiller(w);
    const v = await k.snapshot();
    const pieceSocks = v.v6.filter((s) => s.piece);
    assert.deepStrictEqual(pieceSocks.map((s) => [s.listId, s.accountId, s.subnetId]), [[7, 70, 0x77], [7, 70, 0x77]]);
    assert.ok(!v.v6.some((s) => s.local === w.addrs.FOREIGN), "another list's tag in a piece /64 is not attributed");
    // a per-GB account kill never touches the piece
    await k.kill({ accountId: 10 });
    assert.ok(!w.killed.some((s) => s.local === w.addrs.PIECE || s.lport === 31007));
    // the piece's account: both IPv6 sockets and its IPv4 tuple
    let r = await k.kill({ accountId: 70 });
    assert.deepStrictEqual([r.killed6, r.killed4], [2, 1]);
    assert.ok(w.sockets.some((s) => s.local === w.addrs.FOREIGN), "the foreign socket stays");
    // the piece's list (its login)
    w = pieceWorld();
    w.cgroupSupport = mode === "cgroup";
    k = pieceKiller(w);
    r = await k.kill({ listId: 7, logins: new Set(["netrun-piece7"]) });
    assert.deepStrictEqual([r.killed6, r.killed4], [2, 1]);
    assert.deepStrictEqual(
      w.killed.map((s) => s.lport).sort((a, b) => a - b),
      [31007, 40100, 40101]
    );
  });
}
