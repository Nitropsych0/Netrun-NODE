"use strict";

// Wave IPV6-ROTATION — the pure half of egress.js: IPv6 text, cfg anchors,
// `ip` output, state transitions, GC selection, the address budget, the exact
// nft text (with the forward and exit guards), the exit guard's primary-address
// parser, the proxy-NDP sysctls and the nftables.service boot drop-in.
// Run with: node --test node_runtime/node_agent/egress.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const eg = require(path.resolve(__dirname, "egress.js"));

const NOW = Date.parse("2026-10-07T12:00:00.000Z");
const iso = (ms) => new Date(ms).toISOString();

function stateWith(ports = {}, extra = {}) {
  return { ...eg.emptyState(), ports, ...extra };
}

test("normalizeIpv6: canonical RFC 5952 text for every input form", () => {
  const cases = [
    ["2001:0db8:0001:0002:0a1b:00c2:0003:0d4e", "2001:db8:1:2:a1b:c2:3:d4e"],
    ["2001:DB8::1", "2001:db8::1"],
    ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"], // longest run, first on a tie
    ["2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"], // a single zero group stays
    ["0:0:0:0:0:0:0:1", "::1"],
    ["2001:db8:1:2::", "2001:db8:1:2::"],
    ["::", "::"],
    ["::ffff:192.0.2.1", "::ffff:c000:201"],
    [" 2001:db8::5 ", "2001:db8::5"],
  ];
  for (const [input, want] of cases) assert.strictEqual(eg.normalizeIpv6(input), want, input);
  for (const bad of ["", null, undefined, "1.2.3.4", "2001:db8::1::2", "fe80::1%eth0", "2001:db8:::1", "gggg::1", "2001:db8::/64"]) {
    assert.strictEqual(eg.normalizeIpv6(bad), null, String(bad));
  }
});

test("parsePrefix: a /64 only, host bits ignored", () => {
  assert.deepStrictEqual(eg.parsePrefix("2001:db8:1:2::/64"), { groups: [0x2001, 0xdb8, 1, 2], text: "2001:db8:1:2::/64" });
  assert.strictEqual(eg.parsePrefix("2001:0db8:0001:0002:dead::beef").text, "2001:db8:1:2::/64");
  assert.strictEqual(eg.parsePrefix("2001:db8:1:2::/48"), null);
  assert.strictEqual(eg.parsePrefix("2001:db8:1:2::/128"), null);
  assert.strictEqual(eg.parsePrefix("garbage"), null);
  assert.strictEqual(eg.parsePrefix(""), null);
});

test("generateAddresses: inside the /64, suffix >= 2^32, never taken, unique", () => {
  const prefix = eg.parsePrefix("2001:db8:1:2::/64");
  const draws = [
    Buffer.from("0000000000000001", "hex"), // ::1-style low suffix → redrawn
    Buffer.from("00000000ffffffff", "hex"), // still < 2^32 → redrawn
    Buffer.from("0000000100000000", "hex"), // exactly 2^32 → accepted
    Buffer.from("abcd000000000001", "hex"), // taken → redrawn
    Buffer.from("0000000100000000", "hex"), // same as the first accepted → redrawn
    Buffer.from("1234567890abcdef", "hex"),
  ];
  let i = 0;
  const rnd = (n) => {
    assert.strictEqual(n, 8);
    return draws[i++];
  };
  const taken = new Set(["2001:db8:1:2:abcd::1"]);
  const out = eg.generateAddresses(prefix, 2, taken, rnd);
  assert.deepStrictEqual(out, ["2001:db8:1:2:0:1::", "2001:db8:1:2:1234:5678:90ab:cdef"]);
  for (const a of out) assert.ok(eg.inPrefix(a, prefix), a);

  const real = eg.generateAddresses(prefix, 200, new Set());
  assert.strictEqual(new Set(real).size, 200);
  for (const a of real) {
    const g = eg.ipv6Groups(a);
    assert.ok(eg.inPrefix(a, prefix));
    assert.ok(g[4] !== 0 || g[5] !== 0, `low suffix ${a}`);
    assert.strictEqual(eg.normalizeIpv6(a), a);
  }
  assert.throws(() => eg.generateAddresses(prefix, 1, new Set(), () => Buffer.alloc(8)), /exhausted/);
});

test("parseCfgAnchors: keyed on the socks line's -p/-e, any block shape", () => {
  const cfg = [
    "daemon", "auth strong", "users :CL:", "",
    // current generator block
    "flush", "users AAAA:CL:aaaa", "allow AAAA * 1.2.3.4", "deny *",
    "socks -6 -a -p30000 -i1.2.3.4 -e2001:0db8:0001:0002:0a1b:00c2:0003:0d4e",
    "proxy -6 -n -a -p20000 -i1.2.3.4 -e2001:0db8:0001:0002:0a1b:00c2:0003:0d4e",
    // pre-A2 block
    "flush", "users BBBB:CL:bbbb", "", "allow * * ", "deny *",
    "socks -64 -a -p30001  -i1.2.3.4 -e2001:db8:1:2::b",
    "proxy -64 -n -a -p20001 -i127.0.0.1 -e2001:db8:1:2::b",
    // http-only port: no socks line → not a port of ours
    "flush", "proxy -6 -n -a -p20002 -i1.2.3.4 -e2001:db8:1:2::c",
    // socks without -e
    "flush", "socks -6 -a -p30003 -i1.2.3.4",
    "\tsocks -6 -a -p30004 -i1.2.3.4 -e2001:db8:1:2::d",
  ].join("\n");
  const m = eg.parseCfgAnchors(cfg);
  assert.deepStrictEqual([...m.keys()], [30000, 30001, 30003, 30004]);
  assert.strictEqual(m.get(30000), "2001:0db8:0001:0002:0a1b:00c2:0003:0d4e");
  assert.strictEqual(m.get(30001), "2001:db8:1:2::b");
  assert.strictEqual(m.get(30003), null);
  assert.ok(!m.has(20000) && !m.has(20002), "http ports never key an anchor");
  // a single-port cfg (no flush at all)
  const single = eg.parseCfgAnchors("daemon\nauth strong\nusers c:CL:3\nallow c *\nsocks -a -p42000 -i127.0.0.1 -e2001:db8::42\n");
  assert.deepStrictEqual([...single], [[42000, "2001:db8::42"]]);
});

test("ip output parsers", () => {
  assert.strictEqual(eg.parseDefaultRouteDev("default via fe80::1 dev enp1s0 proto ra metric 1024 expires 1798sec pref medium\n"), "enp1s0");
  assert.strictEqual(eg.parseDefaultRouteDev("default proto static metric 1024 pref medium\n\tnexthop via fe80::1 dev eth1 weight 1\n"), "eth1");
  assert.strictEqual(eg.parseDefaultRouteDev(""), null);
  const out = [
    "2: eth0    inet6 2001:0db8:1:2::5/128 scope global nodad \\       valid_lft forever preferred_lft forever",
    "2: eth0    inet6 2001:db8:1:2::1/64 scope global \\       valid_lft forever preferred_lft forever",
    "2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever",
  ].join("\n");
  const list = eg.parseIpAddrShow(out);
  assert.deepStrictEqual(list.map((a) => [a.addr, a.plen, a.scope]), [
    ["2001:db8:1:2::5", 128, "global"],
    ["2001:db8:1:2::1", 64, "global"],
    ["fe80::1", 64, "link"],
  ]);
  // `ip -6 neigh show proxy dev eth0` (no "dev" column when filtered) and unfiltered
  const proxies = eg.parseNeighProxy([
    "2001:db8:1:2:aaaa::1 proxy",
    "2001:0db8:0001:0002:aaaa:0000:0000:0002 dev eth0 proxy",
    "",
    "garbage proxy",
  ].join("\n"));
  assert.deepStrictEqual([...proxies], ["2001:db8:1:2:aaaa::1", "2001:db8:1:2:aaaa::2"]);
  assert.deepStrictEqual([...eg.parseNeighProxy("")], []);
});

test("proxy-NDP sysctls: what is set, in which order, and the persisted file", () => {
  assert.deepStrictEqual(eg.egressSysctls("enp1s0").map((s) => [s.key.join("/"), s.want]), [
    ["net/ipv6/conf/all/proxy_ndp", "1"], // unicast probes take ip6_forward(), which checks only "all"
    ["net/ipv6/conf/enp1s0/proxy_ndp", "1"],
    ["net/ipv6/neigh/enp1s0/proxy_delay", "0"],
    ["net/ipv6/conf/all/forwarding", "1"],
    ["net/ipv6/conf/enp1s0/forwarding", "1"],
  ]);
  const head = [
    "# NETRUN IPv6 egress rotation (node-agent egress.js). Rotated and per-connection",
    "# addresses are not added to enp1s0: the kernel answers the router's neighbour",
    "# solicitations for them (proxy NDP; `ip -6 neigh show proxy dev enp1s0`).",
    "# Written by the agent at start when it differs; edits are overwritten.",
  ];
  assert.strictEqual(eg.sysctlConfText("enp1s0"), [
    ...head,
    "net.ipv6.conf.all.proxy_ndp = 1",
    "net.ipv6.conf.enp1s0.proxy_ndp = 1",
    "net.ipv6.neigh.enp1s0.proxy_delay = 0",
    "net.ipv6.conf.all.forwarding = 1",
    "net.ipv6.conf.enp1s0.forwarding = 1",
    "",
  ].join("\n"));
  // accept_ra before forwarding (sysctl applies the file in order); a dot in
  // an interface name is written as "/"
  const vlan = eg.sysctlConfText("eth0.100", { acceptRa: true }).split("\n").filter((l) => l && !l.startsWith("#"));
  assert.deepStrictEqual(vlan, [
    "net.ipv6.conf.all.proxy_ndp = 1",
    "net.ipv6.conf.eth0/100.proxy_ndp = 1",
    "net.ipv6.neigh.eth0/100.proxy_delay = 0",
    "net.ipv6.conf.eth0/100.accept_ra = 2",
    "net.ipv6.conf.all.forwarding = 1",
    "net.ipv6.conf.eth0/100.forwarding = 1",
  ]);
});

test("sanitizeState: normalises addresses, drops what it cannot read", () => {
  const s = eg.sanitizeState({
    version: 1,
    ports: {
      30000: { anchor: "2001:0db8:1:2::00a", current: "2001:DB8:1:2::B", mode: "static" },
      30001: { anchor: "2001:db8:1:2::c", current: "2001:db8:1:2::d", mode: "per_connection" },
      30002: { anchor: "nope", current: null, mode: "static" },
      30003: { anchor: "2001:db8:1:2::e", current: null, mode: "weird" },
      99999: { anchor: "2001:db8:1:2::f", current: null, mode: "static" },
    },
    pool: ["2001:db8:1:2::0p", "2001:db8:1:2::10", "2001:db8:1:2:0::10"],
    pool_refreshed_at: "not a date",
    pool_idle_since: iso(NOW),
    draining: [
      { addr: "2001:db8:1:2::11", until: iso(NOW) },
      { addr: "x", until: iso(NOW) },
      { addr: "2001:db8:1:2::11", until: iso(NOW + 5) },
      { addr: "2001:db8:1:2::12", until: iso(NOW), port: 30000 },
      { addr: "2001:db8:1:2::13", until: iso(NOW), port: 70000 }, // bad port → no tag
    ],
  });
  assert.deepStrictEqual(s.ports, {
    30000: { anchor: "2001:db8:1:2::a", current: "2001:db8:1:2::b", mode: "static" },
    30001: { anchor: "2001:db8:1:2::c", current: null, mode: "per_connection" },
  });
  assert.deepStrictEqual(s.pool, ["2001:db8:1:2::10"]);
  assert.strictEqual(s.pool_refreshed_at, null);
  assert.strictEqual(s.pool_idle_since, iso(NOW));
  assert.deepStrictEqual(s.draining, [
    { addr: "2001:db8:1:2::11", until: iso(NOW + 5) },
    { addr: "2001:db8:1:2::12", until: iso(NOW), port: 30000 },
    { addr: "2001:db8:1:2::13", until: iso(NOW) },
  ]);
  assert.deepStrictEqual(eg.sanitizeState(null), eg.emptyState());
  // a file from before the idle clock / the per-port tag still loads
  const old = eg.sanitizeState({ ports: {}, pool: [], pool_refreshed_at: null, draining: [{ addr: "2001:db8:1:2::11", until: iso(NOW) }] });
  assert.deepStrictEqual(old, { ...eg.emptyState(), draining: [{ addr: "2001:db8:1:2::11", until: iso(NOW) }] });
  // an idle clock without a pool is dropped
  assert.strictEqual(eg.sanitizeState({ pool: [], pool_idle_since: iso(NOW) }).pool_idle_since, null);
});

const A = "2001:db8:1:2::a"; // anchors
const B = "2001:db8:1:2::b";
const C = "2001:db8:1:2::c";
const X = "2001:db8:1:2:aaaa::1"; // addresses of ours
const Y = "2001:db8:1:2:aaaa::2";
const P1 = "2001:db8:1:2:bbbb::1";
const P2 = "2001:db8:1:2:bbbb::2";

const anchors = new Map([
  [30000, { anchor: A, cfg: "3proxy_30000.cfg" }],
  [30001, { anchor: B, cfg: "3proxy_30000.cfg" }],
  [30002, { anchor: C, cfg: "3proxy_30000.cfg" }],
  [30003, { anchor: null, cfg: "3proxy_30000.cfg" }],
]);

function call(state, op, ports, extra = {}) {
  const plan = eg.planCall(state, { op, mode: extra.mode, ports, anchors });
  return {
    plan,
    ...eg.applyCall(state, plan, { op, mode: extra.mode, nowMs: NOW, drainSec: 60, poolDrainSec: 600, ...extra }),
  };
}

test("rotate: new current, mode static, the old current drains; errors per port", () => {
  const before = stateWith({ 30000: { anchor: A, current: X, mode: "static" } });
  const { plan, state, items } = call(before, "rotate", [30000, 30001, 30003, 39999, 30002], {
    freshByPort: new Map([[30000, Y], [30001, P1]]), // 30002's add failed
  });
  assert.deepStrictEqual(plan.steps.filter((s) => s.wantsAddress).map((s) => s.port), [30000, 30001, 30002]);
  assert.deepStrictEqual(items, [
    { port: 30000, ok: true, anchor: A, mode: "static", old_ipv6: X, new_ipv6: Y, error: null },
    { port: 30001, ok: true, anchor: B, mode: "static", old_ipv6: null, new_ipv6: P1, error: null },
    { port: 30003, ok: false, anchor: null, mode: null, old_ipv6: null, new_ipv6: null, error: "anchor_not_found" },
    { port: 39999, ok: false, anchor: null, mode: null, old_ipv6: null, new_ipv6: null, error: "port_not_found" },
    { port: 30002, ok: false, anchor: C, mode: null, old_ipv6: null, new_ipv6: null, error: "address_add_failed" },
  ]);
  assert.deepStrictEqual(state.ports, {
    30000: { anchor: A, current: Y, mode: "static" },
    30001: { anchor: B, current: P1, mode: "static" },
  });
  assert.deepStrictEqual(state.draining, [{ addr: X, until: iso(NOW + 60000), port: 30000 }]);
  assert.deepStrictEqual(before.ports[30000].current, X, "input state is never mutated");
});

test("mode per_connection: lazy pool, static mapping leaves, its address drains", () => {
  const before = stateWith({ 30000: { anchor: A, current: X, mode: "static" } });
  const { plan, state, items } = call(before, "mode", [30000, 30001], { mode: "per_connection", freshPool: [P1, P2] });
  assert.strictEqual(plan.wantsPool, true);
  assert.deepStrictEqual(items.map((i) => [i.port, i.ok, i.mode, i.old_ipv6, i.new_ipv6]), [
    [30000, true, "per_connection", X, "pool"],
    [30001, true, "per_connection", null, "pool"],
  ]);
  assert.deepStrictEqual(state.pool, [P1, P2]);
  assert.strictEqual(state.pool_refreshed_at, iso(NOW));
  assert.strictEqual(state.pool_idle_since, null);
  assert.deepStrictEqual(state.draining, [{ addr: X, until: iso(NOW + 60000), port: 30000 }]);

  // an existing pool is reused, not regrown
  assert.strictEqual(eg.planCall(state, { op: "mode", mode: "per_connection", ports: [30002], anchors }).wantsPool, false);

  // no pool could be added → every per_connection item fails, nothing changes
  const failed = call(before, "mode", [30001], { mode: "per_connection", freshPool: [] });
  assert.strictEqual(failed.items[0].error, "address_add_failed");
  assert.deepStrictEqual(failed.state, before);
});

test("mode static / reset; the last per_connection port leaves the pool idle, not drained", () => {
  const before = stateWith(
    {
      30000: { anchor: A, current: null, mode: "per_connection" },
      30001: { anchor: B, current: null, mode: "per_connection" },
      30002: { anchor: C, current: X, mode: "static" },
    },
    { pool: [P1, P2], pool_refreshed_at: iso(NOW - 1000) }
  );
  const one = call(before, "mode", [30000], { mode: "static", drainSec: 0 });
  assert.deepStrictEqual(one.items[0], { port: 30000, ok: true, anchor: A, mode: null, old_ipv6: "pool", new_ipv6: null, error: null });
  assert.strictEqual(one.state.ports["30000"], undefined, "static without an address forgets the port");
  assert.deepStrictEqual(one.state.pool, [P1, P2], "30001 still uses the pool");

  const two = call(one.state, "reset", [30001, 30002, 31000, 39999], { drainSec: 0 });
  assert.deepStrictEqual(two.items.map((i) => [i.port, i.ok, i.mode, i.old_ipv6, i.new_ipv6, i.error]), [
    [30001, true, null, "pool", null, null],
    [30002, true, null, X, null, null],
    [31000, true, null, null, null, null], // never had state: reset is idempotent
    [39999, true, null, null, null, null], // no cfg either
  ]);
  assert.deepStrictEqual(two.state.ports, {});
  assert.deepStrictEqual(two.state.pool, [P1, P2], "kept: a switch back reuses it");
  assert.strictEqual(two.state.pool_refreshed_at, iso(NOW - 1000));
  assert.strictEqual(two.state.pool_idle_since, iso(NOW));
  assert.deepStrictEqual(two.state.draining, [{ addr: X, until: iso(NOW), port: 30002 }]);
  assert.strictEqual(eg.nftDiffScript(one.state, two.state), [
    `delete element ip6 netrun_egress static_egress { ${C} }`,
    `delete element ip6 netrun_egress dyn_anchors { ${B} }`,
    "",
  ].join("\n"), "an idle pool keeps its dyn rule (no port reaches it)");

  // back to per_connection while idle: the pool is reused, the idle clock stops
  const back = call(two.state, "mode", [30001], { mode: "per_connection" });
  assert.strictEqual(back.plan.wantsPool, false);
  assert.deepStrictEqual([back.state.pool, back.state.pool_idle_since], [[P1, P2], null]);

  // an already idle pool keeps its clock through later calls
  const later = eg.applyCall(two.state, eg.planCall(two.state, { op: "reset", ports: [30000], anchors }), {
    op: "reset", nowMs: NOW + 5000, drainSec: 0,
  });
  assert.strictEqual(later.state.pool_idle_since, iso(NOW));
});

test("retireIdlePool: an idle pool drains after idleSec (default drain), nothing else does", () => {
  const idle = stateWith({ 30000: { anchor: A, current: X, mode: "static" } }, {
    pool: [P1, P2], pool_refreshed_at: iso(NOW - 5000), pool_idle_since: iso(NOW - 600000),
  });
  assert.strictEqual(eg.retireIdlePool({ ...idle, pool_idle_since: iso(NOW - 599999) }, { nowMs: NOW, idleSec: 600, drainSec: 300 }), null);
  const out = eg.retireIdlePool(idle, { nowMs: NOW, idleSec: 600, drainSec: 300 });
  assert.deepStrictEqual([out.pool, out.pool_refreshed_at, out.pool_idle_since], [[], null, null]);
  assert.deepStrictEqual(out.draining, [{ addr: P1, until: iso(NOW + 300000) }, { addr: P2, until: iso(NOW + 300000) }]);
  assert.deepStrictEqual(out.ports, idle.ports);
  assert.deepStrictEqual(idle.pool, [P1, P2], "input state is never mutated");
  // in use, or no pool → nothing
  const used = { ...idle, ports: { 30001: { anchor: B, current: null, mode: "per_connection" } } };
  assert.strictEqual(eg.retireIdlePool(used, { nowMs: NOW, idleSec: 600, drainSec: 300 }), null);
  assert.strictEqual(eg.retireIdlePool(eg.emptyState(), { nowMs: NOW, idleSec: 600, drainSec: 300 }), null);
});

test("one draining address per port: retiring a current again ends the port's older drain now", () => {
  const Z = "2001:db8:1:2:aaaa::9";
  const W = "2001:db8:1:2:aaaa::8";
  const before = stateWith({ 30000: { anchor: A, current: Y, mode: "static" }, 30001: { anchor: B, current: P1, mode: "static" } }, {
    draining: [
      { addr: Z, until: iso(NOW + 300000), port: 30000 }, // 30000's previous address, still draining
      { addr: W, until: iso(NOW + 300000), port: 30001 }, // another port's: untouched
      { addr: P2, until: iso(NOW + 300000) }, // a pool member: untouched
    ],
  });
  const { state } = call(before, "rotate", [30000], { freshByPort: new Map([[30000, X]]) });
  assert.deepStrictEqual(state.draining, [
    { addr: Z, until: iso(NOW), port: 30000 },
    { addr: W, until: iso(NOW + 300000), port: 30001 },
    { addr: P2, until: iso(NOW + 300000) },
    { addr: Y, until: iso(NOW + 60000), port: 30000 },
  ]);
  // mode / reset retire a current the same way
  const reset = call(state, "reset", [30000], { drainSec: 600 });
  assert.deepStrictEqual(reset.state.draining.filter((d) => d.port === 30000), [
    { addr: Z, until: iso(NOW), port: 30000 },
    { addr: Y, until: iso(NOW), port: 30000 },
    { addr: X, until: iso(NOW + 600000), port: 30000 },
  ]);
});

test("fitBudget: within the budget nothing changes; over it the soonest drains end, then ports are refused", () => {
  const s = stateWith({ 30000: { anchor: A, current: X, mode: "static" } }, {
    pool: [P1],
    draining: [
      { addr: Y, until: iso(NOW + 500000), port: 30001 },
      { addr: P2, until: iso(NOW + 100000) },
      { addr: "2001:db8:1:2::d1", until: iso(NOW - 1) }, // due: the GC is on it, not counted
    ],
  });
  const ok = eg.fitBudget(s, 2, { max: 6, nowMs: NOW });
  assert.deepStrictEqual([ok.allowed, ok.cut], [2, 0]);
  assert.strictEqual(ok.state, s, "untouched");
  assert.deepStrictEqual(eg.fitBudget(s, 0, { max: 1, nowMs: NOW }), { state: s, allowed: 0, cut: 0 });

  // live 2 + draining 2 + want 3 = 7 > 6 → the drain due soonest (P2) ends now
  const one = eg.fitBudget(s, 3, { max: 6, nowMs: NOW });
  assert.deepStrictEqual([one.allowed, one.cut], [3, 1]);
  assert.deepStrictEqual(one.state.draining.map((d) => [d.addr, d.until]), [
    [Y, iso(NOW + 500000)], [P2, iso(NOW)], ["2001:db8:1:2::d1", iso(NOW - 1)],
  ]);
  assert.strictEqual(s.draining[1].until, iso(NOW + 100000), "input state is never mutated");

  // even with every drain ended only max - live fit
  const tight = eg.fitBudget(s, 5, { max: 4, nowMs: NOW });
  assert.deepStrictEqual([tight.allowed, tight.cut], [2, 2]);
  assert.deepStrictEqual(eg.fitBudget(s, 5, { max: 1, nowMs: NOW }).allowed, 0);
});

test("applyCall: budget-refused ports / pool fail with address_budget_exceeded", () => {
  const before = stateWith({});
  const r = call(before, "rotate", [30000, 30001], { freshByPort: new Map([[30000, X]]), refused: new Set([30001]) });
  assert.deepStrictEqual(r.items.map((i) => [i.port, i.ok, i.error]), [[30000, true, null], [30001, false, "address_budget_exceeded"]]);
  const m = call(before, "mode", [30000], { mode: "per_connection", freshPool: [], poolRefused: true });
  assert.deepStrictEqual([m.items[0].ok, m.items[0].error], [false, "address_budget_exceeded"]);
  assert.deepStrictEqual(m.state, before);
});

test("a state entry whose anchor changed in the cfg is stale: replaced, old address drains", () => {
  const OLD = "2001:db8:1:2::99";
  const before = stateWith({ 30000: { anchor: OLD, current: X, mode: "static" } });
  const { state, items } = call(before, "rotate", [30000], { freshByPort: new Map([[30000, Y]]) });
  assert.deepStrictEqual(items[0], { port: 30000, ok: true, anchor: A, mode: "static", old_ipv6: null, new_ipv6: Y, error: null });
  assert.deepStrictEqual(state.ports[30000], { anchor: A, current: Y, mode: "static" });
  assert.deepStrictEqual(state.draining.map((d) => d.addr), [X]);
});

test("reconcileWithCfgs / dropMissing (startup)", () => {
  const before = stateWith(
    {
      30000: { anchor: A, current: X, mode: "static" },
      30001: { anchor: "2001:db8:1:2::77", current: Y, mode: "static" }, // regenerated
      31000: { anchor: "2001:db8:1:2::31", current: null, mode: "per_connection" }, // cfg gone
    },
    { pool: [P1], pool_refreshed_at: iso(NOW) }
  );
  const rec = eg.reconcileWithCfgs(before, anchors, { nowMs: NOW });
  assert.deepStrictEqual(rec.dropped, [30001, 31000]);
  assert.deepStrictEqual(Object.keys(rec.state.ports), ["30000"]);
  assert.deepStrictEqual(rec.state.pool, [P1], "no per_connection port left → the pool goes idle");
  assert.strictEqual(rec.state.pool_idle_since, iso(NOW));
  assert.deepStrictEqual(rec.state.draining, [{ addr: Y, until: iso(NOW) }]);
  // an idle clock already running is kept
  const again = eg.reconcileWithCfgs({ ...rec.state, pool_idle_since: iso(NOW - 9000) }, anchors, { nowMs: NOW });
  assert.strictEqual(again.state.pool_idle_since, iso(NOW - 9000));

  const s = stateWith(
    { 30000: { anchor: A, current: X, mode: "static" }, 30001: { anchor: B, current: Y, mode: "static" } },
    { pool: [P1, P2], draining: [{ addr: "2001:db8:1:2::d1", until: iso(NOW) }] }
  );
  const present = new Set([X, P2]); // proxy entries (or, not yet moved, NIC addresses)
  const kept = eg.dropMissing(s, present);
  assert.deepStrictEqual(kept.state.ports[30001], { anchor: B, current: null, mode: "static" });
  assert.deepStrictEqual(kept.state.ports[30000].current, X);
  assert.deepStrictEqual(kept.state.pool, [P2]);
  assert.deepStrictEqual(kept.state.draining, []);
  assert.deepStrictEqual(kept.lost.sort(), [P1, Y].sort());
  const noPool = eg.dropMissing({ ...s, pool_refreshed_at: iso(NOW) }, new Set());
  assert.deepStrictEqual([noPool.state.pool, noPool.state.pool_refreshed_at], [[], null]);
});

test("pool refresh: oldest fraction out, shortfall filled, a failed add never shrinks it", () => {
  const pool = ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"];
  assert.strictEqual(eg.poolRefreshNeed(pool, 8, 0.25), 2);
  assert.deepStrictEqual(eg.refreshPoolMembers(pool, 8, 0.25, ["n0", "n1"]), {
    pool: ["p2", "p3", "p4", "p5", "p6", "p7", "n0", "n1"],
    retired: ["p0", "p1"],
  });
  assert.deepStrictEqual(eg.refreshPoolMembers(pool, 8, 0.25, ["n0"]), {
    pool: ["p1", "p2", "p3", "p4", "p5", "p6", "p7", "n0"],
    retired: ["p0"],
  });
  assert.deepStrictEqual(eg.refreshPoolMembers(pool, 8, 0.25, []).pool, pool);
  // an empty / short pool is filled to size
  assert.strictEqual(eg.poolRefreshNeed([], 4, 0.25), 4);
  assert.strictEqual(eg.poolRefreshNeed(["p0", "p1"], 4, 0.25), 3);
  assert.deepStrictEqual(eg.refreshPoolMembers(["p0", "p1"], 4, 0.25, ["n0", "n1", "n2"]).pool, ["p1", "n0", "n1", "n2"]);
  // EGRESS_POOL_SIZE lowered: extra members retire
  assert.deepStrictEqual(eg.refreshPoolMembers(pool, 4, 0.25, ["n0"]), {
    pool: ["p5", "p6", "p7", "n0"],
    retired: ["p0", "p1", "p2", "p3", "p4"],
  });
});

test("planGc: due proxy entries deleted, NIC leftovers with their real prefix length; protected never", () => {
  const Z = "2001:db8:1:2:aaaa::9";
  const s = stateWith({}, {
    draining: [
      { addr: X, until: iso(NOW - 1) }, // due, a proxy entry
      { addr: Y, until: iso(NOW) }, // due, proxy entry + left on the NIC (/64) by the version before
      { addr: Z, until: iso(NOW) }, // due, only on the NIC (its proxy entry never came)
      { addr: P1, until: iso(NOW + 1) }, // not yet
      { addr: P2, until: iso(NOW - 1) }, // due but already gone
      { addr: A, until: iso(NOW - 1) }, // an anchor again → never deleted
    ],
  });
  const plan = eg.planGc(s, {
    nowMs: NOW,
    proxies: new Set([X, Y, P1, A]),
    nic: new Map([[Y, 64], [Z, 128], [A, 128]]),
    protectedAddrs: new Set([A]),
  });
  assert.deepStrictEqual(plan.deletes.map((d) => [d.addr, d.proxy, d.plen]), [[X, true, undefined], [Y, true, 64], [Z, false, 128]]);
  assert.deepStrictEqual(plan.keep.map((d) => d.addr), [P1]);
  assert.deepStrictEqual(eg.gcBatchLines(plan.deletes, "eth0"), [
    `neigh del proxy ${X} dev eth0`,
    `neigh del proxy ${Y} dev eth0`,
    `address del ${Y}/64 dev eth0`,
    `address del ${Z}/128 dev eth0`,
  ]);
  // no NIC leftovers (the usual case): proxy entries only
  assert.deepStrictEqual(eg.planGc(s, { nowMs: NOW, proxies: new Set([X]), protectedAddrs: new Set() }).deletes.map((d) => d.addr), [X]);
});

// chain exit_guard as nftRebuildScript writes it (`primaryLine`: the rule
// for the node's own address(es), or null).
function exitGuardText(prefix, primaryLine) {
  return [
    "\tchain exit_guard {",
    "\t\ttype filter hook input priority filter - 10; policy accept;",
    "\t\tiif \"lo\" accept",
    `\t\tip6 daddr != ${prefix} accept`,
    ...(primaryLine ? [`\t\t${primaryLine}`] : []),
    "\t\tct state established,related accept",
    "\t\ticmpv6 type echo-request drop",
    "\t\tmeta l4proto ipv6-icmp accept",
    "\t\tdrop",
    "\t}",
  ];
}

test("nftRebuildScript: the exact table from the plan, one transaction", () => {
  const s = stateWith(
    {
      30002: { anchor: C, current: Y, mode: "static" },
      30000: { anchor: A, current: X, mode: "static" },
      30001: { anchor: B, current: null, mode: "per_connection" },
      30003: { anchor: "2001:db8:1:2::d", current: null, mode: "static" },
    },
    { pool: [P1, P2] }
  );
  assert.strictEqual(eg.nftRebuildScript(s, "2001:db8:1:2::/64", { primary: ["2001:db8:1:2::1"] }), [
    "add table ip6 netrun_egress",
    "delete table ip6 netrun_egress",
    "table ip6 netrun_egress {",
    "\tset dyn_anchors {",
    "\t\ttype ipv6_addr",
    "\t\telements = {",
    `\t\t\t${B}`,
    "\t\t}",
    "\t}",
    "\tmap static_egress {",
    "\t\ttype ipv6_addr : ipv6_addr",
    "\t\telements = {",
    `\t\t\t${A} : ${X},`,
    `\t\t\t${C} : ${Y}`,
    "\t\t}",
    "\t}",
    "\tchain dyn {",
    `\t\tsnat to numgen random mod 2 map { 0 : ${P1}, 1 : ${P2} }`,
    "\t}",
    "\tchain post {",
    "\t\ttype nat hook postrouting priority srcnat; policy accept;",
    "\t\tip6 saddr @dyn_anchors goto dyn",
    "\t\tsnat to ip6 saddr map @static_egress",
    "\t}",
    "\tchain forward_guard {",
    "\t\ttype filter hook forward priority filter; policy accept;",
    "\t\tip6 daddr 2001:db8:1:2::/64 drop",
    "\t}",
    "\tchain exit_guard {",
    "\t\ttype filter hook input priority filter - 10; policy accept;",
    "\t\tiif \"lo\" accept",
    "\t\tip6 daddr != 2001:db8:1:2::/64 accept",
    "\t\tip6 daddr 2001:db8:1:2::1 accept",
    "\t\tct state established,related accept",
    "\t\ticmpv6 type echo-request drop",
    "\t\tmeta l4proto ipv6-icmp accept",
    "\t\tdrop",
    "\t}",
    "}",
    "",
  ].join("\n"));

  // empty state: same shape, no elements, an empty dyn chain (egress = anchor),
  // the forward guard for whatever /64 the node has; the exit guard is on by
  // default, with no primary line when no primary address is known
  const empty = eg.nftRebuildScript(eg.emptyState(), "2001:db8:aaaa:5::/64");
  assert.ok(!empty.includes("elements"));
  assert.ok(empty.includes("\tchain dyn {\n\t}\n"));
  assert.ok(empty.endsWith([
    "\tchain forward_guard {",
    "\t\ttype filter hook forward priority filter; policy accept;",
    "\t\tip6 daddr 2001:db8:aaaa:5::/64 drop",
    "\t}",
    ...exitGuardText("2001:db8:aaaa:5::/64", null),
    "}",
    "",
  ].join("\n")));
  // several primary addresses → one anonymous set
  const two = eg.nftRebuildScript(eg.emptyState(), "2001:db8:aaaa:5::/64", { primary: ["2001:db8:aaaa:5::1", "2001:db8:aaaa:5::2"] });
  assert.ok(two.endsWith([
    ...exitGuardText("2001:db8:aaaa:5::/64", "ip6 daddr { 2001:db8:aaaa:5::1, 2001:db8:aaaa:5::2 } accept"),
    "}",
    "",
  ].join("\n")));
  // EGRESS_EXIT_GUARD=off: no chain at all (the primary is then irrelevant)
  const off = eg.nftRebuildScript(eg.emptyState(), "2001:db8:aaaa:5::/64", { exitGuard: false, primary: ["2001:db8:aaaa:5::1"] });
  assert.ok(!off.includes("exit_guard") && !off.includes("hook input"));
  assert.ok(off.endsWith("\t\tip6 daddr 2001:db8:aaaa:5::/64 drop\n\t}\n}\n"));
  // the element delta never touches a chain: the guard survives every rotation
  const rotated = stateWith({ 30000: { anchor: A, current: X, mode: "static" } });
  assert.ok(!/chain|exit_guard|hook/.test(eg.nftDiffScript(eg.emptyState(), rotated)));
  // never a table without its guard; never a non-canonical address in the text
  for (const bad of [undefined, null, "", "2001:db8:1::/48", "nope"]) {
    assert.throws(() => eg.nftRebuildScript(s, bad), TypeError, String(bad));
  }
  for (const bad of ["2001:0db8:1:2::1", "2001:db8:1:2::1/64", "2001:db8:1:2::1 accept; drop", "nope"]) {
    assert.throws(() => eg.nftRebuildScript(s, "2001:db8:1:2::/64", { primary: [bad] }), TypeError, bad);
  }
});

test("parsePrimaryAddrs: the node's own /64 address, never an anchor, /128 or nodad; capped", () => {
  const prefix = eg.parsePrefix("2001:db8:1:2::/64");
  const line = (a, rest) => `2: eth0    inet6 ${a} ${rest} \\       valid_lft forever preferred_lft forever`;
  const out = [
    line("2001:db8:1:2:5400:4ff:fe12:3456/64", "scope global dynamic mngtmpaddr noprefixroute"), // SLAAC: the primary
    line("2001:0db8:1:2::1/64", "scope global"), // static (netplan), padded text
    line("2001:db8:1:2:a0a0:b1b:c2c:d3d/128", "scope global nodad"), // generator anchor
    line("2001:db8:1:2:a0a0:b1b:c2c:d3e/64", "scope global nodad"), // anchor restored as /64 at boot
    line("2001:db8:1:2:a0a0:b1b:c2c:d3f/64", "scope global"), // anchor from an older restore (no nodad): a cfg anchor
    line("2001:db8:1:2:aaaa::9/64", "scope global"), // an address of this module (excluded by the caller)
    line("2001:db8:1:2::bad/64", "scope global dadfailed tentative"),
    line("2001:db8:1:2::7/128", "scope global"), // a /128 is never the host's own
    line("2001:db8:9:9::1/64", "scope global"), // another prefix: rule 1 already lets it in
    line("fe80::5400:4ff:fe12:3456/64", "scope link"),
    "garbage",
  ].join("\n");
  const exclude = new Set(["2001:db8:1:2:a0a0:b1b:c2c:d3f", "2001:db8:1:2:aaaa::9"]);
  assert.deepStrictEqual(eg.parsePrimaryAddrs(out, prefix, exclude), {
    addrs: ["2001:db8:1:2:5400:4ff:fe12:3456", "2001:db8:1:2::1"], candidates: 2,
  });
  // without the exclusions the unflagged anchor would pass: the caller must give them
  assert.strictEqual(eg.parsePrimaryAddrs(out, prefix).candidates, 4);
  assert.deepStrictEqual(eg.parsePrimaryAddrs("", prefix), { addrs: [], candidates: 0 });
  // a /64 full of unflagged addresses: fail closed (none), never thousands
  const many = Array.from({ length: eg.MAX_PRIMARY_ADDRS + 1 }, (_, i) => line(`2001:db8:1:2::${(i + 1).toString(16)}/64`, "scope global")).join("\n");
  assert.deepStrictEqual(eg.parsePrimaryAddrs(many, prefix), { addrs: [], candidates: eg.MAX_PRIMARY_ADDRS + 1 });
  const max = many.split("\n").slice(1).join("\n");
  assert.strictEqual(eg.parsePrimaryAddrs(max, prefix).addrs.length, eg.MAX_PRIMARY_ADDRS);
});

test("nftDiffScript: element deltas, value change = delete + add, pool = flush + rule", () => {
  const before = stateWith(
    {
      30000: { anchor: A, current: X, mode: "static" },
      30001: { anchor: B, current: null, mode: "per_connection" },
    },
    { pool: [P1] }
  );
  assert.strictEqual(eg.nftDiffScript(before, before), null);
  assert.strictEqual(
    eg.nftDiffScript(before, { ...before, draining: [{ addr: Y, until: iso(NOW) }] }),
    null,
    "draining addresses are not in nft"
  );

  const after = stateWith(
    {
      30000: { anchor: A, current: Y, mode: "static" },
      30001: { anchor: B, current: P2, mode: "static" },
      30002: { anchor: C, current: null, mode: "per_connection" },
    },
    { pool: [P1, P2] }
  );
  assert.strictEqual(eg.nftDiffScript(before, after), [
    `delete element ip6 netrun_egress static_egress { ${A} }`,
    `delete element ip6 netrun_egress dyn_anchors { ${B} }`,
    `add element ip6 netrun_egress static_egress { ${A} : ${Y}, ${B} : ${P2} }`,
    `add element ip6 netrun_egress dyn_anchors { ${C} }`,
    "flush chain ip6 netrun_egress dyn",
    `add rule ip6 netrun_egress dyn snat to numgen random mod 2 map { 0 : ${P1}, 1 : ${P2} }`,
    "",
  ].join("\n"));

  // pool gone → flush only (an empty dyn chain = anchor)
  assert.strictEqual(
    eg.nftDiffScript(before, { ...before, ports: { 30000: before.ports[30000] }, pool: [] }),
    `delete element ip6 netrun_egress dyn_anchors { ${B} }\nflush chain ip6 netrun_egress dyn\n`
  );

  // 600 changes → statements of at most 256 elements
  const many = {};
  const manyAfter = {};
  for (let i = 0; i < 600; i++) {
    const anchor = `2001:db8:1:2:1::${(i + 1).toString(16)}`;
    many[40000 + i] = { anchor, current: null, mode: "static" };
    manyAfter[40000 + i] = { anchor, current: `2001:db8:1:2:2::${(i + 1).toString(16)}`, mode: "static" };
  }
  const lines = eg.nftDiffScript(stateWith(many), stateWith(manyAfter)).trim().split("\n");
  assert.strictEqual(lines.length, 3);
  assert.deepStrictEqual(lines.map((l) => l.split(" : ").length - 1), [256, 256, 88]);
});

test("parseCallBody / parsePortsQuery: 400 on anything malformed", () => {
  const ok = eg.parseCallBody({ ports: [30000, 30001, 30000], drain_sec: 0 }, { op: "rotate", defaultDrainSec: 600 });
  assert.deepStrictEqual(ok, { ports: [30000, 30001], drainSec: 0, mode: null });
  assert.strictEqual(eg.parseCallBody({ ports: [] }, { op: "reset", defaultDrainSec: 600 }).drainSec, 600);
  assert.strictEqual(eg.parseCallBody({ ports: [1], mode: "static" }, { op: "mode", defaultDrainSec: 1 }).mode, "static");
  const tooMany = Array.from({ length: 1001 }, (_, i) => 20000 + i);
  const bad = [
    [null, "rotate"],
    [[], "rotate"],
    [{}, "rotate"],
    [{ ports: "30000" }, "rotate"],
    [{ ports: [30000.5] }, "rotate"],
    [{ ports: ["30000"] }, "rotate"],
    [{ ports: [0] }, "rotate"],
    [{ ports: [65536] }, "rotate"],
    [{ ports: tooMany }, "rotate"],
    [{ ports: [1], drain_sec: -1 }, "rotate"],
    [{ ports: [1], drain_sec: "60" }, "rotate"],
    [{ ports: [1], drain_sec: 7 * 24 * 3600 + 1 }, "rotate"],
    [{ ports: [1] }, "mode"],
    [{ ports: [1], mode: "timer" }, "mode"],
  ];
  for (const [body, op] of bad) {
    assert.throws(() => eg.parseCallBody(body, { op, defaultDrainSec: 600 }), (err) => err.code === "BAD_REQUEST", JSON.stringify(body));
  }
  assert.deepStrictEqual(eg.parsePortsQuery("30000, 30001,30000"), [30000, 30001]);
  assert.strictEqual(eg.parsePortsQuery(null), null);
  assert.strictEqual(eg.parsePortsQuery(""), null);
  for (const q of ["30000,abc", "0", "70000", "1e3", tooMany.join(",")]) {
    assert.throws(() => eg.parsePortsQuery(q), (err) => err.code === "BAD_REQUEST", q);
  }
});

test("nftDropinText: the boot drop-in; install_node_v2.sh and node_followup_v2.sh write the same text", () => {
  const text = eg.nftDropinText("/usr/sbin/nft");
  assert.ok(text.endsWith("[Service]\nExecStartPost=-/usr/sbin/nft delete table ip6 netrun_egress\n"));
  assert.ok(text.split("\n").slice(0, -3).every((l) => l.startsWith("# ")), "comments only above [Service]");
  const repo = path.resolve(__dirname, "..", "..");
  for (const script of ["install_node_v2.sh", "scripts/node_followup_v2.sh"]) {
    const src = fs.readFileSync(path.join(repo, script), "utf-8");
    const m = /cat > \/etc\/systemd\/system\/nftables\.service\.d\/netrun-egress\.conf <<EOF\n([\s\S]*?)\nEOF\n/.exec(src);
    assert.ok(m, `${script}: drop-in heredoc`);
    assert.strictEqual(`${m[1].replace(/\$\{[A-Za-z_]+\}/g, "/usr/sbin/nft")}\n`, text, script);
  }
});

test("findExecutable: absolute PATH entries first, then the sbin dirs; null when absent", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-which-"));
  try {
    fs.writeFileSync(path.join(dir, "nft"), "#!/bin/sh\n", { mode: 0o755 });
    fs.writeFileSync(path.join(dir, "noexec"), "", { mode: 0o644 });
    assert.strictEqual(eg.findExecutable("nft", `relative/bin:${dir}`), path.join(dir, "nft"));
    assert.strictEqual(eg.findExecutable("noexec", dir), null);
    assert.strictEqual(eg.findExecutable("netrun-no-such-binary", dir), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
