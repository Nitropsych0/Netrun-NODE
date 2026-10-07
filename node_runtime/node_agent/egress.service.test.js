"use strict";

// Wave IPV6-ROTATION — egress.js end to end against a fake host: one NIC's
// IPv6 addresses (iproute2 semantics, incl. the prefix-length match on
// delete), its proxy neighbour entries (`ip -6 neigh ... proxy`), its
// /proc/sys proxy-NDP sysctls and an nftables model that applies our `nft -f`
// scripts as all-or-nothing transactions (a `delete element` of a missing key
// aborts the whole file, like the kernel). After every step the kernel table
// must equal what the persisted state asks for, every address it maps must
// have a proxy entry, and none of ours may sit on the NIC.
// Run with: node --test node_runtime/node_agent/egress.service.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const eg = require(path.resolve(__dirname, "egress.js"));

const T = "ip6 netrun_egress";
const PRIMARY = "2001:db8:1:2::1";
const PREFIX = "2001:db8:1:2::/64";

const roots = [];
test.after(() => {
  for (const r of roots) fs.rmSync(r, { recursive: true, force: true });
});

// ── fake host ────────────────────────────────────────────────────────────

// fwd: the /64 of the forward guard (chain forward_guard), null before a definition.
function emptyTable(fwd = null) {
  return { dyn: new Set(), map: new Map(), pool: [], fwd };
}

function parsePoolRule(text) {
  const m = /^snat to numgen random mod (\d+) map \{ (.+) \}$/.exec(text);
  if (!m) throw new Error(`syntax error: ${text}`);
  const pairs = m[2].split(", ").map((p) => p.split(" : "));
  pairs.forEach(([i], idx) => { if (Number(i) !== idx) throw new Error("numgen keys must be 0..K-1"); });
  if (pairs.length !== Number(m[1])) throw new Error("mod K must equal the map size");
  return pairs.map(([, a]) => a);
}

function readElements(lines, i) {
  // "\t\telements = {" ... "\t\t}"
  const out = [];
  i += 1;
  while (lines[i] !== "\t\t}") {
    if (i >= lines.length) throw new Error("unterminated elements");
    out.push(lines[i].trim().replace(/,$/, ""));
    i += 1;
  }
  return { out, i };
}

// The `table ip6 netrun_egress { ... }` block exactly as egress.js writes it.
function parseTableBlock(lines) {
  const t = emptyTable();
  const expect = (i, text) => { if (lines[i] !== text) throw new Error(`syntax error at "${lines[i]}" (want "${text}")`); };
  let i = 0;
  expect(i++, "\tset dyn_anchors {");
  expect(i++, "\t\ttype ipv6_addr");
  if (lines[i] === "\t\telements = {") {
    const r = readElements(lines, i);
    r.out.forEach((a) => t.dyn.add(a));
    i = r.i + 1;
  }
  expect(i++, "\t}");
  expect(i++, "\tmap static_egress {");
  expect(i++, "\t\ttype ipv6_addr : ipv6_addr");
  if (lines[i] === "\t\telements = {") {
    const r = readElements(lines, i);
    for (const pair of r.out) {
      const [k, v] = pair.split(" : ");
      if (t.map.has(k)) throw new Error(`duplicate map key ${k}`);
      t.map.set(k, v);
    }
    i = r.i + 1;
  }
  expect(i++, "\t}");
  expect(i++, "\tchain dyn {");
  if (lines[i] !== "\t}") t.pool = parsePoolRule(lines[i++].trim());
  expect(i++, "\t}");
  expect(i++, "\tchain post {");
  expect(i++, "\t\ttype nat hook postrouting priority srcnat; policy accept;");
  expect(i++, "\t\tip6 saddr @dyn_anchors goto dyn");
  expect(i++, "\t\tsnat to ip6 saddr map @static_egress");
  expect(i++, "\t}");
  expect(i++, "\tchain forward_guard {");
  expect(i++, "\t\ttype filter hook forward priority filter; policy accept;");
  const guard = /^\t\tip6 daddr (\S+\/64) drop$/.exec(lines[i++] || "");
  if (!guard) throw new Error(`syntax error at "${lines[i - 1]}" (want the forward guard)`);
  t.fwd = guard[1];
  expect(i++, "\t}");
  if (i !== lines.length) throw new Error("trailing lines in table block");
  return t;
}

function nftTransaction(table, script) {
  let t = table && { dyn: new Set(table.dyn), map: new Map(table.map), pool: table.pool.slice(), fwd: table.fwd };
  const need = () => { if (!t) throw new Error("No such file or directory (table)"); };
  const lines = script.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    let m;
    if (line === `add table ${T}`) {
      if (!t) t = emptyTable();
    } else if (line === `delete table ${T}`) {
      need();
      t = null;
    } else if (line === `table ${T} {`) {
      if (t) throw new Error("test model: a definition only follows a delete");
      const block = [];
      for (i += 1; lines[i] !== "}"; i++) {
        if (i >= lines.length) throw new Error("unterminated table");
        block.push(lines[i]);
      }
      t = parseTableBlock(block);
    } else if ((m = /^delete element ip6 netrun_egress (static_egress|dyn_anchors) \{ (.+) \}$/.exec(line))) {
      need();
      const c = m[1] === "static_egress" ? t.map : t.dyn;
      for (const k of m[2].split(", ")) {
        if (!c.has(k)) throw new Error(`Could not process rule: No such file or directory (${k})`);
        c.delete(k);
      }
    } else if ((m = /^add element ip6 netrun_egress static_egress \{ (.+) \}$/.exec(line))) {
      need();
      for (const pair of m[1].split(", ")) {
        const [k, v] = pair.split(" : ");
        if (t.map.has(k) && t.map.get(k) !== v) throw new Error(`Could not process rule: File exists (${k})`);
        t.map.set(k, v);
      }
    } else if ((m = /^add element ip6 netrun_egress dyn_anchors \{ (.+) \}$/.exec(line))) {
      need();
      for (const k of m[1].split(", ")) t.dyn.add(k);
    } else if (line === `flush chain ${T} dyn`) {
      need();
      t.pool = [];
    } else if ((m = /^add rule ip6 netrun_egress dyn (.+)$/.exec(line))) {
      need();
      if (t.pool.length) throw new Error("test model: dyn holds one rule");
      t.pool = parsePoolRule(m[1]);
    } else {
      throw new Error(`syntax error: ${line}`);
    }
  }
  return t;
}

// /proc/sys of a node as the installers leave it: forwarding on (all), proxy
// NDP off, the kernel's default proxy_delay.
function fakeProcSys(iface, values = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-egress-proc-"));
  roots.push(dir);
  const all = {
    "net/ipv6/conf/all/forwarding": "1",
    "net/ipv6/conf/all/proxy_ndp": "0",
    [`net/ipv6/conf/${iface}/forwarding`]: "1",
    [`net/ipv6/conf/${iface}/proxy_ndp`]: "0",
    [`net/ipv6/conf/${iface}/accept_ra`]: "0",
    [`net/ipv6/neigh/${iface}/proxy_delay`]: "80",
    ...values,
  };
  for (const [key, value] of Object.entries(all)) {
    fs.mkdirSync(path.dirname(path.join(dir, key)), { recursive: true });
    fs.writeFileSync(path.join(dir, key), `${value}\n`);
  }
  return dir;
}

function sysctl(host, key) {
  return fs.readFileSync(path.join(host.procSys, key), "utf-8").trim();
}

function fakeHost({ iface = "eth0", route = true, nftMissing = false, sysctls = {} } = {}) {
  const host = {
    iface,
    route,
    nftMissing,
    addrs: new Map([[PRIMARY, 64]]),
    proxies: new Set(), // `ip -6 neigh show proxy dev <iface>`
    procSys: fakeProcSys(iface, sysctls),
    table: null,
    log: [], // every command, in order
    nftScripts: [],
    ipBatches: [],
    refuseAdd: () => false, // (address) → its `neigh add proxy` fails
    refuseLine: () => false, // (batch line) → that line fails
    refuseNft: () => false,
    inFlight: 0,
    maxInFlight: 0,
  };
  function ip(args) {
    const a = args.join(" ");
    if (a === "-6 route show default") {
      return { code: 0, stdout: host.route ? `default via fe80::1 dev ${host.iface} proto static metric 1024 pref medium\n` : "", stderr: "" };
    }
    if (a.startsWith(`-6 -o addr show dev ${host.iface}`)) {
      const lines = [...host.addrs].map(([ad, p]) => `2: ${host.iface}    inet6 ${ad}/${p} scope global nodad \\       valid_lft forever preferred_lft forever`);
      if (!a.endsWith("scope global")) lines.push(`2: ${host.iface}    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever`);
      return { code: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
    }
    if (a === `-6 neigh show proxy dev ${host.iface}`) {
      return { code: 0, stdout: [...host.proxies].map((p) => `${p} proxy\n`).join(""), stderr: "" };
    }
    if (args.slice(0, 3).join(" ") === "-6 -force -batch") {
      const text = fs.readFileSync(args[3], "utf-8");
      host.ipBatches.push(text);
      let failed = 0;
      for (const line of text.split("\n").filter(Boolean)) {
        if (!line.endsWith(` dev ${host.iface}`)) throw new Error(`fake ip: wrong dev in ${line}`);
        if (host.refuseLine(line)) { failed += 1; continue; }
        let m = /^neigh add proxy (\S+) dev \S+$/.exec(line);
        if (m) {
          // adding an entry that exists succeeds (the kernel updates it)
          if (host.refuseAdd(m[1])) failed += 1;
          else host.proxies.add(m[1]);
          continue;
        }
        m = /^neigh del proxy (\S+) dev \S+$/.exec(line);
        if (m) {
          if (!host.proxies.delete(m[1])) failed += 1; // ENOENT
          continue;
        }
        m = /^address del (\S+)\/(\d+) dev \S+$/.exec(line);
        if (m) {
          // the kernel matches IPv6 deletes on address AND prefix length
          if (host.addrs.get(m[1]) !== Number(m[2])) failed += 1;
          else host.addrs.delete(m[1]);
          continue;
        }
        // `address add` included: the module never puts an address on the NIC
        throw new Error(`fake ip: unexpected batch line ${line}`);
      }
      return { code: failed ? 1 : 0, stdout: "", stderr: failed ? `Command failed (${failed})` : "" };
    }
    throw new Error(`fake ip: unexpected args ${a}`);
  }
  function nft(args) {
    if (host.nftMissing) return { code: -1, stdout: "", stderr: "spawn nft ENOENT" };
    if (args.join(" ") === `list chain ${T} post`) {
      return host.table ? { code: 0, stdout: "table ip6 netrun_egress { ... }\n", stderr: "" }
        : { code: 1, stdout: "", stderr: "Error: No such file or directory" };
    }
    assert.strictEqual(args[0], "-f");
    const script = fs.readFileSync(args[1], "utf-8");
    host.nftScripts.push(script);
    if (host.refuseNft(script)) return { code: 1, stdout: "", stderr: "Error: injected failure" };
    try {
      host.table = nftTransaction(host.table, script);
      return { code: 0, stdout: "", stderr: "" };
    } catch (err) {
      return { code: 1, stdout: "", stderr: `Error: ${err.message}` };
    }
  }
  host.run = async (cmd, args) => {
    host.inFlight += 1;
    host.maxInFlight = Math.max(host.maxInFlight, host.inFlight);
    host.log.push(`${cmd} ${args.join(" ")}`);
    try {
      await new Promise((r) => setImmediate(r)); // let concurrent callers interleave if they could
      if (cmd === "ip") return ip(args);
      if (cmd === "nft") return nft(args);
      return { code: -1, stdout: "", stderr: `spawn ${cmd} ENOENT` };
    } finally {
      host.inFlight -= 1;
    }
  };
  return host;
}

// ── fixtures ─────────────────────────────────────────────────────────────

// Anchors as the generator writes them: leading zeros, no "::".
const RAW = {
  30000: "2001:0db8:0001:0002:0a1b:00c2:0003:0d4e",
  30001: "2001:0db8:0001:0002:1111:0000:0000:0001",
  30002: "2001:0db8:0001:0002:2222:0000:0000:0002",
  31000: "2001:db8:1:2:3333::31",
  42000: "2001:db8:1:2:4444::42",
};
const ANCHOR = Object.fromEntries(Object.entries(RAW).map(([p, a]) => [p, eg.normalizeIpv6(a)]));

function block(port, addr, oldShape = false) {
  return [
    "flush",
    `users U${port}:CL:p${port}`,
    oldShape ? "" : null,
    oldShape ? "allow * * " : `allow U${port} * 1.2.3.4`,
    "deny *",
    `socks -6 -a -p${port} -i1.2.3.4 -e${addr}`,
    `proxy -6 -n -a -p${port - 10000} -i1.2.3.4 -e${addr}`,
  ].filter((l) => l !== null);
}

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-egress-"));
  roots.push(root);
  const dir = path.join(root, "3proxy");
  fs.mkdirSync(dir);
  const header = ["daemon", "nserver 127.0.0.1", "maxconn 200", "setgid 65535", "setuid 65535", "auth strong"];
  fs.writeFileSync(path.join(dir, "3proxy_30000.cfg"), [
    ...header,
    ...block(30000, RAW[30000]),
    ...block(30001, RAW[30001]),
    ...block(30002, RAW[30002]),
    "flush", "users N:CL:n", "allow N *", "deny *", "socks -6 -a -p30003 -i1.2.3.4", // no -e
    "",
  ].join("\n"));
  fs.writeFileSync(path.join(dir, "3proxy_31000.cfg"), [...header, ...block(31000, RAW[31000], true), ""].join("\n"));
  // a pay-per-GB single-port cfg parked by /accounts/:port/disable
  fs.writeFileSync(path.join(dir, "3proxy_42000.cfg.disabled"), `daemon\nauth strong\nusers c:CL:3\nallow c *\nsocks -a -p42000 -i127.0.0.1 -e${RAW[42000]}\n`);
  return root;
}

// One counter for every service in this file: a "rebooted" instance must not
// redraw the addresses an earlier one already used (real randomness would not).
let rngCounter = 0;
function deterministicRandom() {
  return (size) => {
    rngCounter += 1;
    const n = rngCounter;
    const b = Buffer.alloc(size);
    b.writeUInt32BE(0xe0000000 + n, 0);
    b.writeUInt32BE(n, 4);
    return b;
  };
}

const quiet = { log() {}, error() {} };

function makeService(host, root, { env = {}, clock = { t: Date.parse("2026-10-07T12:00:00.000Z") }, writeState, findBin } = {}) {
  const svc = eg.createEgressService({
    env: {
      NODE_AGENT_PROXY_ROOT: root,
      EGRESS_POOL_SIZE: "4",
      EGRESS_DRAIN_SEC: "600",
      EGRESS_NFT_DROPIN: "off",
      EGRESS_SYSCTL_CONF: "off",
      EGRESS_PROC_SYS: host.procSys,
      ...env,
    },
    run: host.run,
    now: () => clock.t,
    randomBytes: deterministicRandom(),
    log: quiet,
    ...(writeState ? { writeState } : {}),
    ...(findBin ? { findBin } : {}),
  });
  return { svc, clock };
}

const sorted = (it) => [...it].sort();
const stateFile = (root) => JSON.parse(fs.readFileSync(path.join(root, "egress_state.json"), "utf-8"));

const ourAddresses = (s) => new Set([
  ...Object.values(s.ports).map((e) => e.current).filter(Boolean), ...s.pool, ...s.draining.map((d) => d.addr),
]);

// The kernel holds exactly what the persisted state asks for (the forward
// guard included), every address nft can map to has a proxy entry, no proxy
// entry is left that the state does not know (`foreign`: entries a test put
// there itself), none of ours is on the NIC, and proxy NDP is on.
function assertConsistent(host, svc, root, msg = "", { foreign = new Set() } = {}) {
  const s = svc.snapshot();
  const want = eg.desiredNft(s);
  assert.ok(host.table, `${msg}: table exists`);
  assert.deepStrictEqual(sorted(host.table.map), sorted(want.staticMap), `${msg}: static_egress`);
  assert.deepStrictEqual(sorted(host.table.dyn), sorted(want.dyn), `${msg}: dyn_anchors`);
  assert.deepStrictEqual(host.table.pool, want.pool, `${msg}: dyn pool`);
  assert.strictEqual(host.table.fwd, svc.status().prefix, `${msg}: forward guard for the node's /64`);
  for (const a of [...want.staticMap.values(), ...want.pool]) assert.ok(host.proxies.has(a), `${msg}: ${a} has a proxy entry`);
  const ours = ourAddresses(s);
  for (const a of host.proxies) assert.ok(ours.has(a) || foreign.has(a), `${msg}: proxy entry ${a} leaked`);
  for (const a of ours) assert.ok(!host.addrs.has(a), `${msg}: ${a} is on the NIC`);
  assert.deepStrictEqual(
    eg.egressSysctls(host.iface).map((s) => sysctl(host, s.key.join("/"))),
    eg.egressSysctls(host.iface).map((s) => s.want),
    `${msg}: proxy-NDP sysctls`
  );
  assert.deepStrictEqual(stateFile(root), JSON.parse(JSON.stringify(s)), `${msg}: file == memory`);
  assert.ok(!fs.readdirSync(root).some((f) => f.startsWith(".egress_") || f.endsWith(".tmp")), `${msg}: no temp files left`);
}

// ── tests ────────────────────────────────────────────────────────────────

test("init on a clean node: empty table, no addresses, ready", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc } = makeService(host, root);
  assert.strictEqual(svc.isAvailable(), false);
  assert.strictEqual(await svc.init(), true);
  assert.deepStrictEqual(svc.status(), { available: true, reason: null, iface: "eth0", prefix: "2001:db8:1:2::/64" });
  assert.strictEqual(host.nftScripts.length, 1);
  assert.ok(host.nftScripts[0].startsWith(`add table ${T}\ndelete table ${T}\ntable ${T} {`));
  assert.deepStrictEqual(host.table, emptyTable(PREFIX), "empty, with the forward guard for the node's /64");
  assert.strictEqual(host.ipBatches.length, 0, "nothing to re-add");
  assert.strictEqual(sysctl(host, "net/ipv6/conf/eth0/accept_ra"), "0", "forwarding was on: accept_ra untouched");
  assertConsistent(host, svc, root, "init");
  assert.deepStrictEqual(svc.view(), {
    items: [], pool: { size: 0, refreshed_at: null, idle_since: null }, draining: 0, prefix: "2001:db8:1:2::/64", iface: "eth0",
  });
});

test("rotate: proxy entry added before nft, new current mapped, old one drains, the NIC untouched", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();

  const r1 = await svc.rotate([30000]);
  assert.strictEqual(r1.ok, true);
  const first = r1.items[0];
  assert.deepStrictEqual(Object.keys(first), ["port", "ok", "anchor", "mode", "old_ipv6", "new_ipv6", "error"]);
  assert.strictEqual(first.anchor, ANCHOR[30000], "anchor normalised from the cfg's leading-zero text");
  assert.deepStrictEqual([first.mode, first.old_ipv6, first.error], ["static", null, null]);
  assert.ok(eg.inPrefix(first.new_ipv6, eg.parsePrefix(PREFIX)));
  assert.ok(host.proxies.has(first.new_ipv6));
  assert.deepStrictEqual([...host.addrs.keys()], [PRIMARY], "nothing added to the NIC");
  assert.deepStrictEqual(host.ipBatches.at(-1), `neigh add proxy ${first.new_ipv6} dev eth0\n`);
  const addAt = host.log.findIndex((l) => l.startsWith("ip -6 -force -batch"));
  const nftAt = host.log.findLastIndex((l) => l.startsWith("nft -f"));
  assert.ok(addAt >= 0 && addAt < nftAt, "ip neigh add proxy runs before the nft change");
  assert.deepStrictEqual(host.log.slice(addAt - 2, addAt), ["ip -6 -o addr show dev eth0", "ip -6 neigh show proxy dev eth0"],
    "a new address is checked against the NIC and every proxy entry");
  assert.deepStrictEqual([...host.table.map], [[ANCHOR[30000], first.new_ipv6]]);
  assertConsistent(host, svc, root, "rotate 1");

  clock.t += 1000;
  const r2 = await svc.rotate([30000], { drainSec: 120 });
  const second = r2.items[0];
  assert.strictEqual(second.old_ipv6, first.new_ipv6);
  assert.notStrictEqual(second.new_ipv6, first.new_ipv6);
  assert.deepStrictEqual(svc.snapshot().draining, [{ addr: first.new_ipv6, until: new Date(clock.t + 120000).toISOString(), port: 30000 }]);
  assert.ok(host.nftScripts.at(-1).startsWith("delete element"), "a rotation is an element delta, not a rebuild");
  assert.strictEqual(host.proxies.has(first.new_ipv6), true, "the old address stays until the GC");
  assertConsistent(host, svc, root, "rotate 2");
});

test("errors are per port; the rest of the call still applies", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc } = makeService(host, root);
  await svc.init();
  const res = await svc.rotate([30001, 39999, 30003, 20000, 42000, 31000]);
  assert.strictEqual(res.ok, false);
  assert.deepStrictEqual(res.items.map((i) => [i.port, i.ok, i.error]), [
    [30001, true, null],
    [39999, false, "port_not_found"],
    [30003, false, "anchor_not_found"],
    [20000, false, "port_not_found"], // a paired http port is not a socks port
    [42000, true, null], // .disabled single-port cfg: its anchor is still known
    [31000, true, null], // pre-A2 block shape
  ]);
  assert.strictEqual(res.items[4].anchor, ANCHOR[42000]);
  assertConsistent(host, svc, root, "mixed");
});

test("per_connection: lazy pool of EGRESS_POOL_SIZE, dyn set, back to static, idle pool drains later", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const rot = await svc.rotate([30000]);
  const rotated = rot.items[0].new_ipv6;

  const m1 = await svc.setMode([30000, 30001], "per_connection", { drainSec: 30 });
  assert.strictEqual(m1.ok, true);
  assert.deepStrictEqual(m1.items.map((i) => [i.port, i.mode, i.old_ipv6, i.new_ipv6]), [
    [30000, "per_connection", rotated, "pool"],
    [30001, "per_connection", null, "pool"],
  ]);
  const s1 = svc.snapshot();
  assert.strictEqual(s1.pool.length, 4);
  assert.strictEqual(s1.pool_refreshed_at, new Date(clock.t).toISOString());
  assert.deepStrictEqual(sorted(host.table.dyn), sorted([ANCHOR[30000], ANCHOR[30001]]));
  assert.strictEqual(host.table.map.size, 0, "the static mapping left");
  assert.ok(s1.draining.some((d) => d.addr === rotated));
  assertConsistent(host, svc, root, "per_connection");

  const m2 = await svc.setMode([30002], "per_connection");
  assert.deepStrictEqual(svc.snapshot().pool, s1.pool, "the pool is reused, not regrown");
  assert.strictEqual(m2.items[0].new_ipv6, "pool");

  await svc.setMode([30000, 30001], "static", { drainSec: 0 });
  assert.deepStrictEqual(svc.snapshot().pool, s1.pool, "30002 still uses the pool");
  assert.deepStrictEqual(svc.view([30000]).items, [{ port: 30000, anchor: ANCHOR[30000], current: null, mode: null }]);
  assertConsistent(host, svc, root, "static");

  clock.t += 5000;
  await svc.reset([30002], { drainSec: 0 });
  const s2 = svc.snapshot();
  assert.deepStrictEqual(s2.pool, s1.pool, "the last port left: the pool is kept idle");
  assert.strictEqual(s2.pool_idle_since, new Date(clock.t).toISOString());
  assert.deepStrictEqual(svc.view().pool.idle_since, s2.pool_idle_since);
  assert.deepStrictEqual([host.table.dyn.size, host.table.map.size, host.table.pool], [0, 0, s1.pool]);
  assertConsistent(host, svc, root, "pool idle");

  clock.t += 599 * 1000;
  await svc.gcTick();
  assert.deepStrictEqual(svc.snapshot().pool, s1.pool, "not idle long enough yet");
  clock.t += 1000;
  await svc.gcTick();
  const s3 = svc.snapshot();
  assert.deepStrictEqual([s3.pool, s3.pool_idle_since, s3.pool_refreshed_at], [[], null, null]);
  for (const a of s1.pool) {
    assert.deepStrictEqual(s3.draining.find((d) => d.addr === a), { addr: a, until: new Date(clock.t + 600000).toISOString() }, "pool drains for EGRESS_DRAIN_SEC");
    assert.ok(host.proxies.has(a), "drains, not deleted yet");
  }
  assert.deepStrictEqual(host.table, emptyTable(PREFIX));
  assertConsistent(host, svc, root, "pool drained");
});

test("GC: due proxy entries deleted in one batch, no-op when nothing is due", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const a = (await svc.rotate([30001])).items[0].new_ipv6;
  await svc.rotate([30001]); // a drains 600 s
  const b = (await svc.rotate([30000])).items[0].new_ipv6;
  const c = (await svc.rotate([30000], { drainSec: 0 })).items[0].new_ipv6; // b is due at once

  clock.t += 1000;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.strictEqual(host.ipBatches.at(-1), `neigh del proxy ${b} dev eth0\n`);
  assert.ok(!host.proxies.has(b) && host.proxies.has(a) && host.proxies.has(c));
  assert.deepStrictEqual(svc.snapshot().draining.map((d) => d.addr), [a]);

  const calls = host.log.length;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 0 });
  assert.deepStrictEqual(host.log.slice(calls), [`nft list chain ${T} post`, "ip -6 neigh show proxy dev eth0"],
    "nothing due → only the table and proxy-entry checks");

  clock.t += 600 * 1000;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.strictEqual(host.ipBatches.at(-1), `neigh del proxy ${a} dev eth0\n`);
  assert.ok(!host.proxies.has(a) && host.proxies.has(c), "the current address is untouched");
  assert.ok(!host.log.slice(calls).includes("ip -6 -o addr show dev eth0"), "the GC never lists the NIC");
  assert.deepStrictEqual(svc.snapshot().draining, []);
  assertConsistent(host, svc, root, "after gc");
});

test("GC never deletes an anchor or an address in use, and retries a failed delete", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const clock = { t: Date.parse("2026-10-07T12:00:00.000Z") };
  const cur = "2001:db8:1:2:e000:1:0:1";
  const pool = "2001:db8:1:2:e000:2:0:2";
  const stuck = "2001:db8:1:2:e000:3:0:3";
  const due = new Date(clock.t - 1).toISOString();
  // a hand-damaged file: in-use addresses and a cfg anchor listed as draining
  fs.writeFileSync(path.join(root, "egress_state.json"), JSON.stringify({
    version: 1,
    ports: {
      30000: { anchor: ANCHOR[30000], current: cur, mode: "static" },
      30001: { anchor: ANCHOR[30001], current: null, mode: "per_connection" },
    },
    pool: [pool],
    pool_refreshed_at: due,
    draining: [
      { addr: cur, until: due },
      { addr: pool, until: due },
      { addr: ANCHOR[31000], until: due },
      { addr: stuck, until: due },
    ],
  }));
  host.addrs.set(ANCHOR[31000], 64);
  host.proxies.add(stuck); // a plain agent restart: still there
  let refuseDel = true;
  host.refuseLine = (line) => refuseDel && line.startsWith("neigh del proxy");
  const { svc } = makeService(host, root, { clock });
  await svc.init();
  assert.ok(host.ipBatches.every((b) => !b.includes(ANCHOR[31000])), "an anchor is never touched by this module");
  assert.strictEqual(host.ipBatches.length, 1, "one re-add batch, nothing to move off the NIC");
  assert.deepStrictEqual(sorted(host.ipBatches[0].trim().split("\n")), sorted([cur, pool, stuck].map((a) => `neigh add proxy ${a} dev eth0`)));
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 0 });
  assert.deepStrictEqual(svc.snapshot().draining.map((d) => d.addr), [stuck], "in-use and anchor entries left the list; the failed one stays");
  assert.ok(host.proxies.has(cur) && host.proxies.has(pool) && host.addrs.get(ANCHOR[31000]) === 64 && host.proxies.has(stuck));
  refuseDel = false;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.ok(!host.proxies.has(stuck) && host.addrs.get(ANCHOR[31000]) === 64);
  assertConsistent(host, svc, root, "gc retry");
});

test("pool refresh: the oldest quarter is replaced and drains; no-op without per_connection", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root, { env: { EGRESS_POOL_SIZE: "8" } });
  await svc.init();

  const idle = host.log.length;
  assert.deepStrictEqual(await svc.refreshPool(), { refreshed: 0 });
  assert.strictEqual(host.log.length, idle, "no per_connection port → nothing runs");

  await svc.setMode([30000], "per_connection");
  const before = svc.snapshot().pool;
  assert.strictEqual(before.length, 8);
  clock.t += 600 * 1000;
  assert.deepStrictEqual(await svc.refreshPool(), { refreshed: 2, ok: true });
  const after = svc.snapshot();
  assert.deepStrictEqual(after.pool.slice(0, 6), before.slice(2));
  assert.strictEqual(after.pool.length, 8);
  assert.strictEqual(after.pool_refreshed_at, new Date(clock.t).toISOString());
  assert.deepStrictEqual(after.draining.map((d) => d.addr), before.slice(0, 2));
  assert.ok(host.nftScripts.at(-1).startsWith(`flush chain ${T} dyn\nadd rule`), "a refresh rewrites only the dyn chain");
  assertConsistent(host, svc, root, "refresh");
});

test("address_add_failed: the port keeps its state, nothing reaches nft, nothing leaks", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  await svc.rotate([30000]);
  const scripts = host.nftScripts.length;
  const snap = svc.snapshot();

  host.refuseAdd = () => true;
  const res = await svc.rotate([30000, 30001]);
  assert.deepStrictEqual(res.items.map((i) => [i.port, i.ok, i.error, i.mode, i.new_ipv6]), [
    [30000, false, "address_add_failed", "static", snap.ports[30000].current],
    [30001, false, "address_add_failed", null, null],
  ]);
  assert.strictEqual(host.nftScripts.length, scripts, "no nft change");
  const after = svc.snapshot();
  assert.deepStrictEqual(after.ports, snap.ports);
  assert.strictEqual(after.draining.length, 2, "the attempted addresses wait for the GC (in case the add half-worked)");
  assertConsistent(host, svc, root, "add failed");

  const pc = await svc.setMode([30001], "per_connection");
  assert.deepStrictEqual([pc.items[0].ok, pc.items[0].error], [false, "address_add_failed"]);
  assert.deepStrictEqual(svc.snapshot().pool, []);

  // partial: only some addresses can be added → per-port outcome
  let n = 0;
  host.refuseAdd = () => (n += 1) % 2 === 0;
  const part = await svc.rotate([30001, 30002]);
  assert.deepStrictEqual(part.items.map((i) => i.ok), [true, false]);
  assert.strictEqual(part.items[1].error, "address_add_failed");
  host.refuseAdd = () => false;
  clock.t += 1000;
  await svc.gcTick();
  assertConsistent(host, svc, root, "partial");
  for (const d of svc.snapshot().draining) assert.ok(Date.parse(d.until) > clock.t, "the failed attempts were cleaned up");
});

test("nft_failed: state rolls back, kernel unchanged, the new address is garbage-collected", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const ok = await svc.rotate([30000]);
  const tableBefore = JSON.stringify([...host.table.map]);
  const snap = svc.snapshot();

  host.refuseNft = () => true;
  const res = await svc.rotate([30000, 30001, 39999]);
  assert.strictEqual(res.ok, false);
  assert.deepStrictEqual(res.items.map((i) => [i.port, i.ok, i.error, i.mode, i.old_ipv6, i.new_ipv6]), [
    [30000, false, "nft_failed", "static", ok.items[0].new_ipv6, ok.items[0].new_ipv6],
    [30001, false, "nft_failed", null, null, null],
    [39999, false, "port_not_found", null, null, null],
  ]);
  assert.strictEqual(JSON.stringify([...host.table.map]), tableBefore, "kernel table unchanged");
  const after = svc.snapshot();
  assert.deepStrictEqual(after.ports, snap.ports, "ports rolled back");
  const orphans = after.draining.map((d) => d.addr);
  assert.strictEqual(orphans.length, 2);
  for (const a of orphans) assert.ok(host.proxies.has(a), "added before nft failed");

  host.refuseNft = () => false;
  assertConsistent(host, svc, root, "rolled back");
  clock.t += 1;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 2 });
  for (const a of orphans) assert.ok(!host.proxies.has(a));
});

test("kernel drift (table flushed / deleted outside the agent): the delta fails, a rebuild repairs", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc } = makeService(host, root);
  await svc.init();
  await svc.rotate([30000, 30001]);

  host.table.map.clear(); // e.g. someone reloaded /etc/nftables.conf
  const n = host.nftScripts.length;
  const res = await svc.rotate([30000]);
  assert.strictEqual(res.ok, true);
  assert.strictEqual(host.nftScripts.length, n + 2, "delta refused, then one rebuild");
  assert.ok(host.nftScripts.at(-1).startsWith(`add table ${T}\ndelete table ${T}`));
  assertConsistent(host, svc, root, "after map flush");

  host.table = null; // `nft flush ruleset`
  assert.strictEqual((await svc.setMode([30002], "per_connection")).ok, true);
  assertConsistent(host, svc, root, "after table loss");
});

test("state write failure: 503-class error, nft put back to what the file holds", async () => {
  const host = fakeHost();
  const root = makeRoot();
  let failNext = 0;
  const writeState = (p, text) => {
    if (failNext > 0) {
      failNext -= 1;
      if (failNext === 0) throw new Error("ENOSPC: no space left on device");
    }
    return eg.writeFileAtomic(p, text);
  };
  const { svc } = makeService(host, root, { writeState });
  await svc.init();
  await svc.rotate([30000]);
  const snap = svc.snapshot();

  failNext = 2; // the journal write passes, the final write fails
  await assert.rejects(svc.rotate([30000]), (err) => err.code === "EGRESS_UNAVAILABLE" && /state_write_failed/.test(err.message));
  const after = svc.snapshot();
  assert.deepStrictEqual(after.ports, snap.ports);
  assertConsistent(host, svc, root, "final write failed");

  failNext = 1; // the journal write fails → nothing happens at all
  const adds = host.ipBatches.length;
  await assert.rejects(svc.rotate([30001]), (err) => err.code === "EGRESS_UNAVAILABLE");
  assert.strictEqual(host.ipBatches.length, adds, "no address added when the journal cannot be written");
  assertConsistent(host, svc, root, "journal write failed");
});

test("restart / reboot: one -force proxy re-add batch, rebuild, gone ports dropped, lost addresses forgotten", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const r = await svc.rotate([30000, 30001, 31000]);
  await svc.rotate([30000]);
  await svc.setMode([30002], "per_connection");
  const before = svc.snapshot();

  // agent restart, no reboot: everything is still there
  const { svc: again } = makeService(host, root, { clock });
  await again.init();
  assert.deepStrictEqual(again.snapshot(), before);
  assertConsistent(host, again, root, "plain restart");
  assert.deepStrictEqual(again.view([30001]).items, [{ port: 30001, anchor: ANCHOR[30001], current: before.ports[30001].current, mode: "static" }]);

  // reboot: the kernel forgot our proxy entries and the table; meanwhile 31000
  // was deprovisioned by hand and 30001 regenerated with a new anchor
  host.proxies = new Set();
  host.table = null;
  fs.unlinkSync(path.join(root, "3proxy", "3proxy_31000.cfg"));
  const cfgPath = path.join(root, "3proxy", "3proxy_30000.cfg");
  fs.writeFileSync(cfgPath, fs.readFileSync(cfgPath, "utf-8").replaceAll(RAW[30001], "2001:db8:1:2:9999::1"));
  assert.deepStrictEqual(again.view([30001]).items, [{ port: 30001, anchor: "2001:db8:1:2:9999::1", current: null, mode: null }],
    "a regenerated port is reported from its new anchor, not the stale entry");
  const lost = before.ports[30000].current;
  host.refuseAdd = (a) => a === lost;
  const batches = host.ipBatches.length;
  clock.t += 1000;
  const { svc: boot } = makeService(host, root, { clock });
  await boot.init();
  assert.strictEqual(host.ipBatches.length, batches + 1, "one batch");
  const lines = host.ipBatches.at(-1).trim().split("\n");
  assert.ok(lines.every((l) => /^neigh add proxy \S+ dev eth0$/.test(l)), "proxy entries only");
  const readded = lines.map((l) => l.split(" ")[3]);
  const drained = before.draining.map((d) => d.addr);
  assert.ok(drained.length > 0 && drained.every((a) => readded.includes(a)), "draining addresses are re-added too (the GC deletes them when due)");
  const s = boot.snapshot();
  assert.deepStrictEqual(Object.keys(s.ports), ["30000", "30002"]);
  assert.strictEqual(s.ports[30000].current, null, "an address that could not come back → the anchor");
  assert.ok(host.proxies.has(r.items[2].new_ipv6) && s.draining.some((d) => d.addr === r.items[2].new_ipv6),
    "a dropped port's address is back as a draining one");
  assert.strictEqual(s.pool.length, 4);
  assertConsistent(host, boot, root, "after reboot");
});

test("unavailable: no nft / no default route / bad NODE_EGRESS_PREFIX; override honoured", async () => {
  const noNft = fakeHost({ nftMissing: true });
  const root = makeRoot();
  const a = makeService(noNft, root).svc;
  assert.strictEqual(await a.init(), false);
  assert.strictEqual(a.isAvailable(), false);
  assert.match(a.status().reason, /^nft_failed: spawn nft ENOENT/);
  await assert.rejects(a.rotate([30000]), (err) => err.code === "EGRESS_UNAVAILABLE");
  assert.deepStrictEqual(await a.forgetPorts([30000]), { ok: true, forgotten: 0, skipped: a.status().reason });
  // the GC tick retries init: nft installed later → ready
  noNft.nftMissing = false;
  await a.gcTick();
  assert.strictEqual(a.isAvailable(), true);

  const noRoute = makeService(fakeHost({ route: false }), makeRoot()).svc;
  await noRoute.init();
  assert.strictEqual(noRoute.status().reason, "no_default_ipv6_route");

  const badPrefix = makeService(fakeHost(), makeRoot(), { env: { NODE_EGRESS_PREFIX: "2001:db8:1::/48" } }).svc;
  await badPrefix.init();
  assert.match(badPrefix.status().reason, /^bad_NODE_EGRESS_PREFIX/);

  const host = fakeHost();
  const r2 = makeRoot();
  const custom = makeService(host, r2, { env: { NODE_EGRESS_PREFIX: "2001:db8:aaaa:5::/64" } }).svc;
  await custom.init();
  assert.strictEqual(custom.status().prefix, "2001:db8:aaaa:5::/64");
  const res = await custom.rotate([30000]);
  assert.ok(res.items[0].new_ipv6.startsWith("2001:db8:aaaa:5:"));
});

test("mutations are serialized: concurrent calls never interleave their commands", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  host.maxInFlight = 0;
  clock.t += 1;
  const results = await Promise.all([
    svc.rotate([30000]),
    svc.setMode([30001], "per_connection"),
    svc.rotate([30002]),
    svc.gcTick(),
    svc.refreshPool(),
    svc.reset([30000]),
    svc.rotate([31000]),
  ]);
  assert.strictEqual(host.maxInFlight, 1, "one ip/nft command at a time");
  assert.ok(results.filter((r) => r.items).every((r) => r.ok));
  const s = svc.snapshot();
  assert.deepStrictEqual(Object.keys(s.ports), ["30001", "30002", "31000"]);
  assertConsistent(host, svc, root, "concurrent");
});

test("forgetPorts (deprovision): state dropped, addresses drain at once, pool goes idle", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const cur = (await svc.rotate([30000])).items[0].new_ipv6;
  await svc.setMode([30001], "per_connection");
  const pool = svc.snapshot().pool;

  // cfg blocks already removed by deprovision → no cfg lookup is needed
  assert.deepStrictEqual(await svc.forgetPorts([30000, 30001, 39999]), { ok: true, forgotten: 2 });
  const s = svc.snapshot();
  assert.deepStrictEqual(s.ports, {});
  assert.deepStrictEqual(s.draining.find((d) => d.addr === cur), { addr: cur, until: new Date(clock.t).toISOString(), port: 30000 });
  assert.deepStrictEqual([s.pool, s.pool_idle_since], [pool, new Date(clock.t).toISOString()], "the node-wide pool goes idle");
  assert.strictEqual(host.table.dyn.size, 0);
  assertConsistent(host, svc, root, "forgotten");
  assert.deepStrictEqual(await svc.forgetPorts([30000]), { ok: true, forgotten: 0 });
});

test("start(): a per_connection pool that could not come back is refilled at once; timers stop", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  await svc.setMode([30000], "per_connection");
  const old = svc.snapshot().pool;

  host.proxies = new Set(); // reboot
  host.table = null;
  host.refuseAdd = (a) => old.includes(a); // the pool's addresses cannot come back
  clock.t += 1000;
  const { svc: boot } = makeService(host, root, { clock });
  assert.strictEqual(await boot.start(), true);
  boot.stop();
  const s = boot.snapshot();
  assert.strictEqual(s.pool.length, 4, "refilled to EGRESS_POOL_SIZE");
  assert.ok(s.pool.every((a) => !old.includes(a)));
  assert.strictEqual(s.pool_refreshed_at, new Date(clock.t).toISOString());
  assertConsistent(host, boot, root, "refilled");
});

test("a corrupt state file is moved aside, the agent starts empty", async () => {
  const host = fakeHost();
  const root = makeRoot();
  fs.writeFileSync(path.join(root, "egress_state.json"), "{ not json");
  const { svc } = makeService(host, root);
  assert.strictEqual(await svc.init(), true);
  assert.ok(fs.readdirSync(root).some((f) => f.startsWith("egress_state.json.corrupt-")));
  assert.deepStrictEqual(svc.snapshot(), eg.emptyState());
});

test("state write AND the nft rollback fail: memory keeps what the kernel maps, the module stops, init repairs", async () => {
  const host = fakeHost();
  const root = makeRoot();
  let failNext = 0;
  const writeState = (p, text) => {
    if (failNext > 0) {
      failNext -= 1;
      if (failNext === 0) throw new Error("ENOSPC: no space left on device");
    }
    return eg.writeFileAtomic(p, text);
  };
  const { svc, clock } = makeService(host, root, { writeState });
  await svc.init();
  const old = (await svc.rotate([30000])).items[0].new_ipv6;

  failNext = 2; // the journal write passes, the final write fails...
  host.refuseNft = (script) => script.startsWith(`add table ${T}`); // ...and so does the rollback rebuild
  await assert.rejects(svc.rotate([30000]), (err) => err.code === "EGRESS_UNAVAILABLE" && /state_write_failed/.test(err.message));
  const fresh = host.table.map.get(ANCHOR[30000]);
  assert.notStrictEqual(fresh, old, "the kernel kept the delta");
  assert.ok(host.proxies.has(fresh));
  assert.strictEqual(svc.isAvailable(), false);
  assert.match(svc.status().reason, /^state_write_failed: .*nft_rollback_failed$/);
  assert.strictEqual(svc.snapshot().ports[30000].current, fresh, "memory = what the kernel maps");
  assert.strictEqual(stateFile(root).ports[30000].current, old, "the file = the journal");
  assert.ok(stateFile(root).draining.some((d) => d.addr === fresh));
  await assert.rejects(svc.rotate([30001]), (err) => err.code === "EGRESS_UNAVAILABLE");

  // the GC tick re-runs init (no delete): kernel and memory rebuilt from the file
  host.refuseNft = () => false;
  clock.t += 1000;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 0 });
  assert.strictEqual(svc.isAvailable(), true);
  assert.strictEqual(host.table.map.get(ANCHOR[30000]), old);
  assert.ok(host.proxies.has(fresh), "never deleted while nft mapped it");
  assertConsistent(host, svc, root, "after init");
  // unmapped now: the GC may delete it
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.ok(!host.proxies.has(fresh) && host.proxies.has(old));
  assertConsistent(host, svc, root, "after gc");
});

test("switching per_connection / static back and forth reuses one pool: proxy entries stay bounded", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const N = 8;
  const { svc, clock } = makeService(host, root, { env: { EGRESS_POOL_SIZE: String(N) } });
  await svc.init();
  const base = host.proxies.size;
  // a userbot every 3 s
  for (let i = 0; i < 10; i++) {
    clock.t += 3000;
    assert.strictEqual((await svc.setMode([30000], "per_connection")).ok, true);
    clock.t += 3000;
    assert.strictEqual((await svc.setMode([30000], "static")).ok, true);
    await svc.gcTick();
  }
  assert.strictEqual(host.proxies.size, base + N, "one pool, reused");
  assertConsistent(host, svc, root, "fast toggles");
  // slower than the idle period: one pool drains while the next is in use
  let peak = 0;
  for (let i = 0; i < 6; i++) {
    clock.t += 601 * 1000;
    await svc.gcTick();
    await svc.setMode([30000], "per_connection");
    await svc.setMode([30000], "static");
    peak = Math.max(peak, host.proxies.size - base);
  }
  assert.ok(peak <= 2 * N, `peak ${peak} extra addresses (pool ${N})`);
  assertConsistent(host, svc, root, "slow toggles");
});

test("a port rotated again and again holds at most its current + one draining address", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const seen = [];
  for (let i = 0; i < 12; i++) {
    clock.t += 60 * 1000; // the rotation link's cooldown; drain_sec 600
    seen.push((await svc.rotate([30000], { drainSec: 600 })).items[0].new_ipv6);
    await svc.gcTick();
    assert.ok(host.proxies.size <= 2, `rotation ${i + 1}: ${host.proxies.size} proxy entries`);
  }
  assert.deepStrictEqual(svc.snapshot().draining, [
    { addr: seen.at(-2), until: new Date(clock.t + 600000).toISOString(), port: 30000 },
  ]);
  assertConsistent(host, svc, root, "many rotations");
});

test("EGRESS_MAX_EXTRA_ADDRS: drains end early first, then ports are refused with address_budget_exceeded", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root, { env: { EGRESS_MAX_EXTRA_ADDRS: "3" } });
  await svc.init();
  const a1 = (await svc.rotate([30000, 30001])).items[0].new_ipv6;
  clock.t += 1000;
  assert.strictEqual((await svc.rotate([30000])).ok, true, "2 live + 1 fresh fit");
  clock.t += 1000;
  const r3 = await svc.rotate([30002]);
  assert.strictEqual(r3.ok, true, "the drain of a1 ended to make room");
  assert.deepStrictEqual(svc.snapshot().draining.find((d) => d.addr === a1).until, new Date(clock.t).toISOString());
  clock.t += 1000;
  const batches = host.ipBatches.length;
  const r4 = await svc.rotate([31000, 42000]);
  assert.deepStrictEqual(r4.items.map((i) => [i.port, i.ok, i.error]), [
    [31000, false, "address_budget_exceeded"],
    [42000, false, "address_budget_exceeded"],
  ]);
  assert.strictEqual(host.ipBatches.length, batches, "nothing added");
  const m = await svc.setMode([31000], "per_connection");
  assert.deepStrictEqual([m.items[0].ok, m.items[0].error], [false, "address_budget_exceeded"]);
  assert.deepStrictEqual(svc.snapshot().pool, []);
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.ok(!host.proxies.has(a1));
  assertConsistent(host, svc, root, "budget");
});

test("the GC tick rebuilds a table that vanished (nft flush ruleset / systemctl restart nftables)", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc } = makeService(host, root);
  await svc.init();
  const idle = host.log.length;
  await svc.gcTick();
  assert.strictEqual(host.log.length, idle, "nothing mapped → not even the check");

  await svc.rotate([30000]);
  await svc.setMode([30001], "per_connection");
  host.table = null;
  const n = host.nftScripts.length;
  await svc.gcTick();
  assert.strictEqual(host.nftScripts.length, n + 1, "one rebuild");
  assert.ok(host.nftScripts.at(-1).startsWith(`add table ${T}\ndelete table ${T}`));
  assertConsistent(host, svc, root, "rebuilt");
  const m = host.log.length;
  await svc.gcTick();
  assert.deepStrictEqual(host.log.slice(m), [`nft list chain ${T} post`, "ip -6 neigh show proxy dev eth0"], "present → only the checks");
});

test("start() writes the nftables.service boot drop-in once; daemon-reload only on a change", async () => {
  const host = fakeHost();
  const root = makeRoot();
  fs.mkdirSync(path.join(root, "systemd"));
  const file = path.join(root, "systemd", "nftables.service.d", "netrun-egress.conf");
  const findBin = (name) => (name === "nft" ? "/usr/sbin/nft" : null);
  const { svc } = makeService(host, root, { env: { EGRESS_NFT_DROPIN: file }, findBin });
  assert.strictEqual(await svc.start(), true);
  svc.stop();
  const text = fs.readFileSync(file, "utf-8");
  assert.strictEqual(text, eg.nftDropinText("/usr/sbin/nft"));
  assert.match(text, /^\[Service\]\nExecStartPost=-\/usr\/sbin\/nft delete table ip6 netrun_egress\n$/m);
  const reloads = () => host.log.filter((l) => l === "systemctl daemon-reload").length;
  assert.strictEqual(reloads(), 1);
  assert.deepStrictEqual(await svc.ensureBootDropin(), { changed: false });
  assert.strictEqual(reloads(), 1);
  fs.writeFileSync(file, "[Service]\n");
  assert.deepStrictEqual(await svc.ensureBootDropin(), { changed: true });
  assert.strictEqual(fs.readFileSync(file, "utf-8"), text);
  assert.strictEqual(reloads(), 2);

  const skipped = async (env, opts = {}) => (await makeService(fakeHost(), makeRoot(), { env, ...opts }).svc.ensureBootDropin()).skipped;
  assert.strictEqual(await skipped({}), "off");
  assert.strictEqual(await skipped({ EGRESS_NFT_DROPIN: path.join(root, "no-such", "x.d", "y.conf") }, { findBin }), "no_systemd");
  assert.strictEqual(await skipped({ EGRESS_NFT_DROPIN: file }, { findBin: () => null }), "no_nft");
});

test("writeFileAtomic: a failed write leaves no .tmp behind", () => {
  const root = makeRoot();
  const target = path.join(root, "a-directory");
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, "x"), "1"); // renaming a file over a non-empty directory fails
  assert.throws(() => eg.writeFileAtomic(target, "text"));
  assert.ok(!fs.existsSync(`${target}.tmp`));
});

// ── proxy NDP ────────────────────────────────────────────────────────────

const ALL_PROXY_NDP = "net/ipv6/conf/all/proxy_ndp";
const PROXY_NDP = "net/ipv6/conf/eth0/proxy_ndp";
const PROXY_DELAY = "net/ipv6/neigh/eth0/proxy_delay";
const ALL_FORWARDING = "net/ipv6/conf/all/forwarding";
const FORWARDING = "net/ipv6/conf/eth0/forwarding";
const ACCEPT_RA = "net/ipv6/conf/eth0/accept_ra";
const SYSCTLS = [ALL_PROXY_NDP, PROXY_NDP, PROXY_DELAY, ALL_FORWARDING, FORWARDING, ACCEPT_RA];
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

// mtime 0 on every file: a later write shows as a new mtime, whatever the
// file system's timestamp granularity
function touchZero(files) {
  for (const f of files) fs.utimesSync(f, 0, 0);
}
const untouched = (files) => files.every((f) => fs.statSync(f).mtimeMs === 0);

test("proxy-NDP sysctls: set at init, only what differs is written, persisted when the file differs", async () => {
  const root = makeRoot();
  const conf = path.join(root, "sysctl.d", "99-netrun-egress.conf");
  fs.mkdirSync(path.dirname(conf));
  const env = { EGRESS_SYSCTL_CONF: conf };
  const host = fakeHost(); // as the installers leave a node: forwarding 1, proxy_ndp 0, proxy_delay 80
  const procFiles = SYSCTLS.map((k) => path.join(host.procSys, k));
  touchZero(procFiles);
  assert.strictEqual(await makeService(host, root, { env }).svc.init(), true);
  assert.deepStrictEqual(SYSCTLS.map((k) => sysctl(host, k)), ["1", "1", "0", "1", "1", "0"]);
  assert.ok(untouched([ALL_FORWARDING, FORWARDING, ACCEPT_RA].map((k) => path.join(host.procSys, k))),
    "forwarding already 1 is never written (any write of 1 drops RA-learned default routes)");
  assert.strictEqual(fs.readFileSync(conf, "utf-8"), eg.sysctlConfText("eth0"));

  // a restart: nothing differs, nothing is written
  touchZero([...procFiles, conf]);
  assert.strictEqual(await makeService(host, root, { env }).svc.init(), true);
  assert.ok(untouched([...procFiles, conf]));

  // a hand edit of the file is put back; a missing /etc/sysctl.d is skipped
  fs.writeFileSync(conf, "net.ipv6.conf.eth0.proxy_ndp = 0\n");
  assert.strictEqual(await makeService(host, root, { env }).svc.init(), true);
  assert.strictEqual(fs.readFileSync(conf, "utf-8"), eg.sysctlConfText("eth0"));
  const nowhere = path.join(root, "no-such-dir", "99-netrun-egress.conf");
  assert.strictEqual(await makeService(host, root, { env: { EGRESS_SYSCTL_CONF: nowhere } }).svc.init(), true);
  assert.ok(!fs.existsSync(path.dirname(nowhere)));
});

test("forwarding off: accept_ra 1 → 2 BEFORE forwarding goes on, kept in the file; accept_ra 0 left alone", async () => {
  const root = makeRoot();
  const conf = path.join(root, "99-netrun-egress.conf");
  const env = { EGRESS_SYSCTL_CONF: conf };
  const host = fakeHost({ sysctls: { [ALL_FORWARDING]: "0", [FORWARDING]: "0", [ACCEPT_RA]: "1" } });
  assert.strictEqual(await makeService(host, root, { env }).svc.init(), true);
  assert.deepStrictEqual(SYSCTLS.map((k) => sysctl(host, k)), ["1", "1", "0", "1", "1", "2"]);
  assert.strictEqual(fs.readFileSync(conf, "utf-8"), eg.sysctlConfText("eth0", { acceptRa: true }));
  // the next start (forwarding now 1) keeps the accept_ra line and writes nothing
  touchZero([conf]);
  assert.strictEqual(await makeService(host, root, { env }).svc.init(), true);
  assert.ok(untouched([conf]));

  // accept_ra 0 (static, or a userspace RA client such as systemd-networkd)
  const quiet0 = fakeHost({ sysctls: { [FORWARDING]: "0", [ACCEPT_RA]: "0" } });
  assert.strictEqual(await makeService(quiet0, makeRoot()).svc.init(), true);
  assert.deepStrictEqual([sysctl(quiet0, FORWARDING), sysctl(quiet0, ACCEPT_RA)], ["1", "0"]);
  // the interface already forwards (it ignores RAs today): accept_ra stays
  const onlyAll = fakeHost({ sysctls: { [ALL_FORWARDING]: "0", [ACCEPT_RA]: "1" } });
  assert.strictEqual(await makeService(onlyAll, makeRoot()).svc.init(), true);
  assert.deepStrictEqual([sysctl(onlyAll, ALL_FORWARDING), sysctl(onlyAll, ACCEPT_RA)], ["1", "1"]);

  // accept_ra cannot be switched → forwarding is never turned on, the module stays down
  if (!isRoot) {
    const locked = fakeHost({ sysctls: { [ALL_FORWARDING]: "0", [FORWARDING]: "0", [ACCEPT_RA]: "1" } });
    fs.chmodSync(path.join(locked.procSys, ACCEPT_RA), 0o444);
    const svc = makeService(locked, makeRoot()).svc;
    assert.strictEqual(await svc.init(), false);
    assert.match(svc.status().reason, /^sysctl_failed: /);
    assert.deepStrictEqual([sysctl(locked, ALL_FORWARDING), sysctl(locked, FORWARDING)], ["0", "0"], "never forwarding while accept_ra is 1");
  }
});

test("sysctls that cannot be set: unavailable before anything is touched; the GC tick retries", async () => {
  const host = fakeHost();
  const delayDir = path.join(host.procSys, "net/ipv6/neigh/eth0");
  fs.rmSync(delayDir, { recursive: true });
  const root = makeRoot();
  const { svc } = makeService(host, root);
  assert.strictEqual(await svc.init(), false);
  assert.match(svc.status().reason, /^sysctl_failed: .*proxy_delay/);
  assert.deepStrictEqual([host.nftScripts.length, host.ipBatches.length], [0, 0]);
  await assert.rejects(svc.rotate([30000]), (err) => err.code === "EGRESS_UNAVAILABLE");
  fs.mkdirSync(delayDir, { recursive: true });
  fs.writeFileSync(path.join(delayDir, "proxy_delay"), "80\n");
  await svc.gcTick();
  assert.strictEqual(svc.isAvailable(), true);
  assertConsistent(host, svc, root, "after the retry");
});

test("upgrade from NIC addresses: proxy entry first, then the NIC copy goes; what cannot move keeps working", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const clock = { t: Date.parse("2026-10-07T12:00:00.000Z") };
  const at = (ms) => new Date(ms).toISOString();
  const X = "2001:db8:1:2:e100::1"; // 30000's current
  const P1 = "2001:db8:1:2:e100::11"; // pool; its proxy entry cannot be added
  const P2 = "2001:db8:1:2:e100::12"; // pool; its NIC delete fails
  const D = "2001:db8:1:2:e100::21"; // draining, due
  const Dn = "2001:db8:1:2:e100::22"; // draining, not due
  fs.writeFileSync(path.join(root, "egress_state.json"), JSON.stringify({
    version: 1,
    ports: {
      30000: { anchor: ANCHOR[30000], current: X, mode: "static" },
      30001: { anchor: ANCHOR[30001], current: null, mode: "per_connection" },
    },
    pool: [P1, P2],
    pool_refreshed_at: at(clock.t - 1000),
    draining: [
      { addr: D, until: at(clock.t - 1) },
      { addr: Dn, until: at(clock.t + 300000), port: 30002 },
      { addr: ANCHOR[31000], until: at(clock.t - 1) }, // damaged: an anchor
    ],
  }));
  // what the version before proxy NDP left: its addresses on the NIC (/128)
  // and its table still in the kernel (a plain agent restart)
  for (const a of [X, P1, P2, D, Dn]) host.addrs.set(a, 128);
  host.addrs.set(ANCHOR[31000], 64);
  host.table = { ...emptyTable(), map: new Map([[ANCHOR[30000], X]]), dyn: new Set([ANCHOR[30001]]), pool: [P1, P2] };
  host.refuseAdd = (a) => a === P1;
  host.refuseLine = (line) => line === `address del ${P2}/128 dev eth0`;

  const { svc } = makeService(host, root, { clock });
  assert.strictEqual(await svc.init(), true);
  assert.deepStrictEqual(host.ipBatches.map((b) => b.trim().split("\n")), [
    [X, P1, P2, D, Dn].map((a) => `neigh add proxy ${a} dev eth0`),
    [X, P2, D, Dn].map((a) => `address del ${a}/128 dev eth0`), // only with a proxy entry in place; never the anchor
  ]);
  const batches = host.log.flatMap((l, i) => (l.startsWith("ip -6 -force -batch") ? [i] : []));
  const listed = host.log.indexOf("ip -6 neigh show proxy dev eth0");
  const rebuilt = host.log.findIndex((l) => l.startsWith("nft -f"));
  assert.ok(batches[0] < listed && listed < batches[1] && batches[1] < rebuilt, "add proxies → check them → leave the NIC → nft");
  assert.deepStrictEqual(sorted(host.addrs.keys()), sorted([PRIMARY, ANCHOR[31000], P1, P2]));
  assert.deepStrictEqual(sorted(host.proxies), sorted([X, P2, D, Dn]));
  const s = svc.snapshot();
  assert.strictEqual(s.ports[30000].current, X, "moved, still mapped");
  assert.deepStrictEqual(s.pool, [P1, P2], "P1 still answers from the NIC, P2 from both");
  assert.deepStrictEqual(s.draining.map((d) => d.addr), [D, Dn], "the anchor left the list");
  assert.deepStrictEqual([[...host.table.map], host.table.fwd], [[[ANCHOR[30000], X]], PREFIX]);

  // the next tick gives P1 its proxy entry and deletes D's
  host.refuseAdd = () => false;
  host.refuseLine = () => false;
  clock.t += 1000;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.ok(host.proxies.has(P1) && !host.proxies.has(D));
  assert.ok(host.addrs.has(P1) && host.addrs.has(P2), "in use: their NIC copies stay");

  // the pool goes idle, then drains: its NIC copies go with the proxy entries
  await svc.setMode([30001], "static");
  clock.t += 600 * 1000;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 }, "Dn is due; the idle pool starts draining");
  assert.ok(!host.proxies.has(Dn));
  clock.t += 600 * 1000;
  const n = host.ipBatches.length;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 2 });
  assert.deepStrictEqual(host.ipBatches.slice(n), [[
    `neigh del proxy ${P1} dev eth0`, `address del ${P1}/128 dev eth0`,
    `neigh del proxy ${P2} dev eth0`, `address del ${P2}/128 dev eth0`, "",
  ].join("\n")]);
  assert.deepStrictEqual(sorted(host.addrs.keys()), sorted([PRIMARY, ANCHOR[31000]]));
  assertConsistent(host, svc, root, "moved and drained");

  // a restart has nothing left to move
  const m = host.ipBatches.length;
  const { svc: again } = makeService(host, root, { clock });
  assert.strictEqual(await again.init(), true);
  assert.ok(host.ipBatches.slice(m).every((b) => !b.includes("address del")));
  assertConsistent(host, again, root, "restart");
});

test("the GC tick puts back proxy entries and sysctls lost under it (link flap, re-created interface)", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  await svc.rotate([30000]);
  await svc.setMode([30001], "per_connection");
  const old = (await svc.rotate([30002])).items[0].new_ipv6;
  await svc.rotate([30002]); // old drains 600 s
  const gone = (await svc.rotate([31000])).items[0].new_ipv6;
  await svc.rotate([31000], { drainSec: 0 }); // due at once
  host.proxies.clear();
  for (const [k, v] of [[ALL_PROXY_NDP, "0"], [PROXY_NDP, "0"], [PROXY_DELAY, "80"]]) fs.writeFileSync(path.join(host.procSys, k), `${v}\n`);
  clock.t += 1000;
  const n = host.ipBatches.length;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 0 }, "a due address without an entry is just forgotten");
  const readded = host.ipBatches.slice(n).join("").trim().split("\n");
  assert.ok(readded.every((l) => l.startsWith("neigh add proxy ")) && readded.length === 4 + 3 + 1,
    "the pool, three currents, the draining one that is not due");
  assert.ok(host.proxies.has(old), "a draining address keeps answering for its sessions");
  assert.ok(!host.proxies.has(gone) && !svc.snapshot().draining.some((d) => d.addr === gone));
  assertConsistent(host, svc, root, "after a link flap");
});

test("a new address is never one on the NIC or another proxy entry; foreign entries are never deleted", async () => {
  const host = fakeHost();
  const root = makeRoot();
  const { svc, clock } = makeService(host, root);
  await svc.init();
  const draw = (k) => eg.formatIpv6([0x2001, 0xdb8, 1, 2, ((0xe0000000 + k) >>> 16) & 0xffff, (0xe0000000 + k) & 0xffff, k >>> 16, k & 0xffff]);
  const k = rngCounter + 1;
  host.addrs.set(draw(k), 128); // e.g. an anchor the generator added meanwhile
  host.proxies.add(draw(k + 1)); // a proxy entry someone else put there
  const first = (await svc.rotate([30000])).items[0].new_ipv6;
  assert.strictEqual(first, draw(k + 2));
  await svc.rotate([30000], { drainSec: 0 });
  clock.t += 1000;
  assert.deepStrictEqual(await svc.gcTick(), { deleted: 1 });
  assert.ok(host.proxies.has(draw(k + 1)) && host.addrs.has(draw(k)));
  assertConsistent(host, svc, root, "unique", { foreign: new Set([draw(k + 1)]) });
});
