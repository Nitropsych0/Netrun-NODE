"use strict";

// Pay-per-GB v2, AMENDMENT A1 (lane L9) — /deprovision on a per-GB node hands
// a dropped batch's pool /64s back (release_nets): every /64 its cfg and its
// address list named, minus any /64 something per-piece still names. A
// rewritten (mixed) batch keeps its list, so nothing is handed back; a failed
// release never fails the deprovision; without per-GB nothing is called.
// pgrep / nft / the spawn helper / the ruleset save are stubs.
// Run with: node --test node_runtime/node_agent/deprovision.pergb.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-deprov-pergb-"));
process.env.NODE_AGENT_PROXY_ROOT = ROOT;
process.env.NODE_AGENT_NFT_PERSIST = path.join(ROOT, "nftables.conf");
process.env.NODE_AGENT_DEPROV_GRACE_MS = "0";
process.env.NETRUN_PERGB_ENABLE_FILE = path.join(ROOT, "no-enable.json");
const BIN = path.join(ROOT, "bin");
fs.mkdirSync(BIN, { recursive: true });
for (const [name, body] of [["pgrep", "exit 1"], ["nft", "exit 0"], ["nft-persist", "exit 0"], ["spawn-helper", "exit 0"]]) {
  fs.writeFileSync(path.join(BIN, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}
process.env.NODE_AGENT_NFT_PERSIST_BIN = path.join(BIN, "nft-persist");
process.env.NETRUN_3PROXY_SPAWN = path.join(BIN, "spawn-helper");
process.env.PATH = `${BIN}:${process.env.PATH}`;

const test = require("node:test");
const assert = require("node:assert");
const deprov = require("./deprovision.js");
const pergbPool = require("./pergb_pool.js");

const CFG_DIR = path.join(ROOT, "3proxy");
fs.mkdirSync(CFG_DIR, { recursive: true });
const POOL_FILE = path.join(ROOT, "pergb-pool.conf");
const BASE = pergbPool.net64Of("2602:f2dc:a9::");
const quiet = { log() {}, error() {} };
test.after(() => fs.rmSync(ROOT, { recursive: true, force: true }));

const block = (port, addr) => `flush\nusers u${port}:CL:p\nallow u${port} *\ndeny *\nsocks -6 -a -p${port} -i1.2.3.4 -e${addr}\nproxy -6 -n -a -p${port - 10000} -i1.2.3.4 -e${addr}\n`;
function batch(sp, nets, listNets = nets) {
  fs.writeFileSync(path.join(CFG_DIR, `3proxy_${sp}.cfg`), `daemon\nauth strong\n${nets.map((n, i) => block(sp + i, `2602:f2dc:a9:${n.toString(16)}::1`)).join("")}`);
  fs.writeFileSync(path.join(ROOT, `ipv6_${sp}.list`), listNets.map((n) => `2602:f2dc:a9:${n.toString(16)}::1\n`).join(""));
}

function fakeAccess({ fail = null } = {}) {
  const calls = [];
  const access = pergbPool.createPoolAccess({
    env: { NETRUN_PERGB_POOL_FILE: POOL_FILE },
    log: quiet,
    request: async (op, body) => {
      calls.push([op, body]);
      if (fail) throw Object.assign(new Error(fail), { code: fail });
      return { released: body.nets.length, coolDownUntil: "2026-10-10T12:00:00Z" };
    },
  });
  return { access, calls };
}

test("a dropped batch hands back its cfg's and its list's pool /64s, minus those per-piece still names", async () => {
  fs.writeFileSync(POOL_FILE, "PREFIX=2602:f2dc:a9::/48\nPOOL=0000-fffe\n");
  // 0x12 left the cfg in an earlier rewrite (still in the list); 0x13 is also another batch's
  batch(50000, [0x10, 0x11], [0x10, 0x11, 0x12, 0x13]);
  batch(51000, [0x13, 0x20]);
  const { access, calls } = fakeAccess();
  const res = await deprov.deprovisionPorts([50000, 50001], { pool: access, log: quiet });
  assert.strictEqual(res.ok, true, JSON.stringify(res));
  assert.deepStrictEqual(res.cfgs.map((c) => c.mode), ["drop"]);
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0][0], "release_nets");
  assert.deepStrictEqual(calls[0][1].nets.sort((a, b) => a - b), [0x10, 0x11, 0x12], "0x13 is still 51000's");
  assert.match(calls[0][1].ref, /^deprovision:50000:[0-9a-f]{12}$/);
  assert.deepStrictEqual(res.pergb_release, { requested: 4, released: 3, kept: 1, coolDownUntil: "2026-10-10T12:00:00Z" });
  assert.ok(!fs.existsSync(path.join(ROOT, "ipv6_50000.list")));
});

test("a rewritten (mixed) batch keeps its list: nothing handed back", async () => {
  fs.writeFileSync(POOL_FILE, "PREFIX=2602:f2dc:a9::/48\n");
  batch(52000, [0x30, 0x31, 0x32]);
  const { access, calls } = fakeAccess();
  const res = await deprov.deprovisionPorts([52001], { pool: access, log: quiet });
  assert.deepStrictEqual(res.cfgs.map((c) => [c.mode, c.ok]), [["rewrite", true]], JSON.stringify(res));
  assert.deepStrictEqual(calls, []);
  assert.ok(!("pergb_release" in res));
});

test("RADIUS failing: the deprovision still succeeds, the error is reported; without per-GB nothing is called", async () => {
  fs.writeFileSync(POOL_FILE, "PREFIX=2602:f2dc:a9::/48\n");
  batch(53000, [0x40]);
  const failing = fakeAccess({ fail: "radius_unavailable" });
  const res = await deprov.deprovisionPorts([53000], { pool: failing.access, log: quiet });
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.pergb_release.error, "radius_unavailable");

  fs.rmSync(POOL_FILE);
  batch(54000, [0x50]);
  const off = fakeAccess();
  const r2 = await deprov.deprovisionPorts([54000], { pool: off.access, log: quiet });
  assert.strictEqual(r2.ok, true);
  assert.deepStrictEqual(off.calls, []);
  assert.ok(!("pergb_release" in r2), "a node without per-GB answers as before");
});

test("option A shield: shared ports are dropped from the request (skipped_shared); shared only -> 409 shape", async () => {
  const shield = { sharedPorts: async () => new Set([31000, 31001]) };
  const only = await deprov.deprovisionPorts([31000, 31001], { shield, log: quiet });
  assert.deepStrictEqual(
    [only.ok, only.httpStatus, only.error, only.skipped_shared, only.requested],
    [false, 409, "pergb_shared_port", [31000, 31001], 2],
  );
  assert.deepStrictEqual(only.cfgs, []);
  const mixed = await deprov.deprovisionPorts([31000, 59999], { shield, log: quiet });
  assert.strictEqual(mixed.ok, true);
  assert.deepStrictEqual(mixed.skipped_shared, [31000]);
  assert.deepStrictEqual(mixed.skipped_ports, [59999]);
  assert.ok(!("httpStatus" in mixed));
});
