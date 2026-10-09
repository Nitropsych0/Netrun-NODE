"use strict";

// Pay-per-GB v2 (lane L9) — pergb_shield.js: enable.json -> option A / B,
// the shared ports, the per-GB listeners, the drop-rule form and the
// capacity budget. `ip -4 route get` is faked.
// Run with: node --test node_runtime/node_agent/pergb_shield.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const sh = require(path.resolve(__dirname, "pergb_shield.js"));

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-pergb-shield-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));
const quiet = { log() {}, error() {} };

function shieldWith(enable, { primary = "45.32.10.20", env = {} } = {}) {
  const file = path.join(TMP, `enable-${Math.random().toString(16).slice(2)}.json`);
  if (enable !== undefined) fs.writeFileSync(file, typeof enable === "string" ? enable : JSON.stringify(enable));
  const calls = [];
  const run = async (cmd, args) => {
    calls.push(`${cmd} ${args.join(" ")}`);
    if (primary === null) return { code: 2, stdout: "", stderr: "RTNETLINK answers: Network is unreachable" };
    return { code: 0, stdout: `1.1.1.1 via 45.32.10.1 dev enp1s0 src ${primary} uid 0 \n    cache \n`, stderr: "" };
  };
  return { shield: sh.createShield({ env: { NETRUN_PERGB_ENABLE_FILE: file, ...env }, run, log: quiet }), calls, file };
}

test("parseEnable / parseRouteGetSrc / parseSizeMb", () => {
  assert.deepStrictEqual(sh.parseEnable({ base: 31000, count: 1000, egressIpv4: null, sliceMemMax: "1536M" }), {
    state: "on", base: 31000, count: 1000, last: 31999, candidateIpv4: null, primaryIpv4: null, sliceMemMb: 1536,
  });
  assert.strictEqual(sh.parseEnable({ portBase: 10000 }).last, 10999, "aliases + the default count 1000");
  assert.strictEqual(sh.parseEnable({ base: 31000, enabled: false }).state, "off");
  for (const bad of [null, [], "x", {}, { base: 0 }, { base: 65000, count: 1000 }, { base: 31000, count: 0 }]) {
    assert.strictEqual(sh.parseEnable(bad).state, "error", JSON.stringify(bad));
  }
  assert.strictEqual(sh.parseEnable({ base: 10000, pergbIpv4: "45.32.99.1", egressIpv4: "45.32.10.20" }).candidateIpv4, "45.32.99.1", "an explicit field wins");
  assert.strictEqual(sh.parseRouteGetSrc("1.1.1.1 via 45.32.10.1 dev enp1s0 src 45.32.10.20 uid 0"), "45.32.10.20");
  assert.strictEqual(sh.parseRouteGetSrc("garbage"), null);
  assert.strictEqual(sh.parseSizeMb("1536M"), 1536);
  assert.strictEqual(sh.parseSizeMb("2G"), 2048);
  assert.strictEqual(sh.parseSizeMb(1610612736), 1536, "a plain number is bytes, as systemd reads it");
  assert.strictEqual(sh.parseSizeMb("1610612736"), 1536);
  assert.strictEqual(sh.parseSizeMb("lots"), null);
});

test("no enable.json: per-GB off — nothing shared, nothing ignored but the per-GB loopback, the plain drop rule", async () => {
  const { shield, calls } = shieldWith(undefined);
  assert.strictEqual((await shield.info()).state, "off");
  assert.strictEqual((await shield.sharedPorts()).size, 0);
  assert.strictEqual(await shield.isSharedPort(31000), false);
  assert.deepStrictEqual([...(await shield.ignoredListenAddrs())], ["127.0.0.3", "127.0.0.4"]);
  assert.deepStrictEqual(await shield.dropRule(), { text: "tcp dport @pergb_blocked drop", args: ["tcp", "dport", "@pergb_blocked", "drop"], scoped: false, primaryIpv4: null });
  assert.deepStrictEqual(await shield.capacityBudget(), { enabled: false, memMb: 0, ports: 0, option: null });
  assert.deepStrictEqual(calls, [], "no route lookup without per-GB");
});

test("option A (no dedicated IPv4, or egressIpv4 = the primary): the shared range is shielded, the drop rule stays plain", async () => {
  for (const enable of [{ base: 31000, count: 1000, egressIpv4: null }, { base: 31000, count: 1000, egressIpv4: "45.32.10.20" }]) {
    const { shield } = shieldWith(enable);
    const i = await shield.info();
    assert.strictEqual(i.option, "A", JSON.stringify(enable));
    const shared = await shield.sharedPorts();
    assert.strictEqual(shared.size, 1000);
    assert.ok(shared.has(31000) && shared.has(31999) && !shared.has(32000) && !shared.has(30999));
    assert.strictEqual(await shield.isSharedPort(31500), true);
    assert.strictEqual(await shield.isSharedPort(41500), false, "the socks shadow is not shared itself");
    assert.strictEqual((await shield.dropRule()).scoped, false);
    assert.deepStrictEqual([...(await shield.ignoredListenAddrs())], ["127.0.0.3", "127.0.0.4"]);
  }
});

test("option B (a dedicated per-GB IPv4): nothing shielded, its listeners ignored, the drop rule scoped to the primary IPv4", async () => {
  const { shield, calls } = shieldWith({ base: 10000, count: 1000, egressIpv4: "45.32.99.7", sliceMemMax: "2G" });
  const i = await shield.info();
  assert.deepStrictEqual([i.option, i.dedicatedIpv4, i.primaryIpv4], ["B", "45.32.99.7", "45.32.10.20"]);
  assert.strictEqual((await shield.sharedPorts()).size, 0);
  assert.strictEqual(await shield.isSharedPort(10000), false, "per-piece http 10000-10999 stays blockable");
  assert.ok((await shield.ignoredListenAddrs()).has("45.32.99.7"));
  assert.deepStrictEqual(await shield.dropRule(), {
    text: "ip daddr 45.32.10.20 tcp dport @pergb_blocked drop",
    args: ["ip", "daddr", "45.32.10.20", "tcp", "dport", "@pergb_blocked", "drop"],
    scoped: true,
    primaryIpv4: "45.32.10.20",
  });
  assert.deepStrictEqual(await shield.capacityBudget(), { enabled: true, memMb: 2048, ports: 0, option: "B" });
  assert.strictEqual(calls.filter((c) => c === "ip -4 route get 1.1.1.1").length, 1, "the primary is cached");
});

test("the primary IPv4: NETRUN_PRIMARY_IPV4 / enable.json primaryIpv4 win; unknown → option A (shield too many, never too few)", async () => {
  let s = shieldWith({ base: 10000, egressIpv4: "45.32.99.7" }, { primary: null });
  assert.strictEqual((await s.shield.info()).option, "A");
  assert.strictEqual((await s.shield.sharedPorts()).size, 1000);
  assert.strictEqual((await s.shield.dropRule()).scoped, false);
  s = shieldWith({ base: 10000, egressIpv4: "45.32.99.7" }, { primary: null, env: { NETRUN_PRIMARY_IPV4: "45.32.10.20" } });
  assert.strictEqual((await s.shield.info()).option, "B");
  assert.deepStrictEqual(s.calls, []);
  s = shieldWith({ base: 10000, egressIpv4: "45.32.99.7", primaryIpv4: "45.32.10.20" }, { primary: null });
  assert.strictEqual((await s.shield.dropRule()).text, "ip daddr 45.32.10.20 tcp dport @pergb_blocked drop");
});

test("a broken enable.json shields nothing and says so (state error); a fixed one is picked up", async () => {
  const { shield, file } = shieldWith("{not json");
  assert.strictEqual((await shield.info()).state, "error");
  assert.strictEqual((await shield.sharedPorts()).size, 0);
  fs.writeFileSync(file, JSON.stringify({ base: 31000, count: 10 }));
  assert.strictEqual((await shield.sharedPorts()).size, 10);
});

test("capacityBudget: option A costs the slice memory (default 1536 MiB) and the shared ports", async () => {
  const { shield } = shieldWith({ base: 31000, count: 1000 });
  assert.deepStrictEqual(await shield.capacityBudget(), { enabled: true, memMb: 1536, ports: 1000, option: "A" });
});

test("isPergbProcessCmd: the per-GB 3proxy (own binary / cfgs) is never a per-piece instance", () => {
  assert.ok(sh.isPergbProcessCmd("/opt/netrun/pergb/bin/3proxy-pergb /opt/netrun/pergb/cfg/pergb_31000.cfg"));
  assert.ok(sh.isPergbProcessCmd("3proxy-pergb /x/pergb_31500.cfg"));
  assert.ok(!sh.isPergbProcessCmd("/opt/netrun/proxyserver/3proxy/bin/3proxy /opt/netrun/proxyserver/3proxy/3proxy_18100.cfg"));
  assert.ok(!sh.isPergbProcessCmd("/root/proxyserver/3proxy/bin/3proxy /root/proxyserver/3proxy/3proxy_31000.cfg"));
});
