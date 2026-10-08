"use strict";

// Wave FLEET-HEALTH (RES-10) — /health per-cfg status, IPv6 address coverage
// and the IPv4-only bind. Pure helpers from cfg_status.js + server.js; no
// root, no network.
// Run with: node --test node_runtime/node_agent/server.health_cfgs.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");

const cfgStatus = require("./cfg_status.js");
const server = require("./server.js");

const inst = (startPort, pid = 1000 + startPort) => ({ pid, startPort, cfgPath: `/p/3proxy/3proxy_${startPort}.cfg` });
const cfg = (startPort, count = 1500, probePort = startPort) => ({
  startPort,
  cfgPath: `/p/3proxy/3proxy_${startPort}.cfg`,
  probePort,
  count,
});

function batchCfgText(start, n, { prefix = "2001:db8:0:1", httpIp = "127.0.0.1", from = 0 } = {}) {
  const lines = ["daemon", "  nserver 127.0.0.1", "  maxconn 200", "auth strong"];
  for (let i = from; i < n; i += 1) {
    const p = start + i;
    const e = `${prefix}:${(0xa000 + i).toString(16)}:1:2:${i.toString(16)}`;
    lines.push("flush", `users u${i}:CL:p${i}`, `allow u${i}`, "deny *");
    lines.push(`socks -6 -a -p${p} -i45.32.10.20 -e${e}`);
    lines.push(`proxy -6 -n -a -p${p - 10000} -i${httpIp} -e${e}`);
  }
  return `${lines.join("\n")}\n`;
}

test("3 cfgs, one not listening -> cfgsDown 1 (same fixture as computeProxyReadiness)", () => {
  const instances = [inst(32000), inst(33500), inst(35000)];
  const listening = new Set([32000, 33500, 22]); // 35000 missing
  const view = cfgStatus.computeCfgStatus({
    cfgs: [cfg(32000), cfg(33500), cfg(35000)],
    instances,
    listeningPorts: listening,
    portsOk: true,
  });
  assert.strictEqual(view.cfgsDown, 1);
  assert.deepStrictEqual(view.cfgs, [
    { startPort: 32000, count: 1500, listening: true, pid: 33000 },
    { startPort: 33500, count: 1500, listening: true, pid: 34500 },
    { startPort: 35000, count: 1500, listening: false, pid: 36000 },
  ]);
  assert.deepStrictEqual(view.cfgsWithoutProcess, []);
  // The readiness verdict on the same data agrees: not ready.
  const r = server.computeProxyReadiness(instances, listening, true);
  assert.strictEqual(r.ready, false);
  assert.strictEqual(r.instancesListening, 2);
});

test("a cfg without a 3proxy process is down AND listed in cfgsWithoutProcess", () => {
  const view = cfgStatus.computeCfgStatus({
    cfgs: [cfg(32000), cfg(33500)],
    instances: [inst(32000)],
    listeningPorts: [32000],
    portsOk: true,
  });
  assert.strictEqual(view.cfgsDown, 1);
  assert.deepStrictEqual(view.cfgs[1], { startPort: 33500, count: 1500, listening: false, pid: null });
  assert.deepStrictEqual(view.cfgsWithoutProcess, [{ startPort: 33500, cfgPath: "/p/3proxy/3proxy_33500.cfg" }]);
});

test("failed port probe -> listening/cfgsDown null (unknown, never 'down')", () => {
  const view = cfgStatus.computeCfgStatus({
    cfgs: [cfg(32000)],
    instances: [inst(32000)],
    listeningPorts: new Set(),
    portsOk: false,
  });
  assert.strictEqual(view.cfgsDown, null);
  assert.strictEqual(view.cfgs[0].listening, null);
});

test("a cfg is probed on its first socks port (deprovision dropped the start port's block)", () => {
  // 3proxy_32000.cfg after /deprovision removed ports 32000-32001: serves 32002+.
  const summary = cfgStatus.parseCfgSummary(batchCfgText(32000, 5, { from: 2 }));
  assert.strictEqual(summary.probePort, 32002);
  assert.strictEqual(summary.count, 3);
  const view = cfgStatus.computeCfgStatus({
    cfgs: [cfg(32000, summary.count, summary.probePort)],
    instances: [inst(32000)],
    listeningPorts: [32002, 32003, 32004],
    portsOk: true,
  });
  assert.strictEqual(view.cfgsDown, 0);
  assert.strictEqual(view.cfgs[0].listening, true);
});

test("parseCfgSummary: count, probe port, distinct -e addresses; http-only cfg", () => {
  const s = cfgStatus.parseCfgSummary(batchCfgText(18100, 3));
  assert.strictEqual(s.count, 3);
  assert.strictEqual(s.probePort, 18100);
  assert.deepStrictEqual(s.socksPorts, [18100, 18101, 18102]);
  assert.deepStrictEqual(s.httpPorts, [8100, 8101, 8102]);
  assert.strictEqual(s.egress.length, 3, "socks + paired http share one -e");
  const h = cfgStatus.parseCfgSummary("proxy -6 -n -a -p9000 -i1.2.3.4 -e2001:db8::5\nproxy -6 -n -a -p9001 -i1.2.3.4 -e2001:db8::6\n");
  assert.strictEqual(h.probePort, 9000);
  assert.strictEqual(h.count, 2);
});

test("ipv6ToHex normalizes compressed / leading-zero-less spellings", () => {
  assert.strictEqual(cfgStatus.ipv6ToHex("2001:db8::1"), "20010db8000000000000000000000001");
  assert.strictEqual(cfgStatus.ipv6ToHex("2001:0DB8:0:0:0:0:0:1/64"), "20010db8000000000000000000000001");
  assert.strictEqual(cfgStatus.ipv6ToHex("2001:db8:0:1:a:b:c:d"), "20010db800000001000a000b000c000d");
  assert.strictEqual(cfgStatus.ipv6ToHex("::"), "00000000000000000000000000000000");
  assert.strictEqual(cfgStatus.ipv6ToHex("1.2.3.4"), null);
  assert.strictEqual(cfgStatus.ipv6ToHex("2001:db8::1::2"), null);
  assert.strictEqual(cfgStatus.ipv6ToHex("2001:db8:1:2:3:4:5:6:7"), null);
});

test("address coverage: cfg text + `ip -6 addr` output -> expected missing count", () => {
  const cfgText = [
    "socks -6 -a -p18100 -i45.32.10.20 -e2001:db8:0:1:a:b:c:1",
    "proxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8:0:1:a:b:c:1",
    "socks -6 -a -p18101 -i45.32.10.20 -e2001:db8:0:1:a:b:c:2",
    "proxy -6 -n -a -p8101 -i127.0.0.1 -e2001:db8:0:1:a:b:c:2",
    "socks -6 -a -p18102 -i45.32.10.20 -e2001:0db8:0000:0001:000a:000b:000c:0003",
    "socks -6 -a -p18103 -i45.32.10.20 -e2001:db8:0:1:a:b:c:4",
  ].join("\n");
  const ipAddrShow = [
    "2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000",
    "    inet6 2001:db8:0:1:a:b:c:1/128 scope global nodad ",
    "       valid_lft forever preferred_lft forever",
    "    inet6 2001:db8:0:1:a:b:c:3/64 scope global nodad ", // restored as /64 at boot, padded spelling in cfg
    "       valid_lft forever preferred_lft forever",
    "    inet6 2001:db8:0:1::7/64 scope global dynamic mngtmpaddr ",
    "    inet6 fe80::5400:4ff:fe00:1/64 scope link ",
  ].join("\n");
  const cov = cfgStatus.computeAddressCoverage(cfgStatus.parseCfgSummary(cfgText).egress, cfgStatus.parseIpAddrShow(ipAddrShow));
  assert.strictEqual(cov.expected, 4);
  assert.strictEqual(cov.present, 2);
  assert.strictEqual(cov.missing, 2);
  assert.deepStrictEqual(cov.missingSample, ["2001:db8:0:1:a:b:c:2", "2001:db8:0:1:a:b:c:4"]);
});

test("address coverage from /proc/net/if_inet6 (what the agent reads), iface filter optional", () => {
  const ifInet6 = [
    "20010db800000001000a000b000c0001 02 80 00 80 enp1s0",
    "20010db800000001000a000b000c0002 02 40 00 80 enp1s0",
    "00000000000000000000000000000001 01 80 10 80       lo",
    "fe800000000000005400004fffe00001 02 40 20 80 enp1s0",
  ].join("\n");
  const present = cfgStatus.parseIfInet6(ifInet6);
  assert.strictEqual(present.size, 4);
  assert.strictEqual(cfgStatus.parseIfInet6(ifInet6, { iface: "lo" }).size, 1);
  const cov = cfgStatus.computeAddressCoverage(
    ["2001:db8:0:1:a:b:c:1", "2001:db8:0:1:a:b:c:2", "2001:db8:0:1:a:b:c:9"],
    present
  );
  assert.deepStrictEqual([cov.expected, cov.present, cov.missing], [3, 2, 1]);
});

test("coverage probe is cached for its TTL and recomputed after it", async () => {
  let t = 1_000_000;
  let reads = 0;
  const probe = cfgStatus.createCoverageProbe({
    ttlMs: 60_000,
    now: () => t,
    readCfgs: async () => ({ ok: true, cfgs: [{ egress: ["2001:db8::1", "2001:db8::2"] }] }),
    readPresent: async () => {
      reads += 1;
      return new Set(reads === 1 ? ["20010db8000000000000000000000001"] : ["20010db8000000000000000000000001", "20010db8000000000000000000000002"]);
    },
  });
  const a = await probe.get();
  assert.deepStrictEqual([a.ok, a.expected, a.present, a.missing], [true, 2, 1, 1]);
  t += 30_000;
  const b = await probe.get();
  assert.strictEqual(reads, 1, "within 60 s: cached");
  assert.strictEqual(b.missing, 1);
  t += 31_000;
  const c = await probe.get();
  assert.strictEqual(reads, 2, "after 60 s: recomputed");
  assert.strictEqual(c.missing, 0);
});

test("an address of a prefix routed to the host (local route on lo) is present", () => {
  const routes = cfgStatus.parseLocalRoutes(
    [
      "local 2602:f2dc:a9::/48 dev lo metric 1024 pref medium",
      "local 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf dev enp1s0 proto kernel metric 0 pref medium",
      "anycast 2001:19f0:5c01:cdf:: dev enp1s0 proto kernel metric 0 pref medium",
      "local ::1 dev lo proto kernel metric 0 pref medium",
      "multicast ff00::/8 dev enp1s0 proto kernel metric 256 pref medium",
    ].join("\n")
  );
  assert.strictEqual(routes.length, 1, "only the /48: host addresses and non-local routes are no prefix");
  assert.strictEqual(routes[0].plen, 48);
  // `ip -6 route show table local dev lo` drops the "dev lo" part.
  const lo = cfgStatus.parseLocalRoutes("local ::1 proto kernel metric 0 pref medium\nlocal 2602:f2dc:a9::/48 metric 1024 pref medium\n");
  assert.deepStrictEqual(lo.map((r) => r.plen), [48]);
  const cov = cfgStatus.computeAddressCoverage(
    ["2602:f2dc:a9:1::1", "2602:f2dc:a9:ffff:ffff:ffff:ffff:ffff", "2602:f2dc:aa::1", "2001:db8:0:1:a:b:c:1"],
    new Set(["20010db800000001000a000b000c0001"]),
    { routed: routes }
  );
  assert.deepStrictEqual([cov.expected, cov.present, cov.missing, cov.routed], [4, 3, 1, 2]);
  assert.deepStrictEqual(cov.missingSample, ["2602:f2dc:aa::1"]);
  const noRoute = cfgStatus.computeAddressCoverage(["2602:f2dc:a9:1::1"], new Set());
  assert.deepStrictEqual([noRoute.missing, noRoute.routed], [1, 0], "without the route the address is missing");
});

test("coverage probe counts routed addresses; a failed route read is no prefix", async () => {
  const cfgs = async () => ({ ok: true, cfgs: [{ egress: ["2602:f2dc:a9:1::1", "2602:f2dc:a9:2::1"] }] });
  const routed = cfgStatus.createCoverageProbe({
    readCfgs: cfgs,
    readPresent: async () => new Set(),
    readRouted: async () => cfgStatus.parseLocalRoutes("local 2602:f2dc:a9::/48 dev lo metric 1024 pref medium"),
  });
  const a = await routed.get();
  assert.deepStrictEqual([a.ok, a.present, a.missing, a.routed], [true, 2, 0, 2]);
  const gone = cfgStatus.createCoverageProbe({
    readCfgs: cfgs,
    readPresent: async () => new Set(),
    readRouted: async () => [],
  });
  const b = await gone.get();
  assert.deepStrictEqual([b.ok, b.missing], [true, 2]);
});

test("coverage probe reports a read failure instead of throwing", async () => {
  const probe = cfgStatus.createCoverageProbe({
    readCfgs: async () => ({ ok: true, cfgs: [] }),
    readPresent: async () => {
      throw new Error("ENOENT: /proc/net/if_inet6");
    },
  });
  const v = await probe.get();
  assert.strictEqual(v.ok, false);
  assert.match(v.error, /if_inet6/);
  assert.strictEqual(v.missing, null);
});

test("cfg inventory: active cfgs only, re-parsed only when the file changes", async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "netrun-cfginv-"));
  try {
    await fsp.writeFile(path.join(dir, "3proxy_18100.cfg"), batchCfgText(18100, 3));
    await fsp.writeFile(path.join(dir, "3proxy_20000.cfg.disabled"), batchCfgText(20000, 1));
    await fsp.writeFile(path.join(dir, "3proxy_21000.cfg.deprov.tmp"), batchCfgText(21000, 1));
    let reads = 0;
    const counting = { ...fsp, readFile: (...a) => { reads += 1; return fsp.readFile(...a); } };
    const inv = cfgStatus.createCfgInventory({ cfgDir: dir, fs: counting });
    const r1 = await inv.read();
    assert.strictEqual(r1.ok, true);
    assert.deepStrictEqual(r1.cfgs.map((c) => [c.startPort, c.count, c.probePort]), [[18100, 3, 18100]]);
    await inv.read();
    assert.strictEqual(reads, 1, "unchanged file not re-read");
    await fsp.writeFile(path.join(dir, "3proxy_18100.cfg"), batchCfgText(18100, 4));
    const r3 = await inv.read();
    assert.strictEqual(r3.cfgs[0].count, 4);
    assert.strictEqual(reads, 2);
    const missing = await cfgStatus.createCfgInventory({ cfgDir: path.join(dir, "nope") }).read();
    assert.deepStrictEqual(missing, { ok: true, cfgs: [] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("agent binds IPv4 only: listen called with host 0.0.0.0", () => {
  assert.strictEqual(server.LISTEN_HOST, "0.0.0.0");
  let args = null;
  const fake = { listen: (...a) => { args = a; return fake; } };
  const cb = () => {};
  server.listenAgent(fake, cb);
  assert.strictEqual(args[0], 8085);
  assert.strictEqual(args[1], "0.0.0.0");
  assert.strictEqual(args[2], cb);
});
