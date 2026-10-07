"use strict";

// Audit FP-01 — the static per-cfg checks behind /health cfgsLegacyDns /
// cfgsEgressFamily (cfg_status.js), and node_settings.js (env, then
// /etc/netrun/netrun.env, then the default — the switch file the agent shares
// with the generator and the boot scripts).
// Run with: node --test node_runtime/node_agent/cfg_checks.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert");
const cfgStatus = require("./cfg_status.js");
const settings = require("./node_settings.js");

test("parseCfgSummary: nserver lines and egress family flags", () => {
  const s = cfgStatus.parseCfgSummary(
    "daemon\n  nserver 127.0.0.1\n  nserver ::1\n  maxconn 512\nflush\nsocks -6 -a -p18100 -i1.2.3.4 -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\nsocks -a -p18101 -i1.2.3.4 -e2001:db8::2\n"
  );
  assert.deepStrictEqual(s.nservers, ["127.0.0.1", "::1"]);
  assert.deepStrictEqual(s.modeFlags, ["-6", "none"], "a line without a family flag = 3proxy's default (IPv4)");
  assert.strictEqual(s.probePort, 18100);
});

test("isLocalResolver / staticCfgChecks: third-party DNS and IPv4-capable cfgs in ipv6_only", () => {
  for (const a of ["127.0.0.1", "127.0.0.53", "::1", "localhost", "127.0.0.1:5353", "[::1]:53"]) assert.ok(cfgStatus.isLocalResolver(a), a);
  for (const a of ["1.1.1.1", "8.8.8.8:53", "2606:4700:4700::1111", "1.0.0.19"]) assert.ok(!cfgStatus.isLocalResolver(a), a);
  const cfgs = [
    { startPort: 18100, nservers: ["127.0.0.1", "::1"], modeFlags: ["-6"] },
    { startPort: 20000, nservers: ["1.0.0.19", "1.0.0.19", "::1"], modeFlags: ["-64"] },
    { startPort: 30000, nservers: [], modeFlags: ["-6", "none"] },
  ];
  const v6 = cfgStatus.staticCfgChecks(cfgs, { expectedFlag: "-6" });
  assert.deepStrictEqual(v6.cfgsLegacyDns, { count: 1, items: [{ startPort: 20000, nservers: ["1.0.0.19"] }] });
  assert.deepStrictEqual(v6.cfgsEgressFamily, {
    expectedFlag: "-6",
    mismatched: 2,
    items: [{ startPort: 20000, flags: ["-64"] }, { startPort: 30000, flags: ["-6", "none"] }],
  });
  const ds = cfgStatus.staticCfgChecks(cfgs, { expectedFlag: null });
  assert.deepStrictEqual(ds.cfgsEgressFamily, { expectedFlag: null, mismatched: null, items: [] }, "dualstack: not checked");
});

test("node_settings: env wins, then the netrun.env file, then the default", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-settings-"));
  try {
    const file = path.join(dir, "netrun.env");
    fs.writeFileSync(file, "# comment\nNETRUN_ANCHOR_DEPRECATE=0\n  NETRUN_3PROXY_MAXCONN = \"384\"\n");
    const env = { NETRUN_ENV_FILE: file };
    assert.strictEqual(settings.nodeSetting("NETRUN_ANCHOR_DEPRECATE", "1", { env }), "0");
    assert.strictEqual(settings.settingOn("NETRUN_ANCHOR_DEPRECATE", true, { env }), false);
    assert.strictEqual(settings.settingOn("NETRUN_ANCHOR_DEPRECATE", true, { env: { ...env, NETRUN_ANCHOR_DEPRECATE: "1" } }), true, "env wins");
    assert.strictEqual(settings.settingOn("NETRUN_ANCHOR_READD", true, { env }), true, "absent: default");
    assert.strictEqual(settings.nodeSetting("NETRUN_3PROXY_MAXCONN", "512", { env }), "384");
    assert.strictEqual(settings.nodeSetting("X", "d", { env: { NETRUN_ENV_FILE: path.join(dir, "missing") } }), "d");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Audit RES-11 follow-up — an http-only cfg behind the HTTPS front binds
// 127.0.0.1:<port>; haproxy holds <public-ip>:<port>. Its liveness is the
// 3proxy listener, never haproxy's frontend on the same port number.
test("http-only cfg: probe address recorded; listening only on its own address:port (not haproxy's frontend)", () => {
  const h = cfgStatus.parseCfgSummary("daemon\nflush\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::5\nproxy -6 -n -a -p8101 -i127.0.0.1 -e2001:db8::6\n");
  assert.strictEqual(h.httpOnly, true);
  assert.strictEqual(h.probeAddr, "127.0.0.1");
  const d = cfgStatus.parseCfgSummary("socks -6 -a -p18100 -i1.2.3.4 -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\n");
  assert.strictEqual(d.httpOnly, false);
  assert.strictEqual(d.probeAddr, "1.2.3.4");
  const keysHaproxy = cfgStatus.parseListenKeys("LISTEN 0 4096 45.32.10.20:8100 0.0.0.0:*\nLISTEN 0 13 1.2.3.4:18100 0.0.0.0:*\n");
  const keysBoth = cfgStatus.parseListenKeys("LISTEN 0 4096 45.32.10.20:8100 0.0.0.0:*\nLISTEN 0 13 127.0.0.1:8100 0.0.0.0:*\nLISTEN 0 13 [::1]:9 [::]:*\n");
  assert.ok(keysBoth.has("::1:9"), "brackets stripped");
  const http = { startPort: 8100, probePort: 8100, probeAddr: "127.0.0.1", httpOnly: true };
  const dual = { startPort: 18100, probePort: 18100, probeAddr: "1.2.3.4", httpOnly: false };
  const ports = new Set([8100, 18100]);
  assert.strictEqual(cfgStatus.cfgListening(http, ports, keysHaproxy), false, "haproxy's frontend is not the batch");
  assert.strictEqual(cfgStatus.cfgListening(http, ports, keysBoth), true);
  assert.strictEqual(cfgStatus.cfgListening(http, ports, null), true, "no keys: the old port-only probe");
  assert.strictEqual(cfgStatus.cfgListening(dual, ports, new Set()), true, "socks cfgs keep the port probe (no change on dual nodes)");
  assert.strictEqual(cfgStatus.cfgListening({ ...http, probeAddr: "0.0.0.0" }, ports, keysHaproxy), true, "a wildcard bind: port probe");
  const view = cfgStatus.computeCfgStatus({
    cfgs: [{ ...http, cfgPath: "/c/3proxy_8100.cfg", count: 2 }, { ...dual, cfgPath: "/c/3proxy_18100.cfg", count: 1 }],
    instances: [{ startPort: 18100, pid: 7 }],
    listeningPorts: ports,
    listeningKeys: keysHaproxy,
  });
  assert.deepStrictEqual(view.cfgs.map((c) => [c.startPort, c.listening]), [[8100, false], [18100, true]]);
  assert.strictEqual(view.cfgsDown, 1);
});

test("cfg inventory: a same-size rewrite that keeps the mtime (the spawn helper's DNS fix: tmp + mv) is re-parsed", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-cfgino-"));
  try {
    const cfg = path.join(dir, "3proxy_18100.cfg");
    fs.writeFileSync(cfg, "daemon\nnserver 1.1.1.100\nflush\nsocks -6 -a -p18100 -i1.2.3.4 -e2001:db8::1\n");
    fs.utimesSync(cfg, new Date(1_000_000), new Date(1_000_000));
    const inv = cfgStatus.createCfgInventory({ cfgDir: dir });
    assert.deepStrictEqual((await inv.read()).cfgs[0].nservers, ["1.1.1.100"]);
    const sizeBefore = fs.statSync(cfg).size;
    const tmp = `${cfg}.tmp`;
    fs.writeFileSync(tmp, "daemon\nnserver 127.0.0.1\nflush\nsocks -6 -a -p18100 -i1.2.3.4 -e2001:db8::1\n"); // same length
    fs.utimesSync(tmp, new Date(1_000_000), new Date(1_000_000));
    fs.renameSync(tmp, cfg);
    assert.strictEqual(fs.statSync(cfg).size, sizeBefore, "same size");
    const after = (await inv.read()).cfgs[0];
    assert.strictEqual(after.mtimeMs, 1_000_000, "mtime kept");
    assert.deepStrictEqual(after.nservers, ["127.0.0.1"], "re-parsed: new inode");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
