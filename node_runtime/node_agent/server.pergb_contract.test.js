"use strict";

// Pay-per-GB v2 (lane L9) — the plain agent's contracts that per-GB adds to:
//   GET /health  -> clock { ntpSynchronized: true | false | null, source,
//                   checkedAt, error } (timedatectl; the per-GB gate needs a
//                   synced clock);
//   GET /describe -> the per-piece capacity model minus the per-GB budget
//                   (slice memory; option A: the shared ports), reported as
//                   capacity_model.pergbReserveMb / pergbSharedPorts / pergbOption.
// `ss` and `timedatectl` are PATH stubs, the IPv6 egress URL is a closed local
// port, the geo lookup is stubbed: nothing leaves the box.
// Run with: node --test node_runtime/node_agent/server.pergb_contract.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-pergb-contract-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const BIN = path.join(TMP, "bin");
const ENABLE = path.join(TMP, "enable.json");
const NTP = path.join(TMP, "ntp");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.PATH = `${BIN}:${process.env.PATH}`;
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NETRUN_ENV_FILE = path.join(TMP, "no-netrun.env");
process.env.NETRUN_PERGB_ENABLE_FILE = ENABLE;
process.env.NETRUN_PERGB_POOL_FILE = path.join(TMP, "no-pool.conf");
process.env.NETRUN_PRIMARY_IPV4 = "45.32.10.20";
delete process.env.NETRUN_IPV6_ROUTED_PREFIX;
fs.writeFileSync(path.join(BIN, "ss"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
// one per-piece batch and the two per-GB 3proxy processes (D3: own binary and cfgs)
fs.writeFileSync(path.join(BIN, "ps"), [
  "#!/bin/sh",
  "echo '  PID COMMAND'",
  `echo ' 4242 ${PROXY_ROOT}/3proxy/bin/3proxy ${PROXY_ROOT}/3proxy/3proxy_18100.cfg'`,
  "echo ' 5000 /opt/netrun/pergb/bin/3proxy-pergb /opt/netrun/pergb/cfg/pergb_31000.cfg'",
  "echo ' 5001 /opt/netrun/pergb/bin/3proxy-pergb /opt/netrun/pergb/cfg/pergb_31500.cfg'",
  "",
].join("\n"), { mode: 0o755 });
fs.writeFileSync(path.join(PROXY_ROOT, "3proxy", "3proxy_18100.cfg"), "daemon\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::a\n");
fs.writeFileSync(path.join(BIN, "timedatectl"), `#!/bin/sh\n[ "$*" = "show -p NTPSynchronized --value" ] || exit 2\ncat "${NTP}"\n`, { mode: 0o755 });
fs.writeFileSync(NTP, "yes\n");

// /describe geolocates through https.get: keep it offline
https.get = () => {
  const { EventEmitter } = require("events");
  const req = new EventEmitter();
  req.destroy = () => {};
  process.nextTick(() => req.emit("error", new Error("offline test")));
  return req;
};

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const { server } = require("./server.js");
const describe = require("./describe.js");
const clockSync = require("./clock_sync.js");

test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

function get(port, p) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port, path: p, headers: { "X-API-KEY": "test-key" } }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
      })
      .on("error", reject);
  });
}

test("clock_sync: yes / no / unreadable, cached", async () => {
  assert.strictEqual(clockSync.parseNtpSynchronized("yes\n"), true);
  assert.strictEqual(clockSync.parseNtpSynchronized("no"), false);
  assert.strictEqual(clockSync.parseNtpSynchronized(""), null);
  let answer = { code: 0, stdout: "no\n", stderr: "" };
  let calls = 0;
  let t = 0;
  const c = clockSync.createClockSync({ run: async () => { calls += 1; return answer; }, now: () => t });
  assert.strictEqual((await c.status()).ntpSynchronized, false);
  answer = { code: 0, stdout: "yes\n", stderr: "" };
  assert.strictEqual((await c.status()).ntpSynchronized, false, "cached");
  t += clockSync.CLOCK_TTL_MS;
  const s = await c.status();
  assert.deepStrictEqual([s.ntpSynchronized, s.source, s.error], [true, "timedatectl", null]);
  answer = { code: 1, stdout: "", stderr: "System has not been booted with systemd" };
  t += clockSync.CLOCK_TTL_MS;
  const u = await c.status();
  assert.strictEqual(u.ntpSynchronized, null, "unknown is never 'synced'");
  assert.match(u.error, /systemd/);
  assert.strictEqual(calls, 3);
});

test("capacity model: per-GB takes its slice memory and (option A) its shared ports off the per-piece capacity", () => {
  const meminfo = (gb) => `MemTotal: ${Math.round(gb * 1024 * 1024)} kB\n`;
  const optionA = { enabled: true, memMb: 1536, ports: 1000, option: "A" };
  const optionB = { enabled: true, memMb: 1536, ports: 0, option: "B" };
  // a box capped by the port ceiling: option A lowers the ceiling, option B does not
  assert.strictEqual(describe.estimateCapacity({ meminfoText: meminfo(15.6) }), 27436);
  assert.strictEqual(describe.estimateCapacity({ meminfoText: meminfo(15.6), pergb: optionA }), 26436);
  assert.strictEqual(describe.estimateCapacity({ meminfoText: meminfo(15.6), pergb: optionB }), 27436);
  // a RAM-bound box: 1536 MiB less usable RAM
  const plain = describe.estimateCapacity({ meminfoText: meminfo(3.8) });
  const withPergb = describe.estimateCapacity({ meminfoText: meminfo(3.8), pergb: optionB });
  const perProxyMb = describe.CAPACITY_MODEL.perProxyKb / 1024 + describe.CAPACITY_MODEL.perProcessMb / describe.CAPACITY_MODEL.avgBatchSize;
  assert.ok(Math.abs(plain - withPergb - Math.floor(1536 / perProxyMb)) <= 1, `${plain} - ${withPergb}`);
  assert.strictEqual(describe.estimateCapacity({ meminfoText: meminfo(3.8), pergb: { enabled: false, memMb: 9999, ports: 9999 } }), plain);
  const m = describe.describeCapacityModel({ meminfoText: meminfo(3.8), pergb: optionA });
  assert.deepStrictEqual([m.pergbReserveMb, m.pergbSharedPorts, m.pergbOption], [1536, 1000, "A"]);
  const off = describe.describeCapacityModel({ meminfoText: meminfo(3.8) });
  assert.deepStrictEqual([off.pergbReserveMb, off.pergbSharedPorts, off.pergbOption], [0, 0, null]);
});

test("GET /health carries clock.ntpSynchronized; GET /describe subtracts the per-GB budget", { timeout: 60_000 }, async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const port = server.address().port;
    const h = await get(port, "/health");
    assert.strictEqual(h.status, 200);
    assert.strictEqual(h.json.clock.ntpSynchronized, true);
    assert.strictEqual(h.json.clock.source, "timedatectl");
    assert.ok(Number.isFinite(Date.parse(h.json.clock.checkedAt)));
    // the per-GB 3proxy processes are no per-piece instances (no "unknown_cfg" duplicates)
    assert.strictEqual(h.json.activeInstances, 1, JSON.stringify(h.json.instances));
    assert.strictEqual(h.json.duplicateStatePresent, false);

    const before = await get(port, "/describe");
    assert.strictEqual(before.json.capacity_model.pergbReserveMb, 0, "no per-GB: the model as before");
    fs.writeFileSync(ENABLE, JSON.stringify({ base: 31000, count: 1000, egressIpv4: null, sliceMemMax: "2G" }));
    const after = await get(port, "/describe");
    assert.deepStrictEqual(
      [after.json.capacity_model.pergbReserveMb, after.json.capacity_model.pergbSharedPorts, after.json.capacity_model.pergbOption],
      [2048, 1000, "A"],
    );
    assert.ok(after.json.capacity <= before.json.capacity, `${after.json.capacity} <= ${before.json.capacity}`);
    assert.ok(after.json.capacity <= describe.CAPACITY_MODEL.portCeiling - 1000 || after.json.capacity === describe.CAPACITY_MODEL.minCapacity);
  } finally {
    await new Promise((r) => server.close(r));
  }
});
