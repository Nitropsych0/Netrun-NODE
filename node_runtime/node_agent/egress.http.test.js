"use strict";

// Wave IPV6-ROTATION — the HTTP contract of /egress (status codes and body
// shapes the orchestrator relies on), the server.js wiring (auth, 404
// fall-through, /deprovision dropping egress state) and
// /describe.supports.egress_rotation, the nftables.service boot drop-in and
// the persisted proxy-NDP sysctls. `ip`, `nft`, `pgrep` and `systemctl` are
// stubs on PATH; /proc/sys is a fake tree (EGRESS_PROC_SYS).
// Run with: node --test node_runtime/node_agent/egress.http.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const https = require("https");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-egress-http-"));
const BIN = path.join(ROOT, "bin");
const LOG = path.join(ROOT, "commands.log");
fs.mkdirSync(BIN);
fs.mkdirSync(path.join(ROOT, "3proxy"));
// ip: one NIC with one global address, no proxy entries; every batch succeeds.
fs.writeFileSync(path.join(BIN, "ip"), `#!/bin/sh
echo "ip $*" >> "${LOG}"
case "$*" in
  "-6 route show default") echo "default via fe80::1 dev eth0 proto static metric 1024 pref medium" ;;
  "-6 -o addr show dev eth0"*) echo "2: eth0    inet6 2001:db8:1:2::1/64 scope global \\\\       valid_lft forever preferred_lft forever" ;;
  "-6 neigh show proxy dev eth0") ;;
  "-6 -force -batch "*) cat "$4" >> "${LOG}" ;;
  *) exit 2 ;;
esac
exit 0
`, { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "nft"), `#!/bin/sh
echo "nft $*" >> "${LOG}"
[ "$1" = "-f" ] && cat "$2" >> "${LOG}"
exit 0
`, { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "pgrep"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "systemctl"), `#!/bin/sh\necho "systemctl $*" >> "${LOG}"\nexit 0\n`, { mode: 0o755 });
// the boot drop-in goes to a fake /etc/systemd/system, never the real one
fs.mkdirSync(path.join(ROOT, "systemd"));
const DROPIN = path.join(ROOT, "systemd", "nftables.service.d", "netrun-egress.conf");
process.env.EGRESS_NFT_DROPIN = DROPIN;
// proxy-NDP sysctls: a fake /proc/sys, the file in a fake /etc/sysctl.d
const PROC = path.join(ROOT, "proc");
for (const [key, value] of [
  ["net/ipv6/conf/all/forwarding", "1"], ["net/ipv6/conf/all/proxy_ndp", "0"],
  ["net/ipv6/conf/eth0/forwarding", "1"], ["net/ipv6/conf/eth0/proxy_ndp", "0"],
  ["net/ipv6/conf/eth0/accept_ra", "0"], ["net/ipv6/neigh/eth0/proxy_delay", "80"],
]) {
  fs.mkdirSync(path.dirname(path.join(PROC, key)), { recursive: true });
  fs.writeFileSync(path.join(PROC, key), `${value}\n`);
}
fs.mkdirSync(path.join(ROOT, "sysctl.d"));
const SYSCTL_CONF = path.join(ROOT, "sysctl.d", "99-netrun-egress.conf");
process.env.EGRESS_PROC_SYS = PROC;
process.env.EGRESS_SYSCTL_CONF = SYSCTL_CONF;
process.env.PATH = `${BIN}:${process.env.PATH}`;
process.env.NODE_AGENT_PROXY_ROOT = ROOT;
process.env.NODE_AGENT_JOBS_ROOT = path.join(ROOT, "jobs");
process.env.NODE_AGENT_NFT_PERSIST = path.join(ROOT, "nftables.conf");
process.env.NODE_AGENT_HTTPS_SYNC_BIN = path.join(ROOT, "no-such-netrun-https");
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.EGRESS_POOL_SIZE = "4";

const ANCHOR_30000 = "2001:db8:1:2:a1b:c2:3:d4e";
const ANCHOR_31000 = "2001:db8:1:2:3333::31";
fs.writeFileSync(path.join(ROOT, "3proxy", "3proxy_30000.cfg"),
  "daemon\nauth strong\nflush\nusers a:CL:1\nallow a *\ndeny *\n"
  + "socks -6 -a -p30000 -i1.2.3.4 -e2001:0db8:0001:0002:0a1b:00c2:0003:0d4e\n"
  + "proxy -6 -n -a -p20000 -i1.2.3.4 -e2001:0db8:0001:0002:0a1b:00c2:0003:0d4e\n");
fs.writeFileSync(path.join(ROOT, "3proxy", "3proxy_31000.cfg"),
  `daemon\nauth strong\nflush\nusers b:CL:2\nallow b *\ndeny *\nsocks -6 -a -p31000 -i1.2.3.4 -e${ANCHOR_31000}\n`);

// buildDescribe() geolocates via https.get — keep the test offline.
https.get = () => {
  const { EventEmitter } = require("events");
  const req = new EventEmitter();
  req.destroy = () => {};
  process.nextTick(() => req.emit("error", new Error("offline test")));
  return req;
};

const eg = require(path.resolve(__dirname, "egress.js"));
const { buildDescribe } = require(path.resolve(__dirname, "describe.js"));
const { server } = require(path.resolve(__dirname, "server.js"));

function request(method, urlPath, { body, key = "test-key" } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : typeof body === "string" ? body : JSON.stringify(body);
    const headers = { "Content-Type": "application/json" };
    if (key) headers["X-API-KEY"] = key;
    if (data !== null) headers["Content-Length"] = Buffer.byteLength(data);
    const req = http.request({ host: "127.0.0.1", port: server.address().port, method, path: urlPath, headers }, (res) => {
      let text = "";
      res.on("data", (d) => { text += d; });
      res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    });
    req.on("error", reject);
    if (data !== null) req.write(data);
    req.end();
  });
}

test.before(() => new Promise((resolve) => server.listen(0, "127.0.0.1", resolve)));
test.after(() => new Promise((resolve) => server.close(resolve)).then(() => {
  fs.rmSync(ROOT, { recursive: true, force: true });
}));

test("before start: auth first, then 503 egress_unavailable; other /egress paths are 404", async () => {
  assert.deepStrictEqual(await request("POST", "/egress/rotate", { body: { ports: [30000] }, key: null }), {
    status: 401, body: { success: false, error: "unauthorized" },
  });
  assert.deepStrictEqual(await request("POST", "/egress/rotate", { body: { ports: [30000] } }), {
    status: 503, body: { ok: false, error: "egress_unavailable", detail: "not_initialised" },
  });
  assert.strictEqual((await request("GET", "/egress")).status, 503);
  // a malformed body is a 400 whether or not the module is up
  assert.strictEqual((await request("POST", "/egress/mode", { body: { ports: [30000] } })).body.error, "bad_request");
  for (const [m, p] of [["GET", "/egress/rotate"], ["POST", "/egress"], ["POST", "/egress/other"], ["GET", "/egressx"]]) {
    assert.deepStrictEqual(await request(m, p, { body: m === "POST" ? {} : undefined }), {
      status: 404, body: { success: false, status: "failed", error: "not_found" },
    }, `${m} ${p}`);
  }
  assert.strictEqual(eg.isAvailable(), false);
  const d = await buildDescribe({ egressRotation: eg.isAvailable() });
  assert.strictEqual(d.supports.egress_rotation, false);
  assert.strictEqual((await buildDescribe({})).supports.egress_rotation, false);
});

let started = null;

test("after start: rotate / mode / reset / GET shapes over HTTP", async () => {
  started = eg.start();
  // the first request waits for the start-up init instead of answering 503
  const rot = await request("POST", "/egress/rotate", { body: { ports: [30000, 31000, 39999], drain_sec: 30 } });
  assert.strictEqual(rot.status, 200);
  assert.strictEqual(rot.body.ok, false, "one port is unknown");
  assert.deepStrictEqual(Object.keys(rot.body), ["ok", "items"]);
  const [a, b, c] = rot.body.items;
  assert.deepStrictEqual(Object.keys(a), ["port", "ok", "anchor", "mode", "old_ipv6", "new_ipv6", "error"]);
  assert.deepStrictEqual([a.port, a.ok, a.anchor, a.mode, a.old_ipv6, a.error], [30000, true, ANCHOR_30000, "static", null, null]);
  assert.match(a.new_ipv6, /^2001:db8:1:2:/);
  assert.deepStrictEqual([b.port, b.ok, b.anchor], [31000, true, ANCHOR_31000]);
  assert.deepStrictEqual(c, { port: 39999, ok: false, anchor: null, mode: null, old_ipv6: null, new_ipv6: null, error: "port_not_found" });
  assert.strictEqual(eg.isAvailable(), true);
  assert.strictEqual((await buildDescribe({ egressRotation: eg.isAvailable() })).supports.egress_rotation, true);

  const log = fs.readFileSync(LOG, "utf-8");
  assert.ok(log.includes(`neigh add proxy ${a.new_ipv6} dev eth0\n`));
  assert.ok(!log.includes("address add"), "nothing is added to the NIC");
  assert.ok(log.includes(`add element ip6 netrun_egress static_egress { ${ANCHOR_30000} : ${a.new_ipv6}`));

  const mode = await request("POST", "/egress/mode", { body: { ports: [31000], mode: "per_connection" } });
  assert.deepStrictEqual(mode.body.items[0], {
    port: 31000, ok: true, anchor: ANCHOR_31000, mode: "per_connection", old_ipv6: b.new_ipv6, new_ipv6: "pool", error: null,
  });

  const get = await request("GET", "/egress?ports=30000,31000,30001");
  assert.strictEqual(get.status, 200);
  assert.deepStrictEqual(get.body, {
    items: [
      { port: 30000, anchor: ANCHOR_30000, current: a.new_ipv6, mode: "static" },
      { port: 31000, anchor: ANCHOR_31000, current: null, mode: "per_connection" },
      { port: 30001, anchor: null, current: null, mode: null },
    ],
    pool: { size: 4, refreshed_at: get.body.pool.refreshed_at, idle_since: null },
    draining: 1,
    prefix: "2001:db8:1:2::/64",
    iface: "eth0",
  });
  assert.ok(Number.isFinite(Date.parse(get.body.pool.refreshed_at)));
  assert.strictEqual((await request("GET", "/egress?ports=1,x")).status, 400);

  const reset = await request("POST", "/egress/reset", { body: { ports: [31000] } });
  assert.deepStrictEqual(reset.body, {
    ok: true,
    items: [{ port: 31000, ok: true, anchor: ANCHOR_31000, mode: null, old_ipv6: "pool", new_ipv6: null, error: null }],
  });
  const idle = (await request("GET", "/egress")).body.pool;
  assert.strictEqual(idle.size, 4, "the last per_connection port left the pool idle (reused by a switch back)");
  assert.ok(Number.isFinite(Date.parse(idle.idle_since)));

  const bad = await request("POST", "/egress/rotate", { body: "{not json" });
  assert.deepStrictEqual([bad.status, bad.body.error], [400, "bad_request"]);
  const tooMany = await request("POST", "/egress/reset", { body: { ports: Array.from({ length: 1001 }, (_, i) => 20000 + i) } });
  assert.deepStrictEqual([tooMany.status, tooMany.body.error], [400, "bad_request"]);
});

test("/deprovision drops the removed ports' egress state", async () => {
  const before = await request("GET", "/egress");
  assert.deepStrictEqual(before.body.items.map((i) => i.port), [30000]);
  const dep = await request("POST", "/deprovision", { body: { ports: [30000] } });
  assert.strictEqual(dep.status, 200);
  assert.deepStrictEqual(dep.body.removed_ports, [30000]);
  assert.deepStrictEqual(dep.body.egress, { ok: true, forgotten: 1 });
  const after = await request("GET", "/egress");
  assert.deepStrictEqual(after.body.items, []);
  assert.strictEqual(after.body.draining, before.body.draining + 1, "its address drains (at once) for the GC");
  const state = JSON.parse(fs.readFileSync(path.join(ROOT, "egress_state.json"), "utf-8"));
  assert.deepStrictEqual(state.ports, {});
});

test("start() wrote the nftables.service drop-in with the absolute nft path, then daemon-reload", async () => {
  assert.strictEqual(await started, true);
  assert.strictEqual(fs.readFileSync(DROPIN, "utf-8"), eg.nftDropinText(path.join(BIN, "nft")));
  assert.ok(fs.readFileSync(LOG, "utf-8").includes("systemctl daemon-reload"));
});

test("start() turned proxy NDP on for the default-route interface and persisted it; the table has the forward guard", async () => {
  assert.strictEqual(await started, true);
  const read = (key) => fs.readFileSync(path.join(PROC, key), "utf-8").trim();
  assert.deepStrictEqual(
    eg.egressSysctls("eth0").map((s) => read(s.key.join("/"))),
    ["1", "1", "0", "1", "1"]
  );
  assert.strictEqual(fs.readFileSync(SYSCTL_CONF, "utf-8"), eg.sysctlConfText("eth0"));
  assert.ok(fs.readFileSync(LOG, "utf-8").includes("\tchain forward_guard {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tip6 daddr 2001:db8:1:2::/64 drop\n"));
});
