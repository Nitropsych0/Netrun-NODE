"use strict";

// Wave FLEET-HEALTH (RES-10) — GET /health end to end against a fixture
// PROXY_ROOT: every pre-existing field is still there and the additive
// cfgs / cfgsDown / cfgsWithoutProcess / ipv6Addresses fields are filled.
// `ss` is a PATH stub; the IPv6 egress URL points at a closed local port so
// nothing leaves the box.
// Run with: node --test node_runtime/node_agent/server.health_http.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-health-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const BIN = path.join(TMP, "bin");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.PATH = `${BIN}:${process.env.PATH}`;
// 18100 listens, 20000 does not; neither has a 3proxy process here.
fs.writeFileSync(
  path.join(BIN, "ss"),
  "#!/bin/sh\necho 'LISTEN 0 13 45.32.10.20:18100 0.0.0.0:*'\necho 'LISTEN 0 13 45.32.10.20:18101 0.0.0.0:*'\n",
  { mode: 0o755 }
);
fs.writeFileSync(
  path.join(PROXY_ROOT, "3proxy", "3proxy_18100.cfg"),
  "daemon\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::a\nflush\nsocks -6 -a -p18101 -i45.32.10.20 -e2001:db8::b\n"
);
fs.writeFileSync(
  path.join(PROXY_ROOT, "3proxy", "3proxy_20000.cfg"),
  "daemon\nflush\nsocks -6 -a -p20000 -i45.32.10.20 -e2001:db8::c\n"
);

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const { server } = require("./server.js");

function get(port, p) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port, path: p }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
      })
      .on("error", reject);
  });
}

test("GET /health: old fields kept, cfg + address fields added", { timeout: 30_000 }, async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const { status, json } = await get(server.address().port, "/health");
    assert.strictEqual(status, 200);
    for (const key of [
      "success", "status", "ok", "service", "agentAlive", "timestamp", "jobsRoot", "busy",
      "activeInstances", "duplicateStatePresent", "proxyReady", "proxyReadiness", "instances",
      "ipv6", "ipv6Egress", "dns", "load",
    ]) {
      assert.ok(key in json, `pre-existing field ${key} kept`);
    }
    assert.strictEqual(json.service, "proxy-node-agent");
    assert.deepStrictEqual(json.cfgs, [
      { startPort: 18100, count: 2, listening: true, pid: null },
      { startPort: 20000, count: 1, listening: false, pid: null },
    ]);
    assert.strictEqual(json.cfgsDown, 1);
    assert.strictEqual(json.cfgsTotal, 2);
    assert.deepStrictEqual(
      json.cfgsWithoutProcess.map((c) => c.startPort),
      [18100, 20000]
    );
    assert.ok(json.ipv6Addresses && typeof json.ipv6Addresses === "object");
    assert.strictEqual(json.ipv6Addresses.ttlSec, 60);
    if (fs.existsSync("/proc/net/if_inet6")) {
      assert.strictEqual(json.ipv6Addresses.expected, 3);
    } else {
      assert.strictEqual(json.ipv6Addresses.ok, false, "no /proc on this box: reported, not thrown");
    }
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(TMP, { recursive: true, force: true });
  }
});
