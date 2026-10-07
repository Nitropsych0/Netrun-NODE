"use strict";

// Audit FO-08 — the agent end to end: POST / GET /https/hostnames (API key,
// status codes, body shapes), /health httpsHostnames, /describe
// supports.https_hostnames, the switch. systemd-run / systemctl are stubs on
// PATH; netrun-https is a fake script; nothing leaves the box.
// Run with: node --test node_runtime/node_agent/server.https_hostnames.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-fo08-"));
const BIN = path.join(TMP, "bin");
const LOG = path.join(TMP, "calls.log");
const HOSTNAMES_FILE = path.join(TMP, "etc", "https-hostnames");
const TLS_DIR = path.join(TMP, "tls");
const HTTPS_BIN = path.join(TMP, "netrun-https");
fs.mkdirSync(BIN, { recursive: true });
fs.mkdirSync(path.join(TMP, "proxyserver", "3proxy"), { recursive: true });
fs.mkdirSync(path.join(TLS_DIR, "hosts"), { recursive: true });
fs.writeFileSync(path.join(BIN, "systemd-run"), `#!/bin/sh\necho "systemd-run $*" >> '${LOG}'\nexit 0\n`, { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "systemctl"), `#!/bin/sh\necho "systemctl $*" >> '${LOG}'\necho inactive\nexit 3\n`, { mode: 0o755 });
fs.writeFileSync(HTTPS_BIN, "#!/bin/bash\ncmd_certs() { :; }\n", { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NODE_AGENT_PROXY_ROOT = path.join(TMP, "proxyserver");
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_HTTPS_SYNC_BIN = HTTPS_BIN;
process.env.NETRUN_HTTPS_HOSTNAMES_FILE = HOSTNAMES_FILE;
process.env.NETRUN_HTTPS_TLS_DIR = TLS_DIR;
delete process.env.NODE_AGENT_HTTPS_HOSTNAMES;

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const https = require("https");

// buildDescribe() geolocates via https.get — keep the test offline.
https.get = () => {
  const { EventEmitter } = require("events");
  const req = new EventEmitter();
  req.destroy = () => {};
  process.nextTick(() => req.emit("error", new Error("offline test")));
  return req;
};

const srv = require("./server.js");

function request(method, p, { body, key = "test-key" } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : typeof body === "string" ? body : JSON.stringify(body);
    const headers = { "Content-Type": "application/json" };
    if (key) headers["X-API-KEY"] = key;
    if (data !== null) headers["Content-Length"] = Buffer.byteLength(data);
    const req = http.request({ host: "127.0.0.1", port: srv.server.address().port, method, path: p, headers }, (res) => {
      let text = "";
      res.on("data", (c) => (text += c));
      res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
    });
    req.on("error", reject);
    if (data !== null) req.write(data);
    req.end();
  });
}
const log = () => (fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf-8") : "");
const starts = () => log().split("\n").filter((l) => l.startsWith("systemd-run "));

test.before(() => new Promise((r) => srv.server.listen(0, "127.0.0.1", r)));
test.after(async () => {
  await new Promise((r) => srv.server.close(r));
  fs.rmSync(TMP, { recursive: true, force: true });
});

test("POST /https/hostnames: 401 without the key, 400 on bad JSON / names, 200 written + issuance started", async () => {
  let r = await request("POST", "/https/hostnames", { body: { hostnames: ["us1.proxy.netrun.lol"] }, key: null });
  assert.deepStrictEqual(r, { status: 401, json: { success: false, error: "unauthorized" } });
  r = await request("POST", "/https/hostnames", { body: "{not json" });
  assert.deepStrictEqual([r.status, r.json.error], [400, "invalid_json"]);
  r = await request("POST", "/https/hostnames", { body: { hostnames: ["45.32.10.20"] } });
  assert.deepStrictEqual([r.status, r.json.success, r.json.error], [400, false, "invalid_hostnames"]);
  r = await request("POST", "/https/hostnames", { body: { hostnames: Array.from({ length: 9 }, (_, i) => `n${i}.netrun.lol`) } });
  assert.deepStrictEqual([r.status, r.json.error], [400, "too_many_hostnames"]);
  assert.ok(!fs.existsSync(HOSTNAMES_FILE));

  r = await request("POST", "/https/hostnames", { body: { hostnames: ["US1.proxy.netrun.lol", "us1.proxy.netrun.lol"] } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.deepStrictEqual(r.json, {
    success: true,
    changed: true,
    hostnames: ["us1.proxy.netrun.lol"],
    issuing: true,
    started: true,
    certs: [{ hostname: "us1.proxy.netrun.lol", ok: false, notAfter: null, error: "missing", lastError: null }],
  });
  assert.strictEqual(fs.readFileSync(HOSTNAMES_FILE, "utf-8"), "us1.proxy.netrun.lol\n");
  assert.strictEqual(starts().length, 1);
  assert.match(starts()[0], new RegExp(`--unit netrun-https-certs --collect --quiet .* ${HTTPS_BIN} certs$`));
});

test("GET /https/hostnames + /health httpsHostnames + /describe supports.https_hostnames", { timeout: 30_000 }, async () => {
  let r = await request("GET", "/https/hostnames", { key: null });
  assert.strictEqual(r.status, 401);
  r = await request("GET", "/https/hostnames");
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.success, true);
  assert.strictEqual(r.json.enabled, true);
  assert.strictEqual(r.json.frontendInstalled, true);
  assert.deepStrictEqual(r.json.hostnames, ["us1.proxy.netrun.lol"]);
  assert.strictEqual(r.json.issuing, false, "systemctl says inactive");
  assert.deepStrictEqual(r.json.certs.map((c) => c.error), ["missing"]);
  r = await request("GET", "/health");
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.json.httpsHostnames.hostnames, ["us1.proxy.netrun.lol"]);
  assert.strictEqual(r.json.httpsHostnames.issuing, false);
  assert.strictEqual(r.json.httpsHostnames.certs[0].ok, false);
  for (const key of ["success", "proxyReady", "cfgs", "supervisor", "firewall", "nodeTuning"]) assert.ok(key in r.json, key);
  r = await request("GET", "/describe");
  assert.strictEqual(r.json.supports.https_hostnames, true);
});

test("switch off: POST 404 https_hostnames_disabled, GET enabled:false; missing netrun-https: 409", async () => {
  process.env.NODE_AGENT_HTTPS_HOSTNAMES = "0";
  try {
    let r = await request("POST", "/https/hostnames", { body: { hostnames: [] } });
    assert.deepStrictEqual(r, { status: 404, json: { success: false, error: "https_hostnames_disabled" } });
    r = await request("GET", "/https/hostnames");
    assert.deepStrictEqual([r.status, r.json.enabled], [200, false]);
    r = await request("GET", "/describe");
    assert.strictEqual(r.json.supports.https_hostnames, false);
  } finally {
    delete process.env.NODE_AGENT_HTTPS_HOSTNAMES;
  }
  fs.renameSync(HTTPS_BIN, `${HTTPS_BIN}.away`);
  try {
    const r = await request("POST", "/https/hostnames", { body: { hostnames: [] } });
    assert.deepStrictEqual([r.status, r.json.success, r.json.error], [409, false, "https_frontend_missing"]);
    assert.strictEqual(fs.readFileSync(HOSTNAMES_FILE, "utf-8"), "us1.proxy.netrun.lol\n", "nothing written");
  } finally {
    fs.renameSync(`${HTTPS_BIN}.away`, HTTPS_BIN);
  }
  // other methods on the path fall through to the 404
  const r = await request("DELETE", "/https/hostnames");
  assert.deepStrictEqual([r.status, r.json.error], [404, "not_found"]);
});
