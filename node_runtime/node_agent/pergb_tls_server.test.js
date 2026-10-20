"use strict";

// Pay-per-GB v2 — the :8086 listener opens only where per-GB is installed and
// never while the agent firewall exists without 8086 (deploying the agent
// fleet-wide must not add an internet-facing port to guarded nodes).

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const tlsLib = require("./pergb_tls_server.js");

const QUIET = { log() {}, error() {} };
const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;

function certPair(dir) {
  const crt = path.join(dir, "t.crt");
  const key = path.join(dir, "t.key");
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=t", "-addext", "subjectAltName=IP:127.0.0.1"], { encoding: "utf-8" });
  if (r.status !== 0) throw new Error(r.stderr);
  return { crt, key };
}

const GUARD_8085 = "table inet netrun_agent_guard {\n chain input {\n  iifname \"lo\" accept\n  tcp dport 8085 ip saddr 198.51.100.1 accept\n  tcp dport 8085 drop\n }\n}\n";
const GUARD_BOTH = "table inet netrun_agent_guard {\n chain input {\n  iifname \"lo\" accept\n  tcp dport { 8085, 8086 } ip saddr 198.51.100.1 accept\n  tcp dport { 8085, 8086 } drop\n }\n}\n";

test("agentGuardState: covered / absent / missing_8086", () => {
  assert.strictEqual(tlsLib.agentGuardState(GUARD_BOTH, 0), "covered");
  assert.strictEqual(tlsLib.agentGuardState(GUARD_8085, 0), "missing_8086");
  assert.strictEqual(tlsLib.agentGuardState("", 1), "absent");
});

test("the listener gate: not installed, a guard without 8086, then open", { skip: !haveOpenssl && "openssl is needed" }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pergb-tls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const c = certPair(dir);
  const etc = path.join(dir, "etc-netrun-pergb");
  let guard = { code: 0, stdout: GUARD_8085, stderr: "" };
  const run = async (cmd, args) => {
    assert.deepStrictEqual([cmd, ...args], ["nft", "list", "table", "inet", "netrun_agent_guard"]);
    return guard;
  };
  const srv = tlsLib.createTlsServer({
    pergb: {},
    apiKeyMatches: () => false,
    log: QUIET,
    run,
    settings: { port: 0, host: "127.0.0.1", certPath: c.crt, keyPath: c.key, enabled: true, installedDir: etc },
  });
  t.after(() => srv.stop());
  let st = await srv.tick();
  assert.strictEqual(st.listening, false);
  assert.strictEqual(st.gate.reason, "pergb_not_installed");
  fs.mkdirSync(etc);
  st = await srv.tick();
  assert.strictEqual(st.listening, false);
  assert.strictEqual(st.gate.reason, "agent_firewall_without_8086");
  guard = { code: 0, stdout: GUARD_BOTH, stderr: "" };
  st = await srv.tick();
  assert.strictEqual(st.listening, true, JSON.stringify(st));
  assert.strictEqual(st.gate.firewall, "covered");
  await srv.stop();
  // an unguarded node (no table): the listener opens like 8085 is open
  guard = { code: 1, stdout: "", stderr: "No such file or directory" };
  const srv2 = tlsLib.createTlsServer({
    pergb: {},
    apiKeyMatches: () => false,
    log: QUIET,
    run,
    settings: { port: 0, host: "127.0.0.1", certPath: c.crt, keyPath: c.key, enabled: true, installedDir: etc },
  });
  t.after(() => srv2.stop());
  st = await srv2.tick();
  assert.strictEqual(st.listening, true);
  assert.strictEqual(st.gate.firewall, "absent");
});

// ---- Audit S-ORCH-1 — the listener serves the whole agent API -------------

function httpsRequest(port, method, p, { headers = {}, body = null } = {}) {
  const https = require("https");
  return new Promise((resolve, reject) => {
    const req = https.request({ host: "127.0.0.1", port, path: p, method, rejectUnauthorized: false, headers }, (res) => {
      let text = "";
      res.on("data", (c) => (text += c));
      res.on("end", () => resolve({ status: res.statusCode, text }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

test("with an agentHandler the listener opens without /etc/netrun-pergb; a guard without 8086 still keeps it closed", { skip: !haveOpenssl && "openssl is needed" }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pergb-tls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const c = certPair(dir);
  let guard = { code: 0, stdout: GUARD_8085, stderr: "" };
  const run = async () => guard;
  const mk = (extra = {}) =>
    tlsLib.createTlsServer({
      pergb: {},
      apiKeyMatches: () => false,
      agentHandler: (req, res) => res.end("agent"),
      log: QUIET,
      run,
      env: {}, // no NETRUN_* overrides: the defaults decide
      settings: { port: 0, host: "127.0.0.1", certPath: c.crt, keyPath: c.key, enabled: true, installedDir: path.join(dir, "absent"), vpnInstalledDir: path.join(dir, "absent-vpn"), ...extra },
    });
  const srv = mk();
  t.after(() => srv.stop());
  let st = await srv.tick();
  assert.strictEqual(st.listening, false);
  assert.strictEqual(st.gate.reason, "agent_firewall_without_8086");
  guard = { code: 0, stdout: GUARD_BOTH, stderr: "" };
  st = await srv.tick();
  assert.strictEqual(st.listening, true, JSON.stringify(st));
  assert.strictEqual(st.routes, "full");
  // NETRUN_AGENT_TLS_REQUIRE_PERGB=1 brings the per-GB-only gate back
  const strict = tlsLib.readSettings({ NETRUN_AGENT_TLS_REQUIRE_PERGB: "1" }, { agentHandler: () => {} });
  assert.strictEqual(strict.requireInstalled, true);
  assert.strictEqual(tlsLib.readSettings({}, { agentHandler: () => {} }).requireInstalled, false);
  assert.strictEqual(tlsLib.readSettings({}, {}).requireInstalled, true, "a listener without agentHandler keeps the per-GB gate");
  assert.strictEqual(tlsLib.createTlsServer({ pergb: {}, apiKeyMatches: () => false, log: QUIET, run, settings: { port: 0 } }).status().routes, "pergb_only");
});

test("a non-/pergb path reaches agentHandler with the body unread; /pergb/* and /vpn/* stay local", { skip: !haveOpenssl && "openssl is needed" }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pergb-tls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const c = certPair(dir);
  const seen = [];
  const agentHandler = async (req, res) => {
    const chunks = [];
    for await (const ch of req) chunks.push(ch);
    const raw = Buffer.concat(chunks).toString("utf-8");
    seen.push({ method: req.method, url: req.url, bytes: raw.length, key: req.headers["x-api-key"] });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ via: "agent", bytes: raw.length, parsedOk: raw ? Boolean(JSON.parse(raw).pad) : null }));
  };
  const pergbCalls = [];
  const srv = tlsLib.createTlsServer({
    pergb: { status: async () => ({ pergb: "local" }), enable: async (b) => { pergbCalls.push(b); return { status: 200, body: { enabled: true } }; } },
    apiKeyMatches: (given) => given === "k",
    agentHandler,
    log: QUIET,
    run: async () => ({ code: 1, stdout: "", stderr: "" }),
    env: {},
    settings: { port: 0, host: "127.0.0.1", certPath: c.crt, keyPath: c.key, enabled: true },
  });
  t.after(() => srv.stop());
  const st = await srv.tick();
  assert.strictEqual(st.listening, true, JSON.stringify(st));
  assert.strictEqual(st.routes, "full");
  const port = srv.port;
  // 100 KB JSON body to an agent route arrives intact (the listener did not consume it)
  const big = JSON.stringify({ pad: "x".repeat(100 * 1024) });
  let r = await httpsRequest(port, "POST", "/generate", { headers: { "X-API-KEY": "k", "Content-Type": "application/json", "Content-Length": Buffer.byteLength(big) }, body: big });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(JSON.parse(r.text), { via: "agent", bytes: big.length, parsedOk: true });
  assert.strictEqual(seen[0].url, "/generate");
  // a keyless /health goes to the agent handler too (it answers {ok:true} keyless itself)
  r = await httpsRequest(port, "GET", "/health");
  assert.strictEqual(JSON.parse(r.text).via, "agent");
  // /pergb/* is handled by the listener: its own key check, then the local handler
  r = await httpsRequest(port, "GET", "/pergb/status");
  assert.strictEqual(r.status, 401);
  r = await httpsRequest(port, "GET", "/pergb/status", { headers: { "X-API-KEY": "k" } });
  assert.deepStrictEqual(JSON.parse(r.text), { pergb: "local" });
  r = await httpsRequest(port, "POST", "/pergb/enable", { headers: { "X-API-KEY": "k", "Content-Type": "application/json" }, body: JSON.stringify({ a: 1 }) });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(pergbCalls, [{ a: 1 }]);
  // /vpn/* never goes to the agent handler (no vpn dep here -> the listener's own 404)
  const before = seen.length;
  r = await httpsRequest(port, "GET", "/vpn/status", { headers: { "X-API-KEY": "k" } });
  assert.strictEqual(r.status, 404);
  assert.strictEqual(seen.length, before + 0, "agentHandler was not called for /vpn/*");
  // /pergbx is not /pergb: it is an agent path
  r = await httpsRequest(port, "GET", "/pergbx");
  assert.strictEqual(JSON.parse(r.text).via, "agent");
});
