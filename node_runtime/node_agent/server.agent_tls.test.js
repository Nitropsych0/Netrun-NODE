"use strict";

// Audit S-ORCH-1 — the agent's whole API over the TLS listener :8086: the same
// request handler as the plain :8085 listener (handleAgentRequest), the same
// X-API-KEY auth per route. Skipped without openssl (self-signed IP cert).
// Run with: node --test node_runtime/node_agent/server.agent_tls.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-agent-tls-"));
process.env.NODE_AGENT_PROXY_ROOT = path.join(TMP, "proxyserver");
process.env.NODE_AGENT_JOBS_ROOT = path.join(TMP, "jobs");
process.env.NODE_AGENT_API_KEY = "tls-key";
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
fs.mkdirSync(process.env.NODE_AGENT_PROXY_ROOT, { recursive: true });
fs.mkdirSync(process.env.NODE_AGENT_JOBS_ROOT, { recursive: true });

const test = require("node:test");
const assert = require("node:assert");
const https = require("https");
const tlsLib = require("./pergb_tls_server.js");
const srv = require("./server.js");

const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
const QUIET = { log() {}, error() {} };
const KEY = "tls-key";

function certPair(dir) {
  const crt = path.join(dir, "t.crt");
  const key = path.join(dir, "t.key");
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=t", "-addext", "subjectAltName=IP:127.0.0.1"], { encoding: "utf-8" });
  if (r.status !== 0) throw new Error(r.stderr);
  return { crt, key };
}

function get(port, p, key) {
  return new Promise((resolve, reject) => {
    const headers = key ? { "X-API-KEY": key } : {};
    const req = https.request({ host: "127.0.0.1", port, path: p, method: "GET", rejectUnauthorized: false, headers }, (res) => {
      let text = "";
      res.on("data", (c) => (text += c));
      res.on("end", () => resolve({ status: res.statusCode, json: text ? JSON.parse(text) : null }));
    });
    req.on("error", reject);
    req.end();
  });
}

let tls = null;
test.before(async () => {
  if (!haveOpenssl) return;
  const c = certPair(TMP);
  tls = tlsLib.createTlsServer({
    pergb: srv.pergb,
    vpn: null,
    apiKeyMatches: (given) => srv.apiKeyMatches(given),
    agentHandler: srv.handleAgentRequest,
    log: QUIET,
    run: async () => ({ code: 1, stdout: "", stderr: "no nft" }), // an unguarded node: the firewall gate is "absent"
    env: {},
    settings: { port: 0, host: "127.0.0.1", certPath: c.crt, keyPath: c.key, enabled: true },
  });
  const st = await tls.tick();
  assert.strictEqual(st.listening, true, JSON.stringify(st));
});
test.after(async () => {
  if (tls) await tls.stop();
  fs.rmSync(TMP, { recursive: true, force: true });
});

test("the real agent's own listener is built with the agent handler (routes: full)", () => {
  assert.strictEqual(srv.pergbServer.status().routes, "full");
});

test("/health over TLS: keyless {ok:true}, with the key the full payload", { skip: !haveOpenssl && "openssl is needed" }, async () => {
  let r = await get(tls.port, "/health");
  assert.deepStrictEqual(r.json, { ok: true });
  r = await get(tls.port, "/health", KEY);
  assert.strictEqual(r.status, 200);
  assert.ok(r.json.pergb && r.json.pergb.tls, "the full payload carries pergb.tls");
});

test("/describe over TLS: 401 without the key, 200 with supports.agent_tls", { skip: !haveOpenssl && "openssl is needed" }, async () => {
  let r = await get(tls.port, "/describe");
  assert.strictEqual(r.status, 401);
  r = await get(tls.port, "/describe", "wrong");
  assert.strictEqual(r.status, 401);
  r = await get(tls.port, "/describe", KEY);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.supports.agent_tls, 1);
  assert.ok(Number(r.json.supports.agent_tls_port) > 0);
});

test("other agent routes answer over TLS exactly as over plain HTTP", { skip: !haveOpenssl && "openssl is needed" }, async () => {
  let r = await get(tls.port, "/jobs", KEY);
  assert.strictEqual(r.status, 200);
  r = await get(tls.port, "/jobs");
  assert.strictEqual(r.status, 401);
  r = await get(tls.port, "/no/such/route", KEY);
  assert.strictEqual(r.status, 404);
  assert.strictEqual(r.json.error, "not_found");
  // /firewall/desired is a keyed route too
  r = await get(tls.port, "/firewall/desired");
  assert.strictEqual(r.status, 401);
});

test("NODE_AGENT_ALLOW_PLAIN_HTTP: default true keeps NODE_AGENT_HOST, false pins :8085 to loopback", () => {
  assert.strictEqual(srv.allowPlainHttp({}), true);
  assert.strictEqual(srv.allowPlainHttp({ NODE_AGENT_ALLOW_PLAIN_HTTP: "true" }), true);
  assert.strictEqual(srv.allowPlainHttp({ NODE_AGENT_ALLOW_PLAIN_HTTP: "false" }), false);
  assert.strictEqual(srv.allowPlainHttp({ NODE_AGENT_ALLOW_PLAIN_HTTP: "0" }), false);
  assert.strictEqual(srv.plainListenHost({}), srv.LISTEN_HOST);
  assert.strictEqual(srv.plainListenHost({ NODE_AGENT_ALLOW_PLAIN_HTTP: "false" }), "127.0.0.1");
  assert.strictEqual(srv.plainListenHost({ NODE_AGENT_ALLOW_PLAIN_HTTP: "no", NODE_AGENT_HOST: "::" }), "127.0.0.1");
});
