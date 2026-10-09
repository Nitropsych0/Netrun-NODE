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
