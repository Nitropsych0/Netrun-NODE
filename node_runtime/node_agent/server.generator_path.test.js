"use strict";

// Audit S-NODE-2 — /generate used to run ANY generatorScript from the request
// body (absolute paths allowed, cwd from the body) as root. Now the script must
// resolve (realpath) under NODE_AGENT_GENERATOR_ROOT, an empty request runs
// NODE_AGENT_GENERATOR_SCRIPT, and the request's cwd is ignored. Fake
// generators exit 3 (generator_exit_3 proves which one ran); `ss` is a PATH stub.
// Run with: node --test node_runtime/node_agent/server.generator_path.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-genpath-"));
const OUTSIDE = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-genpath-outside-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const JOBS_ROOT = path.join(TMP, "jobs");
const BIN = path.join(TMP, "bin");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
const DEFAULT_GEN = path.join(TMP, "default_gen.sh");
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NODE_AGENT_JOBS_ROOT = JOBS_ROOT;
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.NODE_AGENT_GENERATOR_ROOT = TMP;
process.env.NODE_AGENT_GENERATOR_SCRIPT = DEFAULT_GEN;
process.env.PATH = `${BIN}:${process.env.PATH}`;
fs.writeFileSync(path.join(BIN, "ss"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });

const fake = (extra = "") =>
  ["#!/bin/bash", "# --random --skip-self-check flags are probed by text: --random --skip-self-check --proxies-type", extra, "exit 3", ""].join("\n");
fs.writeFileSync(DEFAULT_GEN, fake('echo default > "$JOB_DIR/seen_script"'), { mode: 0o755 });
const OTHER_GEN = path.join(TMP, "other_gen.sh");
fs.writeFileSync(OTHER_GEN, fake('echo other > "$JOB_DIR/seen_script"'), { mode: 0o755 });
const CWD_GEN = path.join(TMP, "cwd_gen.sh");
fs.writeFileSync(CWD_GEN, fake('pwd -P > "$JOB_DIR/seen_cwd"'), { mode: 0o755 });
const EVIL_GEN = path.join(OUTSIDE, "evil_gen.sh");
fs.writeFileSync(EVIL_GEN, fake(`touch "${path.join(OUTSIDE, "pwned")}"`), { mode: 0o755 });
const LINK_GEN = path.join(TMP, "link_to_outside.sh");
fs.symlinkSync(EVIL_GEN, LINK_GEN);
const SUBDIR = path.join(TMP, "a_directory");
fs.mkdirSync(SUBDIR);

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const srv = require("./server.js");

async function settled() {
  const lock = path.join(JOBS_ROOT, ".generation.lock");
  for (let i = 0; i < 200 && fs.existsSync(lock); i += 1) await new Promise((r) => setTimeout(r, 10));
}

async function post(port, body) {
  await settled();
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      { host: "127.0.0.1", port, path: "/generate", method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data), "X-API-KEY": "test-key" } },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
      }
    );
    req.on("error", reject);
    req.end(data);
  });
}

function genBody(jobId, startPort, extra = {}) {
  return {
    jobId,
    startPort,
    proxyCount: 2,
    proxiesType: "dual",
    networkProfile: "high_compatibility",
    fingerprintProfileVersion: "v2_android_ipv6_only_dns_custom",
    intendedClientOsProfile: "android_mobile",
    clientOsProfileEnforcement: "not_controlled_by_proxy",
    timeoutSec: 30,
    ...extra,
  };
}

let PORT = 0;
test.before(async () => {
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  PORT = srv.server.address().port;
});
test.after(async () => {
  await new Promise((r) => srv.server.close(r));
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.rmSync(OUTSIDE, { recursive: true, force: true });
});

test("resolveGeneratorScript: default, relative, outside the root, symlink out, directory, missing, valid", async () => {
  assert.strictEqual(srv.GENERATOR_ROOT, TMP);
  assert.strictEqual(srv.GENERATOR_SCRIPT, DEFAULT_GEN);
  const real = fs.realpathSync(DEFAULT_GEN);
  assert.deepStrictEqual(await srv.resolveGeneratorScript(""), { ok: true, scriptPath: real });
  assert.deepStrictEqual(await srv.resolveGeneratorScript(undefined), { ok: true, scriptPath: real });
  assert.deepStrictEqual(await srv.resolveGeneratorScript("   "), { ok: true, scriptPath: real }, "blank = the default");
  const rel = await srv.resolveGeneratorScript("default_gen.sh");
  assert.strictEqual(rel.error, "generator_script_not_allowed");
  assert.strictEqual(rel.detail, "relative_path");
  assert.strictEqual((await srv.resolveGeneratorScript("../../etc/passwd")).error, "generator_script_not_allowed");
  const outside = await srv.resolveGeneratorScript(EVIL_GEN);
  assert.strictEqual(outside.error, "generator_script_not_allowed");
  assert.strictEqual(outside.detail, "outside_generator_root");
  assert.strictEqual((await srv.resolveGeneratorScript(LINK_GEN)).error, "generator_script_not_allowed", "a symlink inside the root pointing outside");
  assert.strictEqual((await srv.resolveGeneratorScript(path.join(TMP, "..", path.basename(OUTSIDE), "evil_gen.sh"))).error, "generator_script_not_allowed", "dot-dot out of the root");
  assert.strictEqual((await srv.resolveGeneratorScript(SUBDIR)).error, "generator_script_not_found", "a directory");
  assert.strictEqual((await srv.resolveGeneratorScript(path.join(TMP, "missing.sh"))).error, "generator_script_not_found");
  assert.deepStrictEqual(await srv.resolveGeneratorScript(OTHER_GEN), { ok: true, scriptPath: fs.realpathSync(OTHER_GEN) });
  assert.strictEqual((await srv.resolveGeneratorScript("/etc/passwd")).error, "generator_script_not_allowed");
});

test("POST /generate with an out-of-root generatorScript -> 400 generator_script_not_allowed, nothing created, nothing run", async () => {
  for (const [jobId, gs] of [["gp-outside", EVIL_GEN], ["gp-symlink", LINK_GEN], ["gp-relative", "evil_gen.sh"], ["gp-etc", "/bin/sh"]]) {
    const r = await post(PORT, genBody(jobId, 41100, { generatorScript: gs }));
    assert.strictEqual(r.status, 400, jobId);
    assert.strictEqual(r.json.error, "generator_script_not_allowed", jobId);
    assert.strictEqual(r.json.allowedRoot, TMP);
    assert.ok(!fs.existsSync(path.join(JOBS_ROOT, jobId)), `${jobId}: no job dir created`);
    assert.ok(!fs.existsSync(path.join(JOBS_ROOT, ".generation.lock")), `${jobId}: no generation lock left`);
  }
  assert.ok(!fs.existsSync(path.join(OUTSIDE, "pwned")), "the out-of-root generator never ran");
  const nf = await post(PORT, genBody("gp-missing", 41100, { generatorScript: path.join(TMP, "nope.sh") }));
  assert.strictEqual(nf.status, 400);
  assert.strictEqual(nf.json.error, "generator_script_not_found");
  const dir = await post(PORT, genBody("gp-dir", 41100, { generatorScript: SUBDIR }));
  assert.strictEqual(dir.json.error, "generator_script_not_found");
});

test("POST /generate: cwd from the body is ignored (and recorded in job.json)", async () => {
  const r = await post(PORT, genBody("gp-cwd", 41200, { generatorScript: CWD_GEN, cwd: "/etc" }));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.error, "generator_exit_3");
  const dir = path.join(JOBS_ROOT, "gp-cwd");
  assert.strictEqual(fs.readFileSync(path.join(dir, "seen_cwd"), "utf-8").trim(), fs.realpathSync(process.cwd()), "the generator ran in the agent's own cwd");
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "job.json"), "utf-8"));
  assert.strictEqual(meta.request.providedCwd, "/etc");
  assert.strictEqual(meta.generator.cwd, process.cwd());
  assert.strictEqual(meta.request.providedGeneratorScript, CWD_GEN);
});

test("POST /generate without generatorScript runs the configured default; naming it explicitly is the same", async () => {
  const a = await post(PORT, genBody("gp-default", 41300));
  assert.strictEqual(a.status, 200);
  assert.strictEqual(a.json.error, "generator_exit_3", "past the guards, into the default generator");
  assert.strictEqual(fs.readFileSync(path.join(JOBS_ROOT, "gp-default", "seen_script"), "utf-8").trim(), "default");
  const b = await post(PORT, genBody("gp-explicit", 41400, { generatorScript: DEFAULT_GEN }));
  assert.strictEqual(b.json.error, "generator_exit_3");
  assert.strictEqual(fs.readFileSync(path.join(JOBS_ROOT, "gp-explicit", "seen_script"), "utf-8").trim(), "default");
  const c = await post(PORT, genBody("gp-other", 41500, { generatorScript: OTHER_GEN }));
  assert.strictEqual(fs.readFileSync(path.join(JOBS_ROOT, "gp-other", "seen_script"), "utf-8").trim(), "other");
});
