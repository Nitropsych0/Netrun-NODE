"use strict";

// Wave FLEET-HEALTH (FO-06) — /generate with explicit per-port credentials
// (clone support): validation (400 invalid_credentials), the conflict guard
// (409 credentials_conflict), the atomic 0600 random_users_<start>.list the
// generator then reuses, freshAddresses, and "no credentials = exactly as
// before". A fake generator records what it saw at spawn time and exits 3;
// `ss` is a PATH stub; cron cleanup is off (it would edit the real crontab).
// Run with: node --test node_runtime/node_agent/server.credentials.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-creds-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const JOBS_ROOT = path.join(TMP, "jobs");
const BIN = path.join(TMP, "bin");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_GENERATOR_ROOT = TMP; // audit S-NODE-2: /generate runs generators only from under this root
process.env.NODE_AGENT_API_KEY = "test-key"; // audit 2026-10-08: the agent fails closed without a key
process.env.NODE_AGENT_JOBS_ROOT = JOBS_ROOT;
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.PATH = `${BIN}:${process.env.PATH}`;
fs.writeFileSync(path.join(BIN, "ss"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });

const FAKE_GEN = path.join(TMP, "fake_generator.sh");
fs.writeFileSync(
  FAKE_GEN,
  [
    "#!/bin/bash",
    "# --random --skip-self-check flags are probed by text: --random --skip-self-check --proxies-type",
    'u="$NODE_AGENT_PROXY_ROOT/random_users_${START_PORT}.list"',
    'if [ -f "$u" ]; then cp "$u" "$JOB_DIR/seen_users.list"; stat -c %a "$u" > "$JOB_DIR/seen_mode" 2>/dev/null || stat -f %Lp "$u" > "$JOB_DIR/seen_mode"; fi',
    'if [ -f "$NODE_AGENT_PROXY_ROOT/ipv6_${START_PORT}.list" ]; then touch "$JOB_DIR/seen_ipv6"; fi',
    'echo "$@" > "$JOB_DIR/seen_args"',
    "exit 3",
    "",
  ].join("\n"),
  { mode: 0o755 }
);

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const srv = require("./server.js");

const USERS = (p) => path.join(PROXY_ROOT, `random_users_${p}.list`);
const IPV6 = (p) => path.join(PROXY_ROOT, `ipv6_${p}.list`);

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

// The agent answers first and releases the generation lock (after its
// cleanup) in a finally block right behind the response.
async function settled() {
  const lock = path.join(JOBS_ROOT, ".generation.lock");
  for (let i = 0; i < 200 && fs.existsSync(lock); i += 1) await new Promise((r) => setTimeout(r, 10));
}

function genBody(jobId, startPort, extra = {}) {
  return {
    jobId,
    generatorScript: FAKE_GEN,
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
});

test("parseCredentialsField: strings and pairs, count / charset / duplicate checks", () => {
  assert.deepStrictEqual(srv.parseCredentialsField(undefined, 2), { ok: true, provided: false, lines: null });
  assert.deepStrictEqual(srv.parseCredentialsField(["a1:b1", ["a2", "b2"]], 2), { ok: true, provided: true, lines: ["a1:b1", "a2:b2"] });
  const bad = (raw, n = 2) => srv.parseCredentialsField(raw, n);
  assert.strictEqual(bad(["a1:b1"]).error, "invalid_credentials", "length mismatch");
  assert.strictEqual(bad("a1:b1,a2:b2").error, "invalid_credentials", "not an array");
  assert.strictEqual(bad(["a1:b1", "a2:b:2"]).error, "invalid_credentials", "extra colon");
  assert.strictEqual(bad(["a1:b1", "a-2:b2"]).error, "invalid_credentials", "charset");
  assert.strictEqual(bad(["a1:b1", `${"x".repeat(33)}:b2`]).error, "invalid_credentials", "33 chars");
  assert.strictEqual(bad(["a1:b1", "a1:b2"]).error, "invalid_credentials", "duplicate login");
  assert.strictEqual(bad(["a1:b1", ["a2"]]).error, "invalid_credentials", "short pair");
  assert.strictEqual(bad(["a1:", "a2:b2"]).error, "invalid_credentials", "empty password");
});

test("writeCredentialsFile: exact content, mode 0600, state same/different/absent", async () => {
  const f = path.join(TMP, "w", "random_users_1.list");
  assert.strictEqual(await srv.credentialsFileState(f, ["a:b"]), "absent");
  await srv.writeCredentialsFile(f, ["Login1:Pass1", "Login2:Pass2"]);
  assert.strictEqual(fs.readFileSync(f, "utf-8"), "Login1:Pass1\nLogin2:Pass2\n");
  assert.strictEqual(fs.statSync(f).mode & 0o777, 0o600);
  assert.deepStrictEqual(fs.readdirSync(path.dirname(f)), ["random_users_1.list"], "no tmp file left");
  assert.strictEqual(await srv.credentialsFileState(f, ["Login1:Pass1", "Login2:Pass2"]), "same");
  assert.strictEqual(await srv.credentialsFileState(f, ["Login1:Pass1", "Login2:Other"]), "different");
  assert.strictEqual(await srv.credentialsFileState(f, ["Login1:Pass1"]), "different");
});

test("POST /generate: credentials length mismatch -> 400 invalid_credentials, nothing written", async () => {
  const r = await post(PORT, genBody("creds-400", 18100, { credentials: ["only1:one"] }));
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.json.error, "invalid_credentials");
  assert.ok(!fs.existsSync(USERS(18100)));
  assert.ok(!fs.existsSync(path.join(JOBS_ROOT, "creds-400")), "rejected before any job state");
});

test("POST /generate: an existing credentials file with OTHER content -> 409 credentials_conflict", async () => {
  fs.writeFileSync(USERS(19600), "old1:old1\nold2:old2\n");
  const r = await post(PORT, genBody("creds-409", 19600, { credentials: ["new1:new1", "new2:new2"] }));
  assert.strictEqual(r.status, 409);
  assert.strictEqual(r.json.error, "credentials_conflict");
  assert.strictEqual(fs.readFileSync(USERS(19600), "utf-8"), "old1:old1\nold2:old2\n", "existing file untouched");
  assert.ok(!fs.existsSync(path.join(JOBS_ROOT, "creds-409", "seen_args")), "generator never ran");
  const meta = JSON.parse(fs.readFileSync(path.join(JOBS_ROOT, "creds-409", "job.json"), "utf-8"));
  assert.strictEqual(meta.status, "failed");
  assert.strictEqual(meta.request.credentialsCount, 2);
  assert.ok(!JSON.stringify(meta).includes("new1"), "credentials never stored in job metadata");
});

test("POST /generate with credentials: the generator sees the exact 0600 file; freshAddresses drops the ipv6 list", async () => {
  fs.writeFileSync(IPV6(21100), "2001:db8::1\n2001:db8::2\n");
  const r = await post(PORT, genBody("creds-ok", 21100, { credentials: [["Aa1", "Bb1"], "Aa2:Bb2"], freshAddresses: true }));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.error, "generator_exit_3", "past every guard, into the generator");
  const dir = path.join(JOBS_ROOT, "creds-ok");
  assert.strictEqual(fs.readFileSync(path.join(dir, "seen_users.list"), "utf-8"), "Aa1:Bb1\nAa2:Bb2\n");
  assert.strictEqual(fs.readFileSync(path.join(dir, "seen_mode"), "utf-8").trim(), "600");
  assert.ok(!fs.existsSync(path.join(dir, "seen_ipv6")), "stale ipv6 list removed before spawn");
  assert.ok(fs.readFileSync(path.join(dir, "seen_args"), "utf-8").includes("--random true"), "agent still forces --random");
  // The job failed before any cfg existed: the file this request created is
  // removed again, so a retry with other credentials is not wedged on a 409.
  await settled();
  assert.ok(!fs.existsSync(USERS(21100)));
});

test("POST /generate with credentials equal to an existing file: accepted (idempotent retry)", async () => {
  fs.writeFileSync(USERS(23100), "Aa1:Bb1\nAa2:Bb2");
  const r = await post(PORT, genBody("creds-same", 23100, { credentials: ["Aa1:Bb1", "Aa2:Bb2"] }));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.error, "generator_exit_3");
  await settled();
  assert.ok(fs.existsSync(USERS(23100)), "a file this request did not create is never removed");
});

test("POST /generate without credentials: exactly as before (no file written, ipv6 list kept)", async () => {
  fs.writeFileSync(IPV6(25100), "2001:db8::1\n2001:db8::2\n");
  const r = await post(PORT, genBody("creds-none", 25100));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.success, false);
  assert.strictEqual(r.json.error, "generator_exit_3");
  const dir = path.join(JOBS_ROOT, "creds-none");
  assert.ok(!fs.existsSync(path.join(dir, "seen_users.list")), "no credentials file handed to the generator");
  assert.ok(fs.existsSync(path.join(dir, "seen_ipv6")), "ipv6 list reused as today");
  await settled();
  assert.ok(!fs.existsSync(USERS(25100)));
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "job.json"), "utf-8"));
  assert.strictEqual(meta.request.credentialsCount, null);
  assert.strictEqual(meta.request.freshAddresses, false);
  assert.strictEqual(meta.request.reclaimStartPorts, null);
});

test("POST /generate: malformed reclaimStartPorts -> 400", async () => {
  const r = await post(PORT, genBody("reclaim-400", 27100, { reclaimStartPorts: "18100" }));
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.json.error, "invalid_reclaim_start_ports");
});

test("reusedItemsMatchCredentials compares socks items in port order", () => {
  const items = [
    { protocol: "socks5", port: 18100, login: "a", password: "b" },
    { protocol: "http", port: 8100, login: "a", password: "b" },
    { protocol: "socks5", port: 18101, login: "c", password: "d" },
  ];
  assert.strictEqual(srv.reusedItemsMatchCredentials(items, 18100, ["a:b", "c:d"]), true);
  assert.strictEqual(srv.reusedItemsMatchCredentials(items, 18100, ["a:b", "c:x"]), false);
});

// ---- Audit L-U2 — stale per-start-port lists ------------------------------

const jobMetaOf = (jobId) => JSON.parse(fs.readFileSync(path.join(JOBS_ROOT, jobId, "job.json"), "utf-8"));

test("POST /generate without credentials drops the stale lists of a batch no 3proxy serves", async () => {
  fs.writeFileSync(USERS(29100), "old1:old1\n"); // proxyCount is 2
  fs.writeFileSync(IPV6(29100), "2001:db8::1\n2001:db8::2\n2001:db8::3\n");
  const r = await post(PORT, genBody("stale-drop", 29100));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.error, "generator_exit_3");
  const dir = path.join(JOBS_ROOT, "stale-drop");
  assert.ok(!fs.existsSync(path.join(dir, "seen_users.list")), "the generator saw no stale credentials");
  assert.ok(!fs.existsSync(path.join(dir, "seen_ipv6")), "the generator saw no wrong-length address list");
  assert.deepStrictEqual(jobMetaOf("stale-drop").result.staleLists, { credentials: "dropped", credentialsLines: 1, ipv6: "dropped", ipv6Lines: 3 });
  await settled();
  assert.ok(!fs.existsSync(USERS(29100)) && !fs.existsSync(IPV6(29100)));
  assert.deepStrictEqual(fs.readdirSync(PROXY_ROOT).filter((n) => n.includes(".tmp")), [], "no .tmp files under PROXY_ROOT");
});

test("a same-count credentials file is also dropped when no instance serves the start port (no explicit credentials)", async () => {
  fs.writeFileSync(USERS(31100), "Aa1:Bb1\nAa2:Bb2\n");
  const r = await post(PORT, genBody("stale-same-count", 31100));
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.error, "generator_exit_3");
  const dir = path.join(JOBS_ROOT, "stale-same-count");
  assert.ok(!fs.existsSync(path.join(dir, "seen_users.list")), "a leftover list of a released batch is never handed on");
  assert.strictEqual(jobMetaOf("stale-same-count").result.staleLists.credentials, "dropped");
  assert.strictEqual(jobMetaOf("stale-same-count").result.staleLists.credentialsLines, 2);
  // ...but the explicit-credentials retry with the SAME content keeps the file (the creds-same test above)
  fs.writeFileSync(USERS(31200), "Aa1:Bb1\nAa2:Bb2\n");
  const r2 = await post(PORT, genBody("stale-same-explicit", 31200, { credentials: ["Aa1:Bb1", "Aa2:Bb2"] }));
  assert.strictEqual(r2.json.error, "generator_exit_3");
  assert.strictEqual(fs.readFileSync(path.join(JOBS_ROOT, "stale-same-explicit", "seen_users.list"), "utf-8"), "Aa1:Bb1\nAa2:Bb2\n");
  assert.strictEqual(jobMetaOf("stale-same-explicit").result.staleLists.credentials, "kept");
});

test("an ipv6 list with exactly proxyCount lines is kept (a retry keeps its addresses)", async () => {
  fs.writeFileSync(IPV6(33100), "2001:db8::1\n2001:db8::2\n");
  const r = await post(PORT, genBody("stale-ipv6-kept", 33100));
  assert.strictEqual(r.json.error, "generator_exit_3");
  assert.ok(fs.existsSync(path.join(JOBS_ROOT, "stale-ipv6-kept", "seen_ipv6")), "the generator saw the list");
  assert.strictEqual(jobMetaOf("stale-ipv6-kept").result.staleLists.ipv6, "kept");
  assert.strictEqual(jobMetaOf("stale-ipv6-kept").result.staleLists.ipv6Lines, 2);
});

test("parkFailedAttempt removes the credentials list of a parked attempt", async () => {
  fs.writeFileSync(path.join(BIN, "pgrep"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
  const cfg = path.join(PROXY_ROOT, "3proxy", "3proxy_35100.cfg");
  fs.writeFileSync(cfg, "daemon\n");
  fs.writeFileSync(USERS(35100), "Aa1:Bb1\nAa2:Bb2\n");
  fs.writeFileSync(IPV6(35100), "2001:db8::1\n2001:db8::2\n");
  const prev = process.env.NODE_AGENT_PARK_FAILED_ATTEMPTS;
  process.env.NODE_AGENT_PARK_FAILED_ATTEMPTS = "1";
  try {
    const out = await srv.parkFailedAttempt(35100, Date.now() - 1000);
    assert.strictEqual(out.parked, true, JSON.stringify(out));
  } finally {
    if (prev === undefined) delete process.env.NODE_AGENT_PARK_FAILED_ATTEMPTS;
    else process.env.NODE_AGENT_PARK_FAILED_ATTEMPTS = prev;
  }
  assert.ok(fs.existsSync(`${cfg}.failed`), "the cfg is parked");
  assert.ok(!fs.existsSync(USERS(35100)), "the credentials list is gone");
  assert.ok(!fs.existsSync(IPV6(35100)), "the address list is gone");
});

test("dropStaleBatchLists: absent / kept / dropped with the line counts", async () => {
  assert.deepStrictEqual(await srv.dropStaleBatchLists({ startPort: 37100, proxyCount: 2 }), { credentials: "absent", credentialsLines: 0, ipv6: "absent", ipv6Lines: 0 });
  fs.writeFileSync(USERS(37100), "a:b\nc:d\n");
  fs.writeFileSync(IPV6(37100), "2001:db8::1\n2001:db8::2\n");
  assert.deepStrictEqual(await srv.dropStaleBatchLists({ startPort: 37100, proxyCount: 2, keepCredentialsFile: true }), { credentials: "kept", credentialsLines: 2, ipv6: "kept", ipv6Lines: 2 });
  assert.ok(fs.existsSync(USERS(37100)), "keepCredentialsFile never unlinks the credentials file");
  assert.deepStrictEqual(await srv.dropStaleBatchLists({ startPort: 37100, proxyCount: 3 }), { credentials: "dropped", credentialsLines: 2, ipv6: "dropped", ipv6Lines: 2 });
  assert.ok(!fs.existsSync(USERS(37100)) && !fs.existsSync(IPV6(37100)));
});
