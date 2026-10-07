"use strict";

// Audit RES-11 / RES-13 / FP-01 / CLN-04 — the agent end to end:
//   - GET /health keeps every field and adds supervisor, firewall,
//     cfgsLegacyDns, cfgsEgressFamily, nodeTuning;
//   - POST/GET /firewall/desired (stub ss / nft in PATH);
//   - POST /generate: mismatched fingerprint / network labels are accepted
//     and ignored (the old contract failed every generation on them), an
//     ipv6-policy mismatch still fails closed, and the batch's firewall
//     blocks are lifted before the generator runs (only its own ports).
// A fake generator exits 3; cron cleanup is off; nothing leaves the box.
// Run with: node --test node_runtime/node_agent/server.n2.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-n2-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const JOBS_ROOT = path.join(TMP, "jobs");
const BIN = path.join(TMP, "bin");
const NFT_LOG = path.join(TMP, "nft.log");
const NFT_SET = path.join(TMP, "nft_set.txt");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_JOBS_ROOT = JOBS_ROOT;
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.NODE_AGENT_FIREWALL_STATE_FILE = path.join(TMP, "desired.json");
process.env.NETRUN_3PROXY_SPAWN = "off";
process.env.PATH = `${BIN}:${process.env.PATH}`;
fs.writeFileSync(path.join(BIN, "ss"), "#!/bin/sh\necho 'LISTEN 0 13 45.32.10.20:18100 0.0.0.0:*'\necho 'LISTEN 0 13 45.32.10.20:40000 0.0.0.0:*'\n", { mode: 0o755 });
// nft: `list set` prints the elements in NFT_SET; `-f FILE` is logged and applied.
fs.writeFileSync(
  path.join(BIN, "nft"),
  `#!/bin/bash
echo "nft $*" >> '${NFT_LOG}'
if [ "$1" = list ] && [ "$2" = set ]; then
  e="$(cat '${NFT_SET}' 2>/dev/null)"
  echo "table inet proxy_accounting {"; echo "  set pergb_blocked {"; echo "    type inet_service"
  [ -n "$e" ] && echo "    elements = { $e }"
  echo "  }"; echo "}"; exit 0
fi
if [ "$1" = -f ]; then cat "$2" >> '${NFT_LOG}'; exit 0; fi
if [ "$1" = list ] && [ "$2" = chain ]; then echo "tcp dport @pergb_blocked drop"; exit 0; fi
exit 0
`,
  { mode: 0o755 }
);
fs.writeFileSync(path.join(PROXY_ROOT, "egress_mode.state"), "ipv6_only\n");
fs.writeFileSync(
  path.join(PROXY_ROOT, "3proxy", "3proxy_18100.cfg"),
  "daemon\nnserver 127.0.0.1\nnserver ::1\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::a\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::a\n"
);
fs.writeFileSync(
  path.join(PROXY_ROOT, "3proxy", "3proxy_40000.cfg"),
  "daemon\nnserver 1.0.0.19\nnserver 2a0d:2a00:1::\nflush\nsocks -64 -a -p40000 -i45.32.10.20 -e2001:db8::b\n"
);
// Long-settled batches (a cfg written in the last 30 min is never a ghost).
for (const f of ["3proxy_18100.cfg", "3proxy_40000.cfg"]) fs.utimesSync(path.join(PROXY_ROOT, "3proxy", f), new Date(0), new Date(0));
const FAKE_GEN = path.join(TMP, "fake_generator.sh");
fs.writeFileSync(FAKE_GEN, "#!/bin/bash\n# --random --skip-self-check --proxies-type\nexit 3\n", { mode: 0o755 });

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const srv = require("./server.js");

function request(port, method, p, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const req = http.request(
      { host: "127.0.0.1", port, path: p, method, headers: data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {} },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
      }
    );
    req.on("error", reject);
    req.end(data || undefined);
  });
}
async function settled() {
  const lock = path.join(JOBS_ROOT, ".generation.lock");
  for (let i = 0; i < 200 && fs.existsSync(lock); i += 1) await new Promise((r) => setTimeout(r, 10));
}
const nftLog = () => (fs.existsSync(NFT_LOG) ? fs.readFileSync(NFT_LOG, "utf-8") : "");

let PORT = 0;
test.before(async () => {
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  PORT = srv.server.address().port;
});
test.after(async () => {
  await new Promise((r) => srv.server.close(r));
  fs.rmSync(TMP, { recursive: true, force: true });
});

test("GET /health: additive supervisor / firewall / static cfg checks / nodeTuning", { timeout: 30_000 }, async () => {
  const { status, json } = await request(PORT, "GET", "/health");
  assert.strictEqual(status, 200);
  for (const key of ["success", "status", "busy", "proxyReady", "cfgs", "cfgsDown", "ipv6Addresses", "hygiene", "dns", "ipv6"]) {
    assert.ok(key in json, `field ${key} kept`);
  }
  assert.strictEqual(json.supervisor.enabled, true);
  assert.strictEqual(json.supervisor.cfgsRespawned, 0);
  assert.deepStrictEqual(json.supervisor.failedCfgs, []);
  assert.strictEqual(json.firewall.enabled, true);
  assert.strictEqual(json.firewall.desired, null);
  assert.deepStrictEqual(json.cfgsLegacyDns, { count: 1, items: [{ startPort: 40000, nservers: ["1.0.0.19", "2a0d:2a00:1::"] }] });
  assert.deepStrictEqual(json.cfgsEgressFamily, { expectedFlag: "-6", mismatched: 1, items: [{ startPort: 40000, flags: ["-64"] }] });
  assert.ok("ipLocalPortRange" in json.nodeTuning && "ephemeralOverlapsProxyPorts" in json.nodeTuning && "pipeUserPagesSoft" in json.nodeTuning);
  assert.strictEqual(json.nodeTuning.proxyListenFloor, 8100);
});

test("POST /firewall/desired: 400 on a bad body, 200 applied (ghost 40000 blocked), GET shows the persisted state", { timeout: 30_000 }, async () => {
  fs.writeFileSync(NFT_SET, "");
  let r = await request(PORT, "POST", "/firewall/desired", { livePorts: "18100", window: [18100, 65535] });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.json.error, "invalid_desired");
  r = await request(PORT, "POST", "/firewall/desired", { livePorts: [18100, 8100], pergbBlocked: [], window: [18100, 65535] });
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.deepStrictEqual(r.json.report.ghosts.sample, [40000]);
  assert.ok(nftLog().includes("add element inet proxy_accounting pergb_blocked { 40000 }"), nftLog());
  r = await request(PORT, "GET", "/firewall/desired");
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.desired.livePorts, 2);
  assert.deepStrictEqual(r.json.desired.ghostSample, [40000]);
});

test("POST /generate: mismatched labels are accepted and ignored (CLN-04); an ipv6-policy mismatch still fails closed", { timeout: 30_000 }, async () => {
  const base = { generatorScript: FAKE_GEN, startPort: 30000, proxyCount: 1, proxiesType: "dual", timeoutSec: 30 };
  let r = await request(PORT, "POST", "/generate", {
    ...base,
    jobId: "labels-1",
    networkProfile: "standard_nat",
    fingerprintProfileVersion: "v9_renamed",
    intendedClientOsProfile: "windows_desktop",
    clientOsProfileEnforcement: "whatever",
  });
  await settled();
  assert.notStrictEqual(r.json.error, "product_profile_contract_mismatch", JSON.stringify(r.json));
  assert.strictEqual(r.json.error, "generator_exit_3", "it got past the contract to the (fake) generator");
  r = await request(PORT, "POST", "/generate", { ...base, jobId: "labels-2", intendedIpv6Policy: "strict_dual_stack" });
  await settled();
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.json.error, "product_profile_contract_mismatch");
  assert.deepStrictEqual(r.json.details.mismatches.map((m) => m.field), ["intended_ipv6_policy"]);
  const c = srv.evaluateProductProfileContract({ networkProfile: "x", ipv6Policy: "ipv6_only" }, srv.buildProfileDiagnostics({
    requested_fingerprint_profile_version: "", fingerprint_profile_version: "v0", intended_ipv6_policy: "ipv6_only", effective_ipv6_policy: "ipv6_only",
  }));
  assert.strictEqual(c.ok, true);
  assert.ok(c.ignoredLabelMismatches.some((m) => m.field === "fingerprint_profile_version"));
  assert.ok(c.ignoredLabelMismatches.some((m) => m.field === "network_profile"));
});

test("POST /generate lifts the firewall blocks of ITS batch (and its http mirror) only", { timeout: 30_000 }, async () => {
  fs.writeFileSync(NFT_SET, "8100, 18100, 18101, 8101, 30000, 40000");
  fs.writeFileSync(NFT_LOG, "");
  const r = await request(PORT, "POST", "/generate", {
    jobId: "lift-1", generatorScript: FAKE_GEN, startPort: 18100, proxyCount: 2, proxiesType: "dual", timeoutSec: 30,
  });
  await settled();
  assert.strictEqual(r.json.error, "generator_exit_3", JSON.stringify(r.json));
  assert.ok(nftLog().includes("destroy element inet proxy_accounting pergb_blocked { 8100, 8101, 18100, 18101 }"), nftLog());
  assert.ok(!/destroy element[^\n]*(30000|40000)/.test(nftLog()), "other ports stay blocked");
  assert.deepStrictEqual(srv.generationBatchPorts({ startPort: 30000, proxyCount: 2, proxiesType: "socks5" }), [30000, 30001], "no mirror for a socks-only batch");
  const st = JSON.parse(fs.readFileSync(process.env.NODE_AGENT_FIREWALL_STATE_FILE, "utf-8"));
  assert.deepStrictEqual(st.ghostPorts, [40000], "the persisted ghosts keep 40000");
});
