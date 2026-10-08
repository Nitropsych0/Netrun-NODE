"use strict";

// Audit follow-ups on POST /generate (RES-13 lift, RES-11 supervisor):
//   - when the kill-on-rebind sweep did not finish (its `ss -p` failed), the
//     firewall lift skips the batch ports an old occupant still listens on
//     (one cheap `ss -Hltn`, address-aware like the generator's pre-check:
//     haproxy's <public-ip>:<http-port> frontend is not an occupant);
//   - the supervisor forgets the start port (a failed attempt's leftover is
//     never respawned as "the batch that served there").
// ss / nft are PATH stubs; a fake generator exits 3; nothing leaves the box.
// Run with: node --test node_runtime/node_agent/server.lift_exclude.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-liftx-"));
const PROXY_ROOT = path.join(TMP, "proxyserver");
const JOBS_ROOT = path.join(TMP, "jobs");
const BIN = path.join(TMP, "bin");
const NFT_LOG = path.join(TMP, "nft.log");
const NFT_SET = path.join(TMP, "nft_set.txt");
const SS_LOG = path.join(TMP, "ss.log");
const HAPROXY_DIR = path.join(TMP, "netrun.d");
fs.mkdirSync(path.join(PROXY_ROOT, "3proxy"), { recursive: true });
fs.mkdirSync(BIN, { recursive: true });
fs.mkdirSync(HAPROXY_DIR, { recursive: true }); // the node has the HTTPS front
process.env.NODE_AGENT_PROXY_ROOT = PROXY_ROOT;
process.env.NODE_AGENT_API_KEY = "test-key"; // audit 2026-10-08: the agent fails closed without a key
process.env.NODE_AGENT_JOBS_ROOT = JOBS_ROOT;
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.NODE_AGENT_IPV6_EGRESS_URL = "https://127.0.0.1:9/";
process.env.NODE_AGENT_FIREWALL_STATE_FILE = path.join(TMP, "desired.json");
process.env.NODE_AGENT_FIREWALL_EPHEMERAL_GUARD = "0";
process.env.NODE_AGENT_SUPERVISOR_STATUS_FILE = path.join(TMP, "supervisor.json");
process.env.NETRUN_HAPROXY_FRONTEND_DIR = HAPROXY_DIR;
process.env.NETRUN_3PROXY_SPAWN = "off";
process.env.PATH = `${BIN}:${process.env.PATH}`;
// The supervisor (a previous agent process) saw 18100 serving.
fs.writeFileSync(process.env.NODE_AGENT_SUPERVISOR_STATUS_FILE, JSON.stringify({ seenServing: [18100, 30000] }));
// ss: the sweep's `ss -tlnp…` fails (as under load: -p walks every fd); the
// cheap `ss -Hltn` works: the old 3proxy still holds socks 18100 on the public
// IPv4, haproxy holds <public>:8101 (its frontend), nothing else.
fs.writeFileSync(
  path.join(BIN, "ss"),
  `#!/bin/bash
echo "ss $*" >> '${SS_LOG}'
case "$1" in -tlnpH|-tlnp) exit 1 ;; esac
echo 'LISTEN 0 13 45.32.10.20:18100 0.0.0.0:*'
echo 'LISTEN 0 4096 45.32.10.20:8101 0.0.0.0:*'
exit 0
`,
  { mode: 0o755 }
);
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
exit 0
`,
  { mode: 0o755 }
);
fs.writeFileSync(path.join(PROXY_ROOT, "egress_mode.state"), "ipv6_only\n");
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
      { host: "127.0.0.1", port, path: p, method, headers: data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data), "X-API-KEY": "test-key" } : { "X-API-KEY": "test-key" } },
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

let PORT = 0;
test.before(async () => {
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  PORT = srv.server.address().port;
});
test.after(async () => {
  await new Promise((r) => srv.server.close(r));
  fs.rmSync(TMP, { recursive: true, force: true });
});

test("selectOccupiedBatchPorts: socks listener (any address) and loopback/wildcard http listener occupy (with their pair); haproxy's frontend does not", () => {
  const params = { startPort: 18100, proxyCount: 5, proxiesType: "dual" };
  const ss = [
    "LISTEN 0 13 45.32.10.20:18100 0.0.0.0:*", // old socks
    "LISTEN 0 13 127.0.0.1:8101 0.0.0.0:*", // old 3proxy http behind haproxy
    "LISTEN 0 4096 45.32.10.20:8102 0.0.0.0:*", // haproxy frontend (or a public 3proxy http without the front)
    "LISTEN 0 13 *:8103 *:*", // wildcard
    "LISTEN 0 13 [::]:18104 [::]:*",
    "LISTEN 0 13 45.32.10.20:18105 0.0.0.0:*", // outside the batch
    "garbage",
  ].join("\n");
  const sortedOf = (s) => [...s].sort((a, b) => a - b);
  assert.deepStrictEqual(sortedOf(srv.selectOccupiedBatchPorts(ss, params, { httpsFront: true })), [8100, 8101, 8103, 8104, 18100, 18101, 18103, 18104]);
  assert.deepStrictEqual(
    sortedOf(srv.selectOccupiedBatchPorts(ss, params, { httpsFront: false })),
    [8100, 8101, 8102, 8103, 8104, 18100, 18101, 18102, 18103, 18104],
    "no HTTPS front: a public listener on an http port is 3proxy's"
  );
  assert.deepStrictEqual(sortedOf(srv.selectOccupiedBatchPorts(ss, { startPort: 18100, proxyCount: 2, proxiesType: "socks5" })), [18100], "socks-only batch: no mirror");
});

test("POST /generate after a failed sweep: the lift keeps the blocks of ports an old occupant still serves; the supervisor forgets the start port", { timeout: 30_000 }, async () => {
  fs.writeFileSync(NFT_SET, "8100, 18100, 8101, 18101, 30000");
  fs.writeFileSync(NFT_LOG, "");
  assert.ok(srv.supervisor.status().seenServing.includes(18100));
  const r = await request(PORT, "POST", "/generate", {
    jobId: "liftx-1", generatorScript: FAKE_GEN, startPort: 18100, proxyCount: 2, proxiesType: "dual", timeoutSec: 30,
  });
  await settled();
  assert.strictEqual(r.json.error, "generator_exit_3", JSON.stringify(r.json));
  const log = fs.readFileSync(NFT_LOG, "utf-8");
  assert.ok(log.includes("destroy element inet proxy_accounting pergb_blocked { 8101, 18101 }"), log);
  assert.ok(!/destroy element[^\n]*\b(8100|18100|30000)\b/.test(log), `the occupant's blocks stay: ${log}`);
  const ssLog = fs.readFileSync(SS_LOG, "utf-8");
  assert.ok(/ss -Hltn sport >= :18100 and sport <= :18101/.test(ssLog) && /ss -Hltn sport >= :8100 and sport <= :8101/.test(ssLog), ssLog);
  const st = srv.supervisor.status();
  assert.ok(!st.seenServing.includes(18100), "forgotten under the generation lock");
  assert.ok(st.seenServing.includes(30000), "other batches untouched");
});
