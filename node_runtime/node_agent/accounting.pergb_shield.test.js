"use strict";

// Pay-per-GB v2 (lane L9) — the per-piece money path next to per-GB:
//   option A (shared ports on the primary IPv4, /etc/netrun-pergb/enable.json):
//     /accounts/{p}/disable|enable of a shared port -> 409 pergb_shared_port,
//     never recorded as a toggle; a per-piece socks port never drags a shared
//     http mirror into the drop set; the boot re-apply drops shared ports from
//     pergb_blocked.list; /deprovision never touches a shared port (409 when
//     only shared ones were asked);
//   option B (a dedicated per-GB IPv4): nothing refused; the drop rule is
//     `ip daddr <primary IPv4> tcp dport @pergb_blocked drop`, swapped in and
//     out in ONE nft -f (delete by handle + insert) as enable.json changes.
// nft is a fake chain model (accounting._setNftExec + a PATH stub for
// deprovision); pgrep never matches.
// Run with: node --test node_runtime/node_agent/accounting.pergb_shield.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-pergb-acct-"));
const ENABLE = path.join(ROOT, "enable.json");
process.env.NODE_AGENT_PROXY_ROOT = ROOT;
process.env.NODE_AGENT_API_KEY = "test-key";
process.env.NODE_AGENT_JOBS_ROOT = path.join(ROOT, "jobs");
process.env.NODE_AGENT_DISABLE_GRACE_MS = "0";
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
process.env.NODE_AGENT_FIREWALL_STATE_FILE = path.join(ROOT, "desired.json");
process.env.NETRUN_PERGB_ENABLE_FILE = ENABLE;
process.env.NETRUN_PRIMARY_IPV4 = "45.32.10.20";
process.env.NETRUN_PERGB_POOL_FILE = path.join(ROOT, "no-pergb-pool.conf");
process.env.NODE_AGENT_NFT_PERSIST = path.join(ROOT, "nftables.conf");
const BIN = path.join(ROOT, "bin");
fs.mkdirSync(BIN, { recursive: true });
fs.writeFileSync(path.join(BIN, "pgrep"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "nft"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
fs.writeFileSync(path.join(BIN, "nft-persist"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
process.env.NODE_AGENT_NFT_PERSIST_BIN = path.join(BIN, "nft-persist");
process.env.PATH = `${BIN}:${process.env.PATH}`;

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const acct = require("./accounting.js");
const srv = require("./server.js");

fs.mkdirSync(path.join(ROOT, "3proxy"), { recursive: true });
acct._setCounterItemsFetcher(async () => []);

const optionA = () => fs.writeFileSync(ENABLE, JSON.stringify({ base: 31000, count: 1000, egressIpv4: null }));
const optionB = () => fs.writeFileSync(ENABLE, JSON.stringify({ base: 10000, count: 1000, egressIpv4: "45.32.99.7" }));
const perGbOff = () => fs.rmSync(ENABLE, { force: true });

// The proxy_accounting input chain as nft keeps it; `-f` scripts are atomic.
function fakeNft({ rules = [{ handle: 7, text: "tcp dport @pergb_blocked drop" }] } = {}) {
  const st = { rules: rules.map((r) => ({ ...r })), nextHandle: 100, set: new Set(), calls: [], scripts: [] };
  const exec = async (cmd, args) => {
    const line = `${cmd} ${args.join(" ")}`;
    st.calls.push(line);
    const listing = (handles) => ({
      code: 0,
      stdout: `table inet proxy_accounting {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tcounter name tcp dport map @cmap_in${handles ? " # handle 3" : ""}\n${st.rules.map((r) => `\t\t${r.text}${handles ? ` # handle ${r.handle}` : ""}\n`).join("")}\t}\n}\n`,
      stderr: "",
    });
    if (args[0] === "list" && args[1] === "chain") return listing(false);
    if (args[0] === "-a" && args[1] === "list" && args[2] === "chain") return listing(true);
    if (args[0] === "insert" && args[1] === "rule") {
      st.rules.unshift({ handle: st.nextHandle++, text: args.slice(5).join(" ") });
      return { code: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "-f") {
      const text = fs.readFileSync(args[1], "utf-8");
      st.scripts.push(text);
      const next = st.rules.map((r) => ({ ...r }));
      for (const l of text.trim().split("\n")) {
        let m = /^delete rule inet proxy_accounting input handle (\d+)$/.exec(l);
        if (m) {
          const i = next.findIndex((r) => r.handle === Number(m[1]));
          if (i < 0) return { code: 1, stdout: "", stderr: "Error: Could not process rule: No such file or directory" };
          next.splice(i, 1);
          continue;
        }
        m = /^insert rule inet proxy_accounting input (.+)$/.exec(l);
        if (m) {
          next.unshift({ handle: st.nextHandle++, text: m[1] });
          continue;
        }
        return { code: 1, stdout: "", stderr: `Error: syntax error: ${l}` };
      }
      st.rules = next;
      return { code: 0, stdout: "", stderr: "" };
    }
    const el = /^(add|delete) element inet proxy_accounting pergb_blocked \{ (\d+) \}$/.exec(args.join(" "));
    if (el) {
      if (el[1] === "add") st.set.add(Number(el[2]));
      else st.set.delete(Number(el[2]));
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { exec, st };
}

test.after(() => {
  acct._setNftExec(null);
  acct._setCounterItemsFetcher(null);
  fs.rmSync(ROOT, { recursive: true, force: true });
});

test("parsePergbDropRules / dropRuleSwapScript", () => {
  const text = "table inet proxy_accounting {\n\tchain input {\n\t\tip daddr 45.32.10.20 tcp dport @pergb_blocked drop # handle 12\n\t\ttcp dport @pergb_blocked drop # handle 7\n\t\tcounter name tcp dport map @cmap_in # handle 3\n\t}\n}\n";
  assert.deepStrictEqual(acct.parsePergbDropRules(text), [
    { text: "ip daddr 45.32.10.20 tcp dport @pergb_blocked drop", handle: 12 },
    { text: "tcp dport @pergb_blocked drop", handle: 7 },
  ]);
  assert.strictEqual(
    acct.dropRuleSwapScript([{ handle: 7 }, { handle: 12 }], { text: "ip daddr 1.2.3.4 tcp dport @pergb_blocked drop" }),
    "delete rule inet proxy_accounting input handle 7\ndelete rule inet proxy_accounting input handle 12\ninsert rule inet proxy_accounting input ip daddr 1.2.3.4 tcp dport @pergb_blocked drop\n",
  );
});

test("option A: a shared port is refused (PERGB_SHARED_PORT) before any nft call; a socks port never blocks a shared http mirror", async () => {
  optionA();
  const nft = fakeNft();
  acct._setNftExec(nft.exec);
  acct._writeBlockedList(new Set());
  await assert.rejects(acct.disablePort(31000), (err) => err.code === "PERGB_SHARED_PORT" && err.port === 31000);
  await assert.rejects(acct.enablePort(31999), { code: "PERGB_SHARED_PORT" });
  assert.deepStrictEqual(nft.st.calls, [], "nothing touched");
  // 41005 is a per-piece socks port whose http mirror (31005) is shared
  const r = await acct.disablePort(41005);
  assert.strictEqual(r.action, "blocked_nft_only");
  assert.deepStrictEqual([...nft.st.set], [41005]);
  assert.deepStrictEqual([...acct._readBlockedList()], [41005], "the shared mirror is not persisted either");
  // a port outside the range keeps its mirror
  await acct.disablePort(42005);
  assert.ok(nft.st.set.has(42005) && nft.st.set.has(32005));
  await acct.enablePort(41005);
  assert.ok(!nft.st.set.has(41005));
});

test("option A: the boot re-apply drops shared ports from pergb_blocked.list and from the set", async () => {
  optionA();
  const nft = fakeNft();
  acct._setNftExec(nft.exec);
  nft.st.set.add(31001);
  acct._writeBlockedList(new Set([31001, 31002, 20000, 10000]));
  const r = await acct.reapplyPergbBlocks();
  assert.deepStrictEqual(r, { reapplied: 2, failed: 0, sharedDropped: 2 });
  assert.deepStrictEqual([...acct._readBlockedList()].sort((a, b) => a - b), [10000, 20000]);
  assert.deepStrictEqual([...nft.st.set].sort((a, b) => a - b), [10000, 20000]);
  acct._writeBlockedList(new Set());
});

test("option B: nothing refused (per-piece http 10000-10999 stays blockable); the drop rule is scoped to the primary IPv4 in one nft -f", async () => {
  optionB();
  const nft = fakeNft();
  acct._setNftExec(nft.exec);
  const r = await acct.disablePort(20005);
  assert.strictEqual(r.action, "blocked_nft_only");
  assert.ok(nft.st.set.has(20005) && nft.st.set.has(10005), "the http mirror inside the per-GB port numbers is blocked: per-GB lives on its own IPv4");
  assert.deepStrictEqual(nft.st.scripts, [
    "delete rule inet proxy_accounting input handle 7\ninsert rule inet proxy_accounting input ip daddr 45.32.10.20 tcp dport @pergb_blocked drop\n",
  ]);
  assert.deepStrictEqual(nft.st.rules.map((x) => x.text), ["ip daddr 45.32.10.20 tcp dport @pergb_blocked drop"]);
  // latched: the next block lists nothing
  const n = nft.st.calls.length;
  await acct.disablePort(20006);
  assert.ok(!nft.st.calls.slice(n).some((c) => c.includes("list chain")), "no chain listing once the form is confirmed");
  // per-GB disabled (enable.json gone): the plain rule comes back, again in one transaction
  perGbOff();
  await acct.ensurePergbBlockInfra();
  assert.deepStrictEqual(nft.st.rules.map((x) => x.text), ["tcp dport @pergb_blocked drop"]);
  assert.strictEqual(nft.st.scripts.length, 2);
  assert.match(nft.st.scripts[1], /^delete rule inet proxy_accounting input handle \d+\ninsert rule inet proxy_accounting input tcp dport @pergb_blocked drop\n$/);
});

test("drop rule: none yet -> inserted in the wanted form; duplicates -> collapsed to one in one transaction; a failed swap stays unlatched", async () => {
  optionB();
  let nft = fakeNft({ rules: [] });
  acct._setNftExec(nft.exec);
  await acct.ensurePergbBlockInfra();
  assert.ok(nft.st.calls.includes("nft insert rule inet proxy_accounting input ip daddr 45.32.10.20 tcp dport @pergb_blocked drop"));
  assert.deepStrictEqual(nft.st.scripts, []);
  nft = fakeNft({ rules: [{ handle: 7, text: "tcp dport @pergb_blocked drop" }, { handle: 9, text: "tcp dport @pergb_blocked drop" }] });
  acct._setNftExec(nft.exec);
  await acct.ensurePergbBlockInfra();
  assert.deepStrictEqual(nft.st.rules.map((x) => x.text), ["ip daddr 45.32.10.20 tcp dport @pergb_blocked drop"]);
  // a handle that vanished between the listing and the swap: refused as a whole, retried next time
  nft = fakeNft();
  const exec = nft.exec;
  acct._setNftExec(async (cmd, args) => {
    if (args[0] === "-f") nft.st.rules = [{ handle: 8, text: "tcp dport @pergb_blocked drop" }];
    return exec(cmd, args);
  });
  await acct.ensurePergbBlockInfra();
  assert.deepStrictEqual(nft.st.rules.map((x) => x.text), ["tcp dport @pergb_blocked drop"], "the kernel kept its rule (atomic)");
  acct._setNftExec(nft.exec);
  await acct.ensurePergbBlockInfra();
  assert.deepStrictEqual(nft.st.rules.map((x) => x.text), ["ip daddr 45.32.10.20 tcp dport @pergb_blocked drop"], "retried");
  perGbOff();
});

function request(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const req = http.request({
      host: "127.0.0.1", port, path: urlPath, method,
      headers: { "X-API-KEY": "test-key", ...(data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}) },
    }, (r) => {
      let t = "";
      r.on("data", (c) => (t += c));
      r.on("end", () => resolve({ status: r.statusCode, json: JSON.parse(t) }));
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

test("HTTP (option A): /accounts/{shared}/disable -> 409 pergb_shared_port, no toggle recorded; /deprovision of shared ports only -> 409, mixed -> 200 with skipped_shared", async () => {
  optionA();
  acct._setNftExec(fakeNft().exec);
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  try {
    const port = srv.server.address().port;
    const dis = await request(port, "POST", "/accounts/31000/disable");
    assert.deepStrictEqual([dis.status, dis.json], [409, { success: false, error: "pergb_shared_port", port: 31000 }]);
    const en = await request(port, "POST", "/accounts/31500/enable");
    assert.strictEqual(en.status, 409);
    let toggles = {};
    try {
      toggles = JSON.parse(fs.readFileSync(path.join(ROOT, "desired.toggles.json"), "utf-8")).toggles;
    } catch {
      toggles = {};
    }
    assert.ok(!("31000" in toggles) && !("31500" in toggles), "a refused toggle is never recorded");

    const only = await request(port, "POST", "/deprovision", { ports: [31000, 31001] });
    assert.strictEqual(only.status, 409);
    assert.strictEqual(only.json.error, "pergb_shared_port");
    assert.deepStrictEqual(only.json.skipped_shared, [31000, 31001]);
    assert.ok(!("httpStatus" in only.json));
    const mixed = await request(port, "POST", "/deprovision", { ports: [31000, 50000] });
    assert.strictEqual(mixed.status, 200, JSON.stringify(mixed.json));
    assert.deepStrictEqual(mixed.json.skipped_shared, [31000]);
    assert.deepStrictEqual(mixed.json.skipped_ports, [50000], "the per-piece port is processed (not found here)");
    assert.strictEqual(mixed.json.requested, 2);

    perGbOff();
    const plain = await request(port, "POST", "/deprovision", { ports: [31000] });
    assert.strictEqual(plain.status, 200, "without per-GB nothing is shielded");
    assert.ok(!("skipped_shared" in plain.json));
  } finally {
    await new Promise((r) => srv.server.close(r));
  }
});
