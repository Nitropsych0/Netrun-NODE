"use strict";

// Wave FLEET-HEALTH (RES-08 hardening) — a pay-per-GB block that did not land
// in nft must NOT be acked: the orchestrator stamps node_blocked_at on every
// 200 of POST /accounts/{port}/disable and never re-sends it. A failed
// `nft add element` (non-zero exit, or SIGKILL on timeout) -> 500
// disable_failed, while the port is still persisted to pergb_blocked.list so a
// reboot re-applies it. Unblock stays best-effort (`delete element` of a
// never-blocked port fails with ENOENT).
// nft is stubbed through accounting._setNftExec.
// Run with: node --test node_runtime/node_agent/accounting.block_fail.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-blockfail-"));
process.env.NODE_AGENT_PROXY_ROOT = ROOT;
process.env.NODE_AGENT_JOBS_ROOT = path.join(ROOT, "jobs");
process.env.NODE_AGENT_DISABLE_GRACE_MS = "0";
process.env.NODE_AGENT_CLEANUP_CRON_AFTER_RUN = "0";
process.env.NODE_AGENT_JOBS_KEEP = "0";
// The account toggles are recorded next to the desired-state file (firewall.js).
process.env.NODE_AGENT_FIREWALL_STATE_FILE = path.join(ROOT, "desired.json");
// No 3proxy runs here: a stub pgrep that never matches (exit 1 = no process).
const BIN = path.join(ROOT, "bin");
fs.mkdirSync(BIN, { recursive: true });
fs.writeFileSync(path.join(BIN, "pgrep"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const acct = require("./accounting.js");
const srv = require("./server.js");

fs.mkdirSync(path.join(ROOT, "3proxy"), { recursive: true });

// A two-service batch cfg named after its start port 41000 (paired http 31000).
fs.writeFileSync(
  acct.configPathForPort(41000),
  [
    "daemon", "auth strong", "flush", "users a:CL:1", "allow a *", "deny *",
    "socks -6 -a -p41000 -i127.0.0.1", "proxy -6 -n -a -p31000 -i127.0.0.1",
    "flush", "users b:CL:2", "allow b *", "deny *",
    "socks -6 -a -p41001 -i127.0.0.1", "proxy -6 -n -a -p31001 -i127.0.0.1", "",
  ].join("\n"),
);

// Fake nft: the drop rule is "present" in `list chain` output; `add element`
// answers with addCodes in order (then 0), `delete element` with delCode.
function fakeNft({ addCodes = [], delCode = 0, ruleListed = true, insertCode = 0 } = {}) {
  const calls = [];
  const queue = [...addCodes];
  const exec = async (cmd, args) => {
    const line = `${cmd} ${args.join(" ")}`;
    calls.push(line);
    if (args[0] === "list" && args[1] === "chain") {
      return { code: 0, stdout: ruleListed ? "tcp dport @pergb_blocked drop\n" : "", stderr: "" };
    }
    if (args[0] === "insert") return { code: insertCode, stdout: "", stderr: insertCode ? "insert failed" : "" };
    if (args[0] === "add" && args[1] === "element") {
      const code = queue.length ? queue.shift() : 0;
      return { code, stdout: "", stderr: code ? "Error: Could not process rule: No such file or directory" : "" };
    }
    if (args[0] === "delete" && args[1] === "element") {
      return { code: delCode, stdout: "", stderr: delCode ? "Error: Could not process rule: No such file or directory" : "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { exec, calls };
}

function clearList() {
  acct._writeBlockedList(new Set());
}

test.after(() => {
  acct._setNftExec(null);
  fs.rmSync(ROOT, { recursive: true, force: true });
});

test("_enforceBlock(true): nft ok -> resolves, socks + http persisted", async () => {
  clearList();
  const nft = fakeNft();
  acct._setNftExec(nft.exec);
  await acct._enforceBlock(33055, true);
  const l = acct._readBlockedList();
  assert.ok(l.has(33055) && l.has(23055));
  assert.ok(nft.calls.includes("nft add element inet proxy_accounting pergb_blocked { 33055 }"));
  assert.ok(nft.calls.includes("nft add element inet proxy_accounting pergb_blocked { 23055 }"));
});

test("_enforceBlock(true): add element keeps failing -> throws nft_block_failed, list still written", async () => {
  clearList();
  const nft = fakeNft({ addCodes: [1, 1, 0, 0] }); // 33055 fails twice (incl. the healed retry)
  acct._setNftExec(nft.exec);
  await assert.rejects(acct._enforceBlock(33055, true), (err) => {
    assert.strictEqual(err.code, "NFTABLES_ERROR");
    assert.strictEqual(err.message, "nft_block_failed");
    assert.match(err.detail, /add 33055/);
    return true;
  });
  const l = acct._readBlockedList();
  assert.ok(l.has(33055) && l.has(23055), "persisted for the boot reapply");
});

test("_enforceBlock(true): a SIGKILLed add (code -1, no stderr) is a failure too", async () => {
  clearList();
  const nft = fakeNft({ addCodes: [-1, -1] });
  acct._setNftExec(nft.exec);
  await assert.rejects(acct._enforceBlock(33055, true), /nft_block_failed/);
});

test("_enforceBlock(true): set gone after a flush -> re-ensure once, retry succeeds", async () => {
  clearList();
  const nft = fakeNft({ addCodes: [1] });
  acct._setNftExec(nft.exec);
  await acct.ensurePergbBlockInfra(); // latch the infra as "present"
  const before = nft.calls.length;
  await acct._enforceBlock(33055, true);
  const after = nft.calls.slice(before);
  const setAdds = after.filter((c) => c.startsWith("nft add set inet proxy_accounting pergb_blocked"));
  assert.strictEqual(setAdds.length, 1, "infra re-ensured once");
  assert.strictEqual(after.filter((c) => c.endsWith("{ 33055 }")).length, 2, "the add was retried");
});

test("_enforceBlock(true): drop rule could not be inserted -> throws", async () => {
  clearList();
  const nft = fakeNft({ ruleListed: false, insertCode: 1 });
  acct._setNftExec(nft.exec);
  await assert.rejects(acct._enforceBlock(33055, true), (err) => /drop rule not confirmed/.test(err.detail));
});

test("_enforceBlock(false): a failing delete (never blocked) stays best-effort", async () => {
  acct._writeBlockedList(new Set([33055, 23055]));
  const nft = fakeNft({ delCode: 1 });
  acct._setNftExec(nft.exec);
  await acct._enforceBlock(33055, false);
  const l = acct._readBlockedList();
  assert.ok(!l.has(33055) && !l.has(23055));
});

test("disablePort: batch start port with a failed block rejects; ok block resolves blocked_nft_only", async () => {
  clearList();
  acct._setNftExec(fakeNft({ addCodes: [1, 1] }).exec);
  await assert.rejects(acct.disablePort(41000), /nft_block_failed/);
  assert.ok(acct._readBlockedList().has(41000));
  acct._setNftExec(fakeNft().exec);
  const ok = await acct.disablePort(41000);
  assert.strictEqual(ok.action, "blocked_nft_only");
  assert.strictEqual(ok.batch, true);
});

test("disablePort: a single-port cfg is still torn down when the block fails, then rejects", async () => {
  clearList();
  const single = acct.configPathForPort(42000);
  fs.writeFileSync(single, "daemon\nauth strong\nusers c:CL:3\nallow c *\nsocks -a -p42000 -i127.0.0.1\n");
  acct._setNftExec(fakeNft({ addCodes: [1, 1] }).exec);
  await assert.rejects(acct.disablePort(42000), /nft_block_failed/);
  assert.ok(!fs.existsSync(single), "cfg demoted out of the restore glob anyway");
  assert.ok(fs.existsSync(acct.disabledConfigPathForPort(42000)));
});

test("reapplyPergbBlocks: counts failures, heals at most once, never throws", async () => {
  acct._writeBlockedList(new Set([40000, 30000, 40001, 30001]));
  const nft = fakeNft({ addCodes: [1, 1, 1, 1, 1, 1, 1, 1] });
  acct._setNftExec(nft.exec);
  const r = await acct.reapplyPergbBlocks();
  assert.deepStrictEqual(r, { reapplied: 0, failed: 4 });
  const setAdds = nft.calls.filter((c) => c.startsWith("nft add set inet proxy_accounting pergb_blocked"));
  assert.strictEqual(setAdds.length, 2, "initial ensure + one heal, not one per port");
  acct._setNftExec(fakeNft().exec);
  assert.deepStrictEqual(await acct.reapplyPergbBlocks(), { reapplied: 4, failed: 0 });
  clearList();
});

function post(port, urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: urlPath, method: "POST" }, (r) => {
      let t = "";
      r.on("data", (c) => (t += c));
      r.on("end", () => resolve({ status: r.statusCode, json: JSON.parse(t) }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("POST /accounts/{port}/disable: failed block -> 500 disable_failed (port still in the list); ok -> 200", async () => {
  clearList();
  await new Promise((r) => srv.server.listen(0, "127.0.0.1", r));
  try {
    const port = srv.server.address().port;
    acct._setNftExec(fakeNft({ addCodes: [1, 1] }).exec);
    const bad = await post(port, "/accounts/41000/disable");
    assert.strictEqual(bad.status, 500);
    assert.strictEqual(bad.json.success, false);
    assert.strictEqual(bad.json.error, "disable_failed");
    assert.match(bad.json.detail, /nft_block_failed/);
    assert.ok(acct._readBlockedList().has(41000), "persisted for the boot reapply");

    acct._setNftExec(fakeNft().exec);
    const good = await post(port, "/accounts/41000/disable");
    assert.strictEqual(good.status, 200);
    assert.strictEqual(good.json.action, "blocked_nft_only");

    // enable stays 200 even when `delete element` fails (never-blocked port)
    acct._setNftExec(fakeNft({ delCode: 1 }).exec);
    const en = await post(port, "/accounts/41001/enable");
    assert.notStrictEqual(en.status, 500, JSON.stringify(en.json));

    // Both toggles are recorded for the desired-state firewall (a re-apply of
    // an older push must never undo them).
    const toggles = JSON.parse(fs.readFileSync(path.join(ROOT, "desired.toggles.json"), "utf-8")).toggles;
    assert.strictEqual(toggles["41000"].blocked, true);
    assert.strictEqual(toggles["41001"].blocked, false);
  } finally {
    await new Promise((r) => srv.server.close(r));
  }
});
