"use strict";

// PERGB-NFT-ENFORCE — unit tests for the firewall pay-per-GB block lifecycle.
//
// Pure / cross-platform: nft is absent in the test env, so the block path's
// nft calls are stubbed to succeed (_setNftExec); we assert the http-port
// pairing and the persisted blocked-list (read/write/_enforceBlock/reapply)
// which are what survive a reboot. Failing nft: accounting.block_fail.test.js.
// The pgrep/SIGKILL cfg path is covered by accounting.lifecycle.test.js.
//
// Run with: node node_runtime/node_agent/accounting.nft_enforce.test.js

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

// accounting.js reads NODE_AGENT_PROXY_ROOT ONCE at module load — set it first.
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-nft-"));
process.env.NODE_AGENT_PROXY_ROOT = ROOT;
const acct = require("./accounting.js");
fs.mkdirSync(path.join(ROOT, "3proxy"), { recursive: true });
acct._setNftExec(async () => ({ code: 0, stdout: "", stderr: "" }));

let passed = 0;
function ok(cond, msg) {
  assert.ok(cond, msg);
  passed += 1;
}

// ── _httpFor: paired http port = socks − 10000, null when out of range ──
ok(acct._httpFor(34742) === 24742, "_httpFor(34742) === 24742");
ok(acct._httpFor(32000) === 22000, "_httpFor(32000) === 22000");
ok(acct._httpFor(10000) === null, "_httpFor(10000) is null (no positive http port)");
ok(acct._httpFor(5000) === null, "_httpFor below offset is null");

// ── blocked-list persistence round-trips under the proxy root ──
acct._writeBlockedList(new Set([34742, 24742, 33000]));
const back = acct._readBlockedList();
ok(back.size === 3 && back.has(34742) && back.has(24742) && back.has(33000), "blocked list round-trips");
ok(acct.BLOCKED_LIST_FILE.startsWith(ROOT), "blocked list lives under the proxy root");
ok(fs.existsSync(acct.BLOCKED_LIST_FILE), "blocked list file is persisted to disk");
acct._writeBlockedList(new Set());
ok(acct._readBlockedList().size === 0, "blocked list clears");

// A missing file reads as an empty set (fresh node), not a throw.
fs.rmSync(acct.BLOCKED_LIST_FILE, { force: true });
ok(acct._readBlockedList().size === 0, "missing blocked list reads as empty set");

(async () => {
  // _enforceBlock(true) must persist BOTH the socks port and its paired http
  // port (the bug was http traffic kept flowing); _enforceBlock(false) lifts
  // both. nft is stubbed here, so this exercises the persistence that a reboot
  // relies on.
  await acct._enforceBlock(33055, true);
  let l = acct._readBlockedList();
  ok(l.has(33055) && l.has(23055), "_enforceBlock(true) persists socks + paired http port");

  // Idempotent: blocking again does not duplicate / lose entries.
  await acct._enforceBlock(33055, true);
  l = acct._readBlockedList();
  ok(l.size === 2 && l.has(33055) && l.has(23055), "_enforceBlock is idempotent");

  await acct._enforceBlock(33055, false);
  l = acct._readBlockedList();
  ok(!l.has(33055) && !l.has(23055), "_enforceBlock(false) clears socks + paired http port");

  // reapplyPergbBlocks tolerates an empty list and a stubbed nft, returning a count.
  const empty = await acct.reapplyPergbBlocks();
  ok(empty && empty.reapplied === 0, "reapplyPergbBlocks on an empty list reapplies 0");

  acct._writeBlockedList(new Set([40000, 30000]));
  const r = await acct.reapplyPergbBlocks();
  ok(r && r.reapplied === 2, "reapplyPergbBlocks re-asserts the persisted entries");

  // cleanup
  acct._writeBlockedList(new Set());

  console.log(`accounting.nft_enforce.test.js: ${passed} assertions passed`);
})();
