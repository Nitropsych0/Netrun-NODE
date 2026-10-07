"use strict";

// Security audit 2026-10-02 — disablePort on a batch's START port must not
// touch the shared batch: no kill, no cfg demote (a reboot would never bring
// the batch back). Only the nft drop applies. A single-port cfg keeps the old
// per-port behaviour.
//
// Run with: node node_runtime/node_agent/accounting.batch_guard.test.js

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-batch-"));
process.env.NODE_AGENT_PROXY_ROOT = ROOT;
process.env.NODE_AGENT_DISABLE_GRACE_MS = "0";
// No 3proxy runs here: a stub pgrep that never matches (exit 1 = no process).
const BIN = path.join(ROOT, "bin");
fs.mkdirSync(BIN);
fs.writeFileSync(path.join(BIN, "pgrep"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;
const acct = require("./accounting.js");
fs.mkdirSync(path.join(ROOT, "3proxy"), { recursive: true });
// nft is absent here: the block path's nft calls succeed via the exec seam
// (a failed block now throws — see accounting.block_fail.test.js).
acct._setNftExec(async () => ({ code: 0, stdout: "", stderr: "" }));

let passed = 0;
function ok(cond, msg) {
  assert.ok(cond, msg);
  passed += 1;
}

const batch = acct.configPathForPort(41000);
fs.writeFileSync(
  batch,
  [
    "daemon", "auth strong", "flush", "users a:CL:1", "allow a *", "deny *",
    "socks -6 -a -p41000 -i127.0.0.1", "proxy -6 -n -a -p31000 -i127.0.0.1",
    "flush", "users b:CL:2", "allow b *", "deny *",
    "socks -6 -a -p41001 -i127.0.0.1", "proxy -6 -n -a -p31001 -i127.0.0.1", "",
  ].join("\n"),
);
const single = acct.configPathForPort(42000);
fs.writeFileSync(single, "daemon\nauth strong\nusers c:CL:3\nallow c *\nsocks -a -p42000 -i127.0.0.1\n");

ok(acct._isBatchCfg(batch) === true, "a 2-service cfg is a batch");
ok(acct._isBatchCfg(single) === false, "a 1-service cfg is not a batch");
ok(acct._isBatchCfg(path.join(ROOT, "3proxy", "missing.cfg")) === false, "missing cfg is not a batch");

(async () => {
  const res = await acct.disablePort(41000);
  ok(res.action === "blocked_nft_only" && res.batch === true, "batch start port → nft only");
  ok(fs.existsSync(batch), "batch cfg stays live (not demoted)");
  ok(!fs.existsSync(acct.disabledConfigPathForPort(41000)), "no .disabled copy of the batch");
  ok(acct._readBlockedList().has(41000) && acct._readBlockedList().has(31000), "port + http mirror blocked");

  const mid = await acct.disablePort(41001);
  ok(fs.existsSync(batch), "a mid-batch port never touches the batch cfg either");
  ok(mid && mid.action !== "killed", "mid-batch port is not a kill");

  const one = await acct.disablePort(42000);
  ok(one.action === "already_disabled" && one.cfgDisabled === true, "single-port cfg keeps the demote path");
  ok(fs.existsSync(acct.disabledConfigPathForPort(42000)), "single-port cfg demoted");

  console.log(`accounting.batch_guard.test.js: ${passed} assertions passed`);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
