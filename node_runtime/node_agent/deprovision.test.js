"use strict";

// Wave NODE-DEPROVISION — pure cfg parse/rewrite safety tests.
//
// The dangerous part of deprovision is rewriting a MIXED batch cfg: it must drop
// the WHOLE 7-line block of each removed port (flush/users/allow/deny/socks/proxy)
// and leave every surviving (customer) block — incl. its unique credentials —
// byte-for-byte intact. A bug here could give a customer port the wrong creds or
// silently drop it. These tests pin that.
//
// Run with: node node_runtime/node_agent/deprovision.test.js
// Exits non-zero on the first failed assertion.

const assert = require("assert");
const path = require("path");

const deprov = require(path.resolve(__dirname, "deprovision.js"));

let passed = 0;
function ok(cond, msg) { assert.ok(cond, msg); passed += 1; }
function eq(a, b, msg) {
  assert.strictEqual(a, b, `${msg}\n  expected: ${JSON.stringify(b)}\n  actual:   ${JSON.stringify(a)}`);
  passed += 1;
}

// Realistic batch cfg: header + global auth + 3 per-port blocks (32000/1/2),
// each with its OWN credentials and a paired http listener (socks - 10000).
const CFG = [
  "daemon",
  "nserver 127.0.0.1",
  "nserver ::1",
  "maxconn 200",
  "setgid 65535",
  "setuid 65535",
  "",
  "auth strong",
  "users :CL:",
  "",
  "allow * * ",
  "deny *",
  "flush",
  "users AAAA:CL:aaaa",
  "",
  "allow * * ",
  "deny *",
  "socks -6 -a -p32000 -i1.2.3.4 -e2001:db8::1",
  "proxy -6 -n -a -p22000 -i1.2.3.4 -e2001:db8::1",
  "flush",
  "users BBBB:CL:bbbb",
  "",
  "allow * * ",
  "deny *",
  "socks -6 -a -p32001 -i1.2.3.4 -e2001:db8::2",
  "proxy -6 -n -a -p22001 -i1.2.3.4 -e2001:db8::2",
  "flush",
  "users CCCC:CL:cccc",
  "",
  "allow * * ",
  "deny *",
  "socks -6 -a -p32002 -i1.2.3.4 -e2001:db8::3",
  "proxy -6 -n -a -p22002 -i1.2.3.4 -e2001:db8::3",
].join("\n") + "\n";

// ── 1. parseCfg splits header + 3 blocks with correct port/ipv6 ──────
{
  const { header, blocks } = deprov.parseCfg(CFG);
  ok(header.includes("auth strong"), "header keeps global auth");
  ok(header.includes("users :CL:"), "header keeps global users");
  ok(!header.some((l) => /^socks/.test(l)), "header has no socks line");
  eq(blocks.length, 3, "three per-port blocks");
  eq(blocks[0].socksPort, 32000, "block0 socks port");
  eq(blocks[0].httpPort, 22000, "block0 http port");
  eq(blocks[0].ipv6, "2001:db8::1", "block0 egress ipv6");
  eq(blocks[2].socksPort, 32002, "block2 socks port");
  eq(blocks[2].ipv6, "2001:db8::3", "block2 egress ipv6");
}

// ── 2. rewrite keeping the CUSTOMER block (32001), removing 32000+32002 ──
{
  const plan = deprov.planRewrite(CFG, new Set([32000, 32002]));
  eq(plan.removeBlocks.length, 2, "two blocks removed");
  eq(plan.keepBlocks.length, 1, "one block kept");
  eq(plan.wholeBatch, false, "not a whole-batch drop");
  eq(plan.removeBlocks[0].ipv6, "2001:db8::1", "removed block ipv6 captured for nft");

  const out = plan.newText;
  // Customer block 32001 fully intact — listener AND its unique creds.
  ok(out.includes("socks -6 -a -p32001 -i1.2.3.4 -e2001:db8::2"), "kept: 32001 socks line");
  ok(out.includes("proxy -6 -n -a -p22001 -i1.2.3.4 -e2001:db8::2"), "kept: 32001 http line");
  ok(out.includes("users BBBB:CL:bbbb"), "kept: 32001 unique creds");
  // Header preserved.
  ok(out.includes("auth strong") && out.includes("daemon"), "kept: header");
  // Removed ports gone entirely — listeners, http pairs, AND their creds.
  ok(!out.includes("-p32000"), "removed: 32000 socks gone");
  ok(!out.includes("-p22000"), "removed: 32000 http gone");
  ok(!out.includes("users AAAA:CL:aaaa"), "removed: 32000 creds gone");
  ok(!out.includes("-p32002"), "removed: 32002 socks gone");
  ok(!out.includes("users CCCC:CL:cccc"), "removed: 32002 creds gone");
  // The kept block must not inherit a removed block's creds: exactly one `users`
  // line in the body besides the global one.
  const userLines = out.split("\n").filter((l) => /^users /.test(l));
  eq(userLines.length, 2, "only global + the one kept block's creds remain");
}

// ── 3. removing ALL ports → whole-batch drop (no rewrite text) ──────
{
  const plan = deprov.planRewrite(CFG, new Set([32000, 32001, 32002]));
  eq(plan.wholeBatch, true, "all ports removed → whole batch");
  eq(plan.keepBlocks.length, 0, "no kept blocks");
  eq(plan.newText, null, "no rewrite body for a whole-batch drop");
}

// ── 4. an http port in the remove set must NOT match (we key on socks) ──
{
  const plan = deprov.planRewrite(CFG, new Set([22000]));
  eq(plan.removeBlocks.length, 0, "http port 22000 does not match any socks block");
}

// ── 5. no matching ports → untouched ────────────────────────────────
{
  const plan = deprov.planRewrite(CFG, new Set([49999]));
  eq(plan.removeBlocks.length, 0, "unknown port removes nothing");
  eq(plan.wholeBatch, false, "not a whole-batch drop");
}

// ── 6. kill waits until a SIGKILLed process is really gone ──────────
// (audit N2 review correctness#1: the spawn helper must never see the dying
// process as the running batch). A child that ignores SIGTERM stands in.
async function killWaitTest() {
  const { spawn } = require("child_process");
  const sp = 59000 + (process.pid % 900);
  const child = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)", `3proxy_${sp}.cfg`], {
    stdio: "ignore",
  });
  await new Promise((r) => setTimeout(r, 300));
  try {
    const res = await deprov.killCfgProcess(sp);
    eq(res.killed, 1, "one process found");
    eq(res.forceKilled, 1, "SIGTERM ignored -> SIGKILLed");
    eq(res.stillAlive, 0, "gone before killCfgProcess returns");
  } finally {
    try { child.kill("SIGKILL"); } catch {}
  }
}

killWaitTest().then(
  () => console.log(`deprovision.test.js: ${passed} assertions passed`),
  (err) => { console.error(err); process.exitCode = 1; }
);
