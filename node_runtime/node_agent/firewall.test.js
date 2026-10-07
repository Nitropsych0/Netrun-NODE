"use strict";

// Audit RES-13 — the desired-state firewall (firewall.js): the pure plan
// (ghosts, pay-per-GB blocks, stale-drop removal, the in-flight-generation
// rule from the 2026-10-07 incident, fresh batches), the request contract,
// and the service against a fake `ss` / `nft` with the real state file and a
// real accounting-style blocked list.
// Run with: node --test node_runtime/node_agent/firewall.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert");
const fw = require("./firewall.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-firewall-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));
const quietLog = { log() {}, warn() {}, error() {} };

test("parseDesiredBody: contract, implied http mirror, validation", () => {
  let r = fw.parseDesiredBody({ livePorts: [18100, 8100], pergbBlocked: [18101], window: [18100, 65535] });
  assert.ok(r.ok);
  assert.deepStrictEqual(r.desired.windows, [[18100, 65535], [8100, 55535]], "socks window + http mirror");
  r = fw.parseDesiredBody({ livePorts: [], window: [18100, 20000], httpMirror: false });
  assert.deepStrictEqual(r.desired.windows, [[18100, 20000]]);
  r = fw.parseDesiredBody({ live_ports: [1], windows: [[8100, 9000], [18100, 19000]], computedAt: "2026-10-07T10:00:00Z" });
  assert.deepStrictEqual(r.desired.windows, [[8100, 9000], [18100, 19000]]);
  assert.strictEqual(r.desired.computedAtMs, Date.parse("2026-10-07T10:00:00Z"));
  const bad = (b) => fw.parseDesiredBody(b).error;
  assert.strictEqual(bad(null), "body_not_an_object");
  assert.strictEqual(bad({ window: [1, 2] }), "livePorts_required");
  assert.strictEqual(bad({ livePorts: "1,2", window: [1, 2] }), "livePorts_not_an_array");
  assert.strictEqual(bad({ livePorts: [70000], window: [1, 2] }), "livePorts_bad_port:0");
  assert.strictEqual(bad({ livePorts: [1], pergbBlocked: [0], window: [1, 2] }), "pergbBlocked_bad_port:0");
  assert.strictEqual(bad({ livePorts: [1] }), "window_required");
  assert.strictEqual(bad({ livePorts: [1], window: [9, 2] }), "window_invalid");
  assert.strictEqual(bad({ livePorts: [1], windows: [] }), "windows_invalid");
  assert.strictEqual(bad({ livePorts: [1], window: [1, 2], computedAt: "yesterday" }), "computedAt_invalid");
});

test("inFlightFromLock: socks range + http mirror of a dual batch; socks-only has no mirror", () => {
  assert.deepStrictEqual([...fw.inFlightFromLock({ startPort: 18100, proxyCount: 2, proxiesType: "dual" })].sort(), [18100, 18101, 8100, 8101].sort());
  assert.deepStrictEqual([...fw.inFlightFromLock({ startPort: 30000, proxyCount: 2, proxiesType: "socks5" })], [30000, 30001]);
  assert.strictEqual(fw.inFlightFromLock({ startPort: 18100 }).size, 3000, "older lock: 1500 + mirror");
  assert.strictEqual(fw.inFlightFromLock(null).size, 0);
});

test("parseSetElements: nft list set output", () => {
  const text = "table inet proxy_accounting {\n\tset pergb_blocked {\n\t\ttype inet_service\n\t\telements = { 8100, 18100,\n\t\t\t     20000 }\n\t}\n}\n";
  assert.deepStrictEqual([...fw.parseSetElements(text)], [8100, 18100, 20000]);
  assert.strictEqual(fw.parseSetElements("table inet proxy_accounting { set pergb_blocked { type inet_service } }").size, 0);
});

test("planFirewall push: ghosts, pergb (+mirror), stale removal, in-flight never blocked and lifted, fresh / protected / outside windows ignored", () => {
  const plan = fw.planFirewall({
    mode: "push",
    listening: new Set([22, 8085, 18100, 18101, 18102, 18200, 8200, 30000, 30001, 40000]),
    current: new Set([18101, 30000, 25000, 18200]),
    live: new Set([18100, 18101, 8200]),
    pergb: fw.withHttpMirror([18101]),
    windows: [[18100, 35000], [8100, 25000]],
    inFlight: new Set([30000, 30001, 20000, 20001]),
    fresh: new Set([18102]),
    protectedPorts: new Set([8085, 22]),
  });
  assert.deepStrictEqual(plan.ghosts, [18200], "listening, in a window, not live / in flight / fresh; 40000 is outside");
  assert.deepStrictEqual(plan.pergbWanted, [8101, 18101]);
  assert.deepStrictEqual(plan.add, [8101], "18101 and 18200 already blocked");
  assert.deepStrictEqual(plan.remove, [30000], "in-flight block lifted; live pergb 18101 kept; stale 25000 (no listener, not live) untouched");
  assert.deepStrictEqual(plan.skippedInFlight, [30000, 30001]);
});

test("planFirewall reapply: re-asserts the pushed ghosts + pergb, never declares a new ghost", () => {
  const plan = fw.planFirewall({
    mode: "reapply",
    current: new Set([8100]), // e.g. what an old ruleset snapshot restored at boot
    live: new Set([8100, 18100]),
    pergb: new Set([19000]),
    windows: [[18100, 65535]],
    inFlight: new Set([21000]),
    fresh: new Set([22000]),
    ghostPorts: new Set([20000, 21000, 22000, 18100]),
  });
  assert.deepStrictEqual(plan.add, [19000, 20000], "pergb + pushed ghost; in-flight / fresh / now-live skipped");
  assert.deepStrictEqual(plan.remove, [8100], "stale drop on a live port removed (the full add/remove reapplyPergbBlocks never did)");
  assert.strictEqual(fw.nftBatchText({ add: plan.add, remove: plan.remove }),
    "destroy element inet proxy_accounting pergb_blocked { 8100 }\nadd element inet proxy_accounting pergb_blocked { 19000, 20000 }\n");
});

// A fake node: `ss -Hltn`, `nft list set` and `nft -f` answered from state.
function fakeFirewall(name, { env = {}, lock = null, cfgs = [] } = {}) {
  const host = { listening: new Set(), blocked: new Set(), batches: [], list: new Set(), lock, nftFail: false, infra: 0 };
  const run = async (cmd, args) => {
    if (cmd === "ss") return { code: 0, stdout: [...host.listening].map((p) => `LISTEN 0 13 1.2.3.4:${p} 0.0.0.0:*`).join("\n"), stderr: "" };
    if (cmd === "nft" && args[0] === "list") {
      return { code: 0, stdout: `table inet proxy_accounting {\n\tset pergb_blocked {\n\t\ttype inet_service\n${host.blocked.size ? `\t\telements = { ${[...host.blocked].join(", ")} }\n` : ""}\t}\n}\n`, stderr: "" };
    }
    if (cmd === "nft" && args[0] === "-f") {
      const text = fs.readFileSync(args[1], "utf-8");
      host.batches.push(text);
      if (host.nftFail) return { code: 1, stdout: "", stderr: "Error: Could not process rule" };
      for (const line of text.trim().split("\n")) {
        const ports = (line.match(/\{([^}]*)\}/)[1].match(/\d+/g) || []).map(Number);
        for (const p of ports) {
          if (line.startsWith("add")) host.blocked.add(p);
          else host.blocked.delete(p);
        }
      }
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: "unexpected" };
  };
  const stateFile = path.join(TMP, name, "desired.json");
  const firewall = fw.createFirewall({
    env: { NODE_AGENT_FIREWALL_STATE_FILE: stateFile, ...env },
    run,
    readCfgs: async () => ({ ok: true, cfgs }),
    readLock: async () => host.lock,
    ensureInfra: async () => { host.infra += 1; },
    updateBlockedList: async (fn) => fn(host.list),
    protectedPorts: [8085, 22],
    log: quietLog,
    tmpDir: TMP,
  });
  return { host, firewall, stateFile };
}

test("push: applies ghosts + pergb, removes stale drops, persists the desired state, syncs the blocked list", async () => {
  const { host, firewall, stateFile } = fakeFirewall("push");
  host.listening = new Set([18100, 18101, 8100, 8101, 18500, 8500]);
  host.blocked = new Set([18100, 8100]); // stale drops on live ports (a reboot snapshot)
  host.list = new Set([18100, 8100, 30000]);
  const out = await firewall.push({ livePorts: [18100, 18101, 8100, 8101], pergbBlocked: [18101], window: [18100, 65535] });
  assert.strictEqual(out.status, 200, JSON.stringify(out.body));
  assert.strictEqual(out.body.applied, true);
  assert.deepStrictEqual([...host.blocked].sort((a, b) => a - b), [8101, 8500, 18101, 18500]);
  assert.strictEqual(host.infra, 1, "set + drop rule ensured before adds");
  assert.deepStrictEqual(out.body.report.ghosts.sample, [8500, 18500]);
  assert.deepStrictEqual(out.body.report.removed.sample, [8100, 18100]);
  assert.deepStrictEqual([...host.list].sort((a, b) => a - b), [8101, 18101, 30000], "live ports out, pergb in, unrelated kept");
  const st = JSON.parse(fs.readFileSync(stateFile, "utf-8"));
  assert.deepStrictEqual(st.ghostPorts, [8500, 18500]);
  assert.deepStrictEqual(st.pergbBlocked, [18101]);
  assert.strictEqual(firewall.status().desired.ghostPorts, 2);
  // Idempotent: the same push adds and removes nothing.
  host.batches = [];
  const again = await firewall.push({ livePorts: [18100, 18101, 8100, 8101], pergbBlocked: [18101], window: [18100, 65535] });
  assert.strictEqual(again.status, 200);
  assert.deepStrictEqual(host.batches, [], "no nft -f when nothing changes");
});

test("push: the in-flight generation's ports are never blocked and their blocks are lifted (incident 2026-10-07)", async () => {
  const { host, firewall } = fakeFirewall("inflight", { lock: { jobId: "j", startPort: 20000, proxyCount: 2, proxiesType: "dual" } });
  host.listening = new Set([20000, 20001, 10000, 10001, 30000]);
  host.blocked = new Set([20000, 10001]); // an earlier attempt's ghost blocks
  const out = await firewall.push({ livePorts: [], pergbBlocked: [20001], window: [18100, 65535], force: true });
  assert.strictEqual(out.status, 200);
  assert.deepStrictEqual([...host.blocked], [30000], "only the real ghost is blocked; the batch is clear");
  assert.deepStrictEqual(out.body.report.skippedInFlight.sample, [10000, 10001, 20000, 20001]);
});

test("push: a batch generated after the orchestrator's snapshot is never a ghost (fresh cfg / computedAt)", async () => {
  const nowMs = Date.now();
  const { host, firewall } = fakeFirewall("fresh", {
    cfgs: [
      { startPort: 18100, socksPorts: [18100], httpPorts: [8100], mtimeMs: nowMs - 60_000 },
      { startPort: 30000, socksPorts: [30000], httpPorts: [20000], mtimeMs: nowMs - 7_200_000 },
    ],
  });
  host.listening = new Set([18100, 8100, 30000, 20000]);
  let out = await firewall.push({ livePorts: [1], window: [18100, 65535] });
  assert.deepStrictEqual(out.body.report.ghosts.sample, [20000, 30000], "the 1-minute-old batch is exempt");
  // computedAt two hours ago: everything written since then is exempt too.
  host.blocked = new Set();
  out = await firewall.push({ livePorts: [1], window: [18100, 65535], computedAt: new Date(nowMs - 3 * 3600_000).toISOString(), dryRun: true });
  assert.deepStrictEqual(out.body.report.ghosts.sample, [], "computedAt before both batches");
});

test("push: refuses a payload that would firewall the stock (409) unless force; dryRun changes nothing", async () => {
  const { host, firewall, stateFile } = fakeFirewall("refuse", { env: { NODE_AGENT_FIREWALL_MAX_NEW_BLOCKS: "2" } });
  host.listening = new Set([18100, 18101, 18102]);
  let out = await firewall.push({ livePorts: [], window: [18100, 65535] });
  assert.strictEqual(out.status, 409);
  assert.strictEqual(out.body.error, "empty_live_ports");
  out = await firewall.push({ livePorts: [5], window: [18100, 65535] });
  assert.strictEqual(out.body.error, "too_many_blocks");
  assert.strictEqual(host.blocked.size, 0);
  assert.ok(!fs.existsSync(stateFile), "a refused push is not persisted");
  out = await firewall.push({ livePorts: [5], window: [18100, 65535], dryRun: true, force: true });
  assert.strictEqual(out.status, 200);
  assert.strictEqual(out.body.applied, false);
  assert.strictEqual(out.body.report.added.count, 3);
  assert.strictEqual(host.blocked.size, 0, "dryRun applied nothing");
  out = await firewall.push({ livePorts: [5], window: [18100, 65535], force: true });
  assert.strictEqual(out.status, 200);
  assert.strictEqual(host.blocked.size, 3);
  out = await firewall.push({ livePorts: "x", window: [1, 2] });
  assert.strictEqual(out.status, 400);
  assert.strictEqual(out.body.error, "invalid_desired");
});

test("reapply after a reboot: pergb + pushed ghosts back, stale drops on live ports gone; lift prunes the persisted lists", async () => {
  const { host, firewall, stateFile } = fakeFirewall("reapply");
  host.listening = new Set([18100, 18200, 8200]);
  await firewall.push({ livePorts: [18100], pergbBlocked: [19000], window: [18100, 65535] });
  assert.deepStrictEqual([...host.blocked].sort((a, b) => a - b), [8200, 9000, 18200, 19000]);
  // Reboot: an old ruleset snapshot comes back with a drop on a live port.
  host.blocked = new Set([18100]);
  host.listening = new Set([18100, 18200, 8200, 18300]); // 18300: a batch generated since — never a ghost on re-apply
  const r = await firewall.reapply("boot");
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual([...host.blocked].sort((a, b) => a - b), [8200, 9000, 18200, 19000]);
  // /generate over 18200 (dual, 1 port): its blocks go, and they are pruned from the state.
  const lift = await firewall.liftPorts([18200, 8200], "generation test");
  assert.strictEqual(lift.lifted, 2);
  assert.deepStrictEqual([...host.blocked].sort((a, b) => a - b), [9000, 19000]);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(stateFile, "utf-8")).ghostPorts, []);
  await firewall.reapply("periodic");
  assert.deepStrictEqual([...host.blocked].sort((a, b) => a - b), [9000, 19000], "a lifted ghost is not re-blocked");
  // No desired state at all: re-apply is a no-op.
  const empty = fakeFirewall("empty");
  assert.deepStrictEqual(await empty.firewall.reapply("boot"), { skipped: true, reason: "no_desired_state" });
});

test("nft failure: 500 nft_failed, nothing persisted; NODE_AGENT_FIREWALL_DESIRED=0 disables everything", async () => {
  const { host, firewall, stateFile } = fakeFirewall("nftfail");
  host.listening = new Set([18100]);
  host.nftFail = true;
  const out = await firewall.push({ livePorts: [1], window: [18100, 65535] });
  assert.strictEqual(out.status, 500);
  assert.strictEqual(out.body.error, "nft_failed");
  assert.ok(!fs.existsSync(stateFile));
  const off = fakeFirewall("off", { env: { NODE_AGENT_FIREWALL_DESIRED: "0" } });
  assert.strictEqual((await off.firewall.push({ livePorts: [1], window: [1, 2] })).status, 404);
  assert.deepStrictEqual(await off.firewall.liftPorts([1]), { skipped: true });
  assert.deepStrictEqual(await off.firewall.reapply(), { skipped: true, reason: "disabled" });
});
