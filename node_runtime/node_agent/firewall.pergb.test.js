"use strict";

// Pay-per-GB v2 (lane L9) — the desired-state firewall next to per-GB:
//   option A: a shared port is never a ghost, never kept in pergbBlocked (not
//     even as a socks port's http mirror), a block on one is lifted and it
//     leaves pergb_blocked.list; an account toggle of one is not recorded;
//   option B: listeners on the dedicated per-GB IPv4 are ignored, per-piece
//     ports with the same numbers are judged (and blocked) as before;
//   always: the per-GB loopback listeners (127.0.0.3 / 127.0.0.4) are ignored;
//   a re-apply with blocks in the set re-checks the drop rule's form.
// Run with: node --test node_runtime/node_agent/firewall.pergb.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert");
const fw = require("./firewall.js");
const { createShield } = require("./pergb_shield.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-firewall-pergb-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));
const quietLog = { log() {}, warn() {}, error() {} };
const sorted = (it) => [...it].sort((a, b) => a - b);

test("parseListeners / listeningPortsExcept: addresses without [] / %iface; a port other listeners hold stays", () => {
  const ss = [
    "LISTEN 0 4096 45.32.10.20:31000 0.0.0.0:*",
    "LISTEN 0 4096 127.0.0.3:31000 0.0.0.0:*",
    "LISTEN 0 4096 127.0.0.4:31001 0.0.0.0:*",
    "LISTEN 0 4096 45.32.99.7:10000 0.0.0.0:*",
    "LISTEN 0 4096 [::]:22 [::]:*",
    "LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*",
    "LISTEN 0 4096 *:8085 *:*",
  ].join("\n");
  assert.deepStrictEqual(fw.parseListeners(ss).slice(4), [{ addr: "::", port: 22 }, { addr: "127.0.0.53", port: 53 }, { addr: "*", port: 8085 }]);
  assert.deepStrictEqual(sorted(fw.listeningPortsExcept(ss, new Set(["127.0.0.3", "127.0.0.4", "45.32.99.7"]))), [22, 53, 8085, 31000]);
});

test("planFirewall: `shared` ports are never ghosts, never pergb-blocked, and a block on one is removed", () => {
  const plan = fw.planFirewall({
    mode: "push",
    listening: new Set([31000, 31001, 18200]),
    current: new Set([31002, 18300]),
    live: new Set(),
    pergb: fw.withHttpMirror([41000, 18300]),
    windows: [[18100, 65535], [8100, 55535]],
    shared: new Set([31000, 31001, 31002]),
  });
  assert.deepStrictEqual(plan.ghosts, [18200]);
  assert.deepStrictEqual(plan.pergbWanted, [8300, 18300, 41000], "41000's mirror 31000 is shared: left out");
  assert.deepStrictEqual(plan.remove, [31002]);
  assert.deepStrictEqual(plan.skippedShared, [31000, 31002]);
});

function fakeNode(name, enable) {
  const host = { listeners: [], blocked: new Set(), list: new Set(), batches: [], infra: 0 };
  const run = async (cmd, args) => {
    if (cmd === "ss") return { code: 0, stdout: host.listeners.map(([a, p]) => `LISTEN 0 4096 ${a}:${p} 0.0.0.0:*`).join("\n"), stderr: "" };
    if (cmd === "nft" && args[0] === "list") {
      return { code: 0, stdout: `table inet proxy_accounting {\n\tset pergb_blocked {\n\t\ttype inet_service\n${host.blocked.size ? `\t\telements = { ${[...host.blocked].join(", ")} }\n` : ""}\t}\n}\n`, stderr: "" };
    }
    if (cmd === "nft" && args[0] === "-f") {
      const text = fs.readFileSync(args[1], "utf-8");
      host.batches.push(text);
      for (const line of text.trim().split("\n")) {
        for (const p of (line.match(/\{([^}]*)\}/)[1].match(/\d+/g) || []).map(Number)) {
          if (line.startsWith("add")) host.blocked.add(p);
          else host.blocked.delete(p);
        }
      }
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: "unexpected" };
  };
  const enableFile = path.join(TMP, `${name}.enable.json`);
  if (enable) fs.writeFileSync(enableFile, JSON.stringify(enable));
  const shield = createShield({ env: { NETRUN_PERGB_ENABLE_FILE: enableFile, NETRUN_PRIMARY_IPV4: "45.32.10.20" }, run: async () => assert.fail("no route lookup"), log: quietLog });
  const firewall = fw.createFirewall({
    env: { NODE_AGENT_FIREWALL_STATE_FILE: path.join(TMP, name, "desired.json") },
    run,
    readCfgs: async () => ({ ok: true, cfgs: [] }),
    ensureInfra: async () => { host.infra += 1; },
    updateBlockedList: async (fn) => fn(host.list),
    protectedPorts: [8085, 22],
    log: quietLog,
    tmpDir: TMP,
    readEphemeralRange: () => null,
    shield,
  });
  return { host, firewall, enableFile };
}

test("push (option A): shared listeners are no ghosts, a shared mirror is not blocked, a stale shared block is lifted and leaves the list", async () => {
  const { host, firewall } = fakeNode("push-a", { base: 31000, count: 1000 });
  host.listeners = [["45.32.10.20", 31000], ["45.32.10.20", 31001], ["127.0.0.3", 31000], ["127.0.0.4", 31001], ["1.2.3.4", 18500], ["1.2.3.4", 41000]];
  host.blocked = new Set([31002]); // blocked before per-GB took the range
  host.list = new Set([31002, 31003]);
  const out = await firewall.push({ livePorts: [41000], pergbBlocked: [41000], window: [18100, 65535] });
  assert.strictEqual(out.status, 200, JSON.stringify(out.body));
  assert.deepStrictEqual(sorted(host.blocked), [18500, 41000], "18500 is a ghost; 41000 pergb; 31000 (its mirror) shared");
  assert.deepStrictEqual(out.body.report.ghosts.sample, [18500]);
  assert.deepStrictEqual(out.body.report.removed.sample, [31002]);
  assert.deepStrictEqual(out.body.report.pergbShared.sample, [31000, 31002]);
  assert.deepStrictEqual(sorted(host.list), [41000], "shared ports out of pergb_blocked.list");
  // the re-apply re-asserts nothing on a shared port either
  host.blocked.add(31005);
  const re = await firewall.reapply("test");
  assert.strictEqual(re.ok, true);
  assert.ok(!host.blocked.has(31005) && !host.blocked.has(31000));
});

test("push (option B): listeners on the per-GB IPv4 / loopback are ignored; per-piece ports with the same numbers are judged as before", async () => {
  const { host, firewall } = fakeNode("push-b", { base: 10000, count: 1000, egressIpv4: "45.32.99.7" });
  host.listeners = [["45.32.99.7", 10000], ["45.32.99.7", 10001], ["127.0.0.3", 10000], ["127.0.0.4", 10001], ["1.2.3.4", 10002], ["1.2.3.4", 20005], ["1.2.3.4", 10005]];
  const out = await firewall.push({ livePorts: [20005, 10005], pergbBlocked: [20005], windows: [[18100, 65535], [8100, 55535]] });
  assert.strictEqual(out.status, 200, JSON.stringify(out.body));
  assert.deepStrictEqual(out.body.report.ghosts.sample, [10002], "a per-piece ghost on the primary IPv4 is still a ghost");
  assert.deepStrictEqual(sorted(host.blocked), [10002, 10005, 20005], "the http mirror 10005 is blockable: per-GB lives on its own IPv4");
  assert.ok(!("pergbShared" in out.body.report));
});

test("no per-GB: the per-GB loopback is still never judged; nothing else changes", async () => {
  const { host, firewall } = fakeNode("push-off", null);
  host.listeners = [["127.0.0.3", 20000], ["1.2.3.4", 20001]];
  const out = await firewall.push({ livePorts: [18100], window: [18100, 65535] });
  assert.deepStrictEqual(out.body.report.ghosts.sample, [20001]);
});

test("account toggles (option A): a shared port is not recorded (the accounting call refuses it); others are", async () => {
  const { firewall } = fakeNode("toggles", { base: 31000, count: 1000 });
  let applied = 0;
  await assert.rejects(firewall.recordAccountToggle(31000, true, async () => {
    applied += 1;
    throw Object.assign(new Error("pergb_shared_port"), { code: "PERGB_SHARED_PORT" });
  }), { code: "PERGB_SHARED_PORT" });
  assert.strictEqual(applied, 1);
  assert.strictEqual(firewall.status().accountToggles, 0);
  await firewall.recordAccountToggle(41000, true, async () => ({ action: "blocked_nft_only" }));
  assert.strictEqual(firewall.status().accountToggles, 1);
});

test("re-apply: with blocks in the set and nothing to add, the drop rule's form is re-checked (ensureInfra)", async () => {
  const { host, firewall } = fakeNode("reapply-form", { base: 10000, count: 1000, egressIpv4: "45.32.99.7" });
  host.listeners = [["1.2.3.4", 20005]];
  await firewall.push({ livePorts: [20005], pergbBlocked: [20005], window: [18100, 65535] });
  const before = host.infra;
  await firewall.reapply("periodic");
  assert.strictEqual(host.infra, before + 1);
  host.blocked.clear();
  await firewall.push({ livePorts: [20005], pergbBlocked: [], window: [18100, 65535] });
  const n = host.infra;
  await firewall.reapply("periodic");
  assert.strictEqual(host.infra, n, "an empty set needs no rule check");
});
