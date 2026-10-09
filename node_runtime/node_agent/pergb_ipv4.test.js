"use strict";

// Pay-per-GB v2, amendments A7 / A9 — pergb_ipv4.js: the per-GB IPv4s are
// added live (`ip addr add <a>/32`), persisted in a netplan drop-in for the
// next boot (never `netplan apply`), only addresses this module added are
// removed, the primary IPv4 is never one of them.
// Run with: node --test node_runtime/node_agent/pergb_ipv4.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const ipv4 = require("./pergb_ipv4.js");

const QUIET = { log() {}, error() {} };

const CLOUD_INIT_SETNAME = `network:
    version: 2
    ethernets:
        eth0:
            match:
                macaddress: 56:00:04:a1:b2:c3
            set-name: enp1s0
            dhcp4: true
            dhcp6: false
`;
const CLOUD_INIT_PLAIN = `network:
  version: 2
  ethernets:
    enp1s0:
      dhcp4: true
`;

test("netplanIdFor: the ethernets id of the interface (plain key or set-name)", () => {
  assert.strictEqual(ipv4.netplanIdFor("enp1s0", [CLOUD_INIT_SETNAME]), "eth0");
  assert.strictEqual(ipv4.netplanIdFor("enp1s0", [CLOUD_INIT_PLAIN]), "enp1s0");
  assert.strictEqual(ipv4.netplanIdFor("enp9s0", [CLOUD_INIT_PLAIN]), "enp9s0", "unknown: the name itself");
});

test("parsers", () => {
  assert.deepStrictEqual(ipv4.parseRouteGet("1.1.1.1 via 203.0.113.1 dev enp1s0 src 203.0.113.10 uid 0\n    cache"), { dev: "enp1s0", src: "203.0.113.10" });
  assert.deepStrictEqual([...ipv4.parseAddrShow("2: enp1s0    inet 203.0.113.10/23 brd 203.0.113.255 scope global dynamic enp1s0\n2: enp1s0    inet 198.51.100.20/32 scope global enp1s0\n")], ["203.0.113.10", "198.51.100.20"]);
});

function fakeNode() {
  const addrs = new Set(["203.0.113.10"]);
  const calls = [];
  const run = async (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (cmd === "ip" && args[1] === "route") return { code: 0, stdout: "1.1.1.1 via 203.0.113.1 dev enp1s0 src 203.0.113.10 uid 0\n", stderr: "" };
    if (cmd === "ip" && args[1] === "-o") return { code: 0, stdout: [...addrs].map((a) => `2: enp1s0    inet ${a}/32 scope global enp1s0`).join("\n"), stderr: "" };
    if (cmd === "ip" && args[0] === "addr" && args[1] === "add") {
      addrs.add(args[2].split("/")[0]);
      return { code: 0, stdout: "", stderr: "" };
    }
    if (cmd === "ip" && args[0] === "addr" && args[1] === "del") {
      addrs.delete(args[2].split("/")[0]);
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: "unexpected" };
  };
  return { addrs, calls, run };
}

test("ensureAddresses: adds the missing ones, writes the drop-in once, removes only its own, never the primary", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgv4-"));
  fs.mkdirSync(path.join(dir, "netplan"));
  fs.writeFileSync(path.join(dir, "netplan", "50-cloud-init.yaml"), CLOUD_INIT_SETNAME);
  const settings = { netplanDir: path.join(dir, "netplan"), statePath: path.join(dir, "etc", "ipv4s.json") };
  const node = fakeNode();
  const ips = ["198.51.100.20", "198.51.100.21", "198.51.100.22"];
  let r = await ipv4.ensureAddresses(ips, { run: node.run, settings, log: QUIET });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.added, ips);
  for (const ip of ips) assert.ok(node.addrs.has(ip));
  const dropin = path.join(settings.netplanDir, ipv4.DROPIN_NAME);
  const text = fs.readFileSync(dropin, "utf-8");
  assert.match(text, /^ {4}eth0:$/m, "the cloud-init id, so netplan merges it");
  for (const ip of ips) assert.match(text, new RegExp(`- ${ip.replace(/\./g, "\\.")}/32`));
  assert.strictEqual(fs.statSync(dropin).mode & 0o777, 0o600);
  assert.ok(!node.calls.some((c) => c.startsWith("netplan")), "netplan apply is never run");
  // the same list again: nothing to do
  r = await ipv4.ensureAddresses(ips, { run: node.run, settings, log: QUIET });
  assert.deepStrictEqual([r.added, r.removed, r.dropin], [[], [], null]);
  // one fewer: only that one goes
  r = await ipv4.ensureAddresses(ips.slice(0, 2), { run: node.run, settings, log: QUIET });
  assert.deepStrictEqual(r.removed, ["198.51.100.22"]);
  assert.ok(node.addrs.has("203.0.113.10"), "the primary stays");
  // the primary is refused as a per-GB address
  r = await ipv4.ensureAddresses(["203.0.113.10"], { run: node.run, settings, log: QUIET });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.error, "bad_params");
  // an address another netplan file already has is not repeated
  fs.writeFileSync(path.join(settings.netplanDir, "60-other.yaml"), "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - 198.51.100.21/32\n");
  r = await ipv4.ensureAddresses(ips.slice(0, 2), { run: node.run, settings, log: QUIET });
  assert.doesNotMatch(fs.readFileSync(dropin, "utf-8"), /198\.51\.100\.21/);
  assert.match(fs.readFileSync(dropin, "utf-8"), /198\.51\.100\.20/);
  // none: the drop-in goes
  r = await ipv4.ensureAddresses([], { run: node.run, settings, log: QUIET });
  assert.ok(!fs.existsSync(dropin));
  assert.ok(node.addrs.has("203.0.113.10"));
  fs.rmSync(dir, { recursive: true, force: true });
});
