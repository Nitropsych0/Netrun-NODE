"use strict";

// VPN (owner 2026-10-15) — vpn_runtime.js: the enable/users bodies, the Xray
// config (an inbound + a marked outbound per free IPv4), the nft guard + SNAT,
// the parsers (stats, access log, x25519, ss), and the runtime against a fake
// `run` (no Xray, no root).
// Run with: node --test node_runtime/node_agent/vpn_runtime.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vpn = require("./vpn_runtime.js");

const QUIET = { log() {}, error() {} };
const U1 = "11111111-2222-4333-8444-555555555555";
const U2 = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

test("validateEnable: entries, port, dest, serverNames, flow", () => {
  const ok = vpn.validateEnable({ entries: ["104.207.139.14", "64.177.112.56", "104.207.139.14"], dest: "dl.google.com" });
  assert.ok(ok.ok);
  assert.deepStrictEqual(ok.params, { entries: ["104.207.139.14", "64.177.112.56"], port: 443, dest: "dl.google.com:443", serverNames: ["dl.google.com"], flow: "xtls-rprx-vision" });
  assert.strictEqual(vpn.validateEnable({ entries: [], dest: "a.com" }).ok, false);
  assert.strictEqual(vpn.validateEnable({ entries: ["2001:db8::1"], dest: "a.com" }).ok, false, "IPv4 only");
  assert.strictEqual(vpn.validateEnable({ entries: ["1.2.3.4"], dest: "not a host" }).ok, false);
  assert.strictEqual(vpn.validateEnable({ entries: ["1.2.3.4"], dest: "a.com", port: 70000 }).ok, false);
  assert.strictEqual(vpn.validateEnable({ entries: ["1.2.3.4"], dest: "a.com", flow: "xtls-rprx-direct" }).ok, false);
  assert.strictEqual(vpn.validateEnable({ entries: ["1.2.3.4"], dest: "www.cloudflare.com:8443", flow: "" }).params.dest, "www.cloudflare.com:8443");
});

test("validateUsers: uuids, one email each, sorted", () => {
  const v = vpn.validateUsers({ users: [{ id: U2.toUpperCase(), email: "v2" }, { id: U1, email: "v1" }] });
  assert.deepStrictEqual(v.users, [{ id: U1, email: "v1" }, { id: U2, email: "v2" }]);
  assert.strictEqual(vpn.validateUsers({ users: [{ id: "x", email: "v1" }] }).ok, false);
  assert.strictEqual(vpn.validateUsers({ users: [{ id: U1, email: "v1" }, { id: U2, email: "v1" }] }).ok, false, "repeated email");
  assert.strictEqual(vpn.validateUsers({ users: [{ id: U1, email: "bad email" }] }).ok, false);
  assert.strictEqual(vpn.validateUsers({}).ok, false);
});

test("diffUsers: by email; a new id is a remove + add", () => {
  const d = vpn.diffUsers([{ email: "a", id: U1 }, { email: "b", id: U1 }], [{ email: "b", id: U2 }, { email: "c", id: U1 }]);
  assert.deepStrictEqual(d.add, [{ email: "b", id: U2 }, { email: "c", id: U1 }]);
  assert.deepStrictEqual(d.remove.sort(), ["a", "b"]);
});

test("normalizeCidr: network addresses for nft and Xray", () => {
  assert.strictEqual(vpn.normalizeCidr("2001:19f0:5c01:cdf:5400:6ff:febe:b5cf/64"), "2001:19f0:5c01:cdf::/64");
  assert.strictEqual(vpn.normalizeCidr("2602:f2dc:a9::/48"), "2602:f2dc:a9::/48");
  assert.strictEqual(vpn.normalizeCidr("198.51.100.7/24"), "198.51.100.0/24");
  assert.strictEqual(vpn.normalizeCidr("203.0.113.9"), "203.0.113.9");
});

test("parseOwnAddresses: every IPv4, the interface /64s, the routed /48", () => {
  const addr = [
    "1: lo    inet 127.0.0.1/8 scope host lo",
    "2: enp1s0    inet 64.177.12.242/23 metric 100 brd 64.177.13.255 scope global dynamic enp1s0",
    "2: enp1s0    inet 104.207.139.14/32 scope global enp1s0",
    "1: lo    inet6 ::1/128 scope host",
    "2: enp1s0    inet6 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf/64 scope global dynamic mngtmpaddr",
    "2: enp1s0    inet6 fe80::5400:6ff:febe:b5cf/64 scope link",
  ].join("\n");
  const routes = "local 2602:f2dc:a9::/48 dev lo table local metric 1024 pref medium\nlocal 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf dev enp1s0 table local proto kernel metric 0 pref medium\n";
  assert.deepStrictEqual(vpn.parseOwnAddresses(addr, routes), {
    v4: ["104.207.139.14", "64.177.12.242"],
    v6: ["2001:19f0:5c01:cdf::/64", "2602:f2dc:a9::/48"],
  });
});

test("renderConfig: an inbound and a marked outbound per entry, the guards in routing", () => {
  const settings = vpn.readSettings({ NETRUN_VPN_RUN_DIR: "/run/netrun-vpn" });
  const params = vpn.validateEnable({ entries: ["104.207.139.14", "64.177.112.56"], dest: "dl.google.com" }).params;
  const keys = { privateKey: "PRIV", publicKey: "PUB", shortIds: ["ab12cd34"] };
  const cfg = vpn.renderConfig({ params, keys, users: [{ id: U1, email: "v1" }], settings, ownIps: ["64.177.12.242", "2001:19f0:5c01:cdf:5400:6ff:febe:b5cf/64"] });
  assert.strictEqual(cfg.inbounds.length, 2);
  assert.deepStrictEqual(cfg.inbounds.map((i) => [i.tag, i.listen, i.port]), [["vpn-in-0", "104.207.139.14", 443], ["vpn-in-1", "64.177.112.56", 443]]);
  assert.deepStrictEqual(cfg.inbounds[0].settings.clients, [{ id: U1, email: "v1", flow: "xtls-rprx-vision", level: 0 }]);
  assert.strictEqual(cfg.inbounds[0].streamSettings.realitySettings.privateKey, "PRIV");
  assert.deepStrictEqual(cfg.inbounds[0].streamSettings.realitySettings.serverNames, ["dl.google.com"]);
  assert.deepStrictEqual(cfg.outbounds.map((o) => [o.tag, o.streamSettings && o.streamSettings.sockopt.mark]), [["vpn-out-0", vpn.markOf(0)], ["vpn-out-1", vpn.markOf(1)], ["block", undefined]]);
  const rules = cfg.routing.rules;
  assert.deepStrictEqual(rules[0], { type: "field", protocol: ["bittorrent"], outboundTag: "block" });
  assert.ok(rules[1].ip.includes("10.0.0.0/8") && rules[1].ip.includes("64.177.12.242") && rules[1].ip.includes("2001:19f0:5c01:cdf::/64"));
  assert.deepStrictEqual(rules[2], { type: "field", port: "25", network: "tcp", outboundTag: "block" });
  assert.deepStrictEqual(rules.slice(3), [
    { type: "field", inboundTag: ["vpn-in-0"], outboundTag: "vpn-out-0" },
    { type: "field", inboundTag: ["vpn-in-1"], outboundTag: "vpn-out-1" },
  ]);
  assert.strictEqual(cfg.api.listen, "127.0.0.1:8087");
  assert.ok(cfg.policy.levels[0].statsUserUplink && cfg.policy.levels[0].statsUserDownlink);
  assert.strictEqual(cfg.log.access, "/run/netrun-vpn/access.log");
});

test("renderNft: the uid-gated guard and one SNAT per entry, replaced atomically", () => {
  const text = vpn.renderNft({ entries: ["104.207.139.14", "64.177.112.56"], uid: 65532, own: { v4: ["64.177.12.242"], v6: ["2602:f2dc:a9::/48"] } });
  const lines = text.split("\n");
  assert.strictEqual(lines[0], "table inet netrun_vpn {}");
  assert.strictEqual(lines[1], "delete table inet netrun_vpn");
  assert.ok(lines.includes("    meta skuid 65532 jump vpn"));
  assert.ok(!/skuid !=/.test(text), "never an ungated skuid != rule (NDP lesson)");
  assert.ok(lines.includes("    ct state established,related accept"));
  assert.ok(lines.includes("    ip daddr 127.0.0.1 udp dport 53 accept"));
  assert.ok(lines.some((l) => /ip daddr \{ 0\.0\.0\.0\/8, 10\.0\.0\.0\/8, .*, 64\.177\.12\.242 \} reject$/.test(l)));
  assert.ok(lines.some((l) => /ip6 daddr \{ ::1, fe80::\/10, fc00::\/7, ff00::\/8, 2602:f2dc:a9::\/48 \} reject/.test(l)));
  assert.ok(lines.includes("    tcp dport 25 reject with tcp reset"));
  assert.ok(lines.includes("    meta nfproto ipv4 meta mark 0x00566e01 snat ip to 104.207.139.14"));
  assert.ok(lines.includes("    meta nfproto ipv4 meta mark 0x00566e02 snat ip to 64.177.112.56"));
});

test("parsers: stats, access log, x25519, ss peers", () => {
  const stats = JSON.stringify({ stat: [
    { name: "user>>>v1>>>traffic>>>uplink", value: 823 },
    { name: "user>>>v1>>>traffic>>>downlink", value: 5013135 },
    { name: "user>>>v2>>>traffic>>>downlink" },
    { name: "inbound>>>vpn-in-0>>>traffic>>>downlink", value: 9 },
  ] });
  assert.deepStrictEqual(vpn.parseStats(stats), { v1: { up: 823, down: 5013135 } });
  assert.deepStrictEqual(vpn.parseStats("{}\n"), {});
  assert.strictEqual(vpn.parseStats("garbage"), null);
  const access = [
    "2026/10/15 01:12:12.229340 from 198.51.100.7:43364 accepted tcp:dl.google.com:443 [vpn-in-0 -> vpn-out-0] email: v1",
    "2026/10/15 01:12:13.000001 from [2001:db8::9]:5001 accepted udp:1.1.1.1:53 [vpn-in-1 -> vpn-out-1] email: v2",
    "2026/10/15 01:12:14.000001 from 203.0.113.5:999 rejected  proxy/vless/encoding: invalid request version",
  ].join("\n");
  assert.deepStrictEqual(vpn.parseAccess(access), [
    { ip: "198.51.100.7", port: 43364, email: "v1" },
    { ip: "2001:db8::9", port: 5001, email: "v2" },
  ]);
  assert.deepStrictEqual(vpn.parseX25519("PrivateKey: EJyS\nPassword (PublicKey): bV-N\nHash32: eZ-s\n"), { privateKey: "EJyS", publicKey: "bV-N" });
  assert.deepStrictEqual(vpn.parseX25519("Private key: AA\nPublic key: BB\n"), { privateKey: "AA", publicKey: "BB" });
  const ss = "0 0 104.207.139.14:443 198.51.100.7:43364\n0 0 [::ffff:64.177.112.56]:443 [::ffff:203.0.113.8]:1000\n0 0 104.207.139.14:8443 198.51.100.7:1\n";
  assert.deepStrictEqual([...vpn.parseSsPeers(ss, 443)].sort(), ["198.51.100.7|43364", "203.0.113.8|1000"]);
});

// ── the runtime against a fake node ─────────────────────────────

function fakeNode() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-"));
  const etc = path.join(dir, "etc");
  const run = path.join(dir, "run");
  fs.mkdirSync(etc, { recursive: true });
  fs.mkdirSync(run, { recursive: true });
  const bin = path.join(dir, "xray");
  fs.writeFileSync(bin, "#!/bin/sh\n");
  const state = { addrs: new Set(["64.177.12.242"]), active: false, calls: [], users: new Map(), stats: {} };
  const ok = (stdout = "") => ({ code: 0, stdout, stderr: "" });
  const runFn = async (cmd, args) => {
    state.calls.push([path.basename(cmd), ...args].join(" "));
    if (cmd === "ip" && args[0] === "-4" && args[1] === "route") return ok("1.1.1.1 via 64.177.12.1 dev enp1s0 src 64.177.12.242 uid 0\n");
    if (cmd === "ip" && args[0] === "-4" && args[1] === "-o") return ok([...state.addrs].map((a) => `2: enp1s0    inet ${a}/32 scope global enp1s0`).join("\n"));
    if (cmd === "ip" && args[0] === "-o") return ok([...state.addrs].map((a) => `2: enp1s0    inet ${a}/32 scope global enp1s0`).join("\n"));
    if (cmd === "ip" && args[0] === "-6") return ok("");
    if (cmd === "ip" && args[0] === "addr" && args[1] === "add") {
      state.addrs.add(args[2].split("/")[0]);
      return ok();
    }
    if (cmd === "ip" && args[0] === "addr" && args[1] === "del") {
      state.addrs.delete(args[2].split("/")[0]);
      return ok();
    }
    if (cmd === "nft") return ok();
    if (cmd === "systemctl") {
      if (args[0] === "is-active") return state.active ? ok("active\n") : { code: 3, stdout: "inactive\n", stderr: "" };
      if (args[0] === "restart") state.active = true;
      if (args[0] === "disable") state.active = false;
      return ok();
    }
    if (cmd === bin && args[0] === "x25519") return ok("PrivateKey: PRIVKEY\nPassword (PublicKey): PUBKEY\nHash32: x\n");
    if (cmd === bin && args[0] === "version") return ok("Xray 26.3.27 (Xray, Penetrates Everything.)\n");
    if (cmd === bin && args[0] === "api") {
      assert.ok(String(args[2]).startsWith("--server="), `--server right after the command: ${args.join(" ")}`);
      const sub = args[1];
      if (sub === "statsquery") {
        if (args.includes("-reset")) {
          const out = JSON.stringify({ stat: Object.entries(state.stats).flatMap(([e, [u, d]]) => [{ name: `user>>>${e}>>>traffic>>>uplink`, value: u }, { name: `user>>>${e}>>>traffic>>>downlink`, value: d }]) });
          state.stats = {};
          return ok(out);
        }
        return ok("{}");
      }
      if (sub === "adu") {
        const doc = JSON.parse(fs.readFileSync(args[3], "utf-8"));
        for (const ib of doc.inbounds) for (const c of ib.settings.clients) state.users.set(`${ib.tag}/${c.email}`, c.id);
        return ok("Added");
      }
      if (sub === "rmu") {
        const tag = args[3].replace("-tag=", "");
        for (const e of args.slice(4)) state.users.delete(`${tag}/${e}`);
        return ok("Removed");
      }
      if (sub === "restartlogger") return ok();
    }
    if (cmd === "ss") return ok(args.includes("-K") ? "0 0 104.207.139.14:443 198.51.100.7:43364\n" : "");
    return { code: 1, stdout: "", stderr: `unexpected ${cmd} ${args.join(" ")}` };
  };
  const rt = vpn.createVpn({
    run: runFn,
    log: QUIET,
    settings: {
      etcDir: etc,
      libDir: path.join(dir, "lib"),
      runDir: run,
      bin,
      pinnedSha: path.join(dir, "no-pin"),
      netplanDir: path.join(dir, "netplan"),
      chown: false,
      systemctl: "systemctl",
    },
  });
  return { dir, etc, run, bin, state, rt };
}

test("runtime: enable adds the entry IPs, writes the config + guard, starts Xray", async () => {
  const n = fakeNode();
  const r = await n.rt.enable({ entries: ["104.207.139.14"], dest: "dl.google.com" });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.deepStrictEqual(
    { publicKey: r.body.publicKey, entries: r.body.entries, port: r.body.port, flow: r.body.flow, serverNames: r.body.serverNames },
    { publicKey: "PUBKEY", entries: ["104.207.139.14"], port: 443, flow: "xtls-rprx-vision", serverNames: ["dl.google.com"] }
  );
  assert.strictEqual(r.body.shortIds.length, 2);
  assert.ok(n.state.addrs.has("104.207.139.14"), "entry address added live");
  assert.ok(fs.existsSync(path.join(n.dir, "netplan", "61-netrun-vpn.yaml")), "and persisted in its own drop-in");
  assert.ok(n.state.calls.some((c) => c.startsWith("nft -f ")));
  assert.ok(n.state.calls.includes("systemctl enable netrun-vpn-xray.service"));
  assert.ok(n.state.active);
  const cfg = JSON.parse(fs.readFileSync(path.join(n.etc, "xray.json"), "utf-8"));
  assert.strictEqual(cfg.inbounds[0].listen, "104.207.139.14");
  const again = await n.rt.enable({ entries: ["104.207.139.14"], dest: "dl.google.com" });
  assert.strictEqual(again.body.publicKey, "PUBKEY", "the keys are kept");
  assert.strictEqual(n.state.calls.filter((c) => c === "systemctl restart netrun-vpn-xray.service").length, 1, "the same params restart nothing");
  assert.strictEqual((await n.rt.enable({ entries: [], dest: "x.com" })).status, 400);
  n.rt.stopLoops();
});

test("runtime: users go in and out through the API, the removed ones lose their connections", async () => {
  const n = fakeNode();
  await n.rt.enable({ entries: ["104.207.139.14", "64.177.112.56"], dest: "dl.google.com" });
  let r = await n.rt.putUsers({ users: [{ id: U1, email: "v1" }, { id: U2, email: "v2" }] });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.deepStrictEqual([r.body.added, r.body.removed, r.body.restarted], [2, 0, false]);
  assert.deepStrictEqual([...n.state.users.keys()].sort(), ["vpn-in-0/v1", "vpn-in-0/v2", "vpn-in-1/v1", "vpn-in-1/v2"]);
  // v2's connection shows up in the access log, then v2 goes
  fs.writeFileSync(path.join(n.run, "access.log"), "2026/10/15 01:12:12.229340 from 198.51.100.7:43364 accepted tcp:dl.google.com:443 [vpn-in-0 -> vpn-out-0] email: v2\n");
  assert.strictEqual(await n.rt.readAccessLog(), 1);
  assert.ok(!fs.existsSync(path.join(n.run, "access.log.1")), "the rotated log is dropped at once");
  r = await n.rt.putUsers({ users: [{ id: U1, email: "v1" }] });
  assert.deepStrictEqual([r.body.added, r.body.removed, r.body.killed], [0, 1, 1]);
  assert.deepStrictEqual([...n.state.users.keys()].sort(), ["vpn-in-0/v1", "vpn-in-1/v1"]);
  assert.ok(n.state.calls.some((c) => /^ss -K .* dst 198\.51\.100\.7 and dport = :43364 \)$/.test(c)));
  const cfg = JSON.parse(fs.readFileSync(path.join(n.etc, "xray.json"), "utf-8"));
  assert.deepStrictEqual(cfg.inbounds[1].settings.clients.map((c) => c.email), ["v1"], "the file follows (a restart keeps the users)");
  assert.strictEqual((await n.rt.putUsers({ users: [{ id: "nope", email: "v1" }] })).status, 400);
  n.rt.stopLoops();
});

test("runtime: traffic batches, acknowledged and folded when nobody reads them", async () => {
  const n = fakeNode();
  await n.rt.enable({ entries: ["104.207.139.14"], dest: "dl.google.com" });
  n.state.stats = { v1: [100, 2000] };
  assert.strictEqual(await n.rt.meterTick(), 1);
  assert.strictEqual(await n.rt.meterTick(), null, "nothing moved: no batch");
  n.state.stats = { v1: [1, 2], v2: [0, 50] };
  assert.strictEqual(await n.rt.meterTick(), 2);
  let u = await n.rt.usage({});
  assert.deepStrictEqual(u.body.batches.map((b) => [b.seq, b.users]), [[1, { v1: { up: 100, down: 2000 } }], [2, { v1: { up: 1, down: 2 }, v2: { up: 0, down: 50 } }]]);
  u = await n.rt.usage({ ack: "1" });
  assert.deepStrictEqual(u.body.batches.map((b) => b.seq), [2]);
  assert.strictEqual(u.body.seq, 2);
  // a fresh runtime reads the same meter file
  const again = vpn.createVpn({ run: async () => ({ code: 1, stdout: "", stderr: "" }), log: QUIET, settings: n.rt.settings });
  assert.deepStrictEqual((await again.usage({})).body.batches.map((b) => b.seq), [2]);
  n.rt.stopLoops();
});

test("runtime: too many unread batches fold together, no byte lost", async () => {
  const n = fakeNode();
  n.rt.settings.maxBatches = 3;
  await n.rt.enable({ entries: ["104.207.139.14"], dest: "dl.google.com" });
  for (let i = 0; i < 6; i += 1) {
    n.state.stats = { v1: [1, 10] };
    await n.rt.meterTick();
  }
  const b = (await n.rt.usage({})).body.batches;
  assert.strictEqual(b.length, 3);
  const total = b.reduce((acc, x) => acc + x.users.v1.up + x.users.v1.down, 0);
  assert.strictEqual(total, 66);
  assert.deepStrictEqual(b.map((x) => x.seq), [4, 5, 6]);
  n.rt.stopLoops();
});

test("runtime: disable stops Xray, drops the table and the entry addresses", async () => {
  const n = fakeNode();
  await n.rt.enable({ entries: ["104.207.139.14"], dest: "dl.google.com" });
  const r = await n.rt.disable();
  assert.strictEqual(r.status, 200);
  assert.ok(n.state.calls.includes("systemctl disable --now netrun-vpn-xray.service"));
  assert.ok(n.state.calls.includes("nft delete table inet netrun_vpn"));
  assert.ok(!n.state.addrs.has("104.207.139.14"));
  assert.ok(n.state.addrs.has("64.177.12.242"), "the primary IPv4 is never touched");
  const s = await n.rt.status();
  assert.strictEqual(s.enabled, false);
});

test("handleRoute: the /vpn/* table", async () => {
  const calls = [];
  const fake = {
    status: async () => ({ success: true }),
    enable: async (b) => (calls.push(["enable", b]), { status: 200, body: {} }),
    disable: async () => (calls.push(["disable"]), { status: 200, body: {} }),
    putUsers: async (b) => (calls.push(["users", b]), { status: 200, body: {} }),
    usage: async (q) => (calls.push(["usage", q]), { status: 200, body: {} }),
    kill: async (b) => (calls.push(["kill", b]), { status: 200, body: {} }),
  };
  assert.strictEqual(await vpn.handleRoute(fake, "GET", "/pergb/status", {}, {}), null);
  assert.strictEqual((await vpn.handleRoute(fake, "GET", "/vpn/status", {}, {})).status, 200);
  await vpn.handleRoute(fake, "POST", "/vpn/enable", {}, { a: 1 });
  await vpn.handleRoute(fake, "PUT", "/vpn/users", {}, { users: [] });
  await vpn.handleRoute(fake, "GET", "/vpn/usage", { ack: "3" }, {});
  await vpn.handleRoute(fake, "POST", "/vpn/kill", {}, { emails: ["v1"] });
  assert.deepStrictEqual(calls.map((c) => c[0]), ["enable", "users", "usage", "kill"]);
  assert.strictEqual((await vpn.handleRoute(fake, "DELETE", "/vpn/users", {}, {})).status, 404);
});
