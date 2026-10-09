"use strict";

// Pay-per-GB v2 — pergb_runtime.js: the 3proxy-pergb cfgs and the per-GB
// haproxy cfg against golden files (testdata/), the exact 3proxy 0.9.3 ACL
// operation names, the enable params, apply() against a fake systemd (files,
// modes, idempotence, rolling restart order on a family change, the stale-range
// cleanup, crash recovery from the start stamps), the refusals (binary hash,
// uid, guard) and enable.json / sharedRange / disable.
// Run with: node --test node_runtime/node_agent/pergb_runtime.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const rt = require("./pergb_runtime.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-pergb-runtime-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const GOLDEN = path.join(__dirname, "testdata");
const SECRET = "GoldenSecretGoldenSecretGoldenSecret0123";
const IPV4 = "203.0.113.10";
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Every operation name 3proxy 0.9.3 accepts in an ACL (conf.c, h_ace).
const OPS_093 = new Set([
  "CONNECT", "BIND", "UDPASSOC", "ICMPASSOC", "HTTP_GET", "HTTP_PUT", "HTTP_POST", "HTTP_HEAD", "HTTP_OTHER",
  "HTTP_CONNECT", "HTTP", "HTTPS", "FTP_GET", "FTP_PUT", "FTP_LIST", "FTP_DATA", "FTP", "ADMIN", "DNSRESOLVE",
]);

function params(over = {}) {
  const n = rt.normalizeParams({ base: 31000, count: 1000, procs: 2, egressIpv4: IPV4, family: "dualstack", maxConns: 8000, ...over });
  assert.ok(n.ok, JSON.stringify(n));
  return n.params;
}

// ── rendering ────────────────────────────────────────────────────────────

test("cfgs and haproxy cfg equal the golden files (I4)", () => {
  const p = params();
  for (const r of rt.procRanges(p.base, p.count, p.procs)) {
    const want = fs.readFileSync(path.join(GOLDEN, `pergb_${r.sp}.cfg.golden`), "utf8");
    assert.strictEqual(rt.renderCfg(p, r, SECRET), want, `pergb_${r.sp}.cfg`);
  }
  assert.strictEqual(rt.renderHaproxy(p), fs.readFileSync(path.join(GOLDEN, "pergb_haproxy.cfg.golden"), "utf8"));
});

test("cfg: header marker, 0.9.3 ACL names only, no daemon/setuid, maxconn layout, every port twice", () => {
  const p = params();
  const [a, b] = rt.procRanges(p.base, p.count, p.procs);
  assert.deepStrictEqual([a.first, a.last, b.first, b.last], [31000, 31499, 31500, 31999]);
  const text = rt.renderCfg(p, a, SECRET);
  const lines = text.trimEnd().split("\n");
  assert.strictEqual(lines[0], `# netrun-pergb v1 sp=31000 first=31000 last=31499 ipv4=${IPV4}`);
  assert.match(lines[0], /^# netrun-pergb v1 sp=(\d+) first=(\d+) last=(\d+) ipv4=(\S+)$/);
  for (const bad of [/^daemon\b/m, /^setuid\b/m, /^setgid\b/m, /^users\b/m, /^flush\b/m, /^monitor\b/m]) {
    assert.doesNotMatch(text, bad);
  }
  for (const want of ["authcache none", `radius ${SECRET} 127.0.0.1`, "auth radius", "deny * * * 25,465,587", "deny *",
    "timeouts 1 3 30 60 180 1800 15 60", "logdump 262144 262144", "log /var/log/netrun-pergb/p31000.log H",
    'logformat "- +_G%Y%m%d%H%M%S.%. %N %p %E %U %C %c %i %e %R %r %I %O %n"', "nserver 127.0.0.1", "nserver ::1"]) {
    assert.ok(lines.includes(want), `missing line: ${want}`);
  }
  const allow = lines.filter((l) => l.startsWith("allow "));
  assert.strictEqual(allow.length, 1);
  const ops = allow[0].split(/\s+/)[5].split(",");
  for (const op of ops) assert.ok(OPS_093.has(op), `${op} is not a 3proxy 0.9.3 operation`);
  for (const forbidden of ["BIND", "UDPASSOC", "ICMPASSOC", "ADMIN", "DNSRESOLVE", "FTP", "FTP_GET", "FTP_PUT", "FTP_LIST", "FTP_DATA", "HTTP", "HTTPS"]) {
    assert.ok(!ops.includes(forbidden), `${forbidden} must not be allowed`);
  }
  assert.deepStrictEqual(ops, ["CONNECT", "HTTP_GET", "HTTP_PUT", "HTTP_POST", "HTTP_HEAD", "HTTP_OTHER", "HTTP_CONNECT"]);
  // order: log / auth / ACL before the first service line (3proxy copies them per service)
  const firstSvc = lines.findIndex((l) => /^(socks|proxy) /.test(l));
  for (const k of ["log ", "logformat ", "auth radius", "allow ", "deny *", "authcache none", "radius "]) {
    assert.ok(lines.findIndex((l) => l.startsWith(k)) < firstSvc, `${k} after the first service`);
  }
  // maxconn: 20000 right before the base port, 2000 before 31001, never again
  const mc = lines.map((l, i) => [l, i]).filter(([l]) => l.startsWith("maxconn "));
  assert.deepStrictEqual(mc.map(([l]) => l), ["maxconn 20000", "maxconn 2000"]);
  assert.strictEqual(lines[mc[0][1] + 1], `socks -64 -a -p31000 -i127.0.0.4 -e${IPV4} -e::1`);
  assert.strictEqual(lines[mc[0][1] + 2], `proxy -64 -n -a -p31000 -i127.0.0.3 -e${IPV4} -e::1`);
  assert.strictEqual(lines[mc[1][1] + 1], `socks -64 -a -p31001 -i127.0.0.4 -e${IPV4} -e::1`);
  for (let port = 31000; port <= 31499; port += 1) {
    assert.ok(lines.includes(`socks -64 -a -p${port} -i127.0.0.4 -e${IPV4} -e::1`), `socks ${port}`);
    assert.ok(lines.includes(`proxy -64 -n -a -p${port} -i127.0.0.3 -e${IPV4} -e::1`), `proxy ${port}`);
  }
  assert.strictEqual(lines.filter((l) => /^(socks|proxy) /.test(l)).length, 1000);
  // the second range has no base port: maxconn 2000 only
  const second = rt.renderCfg(p, b, SECRET);
  assert.deepStrictEqual(second.split("\n").filter((l) => l.startsWith("maxconn ")), ["maxconn 2000"]);
  assert.match(second, /^log \/var\/log\/netrun-pergb\/p31500\.log H$/m);
});

test("cfg: family ipv6_only renders -6, no deny line without deny ports, custom logdump", () => {
  const p = params({ family: "ipv6_only", denyPorts: [], logdumpBytes: 131072 });
  const text = rt.renderCfg(p, rt.procRanges(31000, 1000, 2)[0], SECRET);
  assert.match(text, new RegExp(`^socks -6 -a -p31000 -i127\\.0\\.0\\.4 -e${IPV4.replace(/\./g, "\\.")} -e::1$`, "m"));
  assert.match(text, /^proxy -6 -n -a -p31000 -i127\.0\.0\.3 /m);
  assert.doesNotMatch(text, / -64 /);
  assert.doesNotMatch(text, /^deny \* \* \* /m);
  assert.match(text, /^logdump 131072 131072$/m);
  assert.throws(() => rt.renderCfg(p, rt.procRanges(31000, 1000, 2)[0], "short"));
});

test("haproxy: maxconn 2 x maxConns + 1000, the range bind, TLS/SOCKS split, rejects the rest", () => {
  const p = params({ base: 10000, maxConns: 3000, egressIpv4: "198.51.100.7", dedicatedIpv4: "198.51.100.7" });
  const t = rt.renderHaproxy(p, { crtList: "/x/crt-list", runDir: "/run/x" });
  assert.match(t, /^    maxconn 7000$/m);
  assert.match(t, /^    bind 198\.51\.100\.7:10000-10999$/m);
  assert.match(t, /^    bind abns@netrun_pergb_tls accept-proxy ssl crt-list \/x\/crt-list alpn http\/1\.1$/m);
  assert.match(t, /^    stats socket \/run\/x\/haproxy\.sock mode 600 level admin$/m);
  assert.match(t, /^    server socks 127\.0\.0\.4$/m);
  assert.match(t, /^    server http 127\.0\.0\.3$/m);
  assert.match(t, /^    server tls abns@netrun_pergb_tls send-proxy-v2$/m);
  assert.match(t, /tcp-request content accept if \{ req\.len gt 0 \} \{ req\.payload\(0,1\) -m bin 05 \}\n    tcp-request content reject\n/);
  assert.match(t, /^    log-format "%ci:%cp %fp %bi:%bp %Tt %B %U"$/m);
  assert.match(t, /^    log \/dev\/log local1 info$/m);
  assert.doesNotMatch(t, /abns@netrun_tls\b/, "never the per-piece TLS socket");
});

test("procRanges / normalizeParams / slice drop-ins", () => {
  assert.deepStrictEqual(rt.procRanges(10000, 1000, 2).map((r) => [r.first, r.last, r.unit]), [
    [10000, 10499, "netrun-pergb-3proxy@10000.service"],
    [10500, 10999, "netrun-pergb-3proxy@10500.service"],
  ]);
  assert.deepStrictEqual(rt.procRanges(10000, 7, 3).map((r) => [r.first, r.last]), [[10000, 10002], [10003, 10005], [10006, 10006]]);
  const bad = (o) => rt.normalizeParams({ base: 31000, egressIpv4: IPV4, ...o });
  assert.strictEqual(bad({ base: 80 }).error, "bad_params");
  assert.strictEqual(bad({ base: 65000 }).error, "bad_params"); // 65000 + 999 > 65535
  assert.strictEqual(bad({ egressIpv4: null }).error, "bad_params");
  assert.strictEqual(bad({ egressIpv4: "2001:db8::1" }).error, "bad_params");
  assert.strictEqual(bad({ family: "ipv4_only" }).error, "bad_params");
  assert.strictEqual(bad({ dedicatedIpv4: "198.51.100.1" }).error, "bad_params"); // != egress
  assert.strictEqual(bad({ denyPorts: [25, 0] }).error, "bad_params");
  assert.strictEqual(bad({ sliceMemMax: "100M" }).error, "bad_params");
  assert.strictEqual(bad({ procs: 0 }).error, "bad_params");
  const ok = rt.normalizeParams({ base: "31000", egressIpv4: IPV4, sliceMemMax: "2G", denyPorts: [587, 25, 25] });
  assert.ok(ok.ok);
  assert.deepStrictEqual(
    [ok.params.count, ok.params.last, ok.params.procs, ok.params.family, ok.params.maxConns, ok.params.sliceMemMax, ok.params.denyPorts],
    [1000, 31999, 2, "dualstack", 8000, 2 * 1024 ** 3, [25, 587]],
  );
  const p = params();
  assert.strictEqual(rt.tasksMax(p), 2 * 1000 + 8000 + 500);
  const d = rt.renderSliceDropin(p);
  assert.match(d, /^CPUWeight=50$/m);
  assert.match(d, /^MemoryMax=1536M$/m);
  assert.match(d, /^MemoryHigh=1305M$/m); // 85 %
  assert.match(d, /^TasksMax=10500$/m);
  assert.match(rt.renderParentSliceDropin(p), /^\[Slice\]\nCPUWeight=50$/m);
  assert.strictEqual(rt.cgroupPath("netrun-pergb-3proxy@31000.service"), "/netrun.slice/netrun-pergb.slice/netrun-pergb-3proxy@31000.service");
  for (let i = 0; i < 20; i += 1) assert.match(rt.newSecret(), /^[A-Za-z0-9]{40}$/);
});

// ── apply against a fake node ────────────────────────────────────────────

const BIN = Buffer.from("fake 3proxy-pergb binary\n");

function makeNode(name, over = {}) {
  const root = fs.mkdtempSync(path.join(TMP, `${name}-`));
  const d = (p) => path.join(root, p);
  fs.mkdirSync(d("bin"), { recursive: true });
  fs.writeFileSync(d("bin/3proxy-pergb"), over.bin || BIN, { mode: 0o755 });
  fs.writeFileSync(d("bin/3proxy-pergb.sha256"), `${over.installedHash || sha(BIN)}  3proxy-pergb\n`);
  fs.writeFileSync(d("pinned.sha256"), `${over.pinnedHash || sha(BIN)}  3proxy-pergb\n`);
  fs.mkdirSync(d("etc"), { recursive: true });
  fs.writeFileSync(
    d("etc/passwd"),
    over.passwd || "root:x:0:0:root:/root:/bin/bash\nnetrun-radius:x:998:998::/nonexistent:/usr/sbin/nologin\nnetrun-pergb:x:65533:65533::/nonexistent:/usr/sbin/nologin\n",
  );
  fs.writeFileSync(d("etc/group"), over.group || "root:x:0:\nhaproxy:x:120:\nnetrun-radius:x:998:\nnetrun-pergb:x:65533:\n");
  fs.writeFileSync(d("guard"), "#!/usr/bin/env bash\n");
  const settings = rt.readSettings({
    NETRUN_PERGB_BIN: d("bin/3proxy-pergb"),
    NETRUN_PERGB_BIN_SHA256: d("bin/3proxy-pergb.sha256"),
    NETRUN_PERGB_PINNED_SHA256: d("pinned.sha256"),
    NETRUN_PERGB_CFG_DIR: d("opt/cfg"),
    NETRUN_PERGB_HAPROXY_CFG: d("opt/haproxy/haproxy.cfg"),
    NETRUN_PERGB_ETC_DIR: d("etc-pergb"),
    NETRUN_PERGB_LOG_DIR: "/var/log/netrun-pergb",
    NETRUN_PERGB_RUN_DIR: d("run"),
    NETRUN_PERGB_SYSTEMD_DIR: d("systemd"),
    NETRUN_PERGB_CRT_LIST: "/etc/netrun/tls/crt-list",
    NETRUN_PERGB_PASSWD: d("etc/passwd"),
    NETRUN_PERGB_GROUP: d("etc/group"),
    NETRUN_PROXY_GUARD_BIN: d("guard"),
    NETRUN_PERGB_CHOWN: "0",
  });
  // The fake systemd: unit states, the wants of the target, and the stamps
  // the units' ExecStartPre / ExecReload write (the sha256 of the cfg loaded).
  const units = new Map();
  const st = (u) => {
    if (!units.has(u)) units.set(u, { active: false, enabled: false });
    return units.get(u);
  };
  const calls = [];
  const guard = { loaded: over.guardLoaded !== false, applyFixes: over.guardApplyFixes !== false };
  const failStart = new Set(over.failStart || []);
  const stamp = (u) => {
    const m = /^netrun-pergb-3proxy@(\d+)\.service$/.exec(u);
    const file = m ? path.join(settings.cfgDir, `pergb_${m[1]}.cfg`) : u === rt.HAPROXY_UNIT ? settings.haproxyCfg : null;
    if (!file) return;
    const name = m ? m[1] : "haproxy";
    fs.mkdirSync(path.join(settings.runDir, "applied"), { recursive: true });
    fs.writeFileSync(path.join(settings.runDir, "applied", `${name}.sha256`), `${sha(fs.readFileSync(file))}  -\n`);
  };
  const startUnit = (u) => {
    if (failStart.has(u)) return;
    if (!st(u).active) stamp(u);
    st(u).active = true;
    if (u === rt.TARGET) {
      for (const [n, s] of units) if (s.enabled && n.startsWith("netrun-pergb-3proxy@")) startUnit(n);
      startUnit(rt.HAPROXY_UNIT);
      startUnit(rt.CERTS_PATH_UNIT);
    }
  };
  const run = async (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (cmd === "nft") {
      return guard.loaded
        ? { code: 0, stdout: "table inet netrun_proxy_guard {\n\tchain output {\n\t\tmeta skuid 65535 jump proxy\n\t\tmeta skuid 65533 jump pergb\n\t}\n}\n", stderr: "" }
        : { code: 0, stdout: "table inet netrun_proxy_guard {\n\tchain output {\n\t\tmeta skuid 65535 jump proxy\n\t}\n}\n", stderr: "" };
    }
    if (cmd === "bash" && args[1] === "apply") {
      if (guard.applyFixes) guard.loaded = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (cmd === "ss") return { code: 0, stdout: "", stderr: "" };
    assert.strictEqual(cmd, "systemctl", `unexpected command ${cmd}`);
    const [verb, ...rest] = args;
    switch (verb) {
      case "is-active":
        return { code: st(rest[0]).active ? 0 : 3, stdout: st(rest[0]).active ? "active\n" : "inactive\n", stderr: "" };
      case "is-enabled":
        return { code: st(rest[0]).enabled ? 0 : 1, stdout: st(rest[0]).enabled ? "enabled\n" : "disabled\n", stderr: "" };
      case "enable":
        for (const u of rest) st(u).enabled = true;
        return { code: 0, stdout: "", stderr: "" };
      case "disable": {
        const now = rest[0] === "--now";
        for (const u of rest.filter((x) => x !== "--now")) {
          st(u).enabled = false;
          if (now) st(u).active = false;
        }
        return { code: 0, stdout: "", stderr: "" };
      }
      case "start":
        for (const u of rest) startUnit(u);
        return { code: rest.some((u) => failStart.has(u)) ? 1 : 0, stdout: "", stderr: "" };
      case "restart":
        st(rest[0]).active = false;
        startUnit(rest[0]);
        return { code: 0, stdout: "", stderr: "" };
      case "reload":
        stamp(rest[0]);
        return { code: 0, stdout: "", stderr: "" };
      case "stop":
        for (const u of rest) {
          st(u).active = false;
          if (u === rt.TARGET) for (const [n, s] of units) if (n.startsWith("netrun-pergb") || n === rt.RADIUS_SOCKET) s.active = false;
        }
        return { code: 0, stdout: "", stderr: "" };
      case "show": {
        const names = rest.filter((x) => !x.startsWith("--"));
        const blocks = names.map((u, i) => `ActiveState=${st(u).active ? "active" : "inactive"}\nMainPID=${st(u).active ? 1000 + i : 0}\nUnitFileState=${st(u).enabled ? "enabled" : "disabled"}`);
        return { code: 0, stdout: blocks.join("\n\n") + "\n", stderr: "" };
      }
      case "daemon-reload":
      case "set-property":
        return { code: 0, stdout: "", stderr: "" };
      default:
        throw new Error(`fake systemctl: ${args.join(" ")}`);
    }
  };
  const ready = [];
  const deps = {
    settings,
    run,
    sleep: async () => {},
    now: () => Date.parse("2026-10-09T12:00:00Z"),
    log: { log() {}, error() {} },
    waitReady: async (unit) => {
      ready.push(unit);
      calls.push(`READY ${unit}`);
      return over.ready ? over.ready(unit) : true;
    },
  };
  return { root, d, settings, units, st, calls, deps, guard, ready };
}

const ENABLE = { base: 31000, count: 1000, procs: 2, egressIpv4: IPV4, dedicatedIpv4: null, family: "dualstack", maxConns: 8000, geo: "us", subnets: "0000-fffe", addrKey: "a2V5", probe: { password: "pw", canary: [["192.0.2.1", 443]] } };
const mode = (p) => fs.statSync(p).mode & 0o7777;
const mutating = (calls) => calls.filter((c) => /^systemctl (start|restart|reload|stop|enable|disable|daemon-reload|set-property)\b/.test(c));

test("apply: fresh node — files, modes, secret, enable.json, target enabled and started", async () => {
  const n = makeNode("fresh");
  const res = await rt.apply(ENABLE, n.deps);
  assert.ok(res.ok, JSON.stringify(res));
  assert.ok(res.secretCreated);
  const secret = fs.readFileSync(n.settings.secretPath, "utf8");
  assert.match(secret, /^[A-Za-z0-9]{40}$/, "40 chars, no newline");
  assert.strictEqual(mode(n.settings.secretPath), 0o640);
  for (const sp of [31000, 31500]) {
    const f = rt.cfgPathFor(n.settings, sp);
    assert.strictEqual(mode(f), 0o640);
    assert.match(fs.readFileSync(f, "utf8"), new RegExp(`^radius ${secret} 127\\.0\\.0\\.1$`, "m"));
    assert.ok(n.st(`netrun-pergb-3proxy@${sp}.service`).enabled, "wanted by the target");
    assert.ok(n.st(`netrun-pergb-3proxy@${sp}.service`).active);
  }
  assert.strictEqual(mode(n.settings.haproxyCfg), 0o640);
  assert.ok(n.st(rt.TARGET).enabled && n.st(rt.TARGET).active);
  assert.ok(n.st(rt.HAPROXY_UNIT).active);
  assert.match(fs.readFileSync(path.join(n.settings.systemdDir, "netrun-pergb.slice.d/50-netrun-enable.conf"), "utf8"), /^MemoryMax=1536M$/m);
  assert.match(fs.readFileSync(path.join(n.settings.systemdDir, "netrun.slice.d/50-netrun-enable.conf"), "utf8"), /^CPUWeight=50$/m);
  assert.ok(n.calls.includes("systemctl daemon-reload"));
  // enable.json
  assert.strictEqual(mode(n.settings.enablePath), 0o600);
  const e = JSON.parse(fs.readFileSync(n.settings.enablePath, "utf8"));
  assert.deepStrictEqual(
    { version: e.version, enabled: e.enabled, base: e.base, count: e.count, last: e.last, egressIpv4: e.egressIpv4, dedicatedIpv4: e.dedicatedIpv4, family: e.family, maxConns: e.maxConns, logdumpBytes: e.logdumpBytes, denyPorts: e.denyPorts, sliceMemMax: e.sliceMemMax, cpuWeight: e.cpuWeight },
    { version: 1, enabled: true, base: 31000, count: 1000, last: 31999, egressIpv4: IPV4, dedicatedIpv4: null, family: "dualstack", maxConns: 8000, logdumpBytes: 262144, denyPorts: [25, 465, 587], sliceMemMax: 1536 * 1024 * 1024, cpuWeight: 50 },
  );
  assert.deepStrictEqual(e.procs.map((p) => [p.sp, p.first, p.last, p.unit]), [
    [31000, 31000, 31499, "netrun-pergb-3proxy@31000.service"],
    [31500, 31500, 31999, "netrun-pergb-3proxy@31500.service"],
  ]);
  assert.deepStrictEqual(e.params, ENABLE, "the raw params (addrKey, probe) are kept for L3");
  assert.strictEqual(e.enabledAt, "2026-10-09T12:00:00.000Z");
  assert.deepStrictEqual(rt.sharedRange(n.settings), { enabled: true, base: 31000, last: 31999, count: 1000, egressIpv4: IPV4, dedicatedIpv4: null });
  const s = await rt.status(n.deps);
  assert.deepStrictEqual(s.procs.map((p) => [p.unit, p.first, p.last, p.active]), [
    ["netrun-pergb-3proxy@31000.service", 31000, 31499, true],
    ["netrun-pergb-3proxy@31500.service", 31500, 31999, true],
  ]);
  assert.ok(s.enabled && s.haproxy.active && s.target.active && s.target.enabled);
});

test("apply: the same params again write nothing and restart / reload / start nothing", async () => {
  const n = makeNode("idem");
  assert.ok((await rt.apply(ENABLE, n.deps)).ok);
  const snap = (dir) => {
    const out = {};
    const walk = (p) => {
      for (const f of fs.readdirSync(p)) {
        const q = path.join(p, f);
        const s = fs.statSync(q);
        if (s.isDirectory()) walk(q);
        else out[q] = [s.mtimeMs, s.ino, s.mode, sha(fs.readFileSync(q))];
      }
    };
    walk(dir);
    return out;
  };
  const before = snap(n.root);
  const secret = fs.readFileSync(n.settings.secretPath, "utf8");
  n.calls.length = 0;
  const res = await rt.apply(ENABLE, { ...n.deps, now: () => Date.parse("2026-10-09T13:00:00Z") });
  assert.ok(res.ok, JSON.stringify(res));
  assert.deepStrictEqual(res.changed, []);
  assert.deepStrictEqual([res.restarted, res.reloaded, res.started, res.stopped], [[], [], [], []]);
  assert.deepStrictEqual(mutating(n.calls), [], "no systemd change at all");
  assert.deepStrictEqual(snap(n.root), before, "no file rewritten");
  assert.strictEqual(fs.readFileSync(n.settings.secretPath, "utf8"), secret, "the secret is kept");
  assert.strictEqual(JSON.parse(fs.readFileSync(n.settings.enablePath, "utf8")).updatedAt, "2026-10-09T12:00:00.000Z");
});

test("apply: a family change re-renders both cfgs and restarts the two units one after the other", async () => {
  const n = makeNode("family");
  assert.ok((await rt.apply(ENABLE, n.deps)).ok);
  n.calls.length = 0;
  const res = await rt.apply({ ...ENABLE, family: "ipv6_only" }, n.deps);
  assert.ok(res.ok, JSON.stringify(res));
  assert.deepStrictEqual(res.restarted, ["netrun-pergb-3proxy@31000.service", "netrun-pergb-3proxy@31500.service"]);
  assert.deepStrictEqual(res.reloaded, [], "the haproxy cfg does not depend on the family");
  const seq = n.calls.filter((c) => /^systemctl restart|^READY|^systemctl (start|stop|reload)/.test(c));
  assert.deepStrictEqual(seq, [
    "systemctl restart netrun-pergb-3proxy@31000.service",
    "READY netrun-pergb-3proxy@31000.service",
    "systemctl restart netrun-pergb-3proxy@31500.service",
    "READY netrun-pergb-3proxy@31500.service",
  ]);
  for (const sp of [31000, 31500]) assert.match(fs.readFileSync(rt.cfgPathFor(n.settings, sp), "utf8"), /^socks -6 -a /m);
  assert.strictEqual(JSON.parse(fs.readFileSync(n.settings.enablePath, "utf8")).family, "ipv6_only");
  // and back to the same params: nothing more
  n.calls.length = 0;
  const again = await rt.apply({ ...ENABLE, family: "ipv6_only" }, n.deps);
  assert.deepStrictEqual([again.restarted, mutating(n.calls)], [[], []]);
});

test("apply: a unit that does not come back stops the rolling restart; the next apply finishes it", async () => {
  let failFirst = true;
  const n = makeNode("rolling", { ready: (u) => !(failFirst && u.endsWith("@31000.service")) });
  assert.ok((await rt.apply(ENABLE, n.deps)).ok);
  n.calls.length = 0;
  const res = await rt.apply({ ...ENABLE, family: "ipv6_only" }, n.deps);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, "restart_failed");
  assert.ok(!n.calls.includes("systemctl restart netrun-pergb-3proxy@31500.service"), "the other range keeps serving");
  failFirst = false;
  n.calls.length = 0;
  const res2 = await rt.apply({ ...ENABLE, family: "ipv6_only" }, n.deps);
  assert.ok(res2.ok, JSON.stringify(res2));
  assert.deepStrictEqual(res2.restarted, ["netrun-pergb-3proxy@31500.service"], "31000 already runs the new cfg (stamp)");
});

test("apply: a cfg written before a crash (stamp = old cfg) is restarted by the next apply", async () => {
  const n = makeNode("crash");
  assert.ok((await rt.apply(ENABLE, n.deps)).ok);
  // the agent wrote the new cfg and died before the restart
  const p6 = rt.normalizeParams({ ...ENABLE, family: "ipv6_only" }).params;
  const secret = fs.readFileSync(n.settings.secretPath, "utf8");
  fs.writeFileSync(rt.cfgPathFor(n.settings, 31500), rt.renderCfg(p6, rt.procRanges(31000, 1000, 2)[1], secret), { mode: 0o640 });
  n.calls.length = 0;
  const res = await rt.apply({ ...ENABLE, family: "ipv6_only" }, n.deps);
  assert.ok(res.ok);
  assert.deepStrictEqual(res.restarted, ["netrun-pergb-3proxy@31000.service", "netrun-pergb-3proxy@31500.service"]);
});

test("apply: a new base drops the old ranges (stopped, disabled, cfg removed) and reloads haproxy", async () => {
  const n = makeNode("rebase");
  assert.ok((await rt.apply(ENABLE, n.deps)).ok);
  n.calls.length = 0;
  const res = await rt.apply({ ...ENABLE, base: 32000 }, n.deps);
  assert.ok(res.ok, JSON.stringify(res));
  assert.deepStrictEqual(res.stopped.sort(), ["netrun-pergb-3proxy@31000.service", "netrun-pergb-3proxy@31500.service"]);
  assert.ok(n.calls.includes("systemctl disable --now netrun-pergb-3proxy@31000.service"));
  assert.ok(!fs.existsSync(rt.cfgPathFor(n.settings, 31000)) && !fs.existsSync(rt.cfgPathFor(n.settings, 31500)));
  assert.deepStrictEqual(fs.readdirSync(n.settings.cfgDir).sort(), ["pergb_32000.cfg", "pergb_32500.cfg"]);
  assert.deepStrictEqual(res.reloaded, [rt.HAPROXY_UNIT]);
  assert.deepStrictEqual(res.started.sort(), ["netrun-pergb-3proxy@32000.service", "netrun-pergb-3proxy@32500.service"]);
  assert.match(fs.readFileSync(n.settings.haproxyCfg, "utf8"), /^    bind 203\.0\.113\.10:32000-32999$/m);
  assert.deepStrictEqual(rt.sharedRange(n.settings).base, 32000);
});

test("apply: binary hash mismatch is refused before anything is written or started", async () => {
  for (const [name, over] of [
    ["binary", { bin: Buffer.from("stock 3proxy\n") }],
    ["installed-sha", { installedHash: "0".repeat(64) }],
    ["pinned", { pinnedHash: "1".repeat(64) }],
  ]) {
    const n = makeNode(`hash-${name}`, over);
    const res = await rt.apply(ENABLE, n.deps);
    assert.strictEqual(res.ok, false, name);
    assert.strictEqual(res.error, "binary_hash_mismatch", name);
    assert.ok(!fs.existsSync(n.settings.cfgDir), `${name}: no cfg written`);
    assert.ok(!fs.existsSync(n.settings.enablePath), `${name}: no enable.json`);
    assert.deepStrictEqual(n.calls, [], `${name}: no command run`);
  }
  const n = makeNode("hash-missing");
  fs.unlinkSync(n.settings.binPath);
  assert.strictEqual((await rt.apply(ENABLE, n.deps)).error, "binary_hash_mismatch");
  assert.ok(rt.checkBinary(makeNode("hash-ok").settings).ok);
});

test("apply: uid 65533 taken by someone else / per-GB not installed / bad params are refused", async () => {
  const taken = makeNode("uid", { passwd: "root:x:0:0::/:/bin/sh\nintruder:x:65533:65533::/:/bin/sh\nnetrun-radius:x:998:998::/:/bin/sh\n" });
  const r1 = await rt.apply(ENABLE, taken.deps);
  assert.strictEqual(r1.error, "uid_taken");
  assert.match(r1.detail, /intruder/);
  const wrong = makeNode("uid2", { passwd: "netrun-pergb:x:1001:1001::/:/bin/sh\nnetrun-radius:x:998:998::/:/bin/sh\n" });
  assert.strictEqual((await rt.apply(ENABLE, wrong.deps)).error, "uid_taken");
  const none = makeNode("uid3", { passwd: "root:x:0:0::/:/bin/sh\n" });
  assert.strictEqual((await rt.apply(ENABLE, none.deps)).error, "pergb_not_installed");
  const badp = makeNode("badp");
  const r4 = await rt.apply({ ...ENABLE, egressIpv4: null }, badp.deps);
  assert.strictEqual(r4.error, "bad_params");
  assert.deepStrictEqual(badp.calls, []);
});

test("apply: without the guard's uid-65533 chain nothing starts; netrun-proxy-guard apply is tried first", async () => {
  const n = makeNode("guard", { guardLoaded: false, guardApplyFixes: false });
  const res = await rt.apply(ENABLE, n.deps);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, "proxy_guard_missing");
  assert.ok(n.calls.some((c) => c.startsWith("bash ") && c.endsWith(" apply")), "guard apply tried");
  assert.deepStrictEqual(mutating(n.calls), [], "nothing enabled or started");
  assert.ok(!fs.existsSync(n.settings.cfgDir) && !fs.existsSync(n.settings.enablePath), "nothing written");
  const fixed = makeNode("guard2", { guardLoaded: false, guardApplyFixes: true });
  const ok = await rt.apply(ENABLE, fixed.deps);
  assert.ok(ok.ok, JSON.stringify(ok));
  assert.ok(fixed.st(rt.TARGET).active);
});

test("apply: an existing secret is kept (a stray newline normalised); a broken one is replaced", async () => {
  const n = makeNode("secret");
  fs.mkdirSync(n.settings.etcDir, { recursive: true });
  fs.writeFileSync(n.settings.secretPath, `${SECRET}\n`, { mode: 0o600 });
  const res = await rt.apply(ENABLE, n.deps);
  assert.ok(res.ok && !res.secretCreated);
  assert.strictEqual(fs.readFileSync(n.settings.secretPath, "utf8"), SECRET);
  assert.strictEqual(mode(n.settings.secretPath), 0o640);
  assert.match(fs.readFileSync(rt.cfgPathFor(n.settings, 31000), "utf8"), new RegExp(`^radius ${SECRET} 127`, "m"));
  fs.writeFileSync(n.settings.secretPath, "short");
  const res2 = await rt.apply(ENABLE, n.deps);
  assert.ok(res2.ok && res2.secretCreated);
  assert.notStrictEqual(fs.readFileSync(n.settings.secretPath, "utf8"), SECRET);
  assert.deepStrictEqual(res2.restarted, ["netrun-pergb-3proxy@31000.service", "netrun-pergb-3proxy@31500.service"]);
});

test("disable: target disabled and stopped, enable.json kept with enabled=false, RADIUS socket kept unless stopRadius", async () => {
  const n = makeNode("disable");
  assert.ok((await rt.apply(ENABLE, n.deps)).ok);
  n.st(rt.RADIUS_SOCKET).active = true;
  const res = await rt.disable({}, n.deps);
  assert.ok(res.ok, JSON.stringify(res));
  assert.ok(!n.st(rt.TARGET).enabled && !n.st(rt.TARGET).active);
  for (const u of ["netrun-pergb-3proxy@31000.service", "netrun-pergb-3proxy@31500.service", rt.HAPROXY_UNIT]) {
    assert.ok(!n.st(u).active, `${u} stopped`);
    assert.ok(res.stopped.includes(u), `${u} reported`);
  }
  assert.ok(n.st(rt.RADIUS_SOCKET).active, "the RADIUS socket is started again");
  const e = JSON.parse(fs.readFileSync(n.settings.enablePath, "utf8"));
  assert.strictEqual(e.enabled, false);
  assert.strictEqual(e.base, 31000);
  assert.deepStrictEqual(rt.sharedRange(n.settings), { enabled: false, base: 31000, last: 31999, count: 1000, egressIpv4: IPV4, dedicatedIpv4: null });
  assert.ok(fs.existsSync(rt.cfgPathFor(n.settings, 31000)), "the cfgs stay for a re-enable");
  // re-enable starts everything again without rewriting the cfgs
  n.calls.length = 0;
  const again = await rt.apply(ENABLE, n.deps);
  assert.ok(again.ok);
  assert.deepStrictEqual(again.restarted, []);
  assert.ok(again.started.includes(rt.TARGET) && n.st(rt.TARGET).enabled);
  assert.strictEqual(JSON.parse(fs.readFileSync(n.settings.enablePath, "utf8")).enabled, true);
  // stopRadius
  const n2 = makeNode("disable2");
  assert.ok((await rt.apply(ENABLE, n2.deps)).ok);
  n2.st(rt.RADIUS_SOCKET).active = true;
  const r2 = await rt.disable({ stopRadius: true }, n2.deps);
  assert.ok(r2.stopped.includes(rt.RADIUS_SOCKET));
  assert.ok(!n2.st(rt.RADIUS_SOCKET).active);
});

test("sharedRange: null without enable.json or with a foreign file; option B reports the dedicated IPv4", async () => {
  const n = makeNode("range");
  assert.strictEqual(rt.sharedRange(n.settings), null);
  fs.mkdirSync(n.settings.etcDir, { recursive: true });
  fs.writeFileSync(n.settings.enablePath, "{not json");
  assert.strictEqual(rt.sharedRange(n.settings), null);
  fs.unlinkSync(n.settings.enablePath);
  const res = await rt.apply({ ...ENABLE, egressIpv4: "198.51.100.9", dedicatedIpv4: "198.51.100.9", base: 10000 }, n.deps);
  assert.ok(res.ok, JSON.stringify(res));
  assert.deepStrictEqual(rt.sharedRange(n.settings), { enabled: true, base: 10000, last: 10999, count: 1000, egressIpv4: "198.51.100.9", dedicatedIpv4: "198.51.100.9" });
});

test("detectPrimaryIpv4: the src of the default route, null when unknown", async () => {
  const run = (out, code = 0) => async () => ({ code, stdout: out, stderr: "" });
  assert.strictEqual(await rt.detectPrimaryIpv4({ run: run("1.1.1.1 via 45.76.0.1 dev enp1s0 src 45.76.10.20 uid 0 \\    cache \n") }), "45.76.10.20");
  assert.strictEqual(await rt.detectPrimaryIpv4({ run: run("", 2) }), null);
  assert.strictEqual(await rt.detectPrimaryIpv4({ run: run("1.1.1.1 dev wg0 table 51820\n") }), null);
});
