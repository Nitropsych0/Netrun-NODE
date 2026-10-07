"use strict";

// Audit FO-08 — https_hostnames.js: hostname validation, change detection
// (no rewrite / no issuance when the set is unchanged and every certificate is
// good), the issuance trigger for a missing / expiring / expired / foreign
// certificate, one issuance at a time (systemd-run, or a detached spawn where
// it is missing), the switch and the missing / outdated netrun-https.
// Certificates are real (openssl, self-signed); commands are injected stubs.
// Run with: node --test node_runtime/node_agent/https_hostnames.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { EventEmitter } = require("events");
const lib = require("./https_hostnames.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-https-hostnames-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const DAY = 86_400_000;
const H1 = "us1.proxy.netrun.lol";
const H2 = "us2.proxy.netrun.lol";

let opensslOk = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  opensslOk = false;
}

// A real self-signed certificate + key (PEM text, as netrun-https builds it).
function makePem(name, days) {
  const dir = fs.mkdtempSync(path.join(TMP, "cert-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", String(days),
    "-subj", `/CN=${name}`, "-addext", `subjectAltName=DNS:${name}`,
  ], { stdio: "ignore" });
  return fs.readFileSync(path.join(dir, "c.pem"), "utf-8") + fs.readFileSync(path.join(dir, "k.pem"), "utf-8");
}

let pems = null;
function certs() {
  if (!pems) pems = { h1: makePem(H1, 90), h2: makePem(H2, 90), other: makePem("other.example.com", 90) };
  return pems;
}

// One fresh node: paths, a netrun-https with `certs`, stubbed commands, fake
// timers (n.tick() runs the queued ones and waits for them).
function setup({ systemdRun = true, bin = "#!/bin/bash\ncmd_certs() { :; }\n", env = {}, runningStates = [], maxPolls } = {}) {
  const root = fs.mkdtempSync(path.join(TMP, "node-"));
  const binPath = path.join(root, "netrun-https");
  if (bin !== null) fs.writeFileSync(binPath, bin, { mode: 0o755 });
  const tlsDir = path.join(root, "tls");
  fs.mkdirSync(path.join(tlsDir, "hosts"), { recursive: true });
  const calls = [];
  const states = [...runningStates];
  const spawned = [];
  const timerQueue = [];
  let nowMs = Date.now();
  const svc = lib.createHttpsHostnames({
    timers: {
      setTimeout: (fn, ms) => {
        const t = { fn, ms, unref() {} };
        timerQueue.push(t);
        return t;
      },
      clearTimeout: (t) => {
        const i = timerQueue.indexOf(t);
        if (i >= 0) timerQueue.splice(i, 1);
      },
    },
    ...(maxPolls ? { maxPolls } : {}),
    env: {
      NODE_AGENT_HTTPS_SYNC_BIN: binPath,
      NETRUN_HTTPS_HOSTNAMES_FILE: path.join(root, "etc", "https-hostnames"),
      NETRUN_HTTPS_TLS_DIR: tlsDir,
      PATH: "/nonexistent",
      ...env,
    },
    now: () => nowMs,
    findBin: (name) => (name === "systemctl" ? "/stub/systemctl" : name === "systemd-run" && systemdRun ? "/stub/systemd-run" : null),
    run: async (cmd, args) => {
      calls.push([path.basename(cmd), ...args]);
      if (cmd.endsWith("systemctl")) return { code: 3, stdout: `${states.shift() || "inactive"}\n`, stderr: "" };
      if (cmd.endsWith("systemd-run")) return { code: 0, stdout: "", stderr: "" };
      return { code: 1, stdout: "", stderr: "unexpected" };
    },
    spawnFn: (cmd, args, opts) => {
      const c = new EventEmitter();
      c.exitCode = null;
      c.signalCode = null;
      c.unref = () => {};
      spawned.push({ cmd, args, opts, child: c });
      return c;
    },
    log: { log() {}, error() {} },
  });
  const hostnamesFile = path.join(root, "etc", "https-hostnames");
  const pemPath = (h) => path.join(tlsDir, "hosts", `${h}.pem`);
  return {
    svc, calls, spawned, root, binPath, tlsDir, hostnamesFile, timerQueue,
    starts: () => calls.filter((c) => c[0] === "systemd-run"),
    pem: (h, text) => fs.writeFileSync(pemPath(h), text, { mode: 0o600 }),
    // What netrun-https leaves after a verified reload serving these names:
    // the crt-list lines and served.json with each PEM's sha256.
    serve: (names, { bound = true, crtList = true } = {}) => {
      const sha = (h) => crypto.createHash("sha256").update(fs.readFileSync(pemPath(h))).digest("hex");
      const entries = names.map((h) => ({ hostname: h, pem: pemPath(h), sha256: sha(h) }));
      fs.writeFileSync(path.join(tlsDir, "served.json"), JSON.stringify({
        version: 1, stamp: "f".repeat(64), at: "2026-10-08T00:00:00Z", crtList: path.join(tlsDir, "crt-list"), crtListBound: bound, hostnames: entries,
      }, null, 2));
      if (crtList) {
        fs.writeFileSync(path.join(tlsDir, "crt-list"), [path.join(tlsDir, "node.pem"), ...names.map((h) => `${pemPath(h)} ${h}`)].join("\n") + "\n");
      }
    },
    tick: async () => {
      const due = timerQueue.splice(0);
      for (const t of due) await t.fn();
    },
    setNow: (ms) => { nowMs = ms; },
  };
}

test("normalizeHostname: RFC 1123 FQDN, lowercased, one trailing dot dropped; IPs, wildcards, bad labels refused", () => {
  assert.strictEqual(lib.normalizeHostname("US1.Proxy.Netrun.LOL"), H1);
  assert.strictEqual(lib.normalizeHostname(` ${H1}. `), H1);
  assert.strictEqual(lib.normalizeHostname("xn--p1ai.xn--p1ai"), "xn--p1ai.xn--p1ai");
  assert.strictEqual(lib.normalizeHostname("a-1.b2.example.com"), "a-1.b2.example.com");
  const label63 = "a".repeat(63);
  assert.strictEqual(lib.normalizeHostname(`${label63}.com`), `${label63}.com`);
  for (const bad of [
    "", "localhost", "45.32.10.20", "1.2.3.4.5", "*.proxy.netrun.lol", "bad..name.com", "-bad.com", "bad-.com",
    "bad_name.com", "a b.com", "x.123", `${"a".repeat(64)}.com`, `${"a.".repeat(127)}com`, "x.com..", null, 42, {}, ["a.com"],
  ]) {
    assert.strictEqual(lib.normalizeHostname(bad), null, JSON.stringify(bad));
  }
});

test("parseHostnamesBody: 0..8 names, deduplicated + sorted; 400 shapes for anything else", () => {
  assert.deepStrictEqual(lib.parseHostnamesBody({ hostnames: [] }), { ok: true, hostnames: [] });
  assert.deepStrictEqual(lib.parseHostnamesBody({ hostnames: [H2, H1.toUpperCase(), `${H1}.`] }), { ok: true, hostnames: [H1, H2] });
  const eight = Array.from({ length: 8 }, (_, i) => `n${i}.proxy.netrun.lol`);
  assert.strictEqual(lib.parseHostnamesBody({ hostnames: [...eight, ...eight] }).ok, true, "duplicates do not count");
  assert.strictEqual(lib.parseHostnamesBody({ hostnames: [...eight, "n9.proxy.netrun.lol"] }).error, "too_many_hostnames");
  assert.strictEqual(lib.parseHostnamesBody({ hostnames: Array(65).fill(H1) }).error, "too_many_hostnames");
  for (const body of [null, [], "x", {}, { hostnames: "a.com" }, { hostnames: [H1, "1.2.3.4"] }, { hostnames: [H1, 7] }]) {
    const r = lib.parseHostnamesBody(body);
    assert.strictEqual(r.ok, false, JSON.stringify(body));
    assert.strictEqual(r.error, "invalid_hostnames", JSON.stringify(body));
  }
  assert.deepStrictEqual(lib.parseHostnamesFile(`${H2}\n# c\nbad_name\n${H1}\r\n${H2}\n`), [H1, H2]);
  assert.strictEqual(lib.hostnamesFileText([H1, H2]), `${H1}\n${H2}\n`);
  assert.strictEqual(lib.hostnamesFileText([]), "");
});

test("evaluateCertificate: X509 checkHost + validTo; ok = names the host and valid > 1 day; renewDue < 7 days", { skip: !opensslOk && "no openssl" }, () => {
  const { h1, other } = certs();
  const now = Date.now();
  const good = lib.evaluateCertificate(H1, h1, now);
  assert.strictEqual(good.ok, true);
  assert.strictEqual(good.error, null);
  assert.strictEqual(good.renewDue, false);
  assert.ok(Math.abs(Date.parse(good.notAfter) - (now + 90 * DAY)) < 120_000, good.notAfter);
  const soon = lib.evaluateCertificate(H1, h1, now + 85 * DAY);
  assert.deepStrictEqual([soon.ok, soon.error, soon.renewDue], [true, null, true], "5 days left: still ok, renewal due");
  const lastDay = lib.evaluateCertificate(H1, h1, now + 89.5 * DAY);
  assert.deepStrictEqual([lastDay.ok, lastDay.error], [false, "expiring"]);
  const expired = lib.evaluateCertificate(H1, h1, now + 91 * DAY);
  assert.deepStrictEqual([expired.ok, expired.error, expired.renewDue], [false, "expired", true]);
  const foreign = lib.evaluateCertificate(H1, other, now);
  assert.deepStrictEqual([foreign.ok, foreign.error, foreign.renewDue], [false, "name_mismatch", true]);
  assert.deepStrictEqual(lib.evaluateCertificate(H1, null, now), { hostname: H1, ok: false, notAfter: null, error: "missing", renewDue: true });
  assert.strictEqual(lib.evaluateCertificate(H1, "garbage", now).error, "unreadable");
  assert.strictEqual(lib.evaluateCertificate(H1, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", now).error, "unreadable");
});

test("POST: a new set is written atomically and starts ONE detached issuance via systemd-run", async () => {
  const n = setup();
  const out = await n.svc.post({ hostnames: [H2, H1] });
  assert.strictEqual(out.status, 200, JSON.stringify(out.body));
  assert.strictEqual(out.body.success, true);
  assert.strictEqual(out.body.changed, true);
  assert.strictEqual(out.body.issuing, true);
  assert.strictEqual(out.body.started, true);
  assert.deepStrictEqual(out.body.hostnames, [H1, H2]);
  assert.deepStrictEqual(out.body.certs.map((c) => [c.hostname, c.ok, c.error]), [[H1, false, "missing"], [H2, false, "missing"]]);
  assert.ok(!("renewDue" in out.body.certs[0]), "renewDue stays internal");
  assert.strictEqual(fs.readFileSync(n.hostnamesFile, "utf-8"), `${H1}\n${H2}\n`);
  assert.ok(!fs.existsSync(`${n.hostnamesFile}.tmp`));
  assert.deepStrictEqual(n.starts(), [[
    "systemd-run", "--unit", "netrun-https-certs", "--collect", "--quiet",
    `--setenv=NETRUN_HTTPS_HOSTNAMES_FILE=${n.hostnamesFile}`, `--setenv=NETRUN_HTTPS_TLS_DIR=${n.tlsDir}`,
    n.binPath, "certs",
  ]]);
  assert.deepStrictEqual(n.spawned, [], "no plain spawn where systemd-run exists");
});

test("POST: unchanged set + good certificates = no rewrite, no issuance", { skip: !opensslOk && "no openssl" }, async () => {
  const n = setup();
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H2}\n${H1}\n`); // same set, another order
  const before = fs.statSync(n.hostnamesFile).mtimeMs;
  n.pem(H1, certs().h1);
  n.pem(H2, certs().h2);
  n.serve([H1, H2]);
  fs.utimesSync(n.hostnamesFile, new Date(0), new Date(0));
  const out = await n.svc.post({ hostnames: [H1, H2.toUpperCase()] });
  assert.strictEqual(out.status, 200);
  assert.strictEqual(out.body.changed, false);
  assert.strictEqual(out.body.started, false);
  assert.strictEqual(out.body.issuing, false);
  assert.ok(out.body.certs.every((c) => c.ok && c.error === null && c.notAfter), JSON.stringify(out.body.certs));
  assert.strictEqual(fs.statSync(n.hostnamesFile).mtimeMs, 0, "file not rewritten");
  assert.ok(before > 0);
  assert.deepStrictEqual(n.starts(), []);
});

test("POST: unchanged set but a certificate missing / expiring within 7 days / expired / foreign -> issuance (no rewrite)", { skip: !opensslOk && "no openssl" }, async () => {
  const cases = [
    ["missing", (n) => n.pem(H1, certs().h1), 0],
    ["renewal due (5 days left, still ok)", (n) => { n.pem(H1, certs().h1); n.pem(H2, certs().h2); }, 85 * DAY],
    ["expired", (n) => { n.pem(H1, certs().h1); n.pem(H2, certs().h2); }, 91 * DAY],
    ["foreign certificate", (n) => { n.pem(H1, certs().h1); n.pem(H2, certs().other); }, 0],
  ];
  for (const [label, prep, shift] of cases) {
    const n = setup();
    fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
    fs.writeFileSync(n.hostnamesFile, `${H1}\n${H2}\n`);
    fs.utimesSync(n.hostnamesFile, new Date(0), new Date(0));
    prep(n);
    n.setNow(Date.now() + shift);
    const out = await n.svc.post({ hostnames: [H1, H2] });
    assert.strictEqual(out.status, 200, label);
    assert.strictEqual(out.body.changed, false, label);
    assert.strictEqual(out.body.started, true, label);
    assert.strictEqual(out.body.issuing, true, label);
    assert.strictEqual(n.starts().length, 1, label);
    assert.strictEqual(fs.statSync(n.hostnamesFile).mtimeMs, 0, `${label}: file not rewritten`);
  }
});

test("POST: never a second issuance while netrun-https-certs runs; lastError from netrun-https's note", async () => {
  const n = setup({ runningStates: ["active"] });
  fs.writeFileSync(path.join(n.tlsDir, "hosts", `${H1}.error`), "dns: A 9.9.9.9, not 45.32.10.20\n");
  const out = await n.svc.post({ hostnames: [H1] });
  assert.strictEqual(out.status, 200);
  assert.strictEqual(out.body.changed, true, "the list is still written (the running pass re-reads it)");
  assert.strictEqual(out.body.started, false);
  assert.strictEqual(out.body.issuing, true);
  assert.deepStrictEqual(n.starts(), []);
  assert.deepStrictEqual(n.calls[0], ["systemctl", "is-active", "netrun-https-certs.service"]);
  assert.strictEqual(out.body.certs[0].lastError, "dns: A 9.9.9.9, not 45.32.10.20");
  // An empty list is a change too (stale PEMs go, crt-list shrinks): issuance.
  const out2 = await n.svc.post({ hostnames: [] });
  assert.deepStrictEqual([out2.body.changed, out2.body.started, out2.body.hostnames], [true, true, []]);
  assert.strictEqual(fs.readFileSync(n.hostnamesFile, "utf-8"), "");
});

test("POST: no systemd-run -> detached spawn, env passed, no second child while it runs", async () => {
  const n = setup({ systemdRun: false });
  let out = await n.svc.post({ hostnames: [H1] });
  assert.deepStrictEqual([out.status, out.body.started, out.body.issuing], [200, true, true]);
  assert.strictEqual(n.spawned.length, 1);
  const s = n.spawned[0];
  assert.deepStrictEqual([s.cmd, s.args, s.opts.detached, s.opts.stdio], [n.binPath, ["certs"], true, "ignore"]);
  assert.strictEqual(s.opts.env.NETRUN_HTTPS_HOSTNAMES_FILE, n.hostnamesFile);
  out = await n.svc.post({ hostnames: [H2] });
  assert.deepStrictEqual([out.body.changed, out.body.started, out.body.issuing], [true, false, true]);
  assert.strictEqual(n.spawned.length, 1, "still running: no second child");
  s.child.exitCode = 0;
  out = await n.svc.post({ hostnames: [H2] });
  assert.deepStrictEqual([out.body.changed, out.body.started], [false, true], "certificate still missing: next run");
  assert.strictEqual(n.spawned.length, 2);
});

test("POST: switch off -> 404; bad body -> 400; no netrun-https -> 409 missing; old netrun-https -> 409 outdated", async () => {
  let n = setup({ env: { NODE_AGENT_HTTPS_HOSTNAMES: "off" } });
  let out = await n.svc.post({ hostnames: [H1] });
  assert.deepStrictEqual([out.status, out.body.error], [404, "https_hostnames_disabled"]);
  assert.ok(!fs.existsSync(n.hostnamesFile));
  assert.strictEqual((await n.svc.view()).enabled, false);
  n = setup();
  out = await n.svc.post({ hostnames: ["*.netrun.lol"] });
  assert.deepStrictEqual([out.status, out.body.error], [400, "invalid_hostnames"]);
  n = setup({ bin: null });
  out = await n.svc.post({ hostnames: [H1] });
  assert.deepStrictEqual([out.status, out.body.error], [409, "https_frontend_missing"]);
  assert.ok(!fs.existsSync(n.hostnamesFile), "nothing written");
  assert.strictEqual((await n.svc.view()).frontendInstalled, false);
  n = setup({ bin: "#!/bin/bash\ncase $1 in sync) ;; esac\n" });
  out = await n.svc.post({ hostnames: [H1] });
  assert.deepStrictEqual([out.status, out.body.error], [409, "https_frontend_outdated"]);
  assert.deepStrictEqual(n.starts(), []);
});

test("POST: systemd-run failing -> 500 issue_start_failed (the list is written; a retry starts it)", async () => {
  const n = setup();
  const svc = lib.createHttpsHostnames({
    env: { NODE_AGENT_HTTPS_SYNC_BIN: n.binPath, NETRUN_HTTPS_HOSTNAMES_FILE: n.hostnamesFile, NETRUN_HTTPS_TLS_DIR: n.tlsDir },
    findBin: (name) => `/stub/${name}`,
    run: async (cmd) => (cmd.endsWith("systemctl") ? { code: 3, stdout: "inactive\n", stderr: "" } : { code: 1, stdout: "", stderr: "Failed to start transient service unit" }),
    log: { log() {}, error() {} },
  });
  const out = await svc.post({ hostnames: [H1] });
  assert.strictEqual(out.status, 500);
  assert.strictEqual(out.body.error, "issue_start_failed");
  assert.match(out.body.detail, /Failed to start transient service unit/);
  assert.strictEqual(fs.readFileSync(n.hostnamesFile, "utf-8"), `${H1}\n`);
});

test("view / healthStatus: list, certificate status, issuing; /health cached for a few seconds", { skip: !opensslOk && "no openssl" }, async () => {
  const n = setup({ runningStates: ["inactive", "active"] });
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H1}\n`);
  n.pem(H1, certs().h1);
  n.serve([H1]);
  const v = await n.svc.view();
  assert.deepStrictEqual(
    { enabled: v.enabled, frontendInstalled: v.frontendInstalled, hostnames: v.hostnames, issuing: v.issuing, ok: v.certs[0].ok },
    { enabled: true, frontendInstalled: true, hostnames: [H1], issuing: false, ok: true }
  );
  const h1 = await n.svc.healthStatus();
  assert.strictEqual(h1.issuing, true);
  fs.writeFileSync(n.hostnamesFile, `${H1}\n${H2}\n`);
  assert.strictEqual(await n.svc.healthStatus(), h1, "cached");
  n.setNow(Date.now() + 6000);
  const h2 = await n.svc.healthStatus();
  assert.deepStrictEqual(h2.hostnames, [H1, H2]);
});

test("ok means SERVED: a good PEM is not_served until served.json (verified reload) lists it with this sha256 and the crt-list names it", { skip: !opensslOk && "no openssl" }, async () => {
  const n = setup();
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H1}\n`);
  n.pem(H1, certs().h1);
  const verdict = async () => {
    const c = (await n.svc.view()).certs[0];
    return [c.ok, c.error];
  };
  assert.deepStrictEqual(await verdict(), [false, "not_served"], "no served.json yet");
  n.serve([H1]);
  assert.deepStrictEqual(await verdict(), [true, null]);
  assert.strictEqual((await n.svc.view()).servedAt, "2026-10-08T00:00:00Z");
  // A renewed PEM in place, haproxy not reloaded with it yet: sha256 differs.
  n.pem(H1, makePem(H1, 90));
  assert.deepStrictEqual(await verdict(), [false, "not_served"], "PEM changed since the verified reload");
  n.serve([H1]);
  assert.deepStrictEqual(await verdict(), [true, null]);
  // The crt-list no longer names it (rewritten, reload pending).
  fs.writeFileSync(path.join(n.tlsDir, "crt-list"), `${path.join(n.tlsDir, "node.pem")}\n`);
  assert.deepStrictEqual(await verdict(), [false, "not_served"], "crt-list line gone");
  // haproxy.cfg not migrated to the crt-list (crtListBound false), or served.json garbage.
  n.serve([H1], { bound: false });
  assert.deepStrictEqual(await verdict(), [false, "not_served"], "not bound");
  fs.writeFileSync(path.join(n.tlsDir, "served.json"), "{not json");
  assert.deepStrictEqual(await verdict(), [false, "not_served"], "unreadable served.json");
  // not_served is not a reason for lego: an unchanged POST starts nothing.
  const out = await n.svc.post({ hostnames: [H1] });
  assert.deepStrictEqual([out.body.changed, out.body.started, out.body.pending, out.body.certs[0].error], [false, false, false, "not_served"]);
  assert.deepStrictEqual(n.starts(), []);
  // Pure helpers.
  assert.strictEqual(lib.parseServed(null).size, 0);
  assert.strictEqual(lib.isServed({ hostname: H1, pemPath: "/x", pemSha256: "a", served: new Map(), crtListText: "" }), false);
  const m = lib.parseServed(JSON.stringify({ version: 1, crtListBound: true, hostnames: [{ hostname: H1, pem: "/t//hosts/a.pem", sha256: "AB" }] }));
  assert.ok(lib.isServed({ hostname: H1, pemPath: "/t/hosts/a.pem", pemSha256: "ab", served: m, crtListText: `/t/node.pem\n/t/hosts/a.pem ${H1}\n` }));
  assert.ok(!lib.isServed({ hostname: H1, pemPath: "/t/hosts/a.pem", pemSha256: "ab", served: m, crtListText: `# /t/hosts/a.pem ${H1}\n` }));
});

test("pending: a change POSTed while netrun-https certs runs (or finishes) starts ONE more run once the unit is inactive", async () => {
  // systemctl is-active answers, in order: POST 1, POST 2, poll 1, poll 2, poll 3.
  const n = setup({ runningStates: ["active", "active", "active", "deactivating", "inactive"] });
  const out = await n.svc.post({ hostnames: [H1] });
  assert.deepStrictEqual([out.body.changed, out.body.started, out.body.issuing, out.body.pending], [true, false, true, true]);
  assert.deepStrictEqual(n.starts(), []);
  assert.strictEqual(n.timerQueue.length, 1);
  assert.strictEqual(n.timerQueue[0].ms, 20_000, "polled every 20 s");
  // A second POST while pending: still one pending run, one timer.
  const out2 = await n.svc.post({ hostnames: [H1, H2] });
  assert.deepStrictEqual([out2.body.started, out2.body.pending], [false, true]);
  assert.strictEqual(n.timerQueue.length, 1);
  await n.tick(); // active
  assert.deepStrictEqual(n.starts(), []);
  await n.tick(); // deactivating: still running
  assert.deepStrictEqual(n.starts(), []);
  await n.tick(); // inactive -> the one more run
  assert.strictEqual(n.starts().length, 1);
  assert.strictEqual(n.timerQueue.length, 0, "nothing left scheduled");
  assert.strictEqual((await n.svc.view()).pending, false);
  await n.tick();
  assert.strictEqual(n.starts().length, 1, "exactly one more run");
});

test("pending: bounded — a run that never ends is given up after maxPolls checks (no start)", async () => {
  const n = setup({ runningStates: Array(10).fill("active"), maxPolls: 3 });
  await n.svc.post({ hostnames: [H1] });
  for (let i = 0; i < 5; i += 1) await n.tick();
  assert.deepStrictEqual(n.starts(), []);
  assert.strictEqual(n.timerQueue.length, 0);
  assert.strictEqual((await n.svc.view()).pending, false);
});

test("start(): at agent start, a list that differs from certs-applied (the last certs / renew pass) gets one more run; equal = nothing", async () => {
  let n = setup();
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H1}\n${H2}\n`);
  assert.strictEqual(n.svc.start(), true, "no certs-applied yet");
  assert.strictEqual(n.timerQueue.length, 1);
  assert.ok(n.timerQueue[0].ms <= 5000, "soon after start");
  await n.tick();
  assert.strictEqual(n.starts().length, 1);
  n = setup();
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H2}\n${H1}\n`);
  fs.writeFileSync(path.join(n.tlsDir, "certs-applied"), `${H1}\n${H2}\n`);
  assert.strictEqual(n.svc.start(), false, "same set");
  fs.writeFileSync(path.join(n.tlsDir, "certs-applied"), `${H1}\n`);
  assert.strictEqual(n.svc.start(), true, "H2 never applied");
  n.svc.stop();
  assert.strictEqual(n.timerQueue.length, 0);
  // Empty list, nothing applied: nothing to do. Switch off / no netrun-https: never.
  n = setup();
  assert.strictEqual(n.svc.start(), false);
  n = setup({ env: { NODE_AGENT_HTTPS_HOSTNAMES: "0" } });
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H1}\n`);
  assert.strictEqual(n.svc.start(), false);
  n = setup({ bin: null });
  fs.mkdirSync(path.dirname(n.hostnamesFile), { recursive: true });
  fs.writeFileSync(n.hostnamesFile, `${H1}\n`);
  assert.strictEqual(n.svc.start(), false);
});
