"use strict";

// Audit FO-08 — HTTPS certificates for the node's DNS names, chosen by SNI.
//
// The orchestrator gives the node names like us1.proxy.netrun.lol (A record ->
// the node's IPv4) and hands customers https://login:pass@<name>:port lines;
// the node's Let's Encrypt IP certificate does not name them. This module is
// the agent side:
//   POST /https/hostnames {hostnames: [..]}  (API key) — 0..8 lowercase FQDNs;
//     the list goes to NETRUN_HTTPS_HOSTNAMES_FILE (/etc/netrun/https-hostnames,
//     atomically, only when the SET changed), and when it changed or a listed
//     name has no good certificate (missing / not for the name / expiring
//     within 7 days) `netrun-https certs` is started DETACHED
//     (systemd-run --unit netrun-https-certs --collect; never a second one
//     while it runs; a plain detached spawn where systemd-run is missing).
//     netrun-https does the ACME work (DNS gate, lego, crt-list, reload).
//   GET /https/hostnames (API key) — the list, per-name certificate status,
//     whether an issuance runs (or one more is pending).
//   /health httpsHostnames — the same, cached STATUS_TTL_MS.
// A name is `ok` only when haproxy SERVES its certificate: netrun-https writes
// <tls>/served.json after every verified reload (the names whose crt-list
// lines haproxy loaded, with each PEM's sha256); the name must be there with
// the sha256 of the PEM in place now, and the crt-list must still name it —
// else error "not_served" (the file is fine, haproxy does not serve it yet).
// A change that arrives while `certs` runs (or is just finishing) is not lost:
// one more run is PENDING and starts once the unit is inactive (polled every
// PENDING_POLL_MS, at most PENDING_MAX_POLLS times); at agent start, a list
// that differs from what the last certs / renew pass worked through
// (<tls>/certs-applied) gets one more run the same way.
// NODE_AGENT_HTTPS_HOSTNAMES=0 switches it off (POST answers 404); a node
// without netrun-https (NODE_AGENT_HTTPS_SYNC_BIN, /usr/local/sbin/netrun-https)
// answers 409.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn, execFile } = require("child_process");
const { envSwitch } = require("./hygiene.js");
const { findExecutable } = require("./egress.js");

const DEFAULT_BIN = "/usr/local/sbin/netrun-https";
const DEFAULT_HOSTNAMES_FILE = "/etc/netrun/https-hostnames";
const DEFAULT_TLS_DIR = "/etc/netrun/tls";
const UNIT = "netrun-https-certs";
const MAX_HOSTNAMES = 8;
const MAX_RAW_ENTRIES = 64;
const DAY_MS = 86_400_000;
// ok: valid for more than a day; issuance: less than 7 days left.
const OK_MARGIN_MS = DAY_MS;
const RENEW_MARGIN_MS = 7 * DAY_MS;
const STATUS_TTL_MS = 5000;
const PENDING_POLL_MS = 20_000;
const PENDING_MAX_POLLS = 90; // 30 min of a run still going: the renew timer takes over
const START_DELAY_MS = 5000;
const SERVED_FILE = "served.json";
const CRT_LIST_FILE = "crt-list";
const APPLIED_FILE = "certs-applied";
const RUNNING_STATES = new Set(["active", "activating", "reloading", "deactivating"]);

function readSettings(env = process.env) {
  return {
    enabled: envSwitch(env.NODE_AGENT_HTTPS_HOSTNAMES),
    // The same binary /deprovision runs `sync` with.
    bin: String(env.NODE_AGENT_HTTPS_SYNC_BIN || DEFAULT_BIN),
    hostnamesFile: String(env.NETRUN_HTTPS_HOSTNAMES_FILE || DEFAULT_HOSTNAMES_FILE),
    tlsDir: String(env.NETRUN_HTTPS_TLS_DIR || DEFAULT_TLS_DIR),
  };
}

// ── pure helpers ─────────────────────────────────────────────────────────

const LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const TLD_RE = /^[a-z]([a-z0-9-]*[a-z0-9])?$/;

// RFC 1123 host name with at least two labels, lowercased, one trailing dot
// dropped; labels of 1-63 letters / digits / inner hyphens, 253 in all, and a
// TLD that starts with a letter (so never an IPv4 literal). No wildcards
// (HTTP-01 cannot prove them). The same rule as netrun-https's
// https_hostnames: a name accepted here is never dropped there. null = invalid.
function normalizeHostname(raw) {
  if (typeof raw !== "string") return null;
  let h = raw.trim().toLowerCase();
  if (h.endsWith(".")) h = h.slice(0, -1);
  if (!h || h.length > 253) return null;
  const labels = h.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label.length > 63 || !LABEL_RE.test(label)) return null;
  }
  return TLD_RE.test(labels[labels.length - 1]) ? h : null;
}

// POST body -> { ok: true, hostnames } (normalized, deduplicated, sorted) or
// { ok: false, error, detail }.
function parseHostnamesBody(body) {
  const list = body && typeof body === "object" && !Array.isArray(body) ? body.hostnames : undefined;
  if (!Array.isArray(list)) {
    return { ok: false, error: "invalid_hostnames", detail: "body must be { hostnames: [string, ...] }" };
  }
  if (list.length > MAX_RAW_ENTRIES) {
    return { ok: false, error: "too_many_hostnames", detail: `at most ${MAX_HOSTNAMES} hostnames` };
  }
  const out = new Set();
  const invalid = [];
  for (const raw of list) {
    const h = normalizeHostname(raw);
    if (h) out.add(h);
    else invalid.push(typeof raw === "string" ? raw.slice(0, 260) : String(raw));
  }
  if (invalid.length) {
    return { ok: false, error: "invalid_hostnames", detail: `not a lowercase FQDN: ${invalid.slice(0, 8).join(", ")}` };
  }
  if (out.size > MAX_HOSTNAMES) {
    return { ok: false, error: "too_many_hostnames", detail: `at most ${MAX_HOSTNAMES} hostnames` };
  }
  return { ok: true, hostnames: [...out].sort() };
}

// The hostnames file -> normalized, deduplicated, sorted (invalid lines dropped).
function parseHostnamesFile(text) {
  const out = new Set();
  for (const line of String(text || "").split(/\r?\n/)) {
    const h = normalizeHostname(line);
    if (h) out.add(h);
  }
  return [...out].sort();
}

function sameHostnames(a, b) {
  return a.length === b.length && a.every((h, i) => h === b[i]);
}

function hostnamesFileText(hostnames) {
  return hostnames.length ? `${hostnames.join("\n")}\n` : "";
}

function pemFirstCertificate(text) {
  const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(String(text || ""));
  return m ? m[0] : null;
}

// One name's certificate status from its PEM text (null = no file):
//   { hostname, ok, notAfter, error, renewDue }
// ok = the certificate names the host and is valid for more than a day;
// renewDue = not ok, or less than 7 days left (POST starts an issuance).
// error: null | missing | unreadable | name_mismatch | expired | expiring.
function evaluateCertificate(hostname, pemText, nowMs = Date.now()) {
  const out = { hostname, ok: false, notAfter: null, error: null, renewDue: true };
  if (pemText === null || pemText === undefined) {
    out.error = "missing";
    return out;
  }
  let cert;
  try {
    const block = pemFirstCertificate(pemText);
    if (!block) throw new Error("no certificate block");
    cert = new crypto.X509Certificate(block);
  } catch {
    out.error = "unreadable";
    return out;
  }
  const validTo = cert.validToDate instanceof Date ? cert.validToDate : new Date(cert.validTo);
  const notAfterMs = validTo.getTime();
  out.notAfter = Number.isFinite(notAfterMs) ? validTo.toISOString() : null;
  if (!cert.checkHost(hostname)) out.error = "name_mismatch";
  else if (!Number.isFinite(notAfterMs) || notAfterMs <= nowMs) out.error = "expired";
  else if (notAfterMs <= nowMs + OK_MARGIN_MS) out.error = "expiring";
  out.ok = out.error === null;
  out.renewDue = !out.ok || notAfterMs <= nowMs + RENEW_MARGIN_MS;
  return out;
}

// served.json text -> Map hostname -> { pem, sha256 }. Empty when missing /
// unreadable / of another version, or when haproxy.cfg's TLS bind did not load
// the crt-list (crtListBound false): then no name is served by SNI.
function parseServed(text) {
  const out = new Map();
  if (text === null || text === undefined) return out;
  let j;
  try {
    j = JSON.parse(String(text));
  } catch {
    return out;
  }
  if (!j || j.version !== 1 || j.crtListBound !== true || !Array.isArray(j.hostnames)) return out;
  for (const e of j.hostnames) {
    if (e && typeof e.hostname === "string" && typeof e.sha256 === "string" && typeof e.pem === "string") {
      out.set(e.hostname, { pem: e.pem, sha256: e.sha256.toLowerCase() });
    }
  }
  return out;
}

// true when the crt-list text has the `<pemPath> <hostname>` line.
function crtListNames(crtListText, pemPath, hostname) {
  const want = path.resolve(pemPath);
  for (const line of String(crtListText || "").split(/\r?\n/)) {
    const f = line.trim().split(/\s+/);
    if (f.length >= 2 && !f[0].startsWith("#") && f[1] === hostname && path.resolve(f[0]) === want) return true;
  }
  return false;
}

// haproxy verifiably serves PEM pemPath (sha256 pemSha256) for hostname: the
// last verified reload loaded that very file for the name (served.json), and
// the crt-list still names it.
function isServed({ hostname, pemPath, pemSha256, served, crtListText }) {
  const e = served instanceof Map ? served.get(hostname) : null;
  return Boolean(
    e &&
      pemSha256 &&
      e.sha256 === pemSha256 &&
      path.resolve(e.pem) === path.resolve(pemPath) &&
      crtListNames(crtListText, pemPath, hostname)
  );
}

// ── io ───────────────────────────────────────────────────────────────────

function writeFileAtomic(filePath, text) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  const buf = Buffer.from(text, "utf-8");
  try {
    const fd = fs.openSync(tmp, "w", 0o644);
    try {
      let off = 0;
      while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      // nothing to clean
    }
    throw err;
  }
}

function runCommand(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, encoding: "utf-8" }, (err, stdout, stderr) => {
      const code = err ? (typeof err.code === "number" ? err.code : 1) : 0;
      resolve({ code, stdout: String(stdout || ""), stderr: String(stderr || (err && !stdout ? err.message : "")) });
    });
  });
}

function errText(err) {
  return String((err && err.message) || err);
}

// ── the service ──────────────────────────────────────────────────────────

function createHttpsHostnames({
  env = process.env,
  now = () => Date.now(),
  run = runCommand,
  spawnFn = spawn,
  findBin = (name) => findExecutable(name, env.PATH),
  log = console,
  timers = { setTimeout, clearTimeout },
  pollMs = PENDING_POLL_MS,
  maxPolls = PENDING_MAX_POLLS,
  startDelayMs = START_DELAY_MS,
} = {}) {
  let child = null; // the fallback's detached `netrun-https certs` (no systemd-run)
  let chain = Promise.resolve(); // POSTs (and the pending poll) one at a time
  let cache = null; // { at, value } for /health
  let lastStart = null; // { at, via, error }
  let pending = null; // { since, polls, reason, timer }: one more `certs` run due
  const binCheck = { key: null, supported: true };

  const settings = () => readSettings(env);

  function serialized(fn) {
    const next = chain.then(fn, fn);
    chain = next.catch(() => {});
    return next;
  }

  function readHostnames(s) {
    try {
      return parseHostnamesFile(fs.readFileSync(s.hostnamesFile, "utf-8"));
    } catch {
      return [];
    }
  }

  function readText(file) {
    try {
      return fs.readFileSync(file, "utf-8");
    } catch {
      return null;
    }
  }

  function readBuffer(file) {
    try {
      return fs.readFileSync(file);
    } catch {
      return null;
    }
  }

  // Status of every name: the agent's verdict on the PEM — ok only when the
  // certificate is good AND haproxy serves it (else "not_served") — plus
  // lastError, netrun-https's note of the last attempt (hosts/<name>.error:
  // "dns: ..." skipped without a CA call, "acme: ..." lego failed,
  // "haproxy: rejected..." haproxy -c refused the PEM).
  function certsFor(s, hostnames) {
    const nowMs = now();
    const hostsDir = path.join(s.tlsDir, "hosts");
    const served = parseServed(readText(path.join(s.tlsDir, SERVED_FILE)));
    const crtListText = readText(path.join(s.tlsDir, CRT_LIST_FILE));
    return hostnames.map((h) => {
      const pemPath = path.join(hostsDir, `${h}.pem`);
      const buf = readBuffer(pemPath);
      const c = evaluateCertificate(h, buf === null ? null : buf.toString("utf-8"), nowMs);
      if (c.ok) {
        const pemSha256 = crypto.createHash("sha256").update(buf).digest("hex");
        if (!isServed({ hostname: h, pemPath, pemSha256, served, crtListText })) {
          c.ok = false;
          c.error = "not_served"; // renewDue stays the certificate's: the sync serves it, not lego
        }
      }
      const note = readText(path.join(hostsDir, `${h}.error`));
      const lastError = note ? note.split(/\r?\n/)[0].trim().slice(0, 300) || null : null;
      return { hostname: c.hostname, ok: c.ok, notAfter: c.notAfter, error: c.error, lastError, renewDue: c.renewDue };
    });
  }

  const publicCert = ({ renewDue, ...rest }) => rest; // renewDue stays internal

  // An installed netrun-https that predates FO-08 has no `certs` subcommand
  // (/usr/local/sbin is refreshed by `netrun-https units` /
  // apply_capacity_tuning.sh --only units). Unreadable = assume it does.
  function binSupportsCerts(bin) {
    try {
      const st = fs.statSync(bin);
      const key = `${st.size}:${st.mtimeMs}`;
      if (binCheck.key !== key) {
        binCheck.key = key;
        binCheck.supported = fs.readFileSync(bin, "utf-8").includes("cmd_certs");
      }
      return binCheck.supported;
    } catch {
      return true;
    }
  }

  function childRunning() {
    return Boolean(child && child.exitCode === null && child.signalCode === null);
  }

  // true while a `netrun-https certs` runs (the systemd unit, or the fallback child).
  async function isIssuing() {
    if (childRunning()) return true;
    const systemctl = findBin("systemctl");
    if (!systemctl || !findBin("systemd-run")) return false;
    const r = await run(systemctl, ["is-active", `${UNIT}.service`], 3000);
    return RUNNING_STATES.has(r.stdout.trim().split(/\s+/)[0]);
  }

  // Start `netrun-https certs` detached: a transient systemd unit (its own
  // cgroup: an agent restart never kills it; --collect: gone when done, so the
  // name is free for the next run), else a detached child.
  async function startIssue(s) {
    const pass = { NETRUN_HTTPS_HOSTNAMES_FILE: s.hostnamesFile, NETRUN_HTTPS_TLS_DIR: s.tlsDir };
    const sdRun = findBin("systemd-run");
    if (sdRun) {
      const args = ["--unit", UNIT, "--collect", "--quiet"];
      for (const [k, v] of Object.entries(pass)) args.push(`--setenv=${k}=${v}`);
      args.push(s.bin, "certs");
      const r = await run(sdRun, args, 15_000);
      if (r.code === 0) return { started: true, via: "systemd-run" };
      // Lost a race with another start: that one runs.
      if (await isIssuing()) return { started: false, already: true };
      return { started: false, error: `systemd-run exit ${r.code}: ${r.stderr.trim().slice(-300)}` };
    }
    try {
      const c = spawnFn(s.bin, ["certs"], { detached: true, stdio: "ignore", env: { ...env, ...pass } });
      c.on("error", (err) => log.error(`[https-hostnames] netrun-https certs: ${errText(err)}`));
      if (typeof c.unref === "function") c.unref();
      child = c;
      return { started: true, via: "spawn" };
    } catch (err) {
      return { started: false, error: errText(err) };
    }
  }

  // ── one more run once the current one is over (pending) ──

  function schedulePending(delayMs) {
    if (!pending || pending.timer) return;
    const t = timers.setTimeout(() => {
      if (pending) pending.timer = null;
      return serialized(pollPending).catch((err) => log.error(`[https-hostnames] pending run: ${errText(err)}`));
    }, delayMs);
    if (t && typeof t.unref === "function") t.unref();
    pending.timer = t || true;
  }

  function markPending(reason, delayMs = pollMs) {
    if (pending) return;
    pending = { since: now(), polls: 0, reason, timer: null };
    log.log(`[https-hostnames] one more netrun-https certs run pending: ${reason}`);
    schedulePending(delayMs);
  }

  async function pollPending() {
    if (!pending) return;
    const s = settings();
    if (!s.enabled) {
      pending = null;
      return;
    }
    pending.polls += 1;
    if (await isIssuing()) {
      if (pending.polls >= maxPolls) {
        log.error(`[https-hostnames] netrun-https certs still runs after ${pending.polls} checks — pending run dropped (the renew timer applies the list)`);
        pending = null;
        return;
      }
      schedulePending(pollMs);
      return;
    }
    const r = await startIssue(s);
    lastStart = { at: new Date(now()).toISOString(), via: r.via || null, error: r.error || null };
    cache = null;
    if (r.error) {
      log.error(`[https-hostnames] could not start the pending netrun-https certs: ${r.error}`);
      if (pending.polls >= maxPolls) pending = null;
      else schedulePending(pollMs);
      return;
    }
    log.log(`[https-hostnames] pending netrun-https certs run ${r.started ? "started" : "joined a run just started"} (${pending.reason})`);
    pending = null;
  }

  // Agent start: the list file differs from what the last certs / renew pass
  // worked through (certs-applied; none = nothing yet) -> one more run, as a
  // pending one (it waits for a run in progress). true when one was queued.
  function start() {
    const s = settings();
    if (!s.enabled || !fs.existsSync(s.bin) || !binSupportsCerts(s.bin)) return false;
    const listed = readHostnames(s);
    const applied = parseHostnamesFile(readText(path.join(s.tlsDir, APPLIED_FILE)) || "");
    if (sameHostnames(listed, applied)) return false;
    markPending(`the list (${listed.join(" ") || "empty"}) differs from the last applied one (${applied.join(" ") || "none"})`, startDelayMs);
    return true;
  }

  function stop() {
    if (pending && pending.timer && pending.timer !== true) timers.clearTimeout(pending.timer);
    pending = null;
  }

  async function post(body) {
    const s = settings();
    if (!s.enabled) return { status: 404, body: { success: false, error: "https_hostnames_disabled" } };
    const parsed = parseHostnamesBody(body);
    if (!parsed.ok) return { status: 400, body: { success: false, error: parsed.error, detail: parsed.detail } };
    if (!fs.existsSync(s.bin)) {
      return { status: 409, body: { success: false, error: "https_frontend_missing", detail: `${s.bin} not installed (netrun-https setup)` } };
    }
    if (!binSupportsCerts(s.bin)) {
      return {
        status: 409,
        body: { success: false, error: "https_frontend_outdated", detail: `${s.bin} has no 'certs' subcommand (netrun-https units)` },
      };
    }
    return serialized(async () => {
      const hostnames = parsed.hostnames;
      const changed = !sameHostnames(readHostnames(s), hostnames);
      if (changed) {
        writeFileAtomic(s.hostnamesFile, hostnamesFileText(hostnames));
        log.log(`[https-hostnames] list written: ${hostnames.join(" ") || "(empty)"}`);
      }
      const certs = certsFor(s, hostnames);
      const due = changed || certs.some((c) => c.renewDue);
      let issuing = await isIssuing();
      let started = false;
      if (due && !issuing) {
        const r = await startIssue(s);
        lastStart = { at: new Date(now()).toISOString(), via: r.via || null, error: r.error || null };
        if (r.error) {
          log.error(`[https-hostnames] could not start netrun-https certs: ${r.error}`);
          cache = null;
          return {
            status: 500,
            body: { success: false, error: "issue_start_failed", detail: r.error, changed, hostnames, issuing: false, certs: certs.map(publicCert) },
          };
        }
        started = r.started;
        issuing = r.started || Boolean(r.already);
      }
      // A run in progress (or just finishing) may never see this change:
      // one more once it is over.
      if (due && !started) markPending(changed ? "hostname list changed while netrun-https certs runs" : "certificate due while netrun-https certs runs");
      cache = null;
      return {
        status: 200,
        body: { success: true, changed, hostnames, issuing, started, pending: Boolean(pending), certs: certs.map(publicCert) },
      };
    });
  }

  async function view() {
    const s = settings();
    const hostnames = readHostnames(s);
    const served = readText(path.join(s.tlsDir, SERVED_FILE));
    let servedAt = null;
    try {
      servedAt = served === null ? null : JSON.parse(served).at || null;
    } catch {
      servedAt = null;
    }
    return {
      enabled: s.enabled,
      frontendInstalled: fs.existsSync(s.bin),
      hostnames,
      certs: certsFor(s, hostnames).map(publicCert),
      issuing: await isIssuing(),
      pending: Boolean(pending),
      servedAt,
      lastStart,
    };
  }

  // /health: the view, at most every STATUS_TTL_MS; never throws.
  async function healthStatus() {
    const t = now();
    if (cache && t - cache.at < STATUS_TTL_MS) return cache.value;
    let value;
    try {
      value = await view();
    } catch (err) {
      value = { enabled: settings().enabled, error: errText(err) };
    }
    cache = { at: t, value };
    return value;
  }

  // GET / POST /https/hostnames. false = not this module's path.
  async function handleHttp(req, res, url, { sendJson, parseJsonBody, ensureAuthorized }) {
    if (url.pathname !== "/https/hostnames" || (req.method !== "GET" && req.method !== "POST")) return false;
    if (!ensureAuthorized(req)) {
      sendJson(res, 401, { success: false, error: "unauthorized" });
      return true;
    }
    try {
      if (req.method === "GET") {
        sendJson(res, 200, { success: true, ...(await view()) });
        return true;
      }
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        sendJson(res, 400, { success: false, error: "invalid_json", detail: errText(err) });
        return true;
      }
      const out = await post(body);
      sendJson(res, out.status, out.body);
    } catch (err) {
      sendJson(res, 500, { success: false, error: "https_hostnames_failed", detail: errText(err) });
    }
    return true;
  }

  return { post, view, healthStatus, handleHttp, isIssuing, settings, start, stop };
}

module.exports = {
  createHttpsHostnames,
  readSettings,
  normalizeHostname,
  parseHostnamesBody,
  parseHostnamesFile,
  sameHostnames,
  hostnamesFileText,
  evaluateCertificate,
  parseServed,
  isServed,
  UNIT,
  MAX_HOSTNAMES,
};
