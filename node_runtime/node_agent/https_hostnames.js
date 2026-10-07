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
//     whether an issuance runs.
//   /health httpsHostnames — the same, cached STATUS_TTL_MS.
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
} = {}) {
  let child = null; // the fallback's detached `netrun-https certs` (no systemd-run)
  let chain = Promise.resolve(); // POSTs one at a time
  let cache = null; // { at, value } for /health
  let lastStart = null; // { at, via, error }
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

  // Status of every name: the agent's verdict on the PEM haproxy serves, plus
  // lastError — netrun-https's note of the last attempt (hosts/<name>.error:
  // "dns: ..." skipped without a CA call, "acme: ..." lego failed).
  function certsFor(s, hostnames) {
    const nowMs = now();
    const hostsDir = path.join(s.tlsDir, "hosts");
    return hostnames.map((h) => {
      const c = evaluateCertificate(h, readText(path.join(hostsDir, `${h}.pem`)), nowMs);
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
      cache = null;
      return { status: 200, body: { success: true, changed, hostnames, issuing, started, certs: certs.map(publicCert) } };
    });
  }

  async function view() {
    const s = settings();
    const hostnames = readHostnames(s);
    return {
      enabled: s.enabled,
      frontendInstalled: fs.existsSync(s.bin),
      hostnames,
      certs: certsFor(s, hostnames).map(publicCert),
      issuing: await isIssuing(),
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

  return { post, view, healthStatus, handleHttp, isIssuing, settings };
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
  UNIT,
  MAX_HOSTNAMES,
};
