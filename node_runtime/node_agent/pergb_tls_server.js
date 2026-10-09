"use strict";

// Pay-per-GB v2 — the agent's TLS listener for /pergb/* (plan D16, §3.8,
// interface I6).
//
// https://<node IPv4>:8086 with the node's IP certificate (lego,
// /etc/netrun/lego/certificates/<ip>.crt + .key — Let's Encrypt short-lived,
// renewed every few days by netrun-https; else the combined
// /etc/netrun/tls/node.pem). The files are checked every 30 s and a new
// certificate is taken with setSecureContext — no restart, no dropped
// connection. Header X-API-KEY (the agent's key), JSON, body limit 2 MiB
// (snapshots come in pages of ≤ 2000 lists). netrun-harden opens :8086 to
// the orchestrator only.
//
// The plain :8085 listener answers /pergb/* with 404 pergb_tls_only, except
// the two amendment-A1 routes the node itself uses (the generator, per-piece
// deprovision): POST /pergb/reserve_nets and /pergb/release_nets.
//
// The listener opens only on a node where per-GB is installed
// (deploy/node/install_pergb.sh made /etc/netrun-pergb) and never while the
// node's agent firewall (netrun-harden agent-firewall, table
// inet netrun_agent_guard) exists without 8086: deploying this agent fleet-wide
// must not put a new internet-facing port on nodes guarded before 8086
// existed. status().gate says why it is closed (rerun
// `netrun-harden agent-firewall` to add 8086 for the same orchestrator IP).

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const net = require("net");
const path = require("path");

const BODY_LIMIT_BYTES = 2 * 1024 * 1024;
const DEFAULT_PORT = 8086;
const CERT_CHECK_MS = 30000;

function readSettings(env = process.env) {
  return {
    port: Number(env.NETRUN_PERGB_TLS_PORT || DEFAULT_PORT),
    host: String(env.NETRUN_PERGB_TLS_HOST || "0.0.0.0"),
    enabled: !/^(0|off|false|no)$/i.test(String(env.NETRUN_PERGB_TLS || "1")),
    legoDir: String(env.NETRUN_HTTPS_LEGO_DIR || "/etc/netrun/lego"),
    pemPath: String(env.NETRUN_PERGB_TLS_PEM || "/etc/netrun/tls/node.pem"),
    certPath: env.NETRUN_PERGB_TLS_CERT ? String(env.NETRUN_PERGB_TLS_CERT) : null,
    keyPath: env.NETRUN_PERGB_TLS_KEY ? String(env.NETRUN_PERGB_TLS_KEY) : null,
    ip: env.NETRUN_PERGB_TLS_IP ? String(env.NETRUN_PERGB_TLS_IP) : null,
    installedDir: String(env.NETRUN_PERGB_ETC_DIR || "/etc/netrun-pergb"),
    requireInstalled: !/^(0|off|false|no)$/i.test(String(env.NETRUN_PERGB_TLS_REQUIRE_INSTALLED || "1")),
    requireFirewall: !/^(0|off|false|no)$/i.test(String(env.NETRUN_PERGB_TLS_REQUIRE_FIREWALL || "1")),
  };
}

const AGENT_GUARD_TABLE = "netrun_agent_guard";

// Does the live agent guard (netrun-harden agent-firewall) cover 8086?
// -> "covered" | "absent" (no table: an unguarded node, 8085 is open as well) | "missing_8086"
function agentGuardState(text, code) {
  if (code !== 0) return "absent";
  const t = String(text || "");
  if (/dport \{ 8085, 8086 \} drop/.test(t) || /dport \{ 8085-8086 \} drop/.test(t) || /dport 8086 drop/.test(t)) return "covered";
  return "missing_8086";
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

// -> { body (parsed), bytes } ; rejects Error("payload_too_large" | "invalid_json")
function readBody(req, limit = BODY_LIMIT_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let failed = false;
    req.on("data", (c) => {
      if (failed) return;
      total += c.length;
      if (total > limit) {
        failed = true;
        reject(new Error("payload_too_large"));
        req.resume();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (failed) return;
      const raw = Buffer.concat(chunks).toString("utf-8");
      try {
        resolve({ body: raw ? JSON.parse(raw) : {}, bytes: total });
      } catch {
        reject(new Error("invalid_json"));
      }
    });
    req.on("error", (e) => {
      if (!failed) reject(e);
    });
  });
}

// The certificate files: explicit, else lego's for the node IP, else node.pem.
// -> { cert, key, source, sig, notAfter, subjectAltName } | { error }
function loadCertificate(settings, ip) {
  const tries = [];
  if (settings.certPath && settings.keyPath) tries.push([settings.certPath, settings.keyPath, "explicit"]);
  if (ip) tries.push([path.join(settings.legoDir, "certificates", `${ip}.crt`), path.join(settings.legoDir, "certificates", `${ip}.key`), "lego"]);
  tries.push([settings.pemPath, settings.pemPath, "node.pem"]);
  const errors = [];
  for (const [c, k, source] of tries) {
    let cert;
    let key;
    try {
      cert = fs.readFileSync(c, "utf-8");
      key = c === k ? cert : fs.readFileSync(k, "utf-8");
    } catch (e) {
      errors.push(`${source}: ${e.code || e.message}`);
      continue;
    }
    if (!/-----BEGIN CERTIFICATE-----/.test(cert) || !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) {
      errors.push(`${source}: not a PEM certificate + key`);
      continue;
    }
    let notAfter = null;
    let subjectAltName = null;
    try {
      const x = new crypto.X509Certificate(cert);
      notAfter = new Date(x.validTo).toISOString();
      subjectAltName = x.subjectAltName || null;
    } catch {}
    const sig = crypto.createHash("sha256").update(cert).update("\0").update(key).digest("hex");
    return { cert, key, source, sig, notAfter, subjectAltName, files: [c, k] };
  }
  return { error: "no_ip_cert", detail: errors.join("; ") };
}

function defaultPrimaryIp(run) {
  return async () => {
    const r = await run("ip", ["-4", "-o", "route", "get", "1.1.1.1"], { timeoutMs: 10000 });
    const m = /\bsrc (\d+\.\d+\.\d+\.\d+)\b/.exec(String((r && r.stdout) || ""));
    return r && r.code === 0 && m ? m[1] : null;
  };
}

// deps: { pergb, apiKeyMatches(given) -> bool, env, log, run, primaryIp() }
function createTlsServer(deps) {
  const settings = { ...readSettings(deps.env || process.env), ...(deps.settings || {}) };
  const log = deps.log || console;
  const pergb = deps.pergb;
  const keyOk = deps.apiKeyMatches;
  const run = deps.run || require("./pergb_runtime.js").execCapture;
  const primaryIp = deps.primaryIp || defaultPrimaryIp(run);
  let gate = { open: null, reason: null, firewall: null, checkedAt: null };
  let server = null;
  let listening = false;
  let current = null; // the loaded certificate
  let lastError = null;
  let reloads = 0;
  let timer = null;
  let ip = settings.ip;
  let lastIpCheck = 0;
  const locks = new Map();

  // one at a time per kind (enable/disable; snapshot/delta)
  function serial(kind, fn) {
    const prev = locks.get(kind) || Promise.resolve();
    const next = prev.then(fn, fn);
    locks.set(kind, next.catch(() => {}));
    return next;
  }

  async function nodeIp() {
    if (settings.ip) return settings.ip;
    if (!ip || Date.now() - lastIpCheck > 10 * 60 * 1000) {
      lastIpCheck = Date.now();
      try {
        ip = (await primaryIp()) || ip;
      } catch {}
    }
    return ip;
  }

  async function handle(req, res) {
    let url;
    try {
      url = new URL(req.url, "https://pergb.local");
    } catch {
      return sendJson(res, 400, { success: false, error: "bad_request" });
    }
    const p = url.pathname;
    if (req.method === "GET" && p === "/health") return sendJson(res, 200, { ok: true });
    if (!keyOk(req.headers["x-api-key"])) return sendJson(res, 401, { success: false, error: "unauthorized" });
    const q = Object.fromEntries(url.searchParams.entries());
    let body = {};
    let bytes = 0;
    if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
      try {
        const r = await readBody(req);
        body = r.body;
        bytes = r.bytes;
      } catch (e) {
        const code = e.message === "payload_too_large" ? 413 : 400;
        return sendJson(res, code, { success: false, error: e.message === "payload_too_large" ? "payload_too_large" : "invalid_json", limit: BODY_LIMIT_BYTES });
      }
    }
    let out;
    try {
      if (req.method === "GET" && p === "/pergb/status") out = { status: 200, body: await pergb.status() };
      else if (req.method === "POST" && p === "/pergb/enable") out = await serial("enable", () => pergb.enable(body));
      else if (req.method === "POST" && p === "/pergb/disable") out = await serial("enable", () => pergb.disable(body));
      else if (req.method === "PUT" && p === "/pergb/state") out = await serial("state", () => pergb.putSnapshot(q, body, bytes));
      else if (req.method === "PATCH" && p === "/pergb/state") out = await serial("state", () => pergb.patchState(body));
      else if (req.method === "GET" && p === "/pergb/usage") out = await pergb.usage(q);
      else if (req.method === "POST" && p === "/pergb/kill") out = await pergb.kill(body);
      else if (req.method === "GET" && p === "/pergb/attribution") out = await pergb.attribution(q);
      else if (req.method === "GET" && p === "/pergb/port_check") out = await pergb.portCheck(q);
      else if (req.method === "POST" && p === "/pergb/reserve_nets") out = await pergb.reserveNets(body);
      else if (req.method === "POST" && p === "/pergb/release_nets") out = await pergb.releaseNets(body);
      else out = { status: 404, body: { success: false, error: "not_found" } };
    } catch (e) {
      log.error(`[pergb-tls] ${req.method} ${p}: ${(e && e.stack) || e}`);
      out = { status: 500, body: { success: false, error: "internal_error", detail: String((e && e.message) || e) } };
    }
    return sendJson(res, out.status, out.body);
  }

  async function checkCertificate() {
    const c = loadCertificate(settings, await nodeIp());
    if (c.error) {
      lastError = `${c.error}: ${c.detail}`;
      return false;
    }
    if (current && current.sig === c.sig) return true;
    if (server && listening) {
      try {
        server.setSecureContext({ cert: c.cert, key: c.key });
        reloads += 1;
        log.log(`[pergb-tls] certificate reloaded (${c.source}, notAfter ${c.notAfter})`);
      } catch (e) {
        lastError = `setSecureContext: ${e.message || e}`;
        log.error(`[pergb-tls] ${lastError}`);
        return false;
      }
    }
    current = c;
    lastError = null;
    return true;
  }

  async function start() {
    if (!settings.enabled) return { listening: false, reason: "disabled" };
    if (!timer) {
      timer = setInterval(() => {
        tick().catch(() => {});
      }, CERT_CHECK_MS);
      if (typeof timer.unref === "function") timer.unref();
    }
    return tick();
  }

  // May the listener open? (see the module doc)
  async function checkGate() {
    const out = { open: true, reason: null, firewall: null, checkedAt: new Date().toISOString() };
    if (settings.requireInstalled && !fs.existsSync(settings.installedDir)) {
      Object.assign(out, { open: false, reason: "pergb_not_installed" });
    } else if (settings.requireFirewall) {
      let r;
      try {
        r = await run("nft", ["list", "table", "inet", AGENT_GUARD_TABLE], { timeoutMs: 10000 });
      } catch (e) {
        r = { code: 1, stdout: "", stderr: String((e && e.message) || e) };
      }
      out.firewall = agentGuardState(r && r.stdout, r ? r.code : 1);
      if (out.firewall === "missing_8086") Object.assign(out, { open: false, reason: "agent_firewall_without_8086" });
    }
    if (!out.open && gate.reason !== out.reason) log.error(`[pergb-tls] listener stays closed: ${out.reason}${out.reason === "agent_firewall_without_8086" ? " (run: netrun-harden agent-firewall)" : ""}`);
    gate = out;
    return out;
  }

  async function tick() {
    if (!listening && !server && !(await checkGate()).open) return status();
    const ok = await checkCertificate();
    if (!ok || listening || server) return status();
    server = https.createServer({ cert: current.cert, key: current.key, minVersion: "TLSv1.2" }, (req, res) => {
      handle(req, res).catch((e) => {
        try {
          sendJson(res, 500, { success: false, error: "internal_error", detail: String(e && e.message) });
        } catch {}
      });
    });
    server.headersTimeout = 30000;
    server.requestTimeout = 300000;
    await new Promise((resolve) => {
      server.once("error", (e) => {
        lastError = `listen: ${e.code || e.message}`;
        log.error(`[pergb-tls] ${lastError}`);
        server = null;
        resolve();
      });
      server.listen(settings.port, settings.host, () => {
        listening = true;
        log.log(`[pergb-tls] listening on ${settings.host}:${settings.port} (${current.source}, notAfter ${current.notAfter})`);
        resolve();
      });
    });
    return status();
  }

  async function stop() {
    if (timer) clearInterval(timer);
    timer = null;
    if (server) await new Promise((r) => server.close(() => r()));
    server = null;
    listening = false;
  }

  function status() {
    return {
      listening,
      port: listening && server && server.address() ? server.address().port : settings.port,
      certificate: current ? { source: current.source, notAfter: current.notAfter, subjectAltName: current.subjectAltName } : null,
      reloads,
      error: lastError,
      gate,
    };
  }

  // The plain :8085 listener's /pergb/* (server.js): the two A1 routes, and
  // 404 pergb_tls_only for everything else. -> true when handled.
  async function handlePlain(req, res, url, h) {
    const p = url.pathname;
    if (p !== "/pergb" && !p.startsWith("/pergb/")) return false;
    if (!h.ensureAuthorized(req)) {
      h.sendJson(res, 401, { success: false, error: "unauthorized" });
      return true;
    }
    if (req.method === "POST" && (p === "/pergb/reserve_nets" || p === "/pergb/release_nets")) {
      let body;
      try {
        body = await h.parseJsonBody(req);
      } catch (e) {
        h.sendJson(res, 400, { success: false, error: "invalid_json", detail: String((e && e.message) || e) });
        return true;
      }
      let out;
      try {
        out = p === "/pergb/reserve_nets" ? await pergb.reserveNets(body) : await pergb.releaseNets(body);
      } catch (e) {
        out = { status: 500, body: { success: false, error: "internal_error", detail: String((e && e.message) || e) } };
      }
      h.sendJson(res, out.status, out.body);
      return true;
    }
    h.sendJson(res, 404, { success: false, error: "pergb_tls_only", tlsPort: settings.port });
    return true;
  }

  return {
    start,
    stop,
    tick,
    status,
    handle,
    handlePlain,
    checkCertificate,
    get port() {
      return listening && server && server.address() ? server.address().port : settings.port;
    },
    get server() {
      return server;
    },
  };
}

module.exports = { BODY_LIMIT_BYTES, DEFAULT_PORT, readSettings, readBody, loadCertificate, agentGuardState, createTlsServer, isIP: net.isIP };
