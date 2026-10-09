"use strict";

// Pay-per-GB v2 — the per-GB data path on the node (interface I4).
//
// Writer of everything the per-GB runtime runs from; it never touches a
// per-piece file, process or the per-piece haproxy:
//   /opt/netrun/pergb/cfg/pergb_<sp>.cfg   3proxy-pergb cfg per process range
//                                          (0640 root:netrun-pergb: it holds
//                                          the RADIUS secret)
//   /opt/netrun/pergb/haproxy/haproxy.cfg  the per-GB haproxy (0640 root:haproxy)
//   /etc/netrun-pergb/radius.secret        40 x [A-Za-z0-9], no newline
//                                          (0640 root:netrun-radius; generated
//                                          once, then kept)
//   /etc/netrun-pergb/enable.json          the accepted enable params (0600 root)
//   /etc/systemd/system/netrun-pergb.slice.d/50-netrun-enable.conf and
//   /etc/systemd/system/netrun.slice.d/50-netrun-enable.conf
//                                          slice limits from the enable params
// and the systemd side: netrun-pergb.target (enabled + started by apply,
// disabled + stopped by disable), one netrun-pergb-3proxy@<sp>.service per
// process range (enabled into the target's wants), netrun-pergb-haproxy.
// The units, the binary, the users and the log filesystem come from
// deploy/node/install_pergb.sh.
//
// apply() is idempotent: the same params rewrite nothing and restart nothing.
// A 3proxy unit is restarted only when the cfg it runs differs from the file
// (its ExecStartPre stamps the sha256 of the cfg it is about to load into
// /run/netrun-pergb/applied/<sp>.sha256), one unit at a time, the next only
// once the previous is active and listening again (rolling restart, e.g. on a
// family change). The haproxy is reloaded (graceful, -Ws) when its file
// changed. Refusals: bad_params, pergb_not_installed, uid_taken,
// binary_hash_mismatch (the installed binary or its .sha256 differs from the
// pinned deploy/node/bin/3proxy-pergb.sha256 of this checkout), and
// proxy_guard_missing (the loaded netrun-proxy-guard has no `meta skuid 65533
// jump pergb`: 3proxy-pergb would reach the node itself; netrun-proxy-guard
// apply is tried once first).
//
// enable.json (version 1) — read by L3 (facts, status) and L9 (range shields):
//   { version: 1, enabled, base, count, last, egressIpv4, dedicatedIpv4,
//     family, maxConns, logdumpBytes, denyPorts, sliceMemMax (bytes),
//     cpuWeight, procs: [{sp, first, last, unit, cfg}], params: <the raw
//     enable body, secrets included>, enabledAt, updatedAt }
// egressIpv4 is the address the per-GB haproxy binds and 3proxy-pergb sends
// IPv4 from (the primary IPv4 in option A); dedicatedIpv4 is non-null only in
// option B (a per-GB IPv4 of its own). sharedRange() is the reader for L3/L9.
//
// cgroup: the slice name has a dash, so systemd nests it:
//   /netrun.slice/netrun-pergb.slice/netrun-pergb-3proxy@<sp>.service
// (SLICE_CGROUP, cgroupPath()). netrun.slice carries the CPU weight against
// system.slice (where the per-piece batches run).
//
// Settings (environment; tests point every path at a temp dir):
//   NETRUN_PERGB_BIN, NETRUN_PERGB_BIN_SHA256 (installed hash file),
//   NETRUN_PERGB_PINNED_SHA256 (default: deploy/node/bin/3proxy-pergb.sha256
//   of this checkout), NETRUN_PERGB_CFG_DIR, NETRUN_PERGB_HAPROXY_CFG,
//   NETRUN_PERGB_ETC_DIR, NETRUN_PERGB_LOG_DIR, NETRUN_PERGB_RUN_DIR,
//   NETRUN_PERGB_SYSTEMD_DIR, NETRUN_PERGB_CRT_LIST, NETRUN_PERGB_PASSWD,
//   NETRUN_PERGB_GROUP, NETRUN_PERGB_UID (65533), NETRUN_PROXY_GUARD_BIN,
//   NETRUN_PERGB_REQUIRE_GUARD (1; 0 = skip the guard check),
//   NETRUN_PERGB_CHOWN (1; 0 = never chown, tests).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");
const { spawn } = require("child_process");

const TARGET = "netrun-pergb.target";
const SLICE = "netrun-pergb.slice";
const PARENT_SLICE = "netrun.slice";
const SLICE_CGROUP = "/netrun.slice/netrun-pergb.slice";
const HAPROXY_UNIT = "netrun-pergb-haproxy.service";
const CERTS_PATH_UNIT = "netrun-pergb-certs.path";
const RADIUS_SOCKET = "netrun-radius.socket";
const RADIUS_SERVICE = "netrun-radius.service";
const GUARD_TABLE = "netrun_proxy_guard";
const ENABLE_VERSION = 1;
const DROPIN_NAME = "50-netrun-enable.conf";

const HTTP_LISTEN = "127.0.0.3";
const SOCKS_LISTEN = "127.0.0.4";
const RADIUS_ADDR = "127.0.0.1";
const DEFAULT_COUNT = 1000;
const DEFAULT_PROCS = 2;
const DEFAULT_MAX_CONNS = 8000;
const DEFAULT_LOGDUMP = 262144;
const DEFAULT_DENY_PORTS = [25, 465, 587];
const DEFAULT_SLICE_MEM_MAX = 1536 * 1024 * 1024;
const DEFAULT_CPU_WEIGHT = 50;
const MAXCONN_BASE = 20000;
const MAXCONN_PORT = 2000;
const SECRET_LEN = 40;
const SECRET_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SECRET_RE = /^[A-Za-z0-9]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const FAMILIES = new Set(["dualstack", "ipv6_only"]);
// 3proxy 0.9.3 conf.c (h_ace) operation names. The per-GB ACL allows SOCKS
// CONNECT and the HTTP-proxy operations (plain HTTP methods + CONNECT); never
// BIND / UDPASSOC / ICMPASSOC, FTP, ADMIN or DNSRESOLVE.
const ACL_OPERATIONS = ["CONNECT", "HTTP_GET", "HTTP_PUT", "HTTP_POST", "HTTP_HEAD", "HTTP_OTHER", "HTTP_CONNECT"];
const LOGFORMAT = "- +_G%Y%m%d%H%M%S.%. %N %p %E %U %C %c %i %e %R %r %I %O %n";
const TIMEOUTS = "1 3 30 60 180 1800 15 60";
const READY_TIMEOUT_MS = 20000;
const READY_POLL_MS = 250;

const MODULE_DIR = __dirname;

function envOn(v, def = true) {
  if (v === undefined || v === null || String(v).trim() === "") return def;
  return !/^(0|false|no|off)$/i.test(String(v).trim());
}

function readSettings(env = process.env) {
  const etcDir = String(env.NETRUN_PERGB_ETC_DIR || "/etc/netrun-pergb");
  return {
    binPath: String(env.NETRUN_PERGB_BIN || "/opt/netrun/pergb/bin/3proxy-pergb"),
    binHashPath: String(env.NETRUN_PERGB_BIN_SHA256 || "/opt/netrun/pergb/bin/3proxy-pergb.sha256"),
    pinnedHashPath: String(
      env.NETRUN_PERGB_PINNED_SHA256 || path.resolve(MODULE_DIR, "../../deploy/node/bin/3proxy-pergb.sha256"),
    ),
    cfgDir: String(env.NETRUN_PERGB_CFG_DIR || "/opt/netrun/pergb/cfg"),
    haproxyCfg: String(env.NETRUN_PERGB_HAPROXY_CFG || "/opt/netrun/pergb/haproxy/haproxy.cfg"),
    etcDir,
    secretPath: path.join(etcDir, "radius.secret"),
    enablePath: path.join(etcDir, "enable.json"),
    logDir: String(env.NETRUN_PERGB_LOG_DIR || "/var/log/netrun-pergb"),
    runDir: String(env.NETRUN_PERGB_RUN_DIR || "/run/netrun-pergb"),
    systemdDir: String(env.NETRUN_PERGB_SYSTEMD_DIR || "/etc/systemd/system"),
    crtList: String(env.NETRUN_PERGB_CRT_LIST || "/etc/netrun/tls/crt-list"),
    passwdPath: String(env.NETRUN_PERGB_PASSWD || "/etc/passwd"),
    groupPath: String(env.NETRUN_PERGB_GROUP || "/etc/group"),
    pergbUser: "netrun-pergb",
    pergbUid: Number(env.NETRUN_PERGB_UID || 65533),
    radiusUser: "netrun-radius",
    haproxyGroup: "haproxy",
    guardBin: String(env.NETRUN_PROXY_GUARD_BIN || "/usr/local/sbin/netrun-proxy-guard"),
    requireGuard: envOn(env.NETRUN_PERGB_REQUIRE_GUARD, true),
    chown: envOn(env.NETRUN_PERGB_CHOWN, true),
  };
}

// ── pure helpers ─────────────────────────────────────────────────────────

function unitFor(sp) {
  return `netrun-pergb-3proxy@${sp}.service`;
}

function cfgPathFor(settings, sp) {
  return path.join(settings.cfgDir, `pergb_${sp}.cfg`);
}

function cgroupPath(unit) {
  return `${SLICE_CGROUP}/${unit}`;
}

function isIpv4(s) {
  return typeof s === "string" && net.isIPv4(s);
}

// Contiguous ranges of [base, base+count-1], one per process, as even as
// possible (I4: two processes of 500 ports for the 1000-port range).
function procRanges(base, count, procs) {
  const size = Math.ceil(count / procs);
  const out = [];
  for (let i = 0; i < procs; i += 1) {
    const first = base + i * size;
    const last = Math.min(base + count - 1, first + size - 1);
    if (first > last) break;
    out.push({ sp: first, first, last, unit: unitFor(first) });
  }
  return out;
}

// "1536M" / "2G" / "1610612736" / 1610612736 -> bytes (base 1024), or null.
function parseSize(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v > 0 ? v : null;
  const m = /^\s*(\d+)\s*([KMGT])?\s*$/i.exec(String(v === undefined || v === null ? "" : v));
  if (!m) return null;
  const mult = { K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 }[(m[2] || "").toUpperCase()] || 1;
  const n = Number(m[1]) * mult;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

// bytes -> the systemd form: "<n>M" when a whole number of MiB, else bytes.
function sizeText(bytes) {
  return bytes % (1024 * 1024) === 0 ? `${bytes / (1024 * 1024)}M` : String(bytes);
}

function intIn(v, lo, hi) {
  const n = typeof v === "string" && /^\d+$/.test(v.trim()) ? Number(v) : v;
  return Number.isInteger(n) && n >= lo && n <= hi ? n : null;
}

// The enable params (POST /pergb/enable after L3 resolved egressIpv4) ->
// { ok: true, params } | { ok: false, error: "bad_params", detail }.
// egressIpv4 must be resolved (option A: the primary IPv4); the raw request's
// egressIpv4 (null = option A) arrives as dedicatedIpv4.
function normalizeParams(raw) {
  const p = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const bad = (detail) => ({ ok: false, error: "bad_params", detail });
  const count = p.count === undefined || p.count === null ? DEFAULT_COUNT : intIn(p.count, 2, 5000);
  if (count === null) return bad("count must be an integer 2..5000");
  const base = intIn(p.base, 1024, 65535 - count + 1);
  if (base === null) return bad(`base must be an integer 1024..${65535 - count + 1}`);
  const procCount = p.procs === undefined || p.procs === null ? DEFAULT_PROCS : intIn(p.procs, 1, 16);
  if (procCount === null || procCount > count) return bad("procs must be an integer 1..16 and at most count");
  if (!isIpv4(p.egressIpv4)) return bad("egressIpv4 must be an IPv4 address (the resolved egress address)");
  const dedicated = p.dedicatedIpv4 === undefined || p.dedicatedIpv4 === null ? null : p.dedicatedIpv4;
  if (dedicated !== null && !isIpv4(dedicated)) return bad("dedicatedIpv4 must be null or an IPv4 address");
  if (dedicated !== null && dedicated !== p.egressIpv4) return bad("dedicatedIpv4, when set, is the egressIpv4");
  const family = p.family === undefined || p.family === null ? "dualstack" : p.family;
  if (!FAMILIES.has(family)) return bad("family must be dualstack or ipv6_only");
  const maxConns =
    p.maxConns === undefined || p.maxConns === null ? DEFAULT_MAX_CONNS : intIn(p.maxConns, 100, 1000000);
  if (maxConns === null) return bad("maxConns must be an integer 100..1000000");
  const logdump =
    p.logdumpBytes === undefined || p.logdumpBytes === null ? DEFAULT_LOGDUMP : intIn(p.logdumpBytes, 4096, 1 << 30);
  if (logdump === null) return bad("logdumpBytes must be an integer 4096..1073741824");
  let deny = DEFAULT_DENY_PORTS;
  if (p.denyPorts !== undefined && p.denyPorts !== null) {
    if (!Array.isArray(p.denyPorts) || p.denyPorts.length > 64) return bad("denyPorts must be a list of ports");
    deny = [];
    for (const x of p.denyPorts) {
      const n = intIn(x, 1, 65535);
      if (n === null) return bad("denyPorts must be a list of ports 1..65535");
      if (!deny.includes(n)) deny.push(n);
    }
    deny.sort((a, b) => a - b);
  }
  const mem =
    p.sliceMemMax === undefined || p.sliceMemMax === null ? DEFAULT_SLICE_MEM_MAX : parseSize(p.sliceMemMax);
  if (mem === null || mem < 256 * 1024 * 1024) return bad("sliceMemMax must be a size of at least 256M");
  const cpuWeight =
    p.cpuWeight === undefined || p.cpuWeight === null ? DEFAULT_CPU_WEIGHT : intIn(p.cpuWeight, 1, 10000);
  if (cpuWeight === null) return bad("cpuWeight must be an integer 1..10000");
  return {
    ok: true,
    params: {
      base,
      count,
      last: base + count - 1,
      procs: procCount,
      egressIpv4: p.egressIpv4,
      dedicatedIpv4: dedicated,
      family,
      maxConns,
      logdumpBytes: logdump,
      denyPorts: deny,
      sliceMemMax: mem,
      cpuWeight,
    },
  };
}

function headerLine(sp, first, last, ipv4) {
  return `# netrun-pergb v1 sp=${sp} first=${first} last=${last} ipv4=${ipv4}`;
}

// One 3proxy-pergb cfg (I4). Order matters: 3proxy copies log, auth, ACL and
// maxconn into each service when its line is parsed, so every service line
// comes after them; maxconn is per service (20000 on the base port, 2000 on
// the others). No `daemon` (systemd runs it in the foreground) and no
// setuid/setgid (the unit runs it as netrun-pergb).
function renderCfg(params, range, secret, logDir = "/var/log/netrun-pergb") {
  if (!SECRET_RE.test(String(secret || ""))) throw new Error("renderCfg: bad RADIUS secret");
  const fam = params.family === "ipv6_only" ? "-6" : "-64";
  const ext = `-e${params.egressIpv4} -e::1`;
  const lines = [
    headerLine(range.sp, range.first, range.last, params.egressIpv4),
    `# family=${params.family} base=${params.base} count=${params.count} — written by node_agent/pergb_runtime.js (POST /pergb/enable); do not edit`,
    "nserver 127.0.0.1",
    "nserver ::1",
    `timeouts ${TIMEOUTS}`,
    `log ${logDir}/p${range.sp}.log H`,
    `logformat "${LOGFORMAT}"`,
    `logdump ${params.logdumpBytes} ${params.logdumpBytes}`,
    "authcache none",
    `radius ${secret} ${RADIUS_ADDR}`,
    "auth radius",
  ];
  if (params.denyPorts.length) lines.push(`deny * * * ${params.denyPorts.join(",")}`);
  lines.push(`allow * * * * ${ACL_OPERATIONS.join(",")}`, "deny *");
  let current = null;
  for (let port = range.first; port <= range.last; port += 1) {
    const want = port === params.base ? MAXCONN_BASE : MAXCONN_PORT;
    if (want !== current) {
      lines.push(`maxconn ${want}`);
      current = want;
    }
    lines.push(`socks ${fam} -a -p${port} -i${SOCKS_LISTEN} ${ext}`);
    lines.push(`proxy ${fam} -n -a -p${port} -i${HTTP_LISTEN} ${ext}`);
  }
  return lines.join("\n") + "\n";
}

// The per-GB haproxy (I4): the shared ports on the egress IPv4; a TLS
// ClientHello loops through the own TLS terminator (abstract socket, PROXY v2
// keeps the dialed port) to 3proxy-pergb's HTTP proxy on 127.0.0.3:<port>,
// a SOCKS5 greeting (0x05) goes to 127.0.0.4:<port>, anything else is
// rejected (no plain HTTP). Port-less servers reach the dialed port. The log
// line joins the client to 3proxy's loopback tuple (%bi:%bp = 3proxy's %C:%c).
function renderHaproxy(params, opts = {}) {
  const crtList = opts.crtList || "/etc/netrun/tls/crt-list";
  const runDir = opts.runDir || "/run/netrun-pergb";
  const maxconn = 2 * params.maxConns + 1000;
  return `# NETRUN per-GB haproxy — written by node_agent/pergb_runtime.js (POST /pergb/enable); do not edit.
# Shared ports ${params.base}-${params.last} on ${params.egressIpv4}: TLS -> 3proxy-pergb proxy ${HTTP_LISTEN}:<port>,
# SOCKS5 -> 3proxy-pergb socks ${SOCKS_LISTEN}:<port>, anything else rejected.
global
    log /dev/log local1 info
    log-tag netrun-pergb-haproxy
    maxconn ${maxconn}
    nbthread 2
    ssl-default-bind-options ssl-min-ver TLSv1.2
    stats socket ${runDir}/haproxy.sock mode 600 level admin
    user haproxy
    group haproxy

defaults
    mode tcp
    log global
    option dontlognull
    maxconn ${maxconn}
    timeout connect 10s
    timeout client 1h
    timeout server 1h
    timeout tunnel 1h
    log-format "%ci:%cp %fp %bi:%bp %Tt %B %U"

frontend pergb_in
    bind ${params.egressIpv4}:${params.base}-${params.last}
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    tcp-request content accept if { req.len gt 0 } { req.payload(0,1) -m bin 05 }
    tcp-request content reject
    use_backend pergb_tls_loop if { req.ssl_hello_type 1 }
    default_backend pergb_socks

backend pergb_socks
    server socks ${SOCKS_LISTEN}

backend pergb_tls_loop
    server tls abns@netrun_pergb_tls send-proxy-v2

frontend pergb_tls
    bind abns@netrun_pergb_tls accept-proxy ssl crt-list ${crtList} alpn http/1.1
    default_backend pergb_http

backend pergb_http
    server http ${HTTP_LISTEN}
`;
}

function tasksMax(params) {
  // listener threads (2 per port) + one thread per connection + margin
  return 2 * params.count + params.maxConns + 500;
}

function renderSliceDropin(params) {
  const high = Math.floor((params.sliceMemMax * 0.85) / (1024 * 1024)) * 1024 * 1024;
  return `# NETRUN per-GB — written by node_agent/pergb_runtime.js from POST /pergb/enable; do not edit
[Slice]
CPUWeight=${params.cpuWeight}
MemoryHigh=${sizeText(high)}
MemoryMax=${sizeText(params.sliceMemMax)}
TasksMax=${tasksMax(params)}
`;
}

// netrun-pergb.slice nests in netrun.slice (the dash): the CPU weight that
// counts against system.slice (the per-piece batches) is netrun.slice's.
function renderParentSliceDropin(params) {
  return `# NETRUN per-GB — written by node_agent/pergb_runtime.js from POST /pergb/enable; do not edit
[Slice]
CPUWeight=${params.cpuWeight}
`;
}

function newSecret(randomBytes = crypto.randomBytes) {
  let out = "";
  const limit = 256 - (256 % SECRET_ALPHABET.length);
  while (out.length < SECRET_LEN) {
    for (const b of randomBytes(64)) {
      if (b < limit && out.length < SECRET_LEN) out += SECRET_ALPHABET[b % SECRET_ALPHABET.length];
    }
  }
  return out;
}

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// First token of a sha256sum line ("<hex>  <name>"), or null.
function parseHashFile(text) {
  const tok = String(text || "").trim().split(/\s+/)[0] || "";
  return SHA256_RE.test(tok.toLowerCase()) ? tok.toLowerCase() : null;
}

// passwd / group text -> Map name -> {id, gid?}
function parseIdFile(text) {
  const out = new Map();
  for (const line of String(text || "").split("\n")) {
    const f = line.split(":");
    if (f.length < 3 || !f[0] || line.startsWith("#")) continue;
    const id = Number(f[2]);
    if (!Number.isInteger(id)) continue;
    out.set(f[0], { id, gid: f.length > 3 ? Number(f[3]) : null });
  }
  return out;
}

// ── file helpers ─────────────────────────────────────────────────────────

function readText(p) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

function makeFsOps(settings) {
  const doChown = (p, uid, gid) => {
    if (!settings.chown || uid === null || gid === null) return;
    fs.chownSync(p, uid, gid);
  };
  // Atomic: temp file in the same directory (mode set before any byte is
  // written), fsync, chown, rename, fsync the directory.
  function writeAtomic(p, text, { mode, uid = null, gid = null }) {
    const dir = path.dirname(p);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(dir, `.${path.basename(p)}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`);
    let fd = null;
    try {
      fd = fs.openSync(tmp, "wx", mode);
      fs.fchmodSync(fd, mode);
      fs.writeSync(fd, text);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = null;
      doChown(tmp, uid, gid);
      fs.renameSync(tmp, p);
    } catch (err) {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {}
      }
      try {
        fs.unlinkSync(tmp);
      } catch {}
      throw err;
    }
    try {
      const dfd = fs.openSync(dir, "r");
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch {
      // best effort
    }
  }
  // Write when the content, mode or owner differs. true = written.
  function ensureFile(p, text, opts) {
    let same = false;
    try {
      const st = fs.statSync(p);
      same =
        fs.readFileSync(p, "utf8") === text &&
        (st.mode & 0o7777) === opts.mode &&
        (!settings.chown || opts.uid === null || st.uid === opts.uid) &&
        (!settings.chown || opts.gid === null || st.gid === opts.gid);
    } catch {
      same = false;
    }
    if (same) return false;
    writeAtomic(p, text, opts);
    return true;
  }
  return { writeAtomic, ensureFile };
}

function execCapture(cmd, args, { timeoutMs = 60000 } = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let child;
    try {
      child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (err) {
      resolve({ code: -1, stdout: "", stderr: String((err && err.message) || err) });
      return;
    }
    const timer = setTimeout(() => {
      if (settled) return;
      try {
        child.kill("SIGKILL");
      } catch {}
    }, timeoutMs);
    child.stdout.on("data", (d) => {
      stdout += d.toString("utf-8");
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString("utf-8");
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: stderr || String((err && err.message) || err) });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: typeof code === "number" ? code : -1, stdout, stderr });
    });
  });
}

function short(res) {
  return String((res && (res.stderr || res.stdout)) || "").trim().slice(0, 300);
}

// ── checks ───────────────────────────────────────────────────────────────

// The installed binary, the installed .sha256 (what the units' ExecStartPre
// checks) and the pinned hash of this checkout must all agree.
function checkBinary(settings = readSettings()) {
  const pinned = parseHashFile(readText(settings.pinnedHashPath));
  if (!pinned) {
    return { ok: false, error: "binary_hash_mismatch", detail: `no pinned sha256 in ${settings.pinnedHashPath}` };
  }
  let actual = null;
  try {
    actual = sha256Hex(fs.readFileSync(settings.binPath));
  } catch {
    return {
      ok: false,
      error: "binary_hash_mismatch",
      detail: `${settings.binPath} missing — run deploy/node/install_pergb.sh`,
      pinned,
    };
  }
  if (actual !== pinned) {
    return {
      ok: false,
      error: "binary_hash_mismatch",
      detail: `${settings.binPath} sha256 ${actual} != pinned ${pinned} — run deploy/node/install_pergb.sh`,
      pinned,
      actual,
    };
  }
  const installed = parseHashFile(readText(settings.binHashPath));
  if (installed !== pinned) {
    return {
      ok: false,
      error: "binary_hash_mismatch",
      detail: `${settings.binHashPath} (${installed || "missing"}) != pinned ${pinned} — run deploy/node/install_pergb.sh`,
      pinned,
      actual,
    };
  }
  return { ok: true, sha256: actual };
}

// netrun-pergb must exist with the per-GB uid; the uid must not belong to
// anyone else. Returns the ids the files are chowned to.
function checkUsers(settings = readSettings()) {
  const users = parseIdFile(readText(settings.passwdPath));
  const groups = parseIdFile(readText(settings.groupPath));
  for (const [name, u] of users) {
    if (u.id === settings.pergbUid && name !== settings.pergbUser) {
      return { ok: false, error: "uid_taken", detail: `uid ${settings.pergbUid} belongs to ${name}` };
    }
  }
  const pergb = users.get(settings.pergbUser);
  if (!pergb) {
    return { ok: false, error: "pergb_not_installed", detail: `no user ${settings.pergbUser} — run deploy/node/install_pergb.sh` };
  }
  if (pergb.id !== settings.pergbUid) {
    return {
      ok: false,
      error: "uid_taken",
      detail: `${settings.pergbUser} has uid ${pergb.id}, expected ${settings.pergbUid}`,
    };
  }
  const pergbGroup = groups.get(settings.pergbUser);
  const radiusGroup = groups.get(settings.radiusUser);
  if (!pergbGroup || !radiusGroup) {
    return {
      ok: false,
      error: "pergb_not_installed",
      detail: `groups ${settings.pergbUser} / ${settings.radiusUser} missing — run deploy/node/install_pergb.sh`,
    };
  }
  const haproxyGroup = groups.get(settings.haproxyGroup);
  return {
    ok: true,
    pergbGid: pergbGroup.id,
    radiusGid: radiusGroup.id,
    haproxyGid: haproxyGroup ? haproxyGroup.id : 0,
  };
}

// ── enable.json ──────────────────────────────────────────────────────────

function readEnable(settings = readSettings()) {
  const text = readText(settings.enablePath);
  if (text === null) return null;
  try {
    const obj = JSON.parse(text);
    if (!obj || typeof obj !== "object" || obj.version !== ENABLE_VERSION) return null;
    if (!Number.isInteger(obj.base) || !Number.isInteger(obj.count) || obj.count < 1) return null;
    return obj;
  } catch {
    return null;
  }
}

// The shared per-GB range for the range shields (L9) and the agent (L3):
// { enabled, base, last, count, egressIpv4, dedicatedIpv4 } or null when
// per-GB was never enabled here. A disabled node keeps its range (enabled:
// false) until enable.json is removed: the allocation stays reserved.
function sharedRange(settingsOrEnable) {
  const e =
    settingsOrEnable && typeof settingsOrEnable === "object" && "version" in settingsOrEnable
      ? settingsOrEnable
      : readEnable(settingsOrEnable || readSettings());
  if (!e) return null;
  return {
    enabled: e.enabled === true,
    base: e.base,
    last: e.base + e.count - 1,
    count: e.count,
    egressIpv4: isIpv4(e.egressIpv4) ? e.egressIpv4 : null,
    dedicatedIpv4: isIpv4(e.dedicatedIpv4) ? e.dedicatedIpv4 : null,
  };
}

function enableBody(params, layout, settings, raw) {
  return {
    version: ENABLE_VERSION,
    enabled: true,
    base: params.base,
    count: params.count,
    last: params.last,
    egressIpv4: params.egressIpv4,
    dedicatedIpv4: params.dedicatedIpv4,
    family: params.family,
    maxConns: params.maxConns,
    logdumpBytes: params.logdumpBytes,
    denyPorts: params.denyPorts,
    sliceMemMax: params.sliceMemMax,
    cpuWeight: params.cpuWeight,
    procs: layout.map((r) => ({ sp: r.sp, first: r.first, last: r.last, unit: r.unit, cfg: cfgPathFor(settings, r.sp) })),
    params: raw && typeof raw === "object" ? raw : {},
  };
}

function stableEnableText(body, prev, now) {
  const comparable = (o) => {
    if (!o) return null;
    const { enabledAt, updatedAt, ...rest } = o;
    return JSON.stringify(rest);
  };
  const changed = comparable(body) !== comparable(prev);
  const out = {
    ...body,
    enabledAt: prev && prev.enabled === true && prev.enabledAt ? prev.enabledAt : now,
    updatedAt: changed || !prev || !prev.updatedAt ? now : prev.updatedAt,
  };
  return { changed, text: JSON.stringify(out, null, 2) + "\n" };
}

// ── secret ───────────────────────────────────────────────────────────────

// The RADIUS secret: kept while the file holds a valid one, else generated.
function ensureSecret(settings, ids, ops, randomBytes) {
  const cur = readText(settings.secretPath);
  const curTrim = cur === null ? null : cur.trim();
  if (curTrim !== null && SECRET_RE.test(curTrim)) {
    // normalise ownership / mode / a stray newline without changing the value
    const written = ops.ensureFile(settings.secretPath, curTrim, { mode: 0o640, uid: 0, gid: ids.radiusGid });
    return { secret: curTrim, created: false, rewritten: written };
  }
  const secret = newSecret(randomBytes);
  ops.writeAtomic(settings.secretPath, secret, { mode: 0o640, uid: 0, gid: ids.radiusGid });
  return { secret, created: true, rewritten: true };
}

// ── systemd ──────────────────────────────────────────────────────────────

function makeSystemd(run) {
  const sc = (args, timeoutMs = 120000) => run("systemctl", args, { timeoutMs });
  return {
    sc,
    async isActive(unit) {
      const r = await sc(["is-active", unit], 15000);
      return String(r.stdout || "").trim() === "active";
    },
    async isEnabled(unit) {
      const r = await sc(["is-enabled", unit], 15000);
      return String(r.stdout || "").trim() === "enabled";
    },
    async show(units, props) {
      const r = await sc(["show", ...units, ...props.map((p) => `--property=${p}`)], 15000);
      // blocks separated by blank lines, in the order of the units
      const blocks = String(r.stdout || "").split(/\n\s*\n/);
      return units.map((u, i) => {
        const obj = {};
        for (const line of String(blocks[i] || "").split("\n")) {
          const eq = line.indexOf("=");
          if (eq > 0) obj[line.slice(0, eq)] = line.slice(eq + 1);
        }
        return obj;
      });
    },
  };
}

// A restarted 3proxy unit is ready once systemd says active and the range's
// first SOCKS port listens again on 127.0.0.4.
async function defaultWaitReady(unit, range, { run, sleep, now, timeoutMs = READY_TIMEOUT_MS }) {
  const deadline = now() + timeoutMs;
  for (;;) {
    const a = await run("systemctl", ["is-active", unit], { timeoutMs: 15000 });
    if (String(a.stdout || "").trim() === "active") {
      const l = await run("ss", ["-Hltn", "src", `${SOCKS_LISTEN}:${range.first}`], { timeoutMs: 15000 });
      if (l.code === 0 && String(l.stdout || "").trim()) return true;
    }
    if (now() >= deadline) return false;
    await sleep(READY_POLL_MS);
  }
}

function appliedStampPath(settings, name) {
  return path.join(settings.runDir, "applied", `${name}.sha256`);
}

function readStamp(settings, name) {
  return parseHashFile(readText(appliedStampPath(settings, name)));
}

async function guardHasPergb(run, uid) {
  const r = await run("nft", ["list", "table", "inet", GUARD_TABLE], { timeoutMs: 30000 });
  if (r.code !== 0) return false;
  // the number, or the passwd name (bare or quoted) when nft names uids
  const re = new RegExp(`meta skuid (${uid}|"?netrun-pergb"?) jump pergb\\b`);
  return re.test(String(r.stdout || ""));
}

// ── apply / disable / status ─────────────────────────────────────────────

// Render, write and (re)start the per-GB runtime from the enable params.
// deps: { settings, run, sleep, now, waitReady, randomBytes, log }.
async function apply(raw, deps = {}) {
  const settings = deps.settings || readSettings();
  const run = deps.run || execCapture;
  const sleep = deps.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const now = deps.now || Date.now;
  const log = deps.log || console;
  const waitReady = deps.waitReady || ((unit, range) => defaultWaitReady(unit, range, { run, sleep, now }));
  const sd = makeSystemd(run);
  const ops = makeFsOps(settings);

  const norm = normalizeParams(raw);
  if (!norm.ok) return norm;
  const params = norm.params;
  const ids = checkUsers(settings);
  if (!ids.ok) return ids;
  const bin = checkBinary(settings);
  if (!bin.ok) return bin;

  // The egress guard: uid 65533 must be gated before anything runs as it
  // (checked before any file is written: a refusal leaves the node as it was).
  if (settings.requireGuard && !(await guardHasPergb(run, settings.pergbUid))) {
    if (fs.existsSync(settings.guardBin)) {
      const g = await run("bash", [settings.guardBin, "apply"], { timeoutMs: 120000 });
      if (g.code !== 0) log.error(`[pergb] netrun-proxy-guard apply failed: ${short(g)}`);
    }
    if (!(await guardHasPergb(run, settings.pergbUid))) {
      return {
        ok: false,
        error: "proxy_guard_missing",
        detail: `table inet ${GUARD_TABLE} has no "meta skuid ${settings.pergbUid} jump pergb" — run netrun-proxy-guard apply`,
      };
    }
  }

  const result = {
    ok: true,
    changed: [],
    restarted: [],
    started: [],
    stopped: [],
    reloaded: [],
    procs: [],
    secretCreated: false,
  };
  const sec = ensureSecret(settings, ids, ops, deps.randomBytes);
  result.secretCreated = sec.created;
  if (sec.rewritten) result.changed.push(settings.secretPath);

  const layout = procRanges(params.base, params.count, params.procs);
  result.procs = layout.map((r) => ({ unit: r.unit, first: r.first, last: r.last }));
  const prev = readEnable(settings);

  // Remember what every running unit loaded BEFORE its file changes: a unit
  // without a stamp (started before this agent wrote one) runs today's file.
  fs.mkdirSync(path.join(settings.runDir, "applied"), { recursive: true });
  const preHash = new Map();
  for (const r of layout) {
    const text = readText(cfgPathFor(settings, r.sp));
    preHash.set(r.sp, text === null ? null : sha256Hex(text));
  }
  const preHaproxy = readText(settings.haproxyCfg);

  // Files: cfgs, haproxy, slice drop-ins.
  fs.mkdirSync(settings.cfgDir, { recursive: true });
  for (const r of layout) {
    const text = renderCfg(params, r, sec.secret, settings.logDir);
    if (ops.ensureFile(cfgPathFor(settings, r.sp), text, { mode: 0o640, uid: 0, gid: ids.pergbGid })) {
      result.changed.push(cfgPathFor(settings, r.sp));
    }
  }
  const haproxyText = renderHaproxy(params, { crtList: settings.crtList, runDir: settings.runDir });
  const haproxyChanged = ops.ensureFile(settings.haproxyCfg, haproxyText, {
    mode: 0o640,
    uid: 0,
    gid: ids.haproxyGid,
  });
  if (haproxyChanged) result.changed.push(settings.haproxyCfg);
  const sliceDropin = path.join(settings.systemdDir, `${SLICE}.d`, DROPIN_NAME);
  const parentDropin = path.join(settings.systemdDir, `${PARENT_SLICE}.d`, DROPIN_NAME);
  let unitsChanged = false;
  if (ops.ensureFile(sliceDropin, renderSliceDropin(params), { mode: 0o644, uid: 0, gid: 0 })) {
    result.changed.push(sliceDropin);
    unitsChanged = true;
  }
  if (ops.ensureFile(parentDropin, renderParentSliceDropin(params), { mode: 0o644, uid: 0, gid: 0 })) {
    result.changed.push(parentDropin);
    unitsChanged = true;
  }

  // Ranges that are no longer in the layout (base / count / procs changed).
  const keep = new Set(layout.map((r) => `pergb_${r.sp}.cfg`));
  const stale = [];
  for (const f of fs.readdirSync(settings.cfgDir)) {
    const m = /^pergb_(\d+)\.cfg$/.exec(f);
    if (m && !keep.has(f)) stale.push(Number(m[1]));
  }

  // enable.json (secrets included: 0600 root).
  const ts = new Date(now()).toISOString();
  const en = stableEnableText(enableBody(params, layout, settings, raw), prev, ts);
  if (en.changed || !prev || prev.enabled !== true) {
    ops.writeAtomic(settings.enablePath, en.text, { mode: 0o600, uid: 0, gid: 0 });
    result.changed.push(settings.enablePath);
  } else {
    ops.ensureFile(settings.enablePath, readText(settings.enablePath), { mode: 0o600, uid: 0, gid: 0 });
  }

  const fail = (error, detail) => ({ ...result, ok: false, error, detail });
  if (unitsChanged) {
    const r = await sd.sc(["daemon-reload"]);
    if (r.code !== 0) return fail("systemd_failed", `daemon-reload: ${short(r)}`);
    // the running slices take the limits now too
    const high = Math.floor((params.sliceMemMax * 0.85) / (1024 * 1024)) * 1024 * 1024;
    await sd.sc([
      "set-property",
      "--runtime",
      SLICE,
      `CPUWeight=${params.cpuWeight}`,
      `MemoryHigh=${high}`,
      `MemoryMax=${params.sliceMemMax}`,
      `TasksMax=${tasksMax(params)}`,
    ]);
    await sd.sc(["set-property", "--runtime", PARENT_SLICE, `CPUWeight=${params.cpuWeight}`]);
  }

  // Stale ranges: stop, drop from the target, remove the cfg.
  for (const sp of stale) {
    const unit = unitFor(sp);
    if (await sd.isActive(unit)) result.stopped.push(unit);
    const r = await sd.sc(["disable", "--now", unit]);
    if (r.code !== 0) return fail("systemd_failed", `disable --now ${unit}: ${short(r)}`);
    try {
      fs.unlinkSync(cfgPathFor(settings, sp));
    } catch {}
    try {
      fs.unlinkSync(appliedStampPath(settings, String(sp)));
    } catch {}
    result.changed.push(cfgPathFor(settings, sp));
  }

  // Every range unit is wanted by the target; the target starts at boot.
  for (const r of layout) {
    if (!(await sd.isEnabled(r.unit))) {
      const e = await sd.sc(["enable", r.unit]);
      if (e.code !== 0) return fail("systemd_failed", `enable ${r.unit}: ${short(e)}`);
    }
  }
  if (!(await sd.isEnabled(TARGET))) {
    const e = await sd.sc(["enable", TARGET]);
    if (e.code !== 0) return fail("systemd_failed", `enable ${TARGET}: ${short(e)}`);
  }

  // Rolling restart: one range at a time, in port order, the next only once
  // the previous serves again — the other range keeps serving meanwhile.
  for (const r of layout) {
    if (!(await sd.isActive(r.unit))) continue;
    const want = sha256Hex(readText(cfgPathFor(settings, r.sp)) || "");
    const stamp = readStamp(settings, String(r.sp));
    const loaded = stamp || preHash.get(r.sp);
    if (loaded === want) continue;
    log.log(`[pergb] restarting ${r.unit} (cfg changed)`);
    const rr = await sd.sc(["restart", r.unit]);
    if (rr.code !== 0) return fail("restart_failed", `${r.unit}: ${short(rr)}`);
    if (!(await waitReady(r.unit, r))) {
      return fail("restart_failed", `${r.unit} not active and listening on ${SOCKS_LISTEN}:${r.first} after restart`);
    }
    result.restarted.push(r.unit);
  }

  // haproxy: a graceful reload when its file changed under a running one.
  if (await sd.isActive(HAPROXY_UNIT)) {
    const stamp = readStamp(settings, "haproxy");
    const loaded = stamp || (preHaproxy === null ? null : sha256Hex(preHaproxy));
    if (loaded !== sha256Hex(haproxyText)) {
      const rr = await sd.sc(["reload", HAPROXY_UNIT]);
      if (rr.code !== 0) return fail("reload_failed", `${HAPROXY_UNIT}: ${short(rr)}`);
      result.reloaded.push(HAPROXY_UNIT);
    }
  }

  // Start whatever is not running; nothing is called when all of it runs.
  const members = [...layout.map((r) => r.unit), HAPROXY_UNIT, CERTS_PATH_UNIT, TARGET];
  const inactive = [];
  for (const u of members) if (!(await sd.isActive(u))) inactive.push(u);
  if (inactive.length) {
    // the target pulls its wants (the range units, haproxy, the certs path,
    // the RADIUS socket); the explicit list covers members it already had
    const st = await sd.sc(["start", TARGET, ...inactive.filter((u) => u !== TARGET)]);
    if (st.code !== 0) return fail("start_failed", `start ${inactive.join(" ")}: ${short(st)}`);
    result.started.push(...inactive);
  }
  return result;
}

// Stop the per-GB runtime: the target is disabled (no start at boot) and
// stopped with everything PartOf it; enable.json keeps the params with
// enabled: false (sharedRange still reports the reserved range). The RADIUS
// socket is started again unless stopRadius (its state stays queryable).
async function disable(opts = {}, deps = {}) {
  const settings = deps.settings || readSettings();
  const run = deps.run || execCapture;
  const sd = makeSystemd(run);
  const ops = makeFsOps(settings);
  const stopRadius = opts && opts.stopRadius === true;
  const units = new Set([TARGET, HAPROXY_UNIT, CERTS_PATH_UNIT]);
  const prev = readEnable(settings);
  if (prev && Array.isArray(prev.procs)) for (const p of prev.procs) if (p && p.unit) units.add(String(p.unit));
  try {
    for (const f of fs.readdirSync(settings.cfgDir)) {
      const m = /^pergb_(\d+)\.cfg$/.exec(f);
      if (m) units.add(unitFor(Number(m[1])));
    }
  } catch {}
  const radiusWasActive = await sd.isActive(RADIUS_SOCKET);
  if (stopRadius) {
    units.add(RADIUS_SERVICE);
    units.add(RADIUS_SOCKET);
  }
  const list = [...units];
  const wasActive = [];
  for (const u of list) if (await sd.isActive(u)) wasActive.push(u);
  const d = await sd.sc(["disable", TARGET]);
  const s = await sd.sc(["stop", ...list]);
  if (!stopRadius && radiusWasActive && !(await sd.isActive(RADIUS_SOCKET))) {
    await sd.sc(["start", RADIUS_SOCKET]);
  }
  if (prev && prev.enabled !== false) {
    const out = { ...prev, enabled: false, updatedAt: new Date((deps.now || Date.now)()).toISOString() };
    ops.writeAtomic(settings.enablePath, JSON.stringify(out, null, 2) + "\n", { mode: 0o600, uid: 0, gid: 0 });
  }
  const ok = d.code === 0 && s.code === 0;
  return {
    ok,
    ...(ok ? {} : { error: "systemd_failed", detail: short(s.code !== 0 ? s : d) }),
    stopped: wasActive,
  };
}

// The node's primary IPv4 (option A: the per-GB egress when the enable
// request's egressIpv4 is null): the source of the default route.
async function detectPrimaryIpv4(deps = {}) {
  const run = deps.run || execCapture;
  const r = await run("ip", ["-4", "-o", "route", "get", "1.1.1.1"], { timeoutMs: 10000 });
  const m = /\bsrc (\d+\.\d+\.\d+\.\d+)\b/.exec(String((r && r.stdout) || ""));
  return r && r.code === 0 && m && isIpv4(m[1]) ? m[1] : null;
}

// Unit states for /pergb/status: { enabled, procs: [{unit, first, last,
// active, pid}], haproxy: {active, pid}, target: {active, enabled} }.
async function status(deps = {}) {
  const settings = deps.settings || readSettings();
  const run = deps.run || execCapture;
  const sd = makeSystemd(run);
  const e = readEnable(settings);
  const layout = e && Array.isArray(e.procs) ? e.procs : [];
  const units = [...layout.map((p) => String(p.unit)), HAPROXY_UNIT, TARGET];
  const shown = await sd.show(units, ["ActiveState", "MainPID", "UnitFileState"]);
  const pick = (i) => {
    const o = shown[i] || {};
    const pid = Number(o.MainPID);
    return { active: o.ActiveState === "active", pid: Number.isInteger(pid) && pid > 0 ? pid : null };
  };
  const procs = layout.map((p, i) => ({ unit: String(p.unit), first: p.first, last: p.last, ...pick(i) }));
  const hap = pick(layout.length);
  const tgt = shown[layout.length + 1] || {};
  return {
    enabled: Boolean(e && e.enabled === true),
    procs,
    haproxy: hap,
    target: { active: tgt.ActiveState === "active", enabled: tgt.UnitFileState === "enabled" },
  };
}

module.exports = {
  TARGET,
  SLICE,
  PARENT_SLICE,
  SLICE_CGROUP,
  HAPROXY_UNIT,
  CERTS_PATH_UNIT,
  RADIUS_SOCKET,
  RADIUS_SERVICE,
  HTTP_LISTEN,
  SOCKS_LISTEN,
  ACL_OPERATIONS,
  LOGFORMAT,
  MAXCONN_BASE,
  MAXCONN_PORT,
  DEFAULT_DENY_PORTS,
  readSettings,
  unitFor,
  cfgPathFor,
  cgroupPath,
  procRanges,
  parseSize,
  normalizeParams,
  renderCfg,
  renderHaproxy,
  renderSliceDropin,
  renderParentSliceDropin,
  tasksMax,
  newSecret,
  parseHashFile,
  parseIdFile,
  checkBinary,
  checkUsers,
  readEnable,
  sharedRange,
  detectPrimaryIpv4,
  apply,
  disable,
  status,
  execCapture,
};
