"use strict";

// Pay-per-GB v2, AMENDMENT A1 (2026-10-09) — one address pool per per-GB node.
//
// On a per-GB node the routed /48 is ONE pool: per-GB rotation, sticky and
// static draw from it inside netrun-radius (alloc.py, the allocator of
// record), and per-piece takes single /64s out of it on demand. The node file
// /etc/netrun/pergb-pool.conf (KEY=VALUE lines, written by /pergb/enable,
// removed by /pergb/disable, backed up with /etc/netrun):
//   PREFIX=2602:f2dc:a9::/48   the routed prefix the pool lives in
//   POOL=0000-fffe             subnet ids (hex, relative to PREFIX) of the pool
//   ENABLED=1
// No file = per-GB off = every per-piece allocator behaves exactly as before.
// With the file, a per-piece allocator (egress.js generateRoutedAddresses, the
// generator's routed_ipv6_addresses, the orchestrator's legacy_to_48) takes a
// /64 of the pool ONLY through RADIUS `reserve_nets` (one /64 per address) and
// fails closed when that call fails — never a blind pick. /64s of PREFIX
// outside POOL (none with the default 0000-fffe) stay per-piece's own and are
// picked locally as before. The node's own last /64 (ffff) is never in the
// pool and never a proxy's.
// Per-piece hands /64s back with `release_nets` (24 h cool-down in RADIUS).
//
// This module: the pool file reader, the /64 <-> wire conversions, a minimal
// RADIUS ctl client for reserve_nets / release_nets (I5; the transport can be
// swapped for the agent's own ctl client with setTransport), the per-piece
// /64 scan (cfg anchors incl. .disabled / .failed, ipv6_*.list and .tmp, the
// egress state) and releaseUnusedNets, which hands back only /64s nothing
// per-piece names any more.

const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const path = require("path");

const DEFAULT_POOL_FILE = "/etc/netrun/pergb-pool.conf";
const DEFAULT_CTL_SOCKET = "/run/netrun-radius/ctl.sock";
const DEFAULT_CTL_TIMEOUT_MS = 10_000;
const RESERVE_MAX = 5000; // I5: count 1..5000
const REF_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const PLEN_MIN = 16;
const PLEN_MAX = 63; // a pool needs at least two /64s (one is the node's own)

// ── IPv6 text <-> BigInt (no dependency on egress.js: it requires us) ────

function ipv6ToBig(text) {
  const s = String(text || "").trim().toLowerCase();
  if (!s || s.includes("%") || !/^[0-9a-f:.]+$/.test(s)) return null;
  if (net.isIPv6(s) !== true) return null;
  let head = s;
  let tailGroups = [];
  // an embedded IPv4 tail (::ffff:1.2.3.4) — two groups
  const v4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) {
    const o = v4[2].split(".").map(Number);
    head = v4[1].endsWith("::") ? v4[1] : v4[1].slice(0, -1);
    tailGroups = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
  }
  const parts = head.split("::");
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const fill = 8 - tailGroups.length - left.length - right.length;
  if (parts.length === 1 && fill !== 0) return null;
  if (fill < 0) return null;
  const groups = [...left, ...Array(parts.length === 2 ? fill : 0).fill("0"), ...right].map((g) => parseInt(g, 16));
  const all = [...groups, ...tailGroups];
  if (all.length !== 8 || all.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  return all.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

function bigToIpv6(big) {
  const groups = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((big >> BigInt(i * 16)) & 0xffffn));
  // RFC 5952: the longest run (>= 2) of zero groups becomes "::"
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

// The /64 of an address (or of "<addr>/64" text) as a BigInt key, or null.
function net64Of(text) {
  const s = String(text || "").trim();
  const big = ipv6ToBig(s.includes("/") ? s.slice(0, s.indexOf("/")) : s);
  return big === null ? null : big >> 64n;
}

// BigInt /64 key -> "2602:f2dc:a9:1234::/64".
function net64Text(key) {
  return `${bigToIpv6(BigInt(key) << 64n)}/64`;
}

// "2602:F2DC:A9::5/48" -> { text: "2602:f2dc:a9::/48", plen, base (first /64 key), nets (count) } or null.
function parsePrefix(text, { minLen = PLEN_MIN, maxLen = 64 } = {}) {
  const m = /^([^/\s]+)\/(\d{1,3})$/.exec(String(text || "").trim());
  if (!m) return null;
  const plen = Number(m[2]);
  if (plen < minLen || plen > maxLen) return null;
  const big = ipv6ToBig(m[1]);
  if (big === null) return null;
  const nets = 1n << BigInt(64 - plen);
  const base = (big >> 64n) & ~(nets - 1n);
  return { text: `${bigToIpv6(base << 64n)}/${plen}`, plen, base, nets };
}

// ── the pool file ─────────────────────────────────────────────────────────

function poolFilePath(env = process.env) {
  return String(env.NETRUN_PERGB_POOL_FILE || DEFAULT_POOL_FILE);
}

function unquote(v) {
  return String(v).trim().replace(/^["']|["']$/g, "").trim();
}

// KEY=VALUE text -> { state: "off" } | { state: "on", pool } | { state: "error", error }.
// pool = { prefix, plen, base, nets, lo, hi } with lo / hi absolute /64 keys
// (BigInt) of the pool range; the node's own last /64 is never inside it.
function parsePoolConf(text) {
  const kv = {};
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    kv[line.slice(0, eq).trim().toUpperCase()] = unquote(line.slice(eq + 1));
  }
  const enabled = kv.ENABLED === undefined ? "1" : kv.ENABLED.toLowerCase();
  if (["0", "false", "no", "off"].includes(enabled)) return { state: "off", reason: "ENABLED=0" };
  const p = parsePrefix(kv.PREFIX, { minLen: PLEN_MIN, maxLen: PLEN_MAX });
  if (!p) return { state: "error", error: `bad PREFIX ${JSON.stringify(kv.PREFIX || "")} (want /${PLEN_MIN}../${PLEN_MAX})` };
  let lo = 0n;
  let hi = p.nets - 2n; // default: the whole prefix but its last (the node's own) /64
  if (kv.POOL !== undefined && kv.POOL !== "") {
    const m = /^([0-9a-fA-F]{1,16})\s*-\s*([0-9a-fA-F]{1,16})$/.exec(kv.POOL);
    if (!m) return { state: "error", error: `bad POOL ${JSON.stringify(kv.POOL)} (want <hex>-<hex>)` };
    lo = BigInt(`0x${m[1]}`);
    hi = BigInt(`0x${m[2]}`);
    if (lo > hi || hi >= p.nets) return { state: "error", error: `POOL ${kv.POOL} is outside ${p.text}` };
    if (hi > p.nets - 2n) hi = p.nets - 2n; // never the node's own /64
    if (lo > hi) return { state: "error", error: `POOL ${kv.POOL} holds only the node's own /64` };
  }
  return {
    state: "on",
    pool: { prefix: p.text, plen: p.plen, base: p.base, nets: p.nets, lo: p.base + lo, hi: p.base + hi },
  };
}

// Cached by inode / size / mtime: callers ask on every allocation.
function createPoolReader({ env = process.env } = {}) {
  let cache = null;
  return function read() {
    const file = poolFilePath(env);
    let st;
    try {
      st = fs.statSync(file);
    } catch (err) {
      if (err && err.code === "ENOENT") {
        cache = null;
        return { state: "off", reason: "no_pool_file", file };
      }
      return { state: "error", error: `stat ${file}: ${err.message || err}`, file };
    }
    const sig = `${st.ino}:${st.size}:${st.mtimeMs}`;
    if (cache && cache.sig === sig && cache.file === file) return cache.value;
    let value;
    try {
      value = { ...parsePoolConf(fs.readFileSync(file, "utf-8")), file };
    } catch (err) {
      value = { state: "error", error: `read ${file}: ${err.message || err}`, file };
    }
    cache = { sig, file, value };
    return value;
  };
}

// Is the /64 key inside the pool range?
function inPool(pool, key) {
  return Boolean(pool) && key >= pool.lo && key <= pool.hi;
}

// Do the pool and a prefix ("x::/48" text) share any /64?
function poolOverlaps(pool, prefixText) {
  const p = parsePrefix(prefixText);
  if (!pool || !p) return false;
  return p.base <= pool.hi && p.base + p.nets - 1n >= pool.lo;
}

// A /64 as RADIUS reports it -> its BigInt key, or null. A JSON number is a
// subnet id relative to PREFIX (the `excluded` op's form, I5); a string
// without ':' is a subnet id in hex ("8a3f", as in POOL=0000-fffe); anything
// with ':' is an address or "<net>/64".
function netFromWire(pool, v) {
  if (!pool) return null;
  let id = null;
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) id = BigInt(v);
  else if (typeof v === "string" && /^(0x)?[0-9a-fA-F]{1,16}$/i.test(v.trim())) id = BigInt(`0x${v.trim().replace(/^0x/i, "")}`);
  if (id !== null) return id < pool.nets ? pool.base + id : null;
  if (typeof v === "string" && v.includes(":")) {
    const k = net64Of(v);
    if (k === null || k < pool.base || k >= pool.base + pool.nets) return null;
    return k;
  }
  return null;
}

// BigInt /64 key -> the subnet id RADIUS expects (a Number, as in `excluded`).
function netToWire(pool, key) {
  return Number(key - pool.base);
}

// ── the RADIUS ctl client (I5) ────────────────────────────────────────────

// One JSON request line, one JSON response line per connection; an
// `{error}` reply rejects with err.code = the error string.
function ctlRequest(req, { socketPath = DEFAULT_CTL_SOCKET, timeoutMs = DEFAULT_CTL_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let buf = "";
    let done = false;
    const sock = net.createConnection(socketPath);
    const finish = (err, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) reject(err);
      else resolve(value);
    };
    const timer = setTimeout(() => finish(Object.assign(new Error("radius_ctl_timeout"), { code: "radius_unavailable" })), timeoutMs);
    sock.setEncoding("utf-8");
    sock.on("connect", () => sock.write(`${JSON.stringify(req)}\n`));
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      let reply;
      try {
        reply = JSON.parse(buf.slice(0, nl));
      } catch {
        finish(Object.assign(new Error("radius_ctl_bad_reply"), { code: "radius_unavailable" }));
        return;
      }
      if (reply && typeof reply === "object" && reply.error) {
        finish(Object.assign(new Error(`radius_ctl: ${reply.error}`), { code: String(reply.error), reply }));
        return;
      }
      finish(null, reply);
    });
    sock.on("error", (err) => finish(Object.assign(new Error(`radius_ctl: ${err.message}`), { code: "radius_unavailable" })));
    sock.on("end", () => finish(Object.assign(new Error("radius_ctl: closed without a reply"), { code: "radius_unavailable" })));
  });
}

// The transport every default pool access uses: (op, body) -> Promise<reply>.
// The agent's own RADIUS ctl client (lane L3) can take over with setTransport.
let transport = null;
function setTransport(fn) {
  transport = typeof fn === "function" ? fn : null;
}

function defaultTransport(env) {
  const socketPath = String(env.NETRUN_RADIUS_CTL_SOCKET || DEFAULT_CTL_SOCKET);
  return (op, body) => ctlRequest({ op, ...body }, { socketPath });
}

// The pool as per-piece allocators see it:
//   state()                    -> the pool file (cached)
//   reserve({count, ref, force}) -> { nets: [BigInt], ref }   (throws; fail closed)
//   release({nets, ref})        -> { released, coolDownUntil } (throws)
function createPoolAccess({ env = process.env, request = null, log = console } = {}) {
  const read = createPoolReader({ env });
  const call = (op, body) => (request || transport || defaultTransport(env))(op, body);

  async function reserve({ count, ref, force = false }) {
    const st = read();
    if (st.state !== "on") throw Object.assign(new Error(`pergb pool ${st.state}: ${st.error || st.reason || ""}`), { code: "pergb_off" });
    const n = Number(count);
    if (!Number.isInteger(n) || n < 1 || n > RESERVE_MAX) throw Object.assign(new Error(`reserve count ${count}`), { code: "bad_request" });
    if (!REF_RE.test(String(ref || ""))) throw Object.assign(new Error(`reserve ref ${ref}`), { code: "bad_request" });
    const body = { count: n, owner: "perpiece", ref };
    if (force) body.force = true;
    const reply = await call("reserve_nets", body);
    const raw = Array.isArray(reply && reply.nets) ? reply.nets : null;
    if (!raw) throw Object.assign(new Error("reserve_nets: no nets in the reply"), { code: "bad_reply" });
    const nets = [];
    const seen = new Set();
    for (const v of raw) {
      const k = netFromWire(st.pool, v);
      if (k === null) throw Object.assign(new Error(`reserve_nets: ${JSON.stringify(v)} is not a /64 of ${st.pool.prefix}`), { code: "bad_reply" });
      if (k === st.pool.base + st.pool.nets - 1n) throw Object.assign(new Error("reserve_nets: handed out the node's own /64"), { code: "bad_reply" });
      if (seen.has(k)) throw Object.assign(new Error(`reserve_nets: ${net64Text(k)} twice`), { code: "bad_reply" });
      if (!inPool(st.pool, k)) log.error(`[pergb-pool] reserve_nets: ${net64Text(k)} is outside POOL of ${st.pool.prefix}`);
      seen.add(k);
      nets.push(k);
    }
    if (nets.length !== n) throw Object.assign(new Error(`reserve_nets: ${nets.length} /64(s) for ${n} asked`), { code: "bad_reply" });
    return { nets, ref: (reply && reply.ref) || ref };
  }

  async function release({ nets, ref }) {
    const st = read();
    if (st.state !== "on") throw Object.assign(new Error(`pergb pool ${st.state}`), { code: "pergb_off" });
    if (!REF_RE.test(String(ref || ""))) throw Object.assign(new Error(`release ref ${ref}`), { code: "bad_request" });
    const wire = [...new Set(nets.map((k) => BigInt(k)))]
      .filter((k) => k >= st.pool.base && k < st.pool.base + st.pool.nets)
      .map((k) => netToWire(st.pool, k));
    if (wire.length === 0) return { released: 0 };
    return (await call("release_nets", { nets: wire, ref })) || {};
  }

  return { state: read, reserve, release };
}

let defaultAccessInstance = null;
function defaultAccess() {
  if (!defaultAccessInstance) defaultAccessInstance = createPoolAccess();
  return defaultAccessInstance;
}

// Is this a per-GB node (a pool file, readable or not)? Callers skip the
// hand-back bookkeeping when it is not.
function poolPresent(access = defaultAccess()) {
  try {
    return access.state().state !== "off";
  } catch {
    return false;
  }
}

// A fresh ref for one reservation: "<kind>:<what>:<random>".
function newRef(kind, what = "") {
  const rnd = crypto.randomBytes(6).toString("hex");
  const mid = String(what).replace(/[^A-Za-z0-9._-]/g, "").slice(0, 64);
  return `${kind}:${mid ? `${mid}:` : ""}${rnd}`;
}

// ── the per-piece /64 scan ────────────────────────────────────────────────

const CFG_ANY_RE = /^3proxy_\d+\.cfg/; // .cfg, .cfg.disabled, .cfg.failed, rewrite temps
const LIST_ANY_RE = /^ipv6_\d+\.list/; // .list, .list.tmp
const EGRESS_STATE = "egress_state.json";

function addressesOfText(text, out) {
  for (const m of String(text).matchAll(/\s-e([0-9A-Fa-f:]+)/g)) {
    const k = net64Of(m[1]);
    if (k !== null) out.add(k);
  }
}

function egressStateNets(raw, out) {
  const add = (a) => {
    const k = net64Of(a);
    if (k !== null) out.add(k);
  };
  if (!raw || typeof raw !== "object") return;
  for (const e of Object.values(raw.ports || {})) {
    if (e && typeof e === "object") {
      add(e.anchor);
      add(e.current);
    }
  }
  for (const a of Array.isArray(raw.pool) ? raw.pool : []) add(a);
  for (const d of Array.isArray(raw.draining) ? raw.draining : []) add(d && d.addr);
  for (const h of Array.isArray(raw.pergb_held) ? raw.pergb_held : []) add(h && h.net);
}

// Every /64 per-piece names on this node: cfg anchors (any cfg variant), the
// generator's lists (a batch being generated has its list before its cfg),
// the egress state. complete = every source was read; a caller that hands
// /64s back must not do so on an incomplete scan.
function scanPerPieceNets({ proxyRoot = process.env.NODE_AGENT_PROXY_ROOT || "/opt/netrun/proxyserver", skip = [] } = {}) {
  const nets = new Set();
  const errors = [];
  const skipSet = new Set(skip.map((p) => path.resolve(p)));
  const readDir = (dir, re) => {
    try {
      return fs.readdirSync(dir).filter((f) => re.test(f)).map((f) => path.join(dir, f));
    } catch (err) {
      if (err && err.code === "ENOENT") return [];
      errors.push(`readdir ${dir}: ${err.message || err}`);
      return [];
    }
  };
  for (const file of readDir(path.join(proxyRoot, "3proxy"), CFG_ANY_RE)) {
    if (skipSet.has(path.resolve(file))) continue;
    try {
      addressesOfText(` ${fs.readFileSync(file, "utf-8")}`, nets);
    } catch (err) {
      if (err && err.code !== "ENOENT") errors.push(`read ${file}: ${err.message || err}`);
    }
  }
  for (const file of readDir(proxyRoot, LIST_ANY_RE)) {
    if (skipSet.has(path.resolve(file))) continue;
    try {
      for (const line of fs.readFileSync(file, "utf-8").split("\n")) {
        const k = net64Of(line);
        if (k !== null) nets.add(k);
      }
    } catch (err) {
      if (err && err.code !== "ENOENT") errors.push(`read ${file}: ${err.message || err}`);
    }
  }
  const statePath = path.join(proxyRoot, EGRESS_STATE);
  try {
    egressStateNets(JSON.parse(fs.readFileSync(statePath, "utf-8")), nets);
  } catch (err) {
    if (err && err.code !== "ENOENT") errors.push(`read ${statePath}: ${err.message || err}`);
  }
  return { nets, complete: errors.length === 0, errors };
}

// The /64s named by the given files (cfg `-e` anchors, list lines), read
// BEFORE the caller deletes them. Unreadable / missing files add nothing.
function collectFileNets(files) {
  const out = new Set();
  for (const file of files || []) {
    let text;
    try {
      text = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    addressesOfText(` ${text}`, out);
    for (const line of text.split("\n")) {
      const k = net64Of(line);
      if (k !== null) out.add(k);
    }
  }
  return out;
}

// Hand back the pool /64s of `candidates` (BigInt keys) that nothing
// per-piece names any more (a fresh, complete scan). Never throws:
// { requested, released, kept, skipped?, error? }.
async function releaseUnusedNets(candidates, { access = defaultAccess(), proxyRoot, ref, inUse = new Set(), log = console } = {}) {
  const st = access.state();
  const out = { requested: 0, released: 0, kept: 0 };
  if (st.state !== "on") return { ...out, skipped: st.state === "off" ? "pergb_off" : "pool_file_error" };
  const mine = [...(candidates || [])].map((k) => BigInt(k)).filter((k) => inPool(st.pool, k));
  out.requested = mine.length;
  if (mine.length === 0) return out;
  const scan = scanPerPieceNets({ proxyRoot });
  if (!scan.complete) {
    log.error(`[pergb-pool] ${mine.length} /64(s) not handed back: per-piece scan incomplete (${scan.errors.slice(0, 3).join("; ")})`);
    return { ...out, kept: mine.length, error: "scan_incomplete" };
  }
  const free = mine.filter((k) => !scan.nets.has(k) && !inUse.has(k));
  out.kept = mine.length - free.length;
  if (free.length === 0) return out;
  try {
    const reply = await access.release({ nets: free, ref: ref || newRef("perpiece-release") });
    out.released = Number.isFinite(Number(reply && reply.released)) ? Number(reply.released) : free.length;
    if (reply && reply.coolDownUntil) out.coolDownUntil = reply.coolDownUntil;
  } catch (err) {
    log.error(`[pergb-pool] release_nets of ${free.length} /64(s) failed: ${err.message || err}`);
    return { ...out, error: String((err && err.code) || "release_failed") };
  }
  return out;
}

module.exports = {
  DEFAULT_POOL_FILE,
  DEFAULT_CTL_SOCKET,
  RESERVE_MAX,
  poolFilePath,
  parsePoolConf,
  createPoolReader,
  createPoolAccess,
  defaultAccess,
  poolPresent,
  setTransport,
  ctlRequest,
  inPool,
  poolOverlaps,
  netFromWire,
  netToWire,
  newRef,
  scanPerPieceNets,
  collectFileNets,
  releaseUnusedNets,
  // pure helpers (exported for tests and egress.js)
  ipv6ToBig,
  bigToIpv6,
  net64Of,
  net64Text,
  parsePrefix,
};
