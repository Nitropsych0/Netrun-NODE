"use strict";

// Pay-per-GB v2 — the agent's per-GB service (plan §3.6–§3.8, interface I6,
// amendments A1, A7, A12). The HTTP side is pergb_tls_server.js (and the two
// A1 routes on the plain listener); this module does the work:
//
// - enable / disable: checks (routed /48, the pool file, the IP certificate's
//   crt-list, the ports), the per-GB IPv4s (A7), pergb_runtime.apply()
//   (cfgs, haproxy, units; idempotent), RADIUS facts and excluded, then the
//   pool file /etc/netrun/pergb-pool.conf (PREFIX, POOL, ENABLED=1; A1) —
//   written LAST, removed FIRST on disable: per-piece allocators take /64s
//   through RADIUS only while it exists.
// - state: the paged snapshot (staged by snapshotId, 120 s) and the delta,
//   forwarded to RADIUS; the `transitions` of both are killed at once.
// - the loops: meter (1 s) → smart rotation → enforcer (1 s), guards (2 s),
//   RADIUS probe (5 s), excluded scan push (start, after every /generate
//   job, every 10 min), canary refresh (10 min), RADIUS watch (a new epoch
//   or a recovered DB → facts and excluded again).
// - readers: status, usage, attribution, port_check, the /health block.

const crypto = require("crypto");
const dns = require("dns");
const fs = require("fs");
const fsp = require("fs/promises");
const net = require("net");
const path = require("path");

const runtimeLib = require("./pergb_runtime.js");
const { createRadiusClient, httpError, socketPathFrom } = require("./pergb_radius_client.js");
const meterLib = require("./pergb_meter.js");
const killLib = require("./pergb_kill.js");
const enforcerLib = require("./pergb_enforcer.js");
const guardsLib = require("./pergb_guards.js");
const smartLib = require("./pergb_smart.js");
const tagLib = require("./pergb_tag.js");
const ipv4Lib = require("./pergb_ipv4.js");
const radprobe = require("./pergb_radprobe.js");

const VERSION = "netrun-pergb-agent/1";
const STAGING_TTL_MS = 120000;
const STAGING_MAX_BYTES = 256 * 1024 * 1024;
const EXCLUDED_EVERY_MS = 10 * 60 * 1000;
const CANARY_EVERY_MS = 10 * 60 * 1000;
const RADIUS_WATCH_MS = 2000;
const REF_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const POOL_RE = /^([0-9a-fA-F]{1,4})-([0-9a-fA-F]{1,4})$/;
const SNAPSHOT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DEFAULT_POOL = "0000-fffe";

function readSettings(env = process.env) {
  return {
    poolFile: String(env.NETRUN_PERGB_POOL_FILE || "/etc/netrun/pergb-pool.conf"),
    stateDir: String(env.NETRUN_PERGB_STATE_DIR || "/var/lib/netrun-pergb"),
    proxyRoot: path.normalize(String(env.NODE_AGENT_PROXY_ROOT || "/opt/netrun/proxyserver")),
    cgroupRoot: String(env.NETRUN_PERGB_CGROUP_ROOT || "/sys/fs/cgroup"),
    haproxyLog: String(env.NETRUN_PERGB_HAPROXY_LOG || ""),
    loops: String(env.NETRUN_PERGB_LOOPS || "1") !== "0",
  };
}

function bad(error, detail, extra = {}) {
  return { status: 400, body: { success: false, error, detail, ...extra } };
}

function conflict(error, extra = {}) {
  return { status: 409, body: { success: false, error, ...extra } };
}

// ── the pool file (A1) ───────────────────────────────────────────────────

function parsePoolText(text) {
  const kv = {};
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    kv[line.slice(0, eq).trim().toUpperCase()] = line.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
  }
  const enabled = String(kv.ENABLED === undefined ? "1" : kv.ENABLED).toLowerCase();
  if (["0", "false", "no", "off"].includes(enabled)) return { state: "off" };
  const p = tagLib.parsePrefix48(kv.PREFIX);
  const pool = normalizePool(kv.POOL === undefined || kv.POOL === "" ? DEFAULT_POOL : kv.POOL);
  if (!p || !pool) return { state: "error", error: `bad PREFIX/POOL (${kv.PREFIX} ${kv.POOL})` };
  return { state: "on", prefix: p.text, prefixBase: p.base, pool: pool.text, lo: pool.lo, hi: pool.hi };
}

function normalizePool(text) {
  const m = POOL_RE.exec(String(text || "").trim());
  if (!m) return null;
  const lo = parseInt(m[1], 16);
  const hi = Math.min(parseInt(m[2], 16), 0xfffe);
  if (lo > hi) return null;
  const hex = (n) => n.toString(16).padStart(4, "0");
  return { lo, hi, text: `${hex(lo)}-${hex(hi)}` };
}

function poolText(prefix, pool) {
  return [
    "# NETRUN pay-per-GB v2 — the per-GB address pool (amendment A1): the routed /48",
    "# minus the node's own last /64. Written by POST /pergb/enable, removed by",
    "# POST /pergb/disable (node_agent/pergb_state.js). While it exists, per-piece",
    "# allocators take /64s of the pool ONLY through RADIUS reserve_nets.",
    `PREFIX=${prefix}`,
    `POOL=${pool}`,
    "ENABLED=1",
    "",
  ].join("\n");
}

// "/64 of the pool" text <-> subnet id
function netText(prefixBase, id) {
  return `${tagLib.bigToIpv6(BigInt(prefixBase) | (BigInt(id) << 64n))}/64`;
}

// A JSON number is a subnet id (the ctl `excluded` form); a string without
// ':' is a subnet id in hex ("8a3f" / "0x8a3f", as in POOL=0000-fffe — the
// generator's convention, scripts/lib/pergb_pool.sh); anything with ':' is an
// address or "<net>/64" of the /48.
function subnetIdOf(prefixBase, v) {
  if (typeof v === "number") return Number.isInteger(v) && v >= 0 && v <= 0xffff ? v : null;
  const s = String(v === undefined || v === null ? "" : v).trim();
  if (!s.includes(":")) return /^(0x)?[0-9a-fA-F]{1,4}$/i.test(s) ? parseInt(s.replace(/^0x/i, ""), 16) : null;
  const big = tagLib.ipv6ToBig(s.includes("/") ? s.slice(0, s.indexOf("/")) : s);
  if (big === null || big >> 80n !== BigInt(prefixBase) >> 80n) return null;
  return Number((big >> 64n) & 0xffffn);
}

// ── the per-piece /64 scan (excluded) ────────────────────────────────────

const CFG_ANY_RE = /^3proxy_\d+\.cfg/; // .cfg, .cfg.disabled, .cfg.failed
const LIST_ANY_RE = /^ipv6_\d+\.list/; // .list, .list.tmp

// Every /64 of the /48 per-piece names: cfg anchors (any cfg variant), the
// generator's lists, the egress state. -> { nets: Set<subnet id>, complete, errors }
function scanPerPieceNets({ proxyRoot, prefixBase }) {
  const nets = new Set();
  const errors = [];
  const base = BigInt(prefixBase) >> 80n;
  const add = (text) => {
    const big = tagLib.ipv6ToBig(String(text || "").trim().split("/")[0]);
    if (big !== null && big >> 80n === base) nets.add(Number((big >> 64n) & 0xffffn));
  };
  const readDir = (dir, re) => {
    try {
      return fs.readdirSync(dir).filter((f) => re.test(f)).map((f) => path.join(dir, f));
    } catch (e) {
      if (e && e.code === "ENOENT") return [];
      errors.push(`readdir ${dir}: ${e.message || e}`);
      return [];
    }
  };
  for (const file of readDir(path.join(proxyRoot, "3proxy"), CFG_ANY_RE)) {
    try {
      for (const m of fs.readFileSync(file, "utf-8").matchAll(/\s-e([0-9A-Fa-f:]+)/g)) add(m[1]);
    } catch (e) {
      if (e && e.code !== "ENOENT") errors.push(`read ${file}: ${e.message || e}`);
    }
  }
  for (const file of readDir(proxyRoot, LIST_ANY_RE)) {
    try {
      for (const line of fs.readFileSync(file, "utf-8").split("\n")) if (line.includes(":")) add(line);
    } catch (e) {
      if (e && e.code !== "ENOENT") errors.push(`read ${file}: ${e.message || e}`);
    }
  }
  const sp = path.join(proxyRoot, "egress_state.json");
  try {
    const raw = JSON.parse(fs.readFileSync(sp, "utf-8"));
    for (const e of Object.values((raw && raw.ports) || {})) {
      if (e && typeof e === "object") {
        add(e.anchor);
        add(e.current);
      }
    }
    for (const a of Array.isArray(raw && raw.pool) ? raw.pool : []) add(a);
    for (const d of Array.isArray(raw && raw.draining) ? raw.draining : []) add(d && d.addr);
    // per-piece rotation /64s held from the pool (lane L9's egress.js)
    for (const h of Array.isArray(raw && raw.pergb_held) ? raw.pergb_held : []) add(h && h.net);
  } catch (e) {
    if (e && e.code !== "ENOENT") errors.push(`read ${sp}: ${e.message || e}`);
  }
  return { nets, complete: errors.length === 0, errors };
}

// ── listeners (ports_in_use / port_check) ────────────────────────────────

// `ss -Hltnp` -> [{ ip, port, pids: [n], procs: [name] }]
function parseListeners(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const toks = line.split(/\s+/);
    let ep = null;
    for (const t of toks) {
      const e = killLib.parseEndpoint(t) || (/^(\*|0\.0\.0\.0|\[::\]):(\d+)$/.test(t) ? { ip: t.startsWith("*") ? "*" : t.startsWith("[") ? "::" : "0.0.0.0", port: Number(t.split(":").pop()) } : null);
      if (e) {
        ep = e;
        break;
      }
    }
    if (!ep) continue;
    const pids = [...line.matchAll(/pid=(\d+)/g)].map((m) => Number(m[1]));
    const procs = [...line.matchAll(/\("([^"]+)"/g)].map((m) => m[1]);
    out.push({ ip: ep.ip, port: ep.port, pids, procs });
  }
  return out;
}

function isWildcard(ip) {
  return ip === "*" || ip === "0.0.0.0" || ip === "::";
}

// ── the service ──────────────────────────────────────────────────────────

// deps (all optional; tests inject): { env, now, log, run, runtime, ctl,
// readCgroupOf(pid) -> text, resolve(host) -> Promise<[ip]>, probe }
function createPergb(deps = {}) {
  const env = deps.env || process.env;
  const now = deps.now || Date.now;
  const log = deps.log || console;
  const run = deps.run || runtimeLib.execCapture;
  const rt = deps.runtime || runtimeLib;
  const settings = { ...readSettings(env), ...(deps.settings || {}) };
  const rtSettings = deps.runtimeSettings || rt.readSettings(env);
  const ctl = deps.ctl || createRadiusClient({ socketPath: socketPathFrom(env) });
  const readCgroupOf =
    deps.readCgroupOf ||
    ((pid) => {
      try {
        return fs.readFileSync(`/proc/${pid}/cgroup`, "utf-8");
      } catch {
        return "";
      }
    });
  const resolveHost =
    deps.resolve ||
    (async (host) => {
      const out = [];
      for (const fam of [4, 6]) {
        try {
          const r = await dns.promises.lookup(host, { all: true, family: fam });
          for (const a of r) out.push(a.address);
        } catch {}
      }
      return out;
    });

  let enableDoc = null; // enable.json
  let pool = null; // parsed pool file (on)
  let tagger = null;
  let excludedSet = new Set(); // per-piece /64s: the last scan ∪ reservedLocal
  const reservedLocal = new Set(); // reserve_nets answers since start (until released)
  const excludedInfo = { at: null, count: null, complete: null, error: null, pushes: 0, reason: null };
  let canary = null; // [[ip, port]] in use
  const radius = { epoch: null, seq: null, ready: null, dbRecovered: null, last: null, error: null, at: null };
  const staging = new Map();
  let stagingBytes = 0;
  const timers = [];
  let running = false;
  let tickBusy = false;
  let guardBusy = false;
  let probeBusy = false;
  let lastExcludedAt = 0;
  let lastCanaryAt = 0;
  let lastRadiusWatchAt = 0;
  let sockCache = null; // { at, view }
  const events = [];

  function event(type, detail = {}) {
    events.push({ type, at: new Date(now()).toISOString(), ...detail });
    if (events.length > 100) events.splice(0, events.length - 100);
  }

  function logdump() {
    return (enableDoc && enableDoc.logdumpBytes) || 262144;
  }

  function params() {
    return (enableDoc && enableDoc.params) || {};
  }

  function egressIpv4s() {
    const p = params();
    const list = Array.isArray(p.ipv4s) && p.ipv4s.length ? p.ipv4s : enableDoc && enableDoc.egressIpv4 ? [enableDoc.egressIpv4] : [];
    return list.filter((ip) => net.isIPv4(String(ip)));
  }

  function units() {
    const procs = (enableDoc && Array.isArray(enableDoc.procs) && enableDoc.procs) || [];
    return procs.map((p) => ({ unit: String(p.unit), cgroup: rt.cgroupPath(String(p.unit)) }));
  }

  function rebuildTagger() {
    tagger = null;
    const key = params().addrKey;
    if (!pool || !key) return;
    try {
      tagger = tagLib.createTagger({ key: Buffer.from(String(key), "base64"), prefix: pool.prefix });
    } catch (e) {
      log.error(`[pergb] address key: ${e.message || e}`);
    }
  }

  function readPool() {
    let text;
    try {
      text = fs.readFileSync(settings.poolFile, "utf-8");
    } catch (e) {
      return { state: e && e.code === "ENOENT" ? "off" : "error", error: e && e.message };
    }
    return parsePoolText(text);
  }

  function reload() {
    enableDoc = rt.readEnable(rtSettings);
    const p = readPool();
    pool = p.state === "on" ? p : null;
    rebuildTagger();
    meter.setLogdump(logdump());
  }

  const meter = meterLib.createMeter({
    logDir: rtSettings.logDir,
    statePath: path.join(settings.stateDir, "meter.json"),
    now,
    log,
    onRecords: (recs) => smart.observe(recs),
    onEvent: (e) => event(e.type, e),
  });

  // enforcer and killer resolve each other through these closures
  let enforcer = null;
  const killer = killLib.createKiller({
    run,
    log,
    units,
    fallbackFilter: () => {
      if (!pool) return null;
      return ["(", "src", pool.prefix, "or", "src", "127.0.0.3", "or", "src", "127.0.0.4", ")"];
    },
    ctx: () => ({
      tagger,
      excluded: excludedSet,
      tupleLogin: (k) => meter.tupleLogin(k),
      listAccount: (id) => enforcer.listAccount(id),
      loginAccount: (login) => enforcer.loginAccount(login),
    }),
  });
  enforcer = enforcerLib.createEnforcer({ ctl, meter, killer, now, log, logdumpBytes: logdump });
  const smart = smartLib.createSmart({ ctl, now, log, tagger: () => tagger, excluded: () => excludedSet });

  async function socketView(maxAgeMs = 3000) {
    if (sockCache && now() - sockCache.at <= maxAgeMs) return sockCache.view;
    const view = await killer.snapshot();
    sockCache = { at: now(), view };
    return view;
  }

  function probeSecret() {
    try {
      return fs.readFileSync(rtSettings.secretPath, "utf-8").trim();
    } catch {
      return null;
    }
  }

  const probe =
    deps.probe ||
    (async () => {
      const p = params();
      const pw = p.probe && p.probe.password;
      const target = (canary && canary[0]) || (p.probe && Array.isArray(p.probe.canary) && p.probe.canary[0]);
      const secret = probeSecret();
      if (!pw || !target || !secret || !enableDoc) return null;
      const addr = String(env.NETRUN_RADIUS_ADDR || "127.0.0.1:1812");
      const server = addr.slice(0, addr.lastIndexOf(":"));
      const port = Number(addr.slice(addr.lastIndexOf(":") + 1));
      return radprobe.probeOnce({ server, port, secret, password: pw, nasPort: enableDoc.base, dst: String(target[0]), dstPort: Number(target[1]), timeoutMs: 2000 });
    });

  const guards = guardsLib.createGuards({
    ctl,
    run,
    now,
    log,
    settings: { cgroupRoot: settings.cgroupRoot, sliceCgroup: rt.SLICE_CGROUP, logDir: rtSettings.logDir, ...(deps.guardSettings || {}) },
    readFile: deps.readFile,
    statfs: deps.statfs,
    enable: () => enableDoc,
    egressIpv4s,
    meterLagSec: () => meter.status().meterLagSec,
    liveSessions: async () => {
      const v = await socketView(1000);
      const m = new Map();
      for (const s of [...v.v6, ...v.v4]) if (s.accountId !== null && s.accountId !== undefined) m.set(s.accountId, (m.get(s.accountId) || 0) + 1);
      return m;
    },
    probe: () => probe(),
  });

  // ── RADIUS facts, excluded, logins ──────────────────────────────────────

  function probeHash() {
    const p = params();
    const pw = p.probe && p.probe.password;
    if (!pw) return null;
    const key = Buffer.from(String(p.addrKey || ""), "base64");
    const salt = crypto.createHmac("sha256", key).update("netrun-pergb-probe-salt").digest().subarray(0, 16);
    const hash = crypto.createHash("sha256").update(Buffer.concat([salt, Buffer.from(String(pw), "utf-8")])).digest("hex");
    return { pwSalt: salt.toString("hex"), pwHash: hash };
  }

  function buildFacts() {
    const p = params();
    const ph = probeHash();
    const list = canary || (p.probe && Array.isArray(p.probe.canary) ? p.probe.canary : []) || [];
    const facts = {
      base: enableDoc.base,
      count: enableDoc.count,
      geo: p.geo || null,
      family: enableDoc.family || "dualstack",
      egressIpv4: enableDoc.egressIpv4 || null,
      egressIpv4s: egressIpv4s(),
      prefix: pool.prefix,
      subnets: pool.pool,
      addrKey: p.addrKey,
      logdumpBytes: logdump(),
    };
    if (ph) facts.probe = { ...ph, canary: list.filter((c) => Array.isArray(c) && net.isIP(String(c[0])) && Number(c[1]) > 0).map((c) => [String(c[0]), Number(c[1])]) };
    return facts;
  }

  async function pushFacts() {
    if (!enableDoc || !pool) return { ok: false, error: "pergb_off" };
    await ctl.call("facts", { facts: buildFacts() });
    return { ok: true };
  }

  async function pushExcluded(reason) {
    if (!pool) return { ok: false, error: "pergb_off" };
    const scan = scanPerPieceNets({ proxyRoot: settings.proxyRoot, prefixBase: pool.prefixBase });
    const nets = [...scan.nets].filter((id) => id <= 0xffff).sort((a, b) => a - b);
    const scanId = `${reason}-${now()}`;
    excludedInfo.reason = reason;
    lastExcludedAt = now();
    try {
      const r = await ctl.call("excluded", { nets, complete: scan.complete, scanId });
      excludedSet = new Set([...scan.nets, ...reservedLocal]);
      Object.assign(excludedInfo, { at: new Date(now()).toISOString(), count: r.excluded, scanned: nets.length, complete: scan.complete, error: null });
      excludedInfo.pushes += 1;
      return { ok: true, excluded: r.excluded, scanned: nets.length, complete: scan.complete };
    } catch (e) {
      // a refused shrink keeps its additions in RADIUS; locally the union stays
      for (const id of scan.nets) excludedSet.add(id);
      Object.assign(excludedInfo, { at: new Date(now()).toISOString(), error: e.code || e.message, complete: scan.complete });
      if (e.code === "excluded_shrink") event("pergb_excluded_shrink_refused", { wouldRemove: e.reply && e.reply.wouldRemove, limit: e.reply && e.reply.limit });
      log.error(`[pergb] excluded push (${reason}) failed: ${e.code || e.message}`);
      return { ok: false, error: e.code || e.message };
    }
  }

  async function refreshFromRadius() {
    const [l, a] = await Promise.all([ctl.call("logins", {}), ctl.call("accounts", {})]);
    const lists = (l && l.lists) || [];
    meter.setLogins(lists);
    enforcer.setLists(lists);
    enforcer.setAccounts((a && a.accounts) || []);
    return { lists: lists.length, accounts: ((a && a.accounts) || []).length };
  }

  async function radiusWatch(force = false) {
    lastRadiusWatchAt = now();
    let st;
    try {
      st = await ctl.call("status", {}, { timeoutMs: 3000 });
    } catch (e) {
      radius.error = e.code || e.message;
      radius.at = new Date(now()).toISOString();
      return null;
    }
    const epochChanged = radius.epoch !== null && st.epoch !== radius.epoch;
    const seqChanged = radius.seq !== st.seq;
    // a restart keeps the epoch but loses what RADIUS holds in memory only
    // (the A12 avoid set; admission and the heartbeat are re-sent every tick)
    const restarted = radius.last && Number.isFinite(st.uptimeSec) && Number.isFinite(radius.last.uptimeSec) && st.uptimeSec < radius.last.uptimeSec;
    if (restarted && !epochChanged) {
      event("pergb_radius_restarted", { uptimeSec: st.uptimeSec });
      smart.onRadiusEpoch();
    }
    Object.assign(radius, { epoch: st.epoch, seq: st.seq, ready: st.ready, dbRecovered: st.dbRecovered, last: st, error: null, at: new Date(now()).toISOString() });
    if (enableDoc && enableDoc.enabled && pool && (force || epochChanged || st.ready === false)) {
      if (epochChanged) event("pergb_radius_epoch_changed", { epoch: st.epoch, dbRecovered: st.dbRecovered });
      try {
        await pushFacts();
        await pushExcluded(epochChanged ? "radius_epoch" : force ? "start" : "radius_not_ready");
        smart.onRadiusEpoch();
      } catch (e) {
        log.error(`[pergb] re-push to RADIUS failed: ${e.code || e.message}`);
      }
    }
    if (force || epochChanged || seqChanged || !meter.loginsReady()) {
      try {
        await refreshFromRadius();
      } catch (e) {
        log.error(`[pergb] logins/accounts from RADIUS: ${e.code || e.message}`);
      }
    }
    return st;
  }

  async function refreshCanary() {
    lastCanaryAt = now();
    const p = params();
    const hosts = Array.isArray(p.canaryHosts) ? p.canaryHosts : [];
    if (!hosts.length) return { changed: false };
    const list = [];
    for (const h of hosts) {
      if (!Array.isArray(h) || h.length !== 2) continue;
      const host = String(h[0]);
      const port = Number(h[1]);
      const ips = net.isIP(host) ? [host] : await resolveHost(host);
      for (const ip of ips) if (!list.some((x) => x[0] === ip && x[1] === port)) list.push([ip, port]);
    }
    if (!list.length) return { changed: false };
    const before = JSON.stringify(canary || (p.probe && p.probe.canary) || []);
    const sorted = list.sort((a, b) => (a[0] + a[1]).localeCompare(b[0] + b[1]));
    if (JSON.stringify(sorted) === before) return { changed: false };
    canary = sorted;
    try {
      await pushFacts();
      return { changed: true, canary };
    } catch (e) {
      return { changed: true, error: e.code || e.message };
    }
  }

  // ── loops ───────────────────────────────────────────────────────────────

  async function mainTick() {
    if (tickBusy) return;
    tickBusy = true;
    try {
      if (!enableDoc) return;
      const on = enableDoc.enabled === true && pool;
      if (on && now() - lastRadiusWatchAt >= RADIUS_WATCH_MS) await radiusWatch(false);
      meter.tick();
      if (!on) return;
      await enforcer.tick();
      await smart.push();
      if (now() - lastExcludedAt >= EXCLUDED_EVERY_MS) await pushExcluded("periodic");
      if (now() - lastCanaryAt >= CANARY_EVERY_MS) await refreshCanary();
    } catch (e) {
      log.error(`[pergb] tick: ${(e && e.stack) || e}`);
    } finally {
      tickBusy = false;
    }
  }

  async function guardTick() {
    if (guardBusy || !enableDoc || enableDoc.enabled !== true) return;
    guardBusy = true;
    try {
      await guards.tick();
    } catch (e) {
      log.error(`[pergb] guards: ${(e && e.message) || e}`);
    } finally {
      guardBusy = false;
    }
  }

  async function probeTick() {
    if (probeBusy || !enableDoc || enableDoc.enabled !== true) return;
    probeBusy = true;
    try {
      await guards.probeTick();
    } catch (e) {
      log.error(`[pergb] probe: ${(e && e.message) || e}`);
    } finally {
      probeBusy = false;
    }
  }

  function startLoops() {
    if (running || !settings.loops) return;
    running = true;
    const every = (fn, ms) => {
      const t = setInterval(() => {
        fn().catch(() => {});
      }, ms);
      if (typeof t.unref === "function") t.unref();
      timers.push(t);
    };
    every(mainTick, 1000);
    every(guardTick, 2000);
    every(probeTick, 5000);
    const sweep = setInterval(sweepStaging, 10000);
    if (typeof sweep.unref === "function") sweep.unref();
    timers.push(sweep);
  }

  function stopLoops() {
    while (timers.length) clearInterval(timers.pop());
    running = false;
  }

  // At agent start: per-GB enabled here → facts + excluded + logins, loops.
  async function start() {
    reload();
    if (!enableDoc) return { started: false };
    startLoops();
    if (enableDoc.enabled === true && pool) {
      await radiusWatch(true).catch(() => null);
      lastCanaryAt = 0;
    }
    return { started: true };
  }

  function stop() {
    stopLoops();
  }

  // ── enable / disable ────────────────────────────────────────────────────

  async function routedPrefixes() {
    const r = await run("ip", ["-6", "route", "show", "table", "local", "dev", "lo"], { timeoutMs: 10000 });
    const out = [];
    for (const m of String((r && r.stdout) || "").matchAll(/^local\s+([0-9a-fA-F:]+)\/(\d+)\b/gm)) {
      if (Number(m[2]) !== 48) continue;
      const p = tagLib.parsePrefix48(`${m[1]}/48`);
      if (p && !out.includes(p.text)) out.push(p.text);
    }
    const configured = String(env.NETRUN_IPV6_ROUTED_PREFIX || "").trim();
    if (configured) {
      const p = tagLib.parsePrefix48(configured);
      if (p && !out.includes(p.text)) out.push(p.text);
    }
    return out;
  }

  function validateEnable(body) {
    if (!body || typeof body !== "object" || Array.isArray(body)) return { error: bad("bad_params", "body must be an object") };
    let key;
    try {
      key = Buffer.from(String(body.addrKey || ""), "base64");
    } catch {
      key = Buffer.alloc(0);
    }
    if (key.length !== 32) return { error: bad("bad_params", "addrKey must be 32 bytes, base64") };
    const pr = body.probe;
    if (!pr || typeof pr !== "object" || typeof pr.password !== "string" || pr.password.length < 8 || pr.password.length > 128) {
      return { error: bad("bad_params", "probe.password must be a string of 8..128 chars") };
    }
    const canaryList = pr.canary === undefined ? body.canary || [] : pr.canary;
    if (!Array.isArray(canaryList) || canaryList.some((c) => !Array.isArray(c) || c.length !== 2 || !net.isIP(String(c[0])) || !(Number(c[1]) >= 1 && Number(c[1]) <= 65535))) {
      return { error: bad("bad_params", "probe.canary must be [[ip, port], ...]") };
    }
    const pool0 = normalizePool(body.pool || body.subnets || DEFAULT_POOL);
    if (!pool0) return { error: bad("bad_params", "subnets must be <hex>-<hex>, e.g. 0000-fffe") };
    if (body.geo !== undefined && body.geo !== null && !/^[A-Za-z]{2}$/.test(String(body.geo))) return { error: bad("bad_params", "geo must be a 2-letter code") };
    const ipv4s = Array.isArray(body.ipv4s) ? body.ipv4s.map(String) : [];
    if (ipv4s.length > 64 || ipv4s.some((ip) => !net.isIPv4(ip)) || new Set(ipv4s).size !== ipv4s.length) {
      return { error: bad("bad_params", "ipv4s must be up to 64 distinct IPv4 addresses") };
    }
    if (body.egressIpv4 !== undefined && body.egressIpv4 !== null && !net.isIPv4(String(body.egressIpv4))) {
      return { error: bad("bad_params", "egressIpv4 must be null or an IPv4 address") };
    }
    if (ipv4s.length && body.egressIpv4 && body.egressIpv4 !== ipv4s[0]) {
      return { error: bad("bad_params", "egressIpv4, when set with ipv4s, is ipv4s[0] (the entry address)") };
    }
    let prefix = null;
    if (body.prefix !== undefined && body.prefix !== null) {
      const p = tagLib.parsePrefix48(body.prefix);
      if (!p) return { error: bad("bad_params", "prefix must be an IPv6 /48") };
      prefix = p.text;
    }
    const canaryHosts = Array.isArray(body.canaryHosts) ? body.canaryHosts.filter((h) => Array.isArray(h) && h.length === 2) : [];
    return { ok: true, pool: pool0, prefix, ipv4s, canary: canaryList.map((c) => [String(c[0]), Number(c[1])]), canaryHosts };
  }

  async function listenersInRange(ipv4, lo, hi) {
    const r = await run("ss", ["-Hltnp", "sport", "ge", `:${lo}`, "and", "sport", "le", `:${hi}`], { timeoutMs: 15000 });
    if (r.code !== 0) return { ok: false, error: String(r.stderr || "").trim().slice(0, 200) };
    const out = [];
    for (const l of parseListeners(r.stdout)) {
      if (l.port < lo || l.port > hi) continue;
      if (ipv4 && !(isWildcard(l.ip) || l.ip === ipv4)) continue;
      // per-GB's own listeners (its haproxy) are no conflict
      const own = l.pids.length > 0 && l.pids.every((pid) => /netrun-pergb/.test(readCgroupOf(pid)));
      if (own) continue;
      out.push(l);
    }
    return { ok: true, listeners: out };
  }

  function cfgPortsInRange(lo, hi) {
    const out = [];
    let names = [];
    try {
      names = fs.readdirSync(path.join(settings.proxyRoot, "3proxy")).filter((f) => CFG_ANY_RE.test(f));
    } catch {}
    for (const f of names) {
      let text = "";
      try {
        text = fs.readFileSync(path.join(settings.proxyRoot, "3proxy", f), "utf-8");
      } catch {
        continue;
      }
      for (const m of text.matchAll(/^\s*(socks|proxy)\b[^\n]*\s-p(\d+)\b/gm)) {
        const port = Number(m[2]);
        if (port >= lo && port <= hi) out.push({ port, cfg: f, service: m[1] });
      }
    }
    return out;
  }

  // -> { free, conflicts: [{port, listener, pid, process, unit|cfg, shadow?}] }
  async function portCheck(query) {
    const base = Number(query.base);
    const count = Number(query.count || 1000);
    if (!Number.isInteger(base) || !Number.isInteger(count) || base < 1024 || count < 1 || base + count - 1 > 65535) {
      return bad("bad_params", "base and count must describe a port range inside 1024..65535");
    }
    const ipv4 = query.ipv4 ? String(query.ipv4) : null;
    if (ipv4 && !net.isIPv4(ipv4)) return bad("bad_params", "ipv4 must be an IPv4 address");
    const last = base + count - 1;
    const conflicts = [];
    const l1 = await listenersInRange(ipv4, base, last);
    if (!l1.ok) return { status: 503, body: { success: false, error: "ss_failed", detail: l1.error } };
    for (const l of l1.listeners) conflicts.push({ port: l.port, listener: `${l.ip}:${l.port}`, pid: l.pids[0] || null, process: l.procs[0] || null, unit: unitOfPid(l.pids[0]) });
    for (const c of cfgPortsInRange(base, last)) if (!conflicts.some((x) => x.port === c.port && x.cfg === c.cfg)) conflicts.push({ port: c.port, listener: null, cfg: c.cfg });
    // option A: the per-piece socks ports that shadow the range (their http mirror would sit on it)
    let primary = null;
    try {
      primary = await rt.detectPrimaryIpv4({ run });
    } catch {}
    const optionA = !ipv4 || ipv4 === primary;
    if (optionA && last + 10000 <= 65535) {
      const l2 = await listenersInRange(null, base + 10000, last + 10000);
      if (l2.ok) for (const l of l2.listeners) conflicts.push({ port: l.port, listener: `${l.ip}:${l.port}`, pid: l.pids[0] || null, process: l.procs[0] || null, unit: unitOfPid(l.pids[0]), shadow: true });
      for (const c of cfgPortsInRange(base + 10000, last + 10000)) conflicts.push({ port: c.port, listener: null, cfg: c.cfg, shadow: true });
    }
    conflicts.sort((a, b) => a.port - b.port);
    return { status: 200, body: { success: true, free: conflicts.length === 0, base, count, ipv4, optionA, conflicts: conflicts.slice(0, 1000), conflictsTotal: conflicts.length } };
  }

  function unitOfPid(pid) {
    if (!pid) return null;
    const m = /([^/\s]+\.(?:service|scope))\s*$/m.exec(readCgroupOf(pid));
    return m ? m[1] : null;
  }

  async function enable(body) {
    const v = validateEnable(body);
    if (v.error) return v.error;
    // the routed /48
    const routed = await routedPrefixes();
    let prefix = v.prefix;
    if (prefix ? !routed.includes(prefix) : routed.length !== 1) {
      return conflict("no_routed_prefix", { routed, wanted: prefix });
    }
    prefix = prefix || routed[0];
    // the pool file must not say something else
    const cur = readPool();
    if (cur.state === "on" && (cur.prefix !== prefix || cur.pool !== v.pool.text)) {
      return conflict("slice_mismatch", { current: { prefix: cur.prefix, pool: cur.pool }, wanted: { prefix, pool: v.pool.text } });
    }
    if (cur.state === "error") return conflict("slice_mismatch", { detail: cur.error });
    // the node's TLS certificates (the per-GB haproxy serves the crt-list)
    let crt = "";
    try {
      crt = fs.readFileSync(rtSettings.crtList, "utf-8");
    } catch {}
    if (!crt.split("\n").some((l) => l.trim() && !l.trim().startsWith("#"))) return conflict("no_ip_cert", { crtList: rtSettings.crtList });
    // the entry / egress IPv4
    const dedicated = v.ipv4s[0] || (body.egressIpv4 ? String(body.egressIpv4) : null);
    const egress = dedicated || (await rt.detectPrimaryIpv4({ run }));
    if (!egress) return conflict("no_egress_ipv4");
    // the shared ports must be free on it (our own listeners excluded)
    const base = Number(body.base);
    const count = Number(body.count || 1000);
    if (Number.isInteger(base) && Number.isInteger(count) && count > 0) {
      const l = await listenersInRange(egress, base, base + count - 1);
      if (l.ok && l.listeners.length) {
        return conflict("ports_in_use", { conflicts: l.listeners.slice(0, 200).map((x) => ({ port: x.port, pid: x.pids[0] || null, unit: unitOfPid(x.pids[0]), listener: `${x.ip}:${x.port}` })) });
      }
    }
    // A7: the per-GB IPv4s on the interface (+ netplan for the next boot)
    let ipv4Result = null;
    if (v.ipv4s.length) {
      ipv4Result = await ipv4Lib.ensureAddresses(v.ipv4s, { run, log, settings: deps.ipv4Settings });
      if (!ipv4Result.ok) return conflict(ipv4Result.error || "ipv4_config_failed", { detail: ipv4Result.detail });
    }
    const raw = { ...body, subnets: v.pool.text, prefix, canary: v.canary, probe: { ...body.probe, canary: v.canary } };
    const applied = await rt.apply({ ...raw, egressIpv4: egress, dedicatedIpv4: dedicated }, deps.runtimeDeps || {});
    if (!applied.ok) {
      const code = applied.error || "apply_failed";
      const status = code === "bad_params" ? 400 : ["uid_taken", "binary_hash_mismatch", "pergb_not_installed", "proxy_guard_missing"].includes(code) ? 409 : 500;
      return { status, body: { success: false, error: code, detail: applied.detail || null } };
    }
    enableDoc = rt.readEnable(rtSettings);
    pool = { state: "on", ...normalizePoolOn(prefix, v.pool) };
    canary = null;
    rebuildTagger();
    meter.setLogdump(logdump());
    // RADIUS: started by the target (socket); the service now, for its ctl socket
    await run("systemctl", ["start", rt.RADIUS_SOCKET || "netrun-radius.socket", rt.RADIUS_SERVICE || "netrun-radius.service"], { timeoutMs: 60000 });
    const deadline = now() + Number(deps.radiusWaitMs === undefined ? 15000 : deps.radiusWaitMs);
    let up = false;
    for (;;) {
      try {
        await ctl.call("status", {}, { timeoutMs: 2000 });
        up = true;
        break;
      } catch {}
      if (now() >= deadline) break;
      await new Promise((r) => setTimeout(r, 250));
    }
    if (!up) return { status: 503, body: { success: false, error: "radius_unavailable", detail: "netrun-radius did not answer on its ctl socket" } };
    try {
      await pushFacts();
    } catch (e) {
      const h = httpError(e);
      return { status: h.status, body: { ...h.body, stage: "facts" } };
    }
    const ex = await pushExcluded("enable");
    if (!ex.ok && ex.error === "radius_unavailable") return { status: 503, body: { success: false, error: "radius_unavailable", stage: "excluded" } };
    // the pool file last: per-piece now reserves its /64s through RADIUS
    const text = poolText(prefix, v.pool.text);
    let curText = null;
    try {
      curText = fs.readFileSync(settings.poolFile, "utf-8");
    } catch {}
    if (curText !== text) {
      fs.mkdirSync(path.dirname(settings.poolFile), { recursive: true });
      const tmp = `${settings.poolFile}.tmp`;
      fs.writeFileSync(tmp, text, { mode: 0o644 });
      fs.chmodSync(tmp, 0o644);
      fs.renameSync(tmp, settings.poolFile);
    }
    await radiusWatch(true).catch(() => null);
    startLoops();
    event("pergb_enabled", { base: enableDoc.base, changed: applied.changed.length, restarted: applied.restarted });
    const st = await status();
    return { status: 200, body: { ...st, applied: { changed: applied.changed, restarted: applied.restarted, started: applied.started, reloaded: applied.reloaded, secretCreated: applied.secretCreated }, excludedPush: ex, ipv4: ipv4Result } };
  }

  function normalizePoolOn(prefix, poolNorm) {
    const p = tagLib.parsePrefix48(prefix);
    return { prefix: p.text, prefixBase: p.base, pool: poolNorm.text, lo: poolNorm.lo, hi: poolNorm.hi };
  }

  async function disable(body = {}) {
    const stopRadius = Boolean(body && body.stopRadius === true);
    // the pool file FIRST: per-piece allocators go back to their own picks
    try {
      fs.unlinkSync(settings.poolFile);
    } catch (e) {
      if (!e || e.code !== "ENOENT") return { status: 500, body: { success: false, error: "pool_file_remove_failed", detail: e.message } };
    }
    pool = null;
    const r = await rt.disable({ stopRadius }, deps.runtimeDeps || {});
    enableDoc = rt.readEnable(rtSettings);
    event("pergb_disabled", { stopRadius, stopped: r.stopped });
    return { status: r.ok ? 200 : 500, body: { success: r.ok, stopped: r.stopped || [], ...(r.ok ? {} : { error: r.error, detail: r.detail }) } };
  }

  // ── state: snapshot pages and deltas ────────────────────────────────────

  function sweepStaging() {
    const t = now();
    for (const [id, s] of staging) {
      if (t - s.createdAt > STAGING_TTL_MS) {
        stagingBytes -= s.bytes;
        staging.delete(id);
      }
    }
  }

  async function killTransitions(t) {
    const out = { accounts: [], lists: [] };
    if (!t) return out;
    let view = null;
    const tx = [...(t.accounts || []).map((a) => ({ accountId: Number(a.id), why: a.why })), ...(t.lists || []).map((l) => ({ listId: Number(l.id), why: l.why }))];
    if (!tx.length) return out;
    try {
      view = await killer.snapshot();
    } catch (e) {
      log.error(`[pergb] transitions: socket listing failed: ${e.message || e}`);
      return out;
    }
    for (const x of tx) {
      try {
        if (x.accountId !== undefined) {
          const r = await killer.kill({ accountId: x.accountId }, view);
          out.accounts.push({ id: x.accountId, why: x.why, ...r });
        } else {
          const r = await killer.kill({ listId: x.listId, logins: enforcer.listLogins(x.listId) }, view);
          out.lists.push({ id: x.listId, why: x.why, ...r });
        }
      } catch (e) {
        log.error(`[pergb] kill (${x.why}): ${e.message || e}`);
      }
    }
    return out;
  }

  function stateOn() {
    return Boolean(enableDoc && enableDoc.enabled === true && pool);
  }

  async function putSnapshot(query, body, bodyBytes = 0) {
    if (!stateOn()) return { status: 404, body: { success: false, error: "pergb_off" } };
    sweepStaging();
    const id = String(query.snapshotId || "");
    const page = Number(query.page);
    const pages = Number(query.pages);
    const seq = Number(query.seq);
    if (!SNAPSHOT_ID_RE.test(id)) return bad("bad_request", "snapshotId");
    if (!Number.isInteger(pages) || pages < 1 || pages > 10000 || !Number.isInteger(page) || page < 1 || page > pages) return bad("bad_request", "page / pages (page is 1-based)");
    if (!Number.isSafeInteger(seq) || seq < 0) return bad("bad_request", "seq");
    const b = body || {};
    for (const k of ["accounts", "lists", "static"]) if (b[k] !== undefined && !Array.isArray(b[k])) return bad("bad_request", `${k} must be a list`);
    let s = staging.get(id);
    if (s && (s.pages !== pages || s.seq !== seq)) {
      stagingBytes -= s.bytes;
      staging.delete(id);
      return conflict("snapshot_mismatch", { detail: "pages or seq differ from the staged snapshot", snapshotId: id });
    }
    if (!s) {
      s = { pages, seq, parts: new Map(), createdAt: now(), bytes: 0 };
      staging.set(id, s);
    }
    if (stagingBytes + bodyBytes > STAGING_MAX_BYTES) {
      stagingBytes -= s.bytes;
      staging.delete(id);
      return { status: 413, body: { success: false, error: "staging_full" } };
    }
    if (!s.parts.has(page)) {
      s.bytes += bodyBytes;
      stagingBytes += bodyBytes;
    }
    s.parts.set(page, { accounts: b.accounts || [], lists: b.lists || [], static: b.static || [] });
    if (page !== pages) return { status: 202, body: { success: true, received: page, pages } };
    const missing = [];
    for (let i = 1; i <= pages; i += 1) if (!s.parts.has(i)) missing.push(i);
    if (missing.length) {
      stagingBytes -= s.bytes;
      staging.delete(id);
      return conflict("snapshot_mismatch", { detail: "pages missing", missing: missing.slice(0, 100) });
    }
    const accounts = [];
    const lists = [];
    const stat = [];
    for (let i = 1; i <= pages; i += 1) {
      const p = s.parts.get(i);
      accounts.push(...p.accounts);
      lists.push(...p.lists);
      stat.push(...p.static);
    }
    stagingBytes -= s.bytes;
    staging.delete(id);
    let reply;
    try {
      reply = await ctl.call("snapshot", { seq, accounts, lists, static: stat });
    } catch (e) {
      const h = httpError(e);
      return { status: h.status, body: h.body };
    }
    const killed = await killTransitions(reply.transitions);
    radius.epoch = reply.epoch;
    radius.seq = reply.seq;
    try {
      await refreshFromRadius();
    } catch (e) {
      log.error(`[pergb] refresh after snapshot: ${e.code || e.message}`);
    }
    return { status: 200, body: { success: true, epoch: reply.epoch, seq: reply.seq, transitions: reply.transitions, static: reply.static || null, killed } };
  }

  async function patchState(body) {
    if (!stateOn()) return { status: 404, body: { success: false, error: "pergb_off" } };
    const b = body || {};
    if (!Number.isSafeInteger(Number(b.baseSeq)) || !Number.isSafeInteger(Number(b.seq))) return bad("bad_request", "baseSeq and seq are integers");
    for (const k of ["accounts", "lists"]) if (b[k] !== undefined && !Array.isArray(b[k])) return bad("bad_request", `${k} must be a list`);
    let reply;
    try {
      reply = await ctl.call("apply", { baseSeq: Number(b.baseSeq), seq: Number(b.seq), accounts: b.accounts || [], lists: b.lists || [] });
    } catch (e) {
      const h = httpError(e);
      return { status: h.status, body: h.body };
    }
    const killed = await killTransitions(reply.transitions);
    radius.epoch = reply.epoch;
    radius.seq = reply.seq;
    try {
      await refreshFromRadius();
    } catch (e) {
      log.error(`[pergb] refresh after apply: ${e.code || e.message}`);
    }
    return { status: 200, body: { success: true, epoch: reply.epoch, seq: reply.seq, transitions: reply.transitions, killed } };
  }

  // ── A1: per-piece takes /64s of the pool through RADIUS ─────────────────

  async function reserveNets(body) {
    const p = readPool();
    if (p.state !== "on") return { status: 404, body: { success: false, error: "pergb_off" } };
    const b = body || {};
    const count = Number(b.count);
    if (!Number.isInteger(count) || count < 1 || count > 5000) return bad("bad_request", "count must be 1..5000");
    if (!REF_RE.test(String(b.ref || ""))) return bad("bad_request", "ref must match [A-Za-z0-9:._-]{1,128}");
    if (b.owner !== undefined && b.owner !== "perpiece") return bad("bad_request", "owner must be perpiece");
    const req = { count, owner: "perpiece", ref: String(b.ref) };
    if (b.force === true) req.force = true;
    let reply;
    try {
      reply = await ctl.call("reserve_nets", req, { timeoutMs: 30000 });
    } catch (e) {
      const h = httpError(e);
      return { status: h.status, body: h.body };
    }
    const ids = (reply.nets || []).map(Number).filter((n) => Number.isInteger(n));
    for (const id of ids) {
      excludedSet.add(id);
      reservedLocal.add(id);
    }
    return { status: 200, body: { success: true, ref: reply.ref || req.ref, nets: ids.map((id) => netText(p.prefixBase, id)), subnetIds: ids, prefix: p.prefix } };
  }

  async function releaseNets(body) {
    const p = readPool();
    if (p.state !== "on") return { status: 404, body: { success: false, error: "pergb_off" } };
    const b = body || {};
    if (!REF_RE.test(String(b.ref || ""))) return bad("bad_request", "ref must match [A-Za-z0-9:._-]{1,128}");
    if (!Array.isArray(b.nets) || b.nets.length > 5000) return bad("bad_request", "nets must be a list of up to 5000 /64s");
    const ids = [];
    for (const n of b.nets) {
      const id = subnetIdOf(p.prefixBase, n);
      if (id === null) return bad("bad_request", `not a /64 of ${p.prefix}: ${JSON.stringify(n)}`);
      if (!ids.includes(id)) ids.push(id);
    }
    if (!ids.length) return { status: 200, body: { success: true, released: 0 } };
    let reply;
    try {
      reply = await ctl.call("release_nets", { nets: ids, ref: String(b.ref) }, { timeoutMs: 30000 });
    } catch (e) {
      const h = httpError(e);
      return { status: h.status, body: h.body };
    }
    for (const id of ids) reservedLocal.delete(id);
    return { status: 200, body: { success: true, released: reply.released, coolDownUntil: reply.coolDownUntil === undefined ? null : reply.coolDownUntil } };
  }

  // ── readers ─────────────────────────────────────────────────────────────

  async function radiusStatusNow() {
    try {
      const st = await ctl.call("status", {}, { timeoutMs: 3000 });
      Object.assign(radius, { epoch: st.epoch, seq: st.seq, ready: st.ready, dbRecovered: st.dbRecovered, last: st, error: null, at: new Date(now()).toISOString() });
      return st;
    } catch (e) {
      radius.error = e.code || e.message;
      return null;
    }
  }

  async function status() {
    reloadIfChanged();
    const e = enableDoc;
    let units = null;
    try {
      units = e ? await rt.status({ settings: rtSettings, run }) : null;
    } catch (err) {
      units = { error: err.message };
    }
    const st = e && e.enabled ? await radiusStatusNow() : null;
    let live = null;
    if (e && e.enabled) {
      try {
        const v = await socketView(5000);
        live = v.v4.length + v.loopUnknown;
      } catch {}
    }
    const g = guards.status();
    const m = meter.status();
    return {
      success: true,
      enabled: Boolean(e && e.enabled === true),
      version: VERSION,
      base: e ? e.base : null,
      count: e ? e.count : null,
      last: e ? e.last : null,
      egressIpv4: e ? e.egressIpv4 : null,
      dedicatedIpv4: e ? e.dedicatedIpv4 : null,
      egressIpv4s: e ? egressIpv4s() : [],
      family: e ? e.family : null,
      procs: units && Array.isArray(units.procs) ? units.procs : [],
      haproxy: units && units.haproxy ? units.haproxy : null,
      target: units && units.target ? units.target : null,
      subnets: pool ? pool.pool : null,
      prefix: pool ? pool.prefix : null,
      radius: {
        alive: g.radiusAlive === null ? Boolean(st) : Boolean(g.radiusAlive && st),
        ctl: Boolean(st),
        epoch: st ? st.epoch : radius.epoch,
        seq: st ? st.seq : radius.seq,
        ready: st ? st.ready : null,
        p50Ms: st && st.latency ? st.latency.p50Ms : null,
        p99Ms: st && st.latency ? st.latency.p99Ms : null,
        dbRecovered: st ? st.dbRecovered : null,
        admission: st ? st.admission : null,
        ipv4AdmissionOpen: st ? st.ipv4AdmissionOpen : null,
        alloc: st ? st.alloc : null,
        counts: st ? st.counts : null,
        rejects: st ? st.rejects : null,
        noDst: st ? st.noDst : null,
        deadman: st ? st.deadman : null,
        probe: g.probe,
        error: st ? null : radius.error,
      },
      conns: { live, max: e ? e.maxConns : null },
      guards: {
        memPct: g.memPct,
        pidsPct: g.pidsPct,
        ipv4PortsPct: g.ipv4PortsPct,
        logFsFreePct: g.logFsFreePct,
        meterLagSec: m.meterLagSec,
        clockSynced: g.clockSynced,
        admissionOpen: g.admissionOpen,
        ipv4AdmissionOpen: g.ipv4AdmissionOpen,
        level: g.level,
        softAccounts: g.softAccounts,
        closedBy: g.closedBy,
        ipv4: g.ipv4,
      },
      meter: {
        epoch: m.epoch,
        seq: m.seq,
        logLagSec: m.logLagSec,
        droppedLines: m.droppedLines,
        unknownBytes: m.unknownBytes,
        pendingFiles: m.pendingFiles,
        skipped: m.skipped,
        persistFailures: m.persistFailures,
        lastError: m.lastError,
      },
      enforcer: enforcer.status(),
      kill: killer.status(),
      excluded: { ...excludedInfo, local: excludedSet.size },
      smartRotation: smart.status(st && st.smartRotation ? st.smartRotation : null),
      events: events.slice(-20),
    };
  }

  let enableSig = null;
  function reloadIfChanged() {
    let sig = "";
    try {
      const s = fs.statSync(rtSettings.enablePath);
      sig += `${s.ino}:${s.mtimeMs}:${s.size}`;
    } catch {}
    try {
      const s = fs.statSync(settings.poolFile);
      sig += `|${s.ino}:${s.mtimeMs}:${s.size}`;
    } catch {}
    if (sig !== enableSig) {
      enableSig = sig;
      reload();
    }
  }

  async function usage(query) {
    reloadIfChanged();
    if (!enableDoc) return { status: 404, body: { success: false, error: "pergb_off" } };
    const since = Number(query.since || 0);
    const after = Number(query.bindingsAfter || 0);
    if (!Number.isSafeInteger(since) || since < 0 || !Number.isSafeInteger(after) || after < 0) return bad("bad_request", "since and bindingsAfter are integers");
    const u = meter.usage({ since });
    let bindings = { items: [], last: after };
    let rejects = {};
    let radiusError = null;
    try {
      const b = await ctl.call("bindings", { after, limit: 1000 });
      bindings = { items: b.items || [], last: b.last === undefined ? after : b.last };
    } catch (e) {
      radiusError = e.code || e.message;
    }
    try {
      rejects = ((await ctl.call("rejects", {})) || {}).lists || {};
    } catch (e) {
      radiusError = radiusError || e.code || e.message;
    }
    const st = await status();
    return {
      status: 200,
      body: { success: true, epoch: u.epoch, seq: u.seq, asOf: u.asOf, logins: u.logins, bindings, localBlocks: enforcer.localBlocks(), rejects, radiusError, status: st },
    };
  }

  async function kill(body) {
    reloadIfChanged();
    if (!stateOn()) return { status: 404, body: { success: false, error: "pergb_off" } };
    const b = body || {};
    let target;
    if (b.accountId !== undefined && b.accountId !== null) target = { accountId: Number(b.accountId) };
    else if (b.listId !== undefined && b.listId !== null) target = { listId: Number(b.listId), logins: enforcer.listLogins(Number(b.listId)) };
    else return bad("bad_request", "accountId or listId");
    if (!Number.isInteger(target.accountId === undefined ? target.listId : target.accountId)) return bad("bad_request", "ids are integers");
    try {
      const r = await killer.kill(target);
      return { status: 200, body: { success: true, killed6: r.killed6, killed4: r.killed4, pending4: r.pending4 } };
    } catch (e) {
      return { status: 500, body: { success: false, error: "kill_failed", detail: e.message } };
    }
  }

  function parseWhen(v, def) {
    if (v === undefined || v === null || v === "") return def;
    const n = Number(v);
    if (Number.isFinite(n)) return n > 1e12 ? n : n * 1000;
    const t = Date.parse(String(v));
    return Number.isFinite(t) ? t : null;
  }

  // haproxy access log lines `<syslog prefix> %ci:%cp %fp %bi:%bp %Tt %B %U`
  async function haproxyClients(keys) {
    const want = new Map(); // "bi:bp|fp" -> []
    for (const k of keys) want.set(k, []);
    if (!want.size) return [];
    const logFile = settings.haproxyLog || path.join(rtSettings.logDir, "haproxy.log");
    const files = [];
    for (const suffix of ["", ".1"]) files.push(`${logFile}${suffix}`);
    for (let i = 2; i <= 14; i += 1) files.push(`${logFile}.${i}.gz`);
    const zlib = require("zlib");
    const readline = require("readline");
    const found = [];
    for (const f of files) {
      let input;
      try {
        // the log directory belongs to the proxy user: never follow a symlink
        const fd = fs.openSync(f, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        if (!fs.fstatSync(fd).isFile()) {
          fs.closeSync(fd);
          continue;
        }
        input = fs.createReadStream(null, { fd });
      } catch {
        continue;
      }
      if (f.endsWith(".gz")) input = input.pipe(zlib.createGunzip());
      const rl = readline.createInterface({ input, crlfDelay: Infinity });
      try {
        for await (const line of rl) {
          const m = /(\S+):(\d+) (\d+) (\S+):(\d+) (\d+) (\d+) (\d+)\s*$/.exec(line);
          if (!m) continue;
          const key = `${m[4]}:${m[5]}|${m[3]}`;
          if (want.has(key)) found.push({ client: `${m[1]}:${m[2]}`, port: Number(m[3]), backend: `${m[4]}:${m[5]}`, totalMs: Number(m[6]), bytes: Number(m[7]), line: line.slice(0, 300) });
          if (found.length >= 1000) break;
        }
      } catch {}
      rl.close();
      input.destroy();
      if (found.length >= 1000) break;
    }
    return found;
  }

  async function attribution(query) {
    reloadIfChanged();
    const addr = String(query.addr || "").trim();
    if (!net.isIP(addr)) return bad("bad_request", "addr must be an IP address");
    const to = parseWhen(query.to, now());
    const from = parseWhen(query.from, (to || now()) - 24 * 3600 * 1000);
    if (from === null || to === null || from > to) return bad("bad_request", "from / to");
    let listId = null;
    let tagValid = false;
    let subnet = null;
    if (net.isIPv6(addr) && tagger) {
      const d = tagger.decodeAddress(addr);
      if (d) {
        subnet = d.subnetId;
        tagValid = d.valid && !excludedSet.has(d.subnetId);
        listId = tagValid ? d.listId : null;
      }
    }
    const want = net.isIPv6(addr) ? tagLib.ipv6ToBig(addr) : addr;
    const records = [];
    for await (const r of meter.recordsBetween(from, to)) {
      const match = net.isIPv6(addr) ? tagLib.ipv6ToBig(r.bound) === want : r.bound === want;
      if (!match) continue;
      records.push({
        time: new Date(r.t).toISOString(),
        service: r.service,
        port: r.port,
        code: r.code,
        user: r.user,
        client: `${r.clientIp}:${r.clientPort}`,
        local: r.localIp,
        bound: r.bound,
        dst: r.dstIp,
        dstPort: r.dstPort,
        in: r.inBytes,
        out: r.outBytes,
        host: r.host,
      });
      if (records.length >= 1000) break;
    }
    const keys = [...new Set(records.map((r) => `${r.client}|${r.port}`))];
    const clients = await haproxyClients(keys);
    return { status: 200, body: { success: true, addr, from: new Date(from).toISOString(), to: new Date(to).toISOString(), listId, tagValid, subnet, records, clients } };
  }

  // The compact /health block (plain listener; no secrets).
  function healthBlock() {
    reloadIfChanged();
    const g = guards.status();
    return {
      enabled: Boolean(enableDoc && enableDoc.enabled === true),
      pool: pool ? { prefix: pool.prefix, pool: pool.pool } : null,
      radiusAlive: g.radiusAlive,
      live: sockCache ? sockCache.view.v4.length + sockCache.view.loopUnknown : null,
      guards: {
        admissionOpen: g.admissionOpen,
        ipv4AdmissionOpen: g.ipv4AdmissionOpen,
        level: g.level,
        memPct: g.memPct,
        ipv4PortsPct: g.ipv4PortsPct,
        logFsFreePct: g.logFsFreePct,
        meterLagSec: enableDoc ? meter.status().meterLagSec : null,
        clockSynced: g.clockSynced,
      },
    };
  }

  // /generate (option A): the new batch must stay off the shared range and
  // its shadow (socks base+10000.. whose http mirror would land on it).
  function generateConflict(startPort, proxyCount) {
    const r = rt.sharedRange(rtSettings);
    if (!r || r.dedicatedIpv4) return null;
    const sp = Number(startPort);
    const n = Number(proxyCount);
    if (!Number.isInteger(sp) || !Number.isInteger(n) || n < 1) return null;
    const lo = sp;
    const hi = sp + n - 1;
    const hit = (a, b) => lo <= b && hi >= a;
    // the socks range on the shared range, or on its shadow (the batch's
    // http mirror, socks - 10000, would then sit on the shared range)
    const onRange = hit(r.base, r.last);
    const onShadow = hit(r.base + 10000, r.last + 10000);
    if (!onRange && !onShadow) return null;
    return { error: "ports_reserved_pergb", base: r.base, last: r.last, shadow: [r.base + 10000, r.last + 10000], via: onRange ? "range" : "shadow", enabled: r.enabled };
  }

  // After every /generate job: the per-piece /64s changed.
  function onGenerateDone() {
    if (!stateOn()) return Promise.resolve(null);
    return pushExcluded("generate").catch(() => null);
  }

  function isOn() {
    return readPool().state === "on";
  }

  return {
    start,
    stop,
    reload,
    enable,
    disable,
    status,
    putSnapshot,
    patchState,
    usage,
    kill,
    attribution,
    portCheck,
    reserveNets,
    releaseNets,
    healthBlock,
    generateConflict,
    onGenerateDone,
    isOn,
    // for tests and the TLS server
    mainTick,
    guardTick,
    probeTick,
    pushExcluded,
    pushFacts,
    refreshCanary,
    radiusWatch,
    meter,
    enforcer,
    killer,
    guards,
    smart,
    ctl,
    settings,
    rtSettings,
    _staging: staging,
    _tagger: () => tagger,
    _excluded: () => excludedSet,
  };
}

module.exports = {
  VERSION,
  STAGING_TTL_MS,
  DEFAULT_POOL,
  readSettings,
  parsePoolText,
  normalizePool,
  poolText,
  netText,
  subnetIdOf,
  scanPerPieceNets,
  parseListeners,
  createPergb,
};
