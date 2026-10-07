"use strict";

// Audit RES-11 — the 3proxy supervisor. Until now a batch whose 3proxy died
// (OOM kill, crash, an operator's kill) stayed dead until the next reboot, and
// anchors that vanished from the NIC (a networkd reconfigure, a failed boot
// restore) were never re-added: the node kept reporting itself healthy while
// up to 1500 sold proxies were dead. Every NODE_AGENT_SUPERVISOR_INTERVAL_SEC
// (60) the agent now:
//
//   respawns a batch cfg (3proxy_<sp>.cfg — never a *.cfg.disabled) when NO
//   3proxy runs it (by realpath of the cfg argument, so /root/proxyserver and
//   /opt/netrun/proxyserver are one cfg) AND its first socks port does not
//   listen — on two consecutive ticks (a restart by someone else is never
//   raced), not within NODE_AGENT_SUPERVISOR_SETTLE_SEC of a cfg write (a
//   /deprovision or /egress_mode rewrite restarts it itself), never while a
//   /generate holds the generation lock (checked per tick and again right
//   before each spawn, under the shared process lock — process_lock.js) and
//   never while the boot restore unit is still running. At most
//   NODE_AGENT_SUPERVISOR_MAX_RESPAWNS_PER_HOUR (5) per cfg; past that the cfg
//   is marked failed (logged once, in /health) until it listens again or its
//   file changes. The start goes through the node's spawn helper (own systemd
//   scope, idempotent, per-cfg flock).
//   Only a batch that DIED is respawned: one seen serving since boot (the set
//   survives agent restarts in the status file, which lives on /run), or one
//   whose cfg predates the boot (the boot restore was due to start it). A cfg
//   written after the boot that never served — a failed generation's leftover —
//   is left alone and listed as `unsupervised` (a reboot starts it, as before).
//   It never fights the duplicate reaper (hygiene.js): it starts a cfg only
//   when it runs ZERO times, the reaper acts only on cfgs that run twice and
//   never kills the last copy; both take the same process lock.
//
//   re-adds missing anchors — the cfgs' -e addresses absent from
//   /proc/net/if_inet6 whose /64 the node still has — in ONE
//   `ip -6 -force -batch` (/128, nodad, deprecated: see below), at most
//   NODE_AGENT_ANCHOR_READD_BATCH (2000) per tick (an add costs O(addresses on
//   the NIC) in the kernel). NETRUN_ANCHOR_READD=0: off.
//
//   deprecates anchors (audit FP-01): preferred_lft 0 on every anchor that is
//   not yet deprecated, NODE_AGENT_ANCHOR_DEPRECATE_BATCH (2000) per tick
//   (`ip address change`, lifetimes only; the anchor stays valid forever and
//   keeps nodad). A deprecated address is never the kernel's choice of SOURCE
//   (RFC 6724 rule 3), so the node's own traffic — unbound's recursion, apt,
//   the agent's egress / DNS checks — leaves from the node's primary IPv6, not
//   from a customer's exit address; 3proxy binds -e<anchor> explicitly and is
//   unaffected. NETRUN_ANCHOR_DEPRECATE=0: off (new anchors preferred again).
//
// Status: GET /health `supervisor`, and NODE_AGENT_SUPERVISOR_STATUS_FILE
// (/run/netrun/supervisor.json). NODE_AGENT_SUPERVISOR=0 turns it all off.

const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const hygieneLib = require("./hygiene.js");
const cfgStatus = require("./cfg_status.js");
const { settingOn } = require("./node_settings.js");

const DEFAULT_INTERVAL_SEC = 60;
const MIN_INTERVAL_SEC = 15;
const DEFAULT_FIRST_DELAY_SEC = 120;
const DEFAULT_MAX_RESPAWNS_PER_HOUR = 5;
const DEFAULT_SETTLE_SEC = 120;
const DEFAULT_READD_BATCH = 2000;
const DEFAULT_DEPRECATE_BATCH = 2000;
const HOUR_MS = 3600_000;
const IFA_F_NODAD = 0x02;
const IFA_F_DEPRECATED = 0x20;
const IFA_F_TENTATIVE = 0x40;
const LISTEN_PROBE_CHUNK = 256;
const RECENT_KEEP = 10;
const RESTORE_UNIT = "netrun-3proxy-restore.service";

function execCapture(cmd, args, { timeoutMs = 8000 } = {}) {
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
      try { child.kill("SIGKILL"); } catch {}
    }, timeoutMs);
    child.stdout.on("data", (d) => { stdout += d.toString("utf-8"); });
    child.stderr.on("data", (d) => { stderr += d.toString("utf-8"); });
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

function intEnv(raw, def, min, max = Number.MAX_SAFE_INTEGER) {
  const n = Number(raw);
  if (!Number.isFinite(n) || raw === undefined || raw === null || String(raw).trim() === "") return def;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function readSettings(env = process.env, settingOpts = {}) {
  return {
    enabled: hygieneLib.envSwitch(env.NODE_AGENT_SUPERVISOR),
    intervalSec: intEnv(env.NODE_AGENT_SUPERVISOR_INTERVAL_SEC, DEFAULT_INTERVAL_SEC, MIN_INTERVAL_SEC),
    firstDelaySec: intEnv(env.NODE_AGENT_SUPERVISOR_FIRST_DELAY_SEC, DEFAULT_FIRST_DELAY_SEC, 0),
    maxRespawnsPerHour: intEnv(env.NODE_AGENT_SUPERVISOR_MAX_RESPAWNS_PER_HOUR, DEFAULT_MAX_RESPAWNS_PER_HOUR, 1),
    settleSec: intEnv(env.NODE_AGENT_SUPERVISOR_SETTLE_SEC, DEFAULT_SETTLE_SEC, 0),
    readdAnchors: settingOn("NETRUN_ANCHOR_READD", true, { env, ...settingOpts }),
    deprecateAnchors: settingOn("NETRUN_ANCHOR_DEPRECATE", true, { env, ...settingOpts }),
    readdBatch: intEnv(env.NODE_AGENT_ANCHOR_READD_BATCH, DEFAULT_READD_BATCH, 1),
    deprecateBatch: intEnv(env.NODE_AGENT_ANCHOR_DEPRECATE_BATCH, DEFAULT_DEPRECATE_BATCH, 1),
    iface: String(env.NETRUN_IPV6_IFACE || "").trim() || null,
  };
}

// ── pure helpers ─────────────────────────────────────────────────────────

// /proc/net/if_inet6 -> Map hex -> { plen, scope, flags, ifname }.
function parseIfInet6Rows(text) {
  const out = new Map();
  for (const raw of String(text || "").split(/\r?\n/)) {
    const f = raw.trim().split(/\s+/);
    if (f.length < 6 || !/^[0-9a-f]{32}$/i.test(f[0])) continue;
    out.set(f[0].toLowerCase(), {
      plen: parseInt(f[2], 16),
      scope: parseInt(f[3], 16),
      flags: parseInt(f[4], 16),
      ifname: f[5],
    });
  }
  return out;
}

function hexToIpv6(hex) {
  const groups = [];
  for (let i = 0; i < 32; i += 4) groups.push(String(parseInt(hex.slice(i, i + 4), 16).toString(16)));
  return groups.join(":");
}

// The /64s the interface already has: global (scope 0), not tentative.
function presentPrefixes(rows, iface) {
  const out = new Set();
  for (const [hex, r] of rows) {
    if (iface && r.ifname !== iface) continue;
    if (r.scope !== 0 || (r.flags & IFA_F_TENTATIVE)) continue;
    out.add(hex.slice(0, 16));
  }
  return out;
}

// cfgs' anchors vs the kernel: { missing: [text], pendingDeprecate: [{addr, plen, ifname}], expected }.
// missing: not on any interface, but inside a /64 the node has (an anchor of a
// prefix the node lost is no use on the NIC). pendingDeprecate: present, not
// yet deprecated, and flagged nodad — every anchor is added nodad (generator,
// boot restore, this module), the host's own SLAAC / netplan address never
// is: even a cfg that named the primary address could not deprecate it.
function planAnchors(cfgs, rows, { iface = null } = {}) {
  const expected = new Map(); // hex -> text
  for (const c of Array.isArray(cfgs) ? cfgs : []) {
    for (const a of c.egress || []) {
      const hex = cfgStatus.ipv6ToHex(a);
      if (hex && !expected.has(hex)) expected.set(hex, a);
    }
  }
  const prefixes = presentPrefixes(rows, iface);
  const missing = [];
  const pendingDeprecate = [];
  for (const [hex, text] of expected) {
    const r = rows.get(hex);
    if (!r) {
      if (prefixes.has(hex.slice(0, 16))) missing.push(text);
      continue;
    }
    if (!(r.flags & IFA_F_DEPRECATED) && (r.flags & IFA_F_NODAD)) {
      pendingDeprecate.push({ addr: hexToIpv6(hex), plen: r.plen, ifname: r.ifname });
    }
  }
  return { expected: expected.size, missing, pendingDeprecate };
}

function readdBatchText(addrs, iface, { deprecate = true } = {}) {
  const lft = deprecate ? " preferred_lft 0" : "";
  return addrs.map((a) => `address add ${a}/128 dev ${iface} nodad${lft}`).join("\n") + "\n";
}

function deprecateBatchText(items) {
  return items.map((i) => `address change ${i.addr}/${i.plen} dev ${i.ifname} nodad valid_lft forever preferred_lft 0`).join("\n") + "\n";
}

// One supervisor decision per cfg. state: { downSince: Map, history: Map,
// failed: Map, seen: Set }. Returns { respawn: [cfg], pending: [sp],
// settling: [sp], unsupervised: [sp], failedNew: [{startPort, respawns}],
// recovered: [sp] } and updates state. bootMs: when the host booted.
function planRespawns(cfgs, { runningKeys, listening, keyOf, nowMs, settleMs, maxPerHour, state, bootMs = 0 }) {
  const respawn = [];
  const pending = [];
  const settling = [];
  const unsupervised = [];
  const failedNew = [];
  const recovered = [];
  const live = new Set();
  if (!state.seen) state.seen = new Set();
  for (const c of Array.isArray(cfgs) ? cfgs : []) {
    const sp = c.startPort;
    live.add(sp);
    const probe = Number.isInteger(c.probePort) && c.probePort > 0 ? c.probePort : sp;
    const running = runningKeys.has(keyOf(c));
    const up = listening.has(probe);
    if (up) state.seen.add(sp);
    if (running || up) {
      state.downSince.delete(sp);
      if (up && state.failed.has(sp)) {
        state.failed.delete(sp);
        recovered.push(sp);
      }
      continue;
    }
    // Died (seen serving since boot) or due since boot (cfg older than the
    // boot) — anything else never served: not ours to start.
    if (!state.seen.has(sp) && !(Number.isFinite(c.mtimeMs) && c.mtimeMs < bootMs)) {
      state.downSince.delete(sp);
      unsupervised.push(sp);
      continue;
    }
    const f = state.failed.get(sp);
    if (f && f.mtimeMs === c.mtimeMs) continue; // failed: wait for a change or a listener
    if (f) state.failed.delete(sp); // the cfg was rewritten: try again
    if (Number.isFinite(c.mtimeMs) && nowMs - c.mtimeMs < settleMs) {
      settling.push(sp);
      continue;
    }
    if (!state.downSince.has(sp)) {
      state.downSince.set(sp, nowMs);
      pending.push(sp);
      continue;
    }
    const recent = (state.history.get(sp) || []).filter((t) => nowMs - t < HOUR_MS);
    state.history.set(sp, recent);
    if (recent.length >= maxPerHour) {
      state.failed.set(sp, { at: nowMs, reason: "rate_limited", respawns: recent.length, mtimeMs: c.mtimeMs });
      failedNew.push({ startPort: sp, respawns: recent.length });
      continue;
    }
    respawn.push(c);
  }
  for (const m of [state.downSince, state.history, state.failed]) {
    for (const sp of [...m.keys()]) if (!live.has(sp)) m.delete(sp);
  }
  for (const sp of [...state.seen]) if (!live.has(sp)) state.seen.delete(sp);
  return { respawn, pending, settling, unsupervised, failedNew, recovered };
}

// Host boot time (ms) from /proc/stat btime; else now - uptime.
function readBootTimeMs(readFileSync = (p) => fs.readFileSync(p, "utf-8")) {
  try {
    const m = /^btime\s+(\d+)/m.exec(readFileSync("/proc/stat"));
    if (m) return Number(m[1]) * 1000;
  } catch {
    // no /proc (tests on macOS)
  }
  return Date.now() - os.uptime() * 1000;
}

// ── the service ──────────────────────────────────────────────────────────

function createSupervisor({
  env = process.env,
  settingOpts = {},
  readCfgs,
  spawnCfg,
  run = execCapture,
  realpath = (p) => fsp.realpath(p),
  readFile = (p) => fsp.readFile(p, "utf-8"),
  writeFile = null,
  exists = fs.existsSync,
  isGenerationBusy = async () => false,
  processLock = (fn) => fn(),
  now = () => Date.now(),
  log = console,
  ifInet6Path = "/proc/net/if_inet6",
  statusFile = env.NODE_AGENT_SUPERVISOR_STATUS_FILE || "/run/netrun/supervisor.json",
  tmpDir = os.tmpdir(),
  bootTimeMs = () => readBootTimeMs(),
} = {}) {
  const settings = readSettings(env, settingOpts);
  const state = { downSince: new Map(), history: new Map(), failed: new Map(), seen: new Set() };
  let unsupervised = [];
  let bootMs = null;
  // The batches seen serving since boot survive an agent restart: the status
  // file lives on /run (tmpfs), so a reboot starts from an empty set.
  try {
    const prev = JSON.parse(fs.readFileSync(statusFile, "utf-8"));
    for (const sp of (prev && prev.seenServing) || []) if (Number.isInteger(sp)) state.seen.add(sp);
  } catch {
    // first start since boot
  }
  const stats = {
    lastRunAt: null,
    lastOutcome: null,
    lastDurationMs: null,
    cfgsRespawned: 0,
    respawnFailures: 0,
    lastRespawns: [],
    addressesReadded: 0,
    addressesMissing: null,
    lastReaddAt: null,
    anchorsDeprecated: 0,
    anchorsPendingDeprecate: null,
    anchorsExpected: null,
    iface: null,
  };
  let inFlight = null;
  let timers = null;
  let ifaceCache = settings.iface;

  const iso = (ms = now()) => new Date(ms).toISOString();

  async function busy() {
    try {
      return Boolean(await isGenerationBusy());
    } catch {
      return true; // never act on an unknown lock
    }
  }

  async function bootRestoreRunning() {
    const res = await run("systemctl", ["is-active", RESTORE_UNIT], { timeoutMs: 8000 });
    return String(res.stdout || "").trim() === "activating";
  }

  async function listProcesses() {
    const res = await run("ps", ["-eo", "pid=,etimes=,args="], { timeoutMs: 8000 });
    if (res.code !== 0) return { ok: false, error: String(res.stderr || "").trim().slice(0, 200) || `exit ${res.code}` };
    const procs = hygieneLib.parsePsProcesses(res.stdout);
    const keys = new Set();
    const dirs = new Map();
    for (const p of procs) {
      const dir = path.dirname(p.cfgArg);
      if (!dirs.has(dir)) {
        let real = dir;
        try { real = await realpath(dir); } catch { real = dir; }
        dirs.set(dir, real);
      }
      keys.add(path.join(dirs.get(dir), path.basename(p.cfgArg)));
    }
    return { ok: true, keys };
  }

  const dirCache = new Map();
  async function keyOfCfg(c) {
    const dir = path.dirname(c.cfgPath);
    if (!dirCache.has(dir)) {
      let real = dir;
      try { real = await realpath(dir); } catch { real = dir; }
      dirCache.set(dir, real);
    }
    return path.join(dirCache.get(dir), path.basename(c.cfgPath));
  }

  async function listListening(ports) {
    const list = [...new Set(ports)].filter((p) => Number.isInteger(p) && p > 0);
    const out = new Set();
    for (let i = 0; i < list.length; i += LISTEN_PROBE_CHUNK) {
      const filter = list.slice(i, i + LISTEN_PROBE_CHUNK).map((p) => `sport = :${p}`).join(" or ");
      const res = await run("ss", ["-ltnH", filter], { timeoutMs: 8000 });
      if (res.code !== 0) return { ok: false, error: String(res.stderr || "").trim().slice(0, 200) || `exit ${res.code}` };
      for (const p of hygieneLib.parseListeningPorts(res.stdout)) out.add(p);
    }
    return { ok: true, ports: out };
  }

  async function egressIface() {
    if (ifaceCache) return ifaceCache;
    const res = await run("ip", ["-6", "route", "show", "default"], { timeoutMs: 8000 });
    const m = /\bdev\s+([A-Za-z0-9_.-]{1,32})\b/.exec(String(res.stdout || ""));
    if (m) ifaceCache = m[1];
    return ifaceCache;
  }

  async function ipBatch(text, label) {
    let dir = null;
    try {
      dir = fs.mkdtempSync(path.join(tmpDir, "netrun-supervisor-"));
      const file = path.join(dir, `${label}.batch`);
      fs.writeFileSync(file, text);
      return await run("ip", ["-6", "-force", "-batch", file], { timeoutMs: 15 * 60_000 });
    } catch (err) {
      return { code: -1, stdout: "", stderr: String((err && err.message) || err) };
    } finally {
      if (dir) {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      }
    }
  }

  function remember(entry) {
    stats.lastRespawns.unshift(entry);
    if (stats.lastRespawns.length > RECENT_KEEP) stats.lastRespawns.length = RECENT_KEEP;
  }

  async function respawnPhase(cfgs) {
    const procs = await listProcesses();
    if (!procs.ok) {
      log.error(`[supervisor] ps failed (${procs.error}); no respawn this tick`);
      return "ps_failed";
    }
    const probes = cfgs.map((c) => (Number.isInteger(c.probePort) && c.probePort > 0 ? c.probePort : c.startPort));
    const listening = await listListening(probes);
    if (!listening.ok) {
      log.error(`[supervisor] ss failed (${listening.error}); no respawn this tick`);
      return "ss_failed";
    }
    const keys = new Map();
    for (const c of cfgs) keys.set(c.startPort, await keyOfCfg(c));
    if (bootMs === null) bootMs = bootTimeMs();
    const plan = planRespawns(cfgs, {
      runningKeys: procs.keys,
      listening: listening.ports,
      keyOf: (c) => keys.get(c.startPort),
      nowMs: now(),
      settleMs: settings.settleSec * 1000,
      maxPerHour: settings.maxRespawnsPerHour,
      state,
      bootMs,
    });
    if (plan.unsupervised.join(",") !== unsupervised.join(",") && plan.unsupervised.length) {
      log.warn(
        `[supervisor] batch(es) ${plan.unsupervised.join(",")}: not running and never served since boot ` +
          "(a failed generation's leftover?) — not started by the supervisor"
      );
    }
    unsupervised = plan.unsupervised;
    for (const sp of plan.pending) log.warn(`[supervisor] batch ${sp}: no 3proxy and not listening — respawn if still down next tick`);
    for (const sp of plan.recovered) log.log(`[supervisor] batch ${sp}: listening again — cleared the failed mark`);
    for (const f of plan.failedNew) {
      log.error(
        `[supervisor] batch ${f.startPort}: respawned ${f.respawns} times in the last hour and still dead — ` +
          "giving up until its cfg changes or it listens again"
      );
    }
    let outcome = "ok";
    for (const c of plan.respawn) {
      const done = await processLock(async () => {
        if (await busy()) return "generation_in_progress";
        if (!exists(c.cfgPath)) return "gone";
        const fresh = await listProcesses();
        if (!fresh.ok) return "ps_failed";
        if (fresh.keys.has(keys.get(c.startPort))) return "running";
        let res;
        try {
          res = await spawnCfg(c.cfgPath);
        } catch (err) {
          res = { ok: false, outcome: "failed", detail: String((err && err.message) || err), pid: null, via: null };
        }
        const at = now();
        const hist = state.history.get(c.startPort) || [];
        hist.push(at);
        state.history.set(c.startPort, hist);
        state.downSince.delete(c.startPort);
        remember({ startPort: c.startPort, at: iso(at), outcome: res.outcome, ok: res.ok, pid: res.pid || null, via: res.via || null });
        if (res.ok) {
          stats.cfgsRespawned += 1;
          log.log(`[supervisor] batch ${c.startPort}: 3proxy was dead — ${res.outcome}${res.pid ? ` pid ${res.pid}` : ""} (${res.via})`);
        } else {
          stats.respawnFailures += 1;
          log.error(`[supervisor] batch ${c.startPort}: respawn failed: ${res.detail || res.outcome}`);
        }
        return "respawned";
      });
      if (done === "generation_in_progress") {
        outcome = "generation_in_progress";
        break;
      }
    }
    return outcome;
  }

  async function addressPhase(cfgs) {
    if (!settings.readdAnchors && !settings.deprecateAnchors) return "anchors_off";
    let rows;
    try {
      rows = parseIfInet6Rows(await readFile(ifInet6Path));
    } catch (err) {
      log.error(`[supervisor] cannot read ${ifInet6Path}: ${(err && err.message) || err}`);
      return "if_inet6_failed";
    }
    const iface = await egressIface();
    stats.iface = iface;
    const plan = planAnchors(cfgs, rows, { iface });
    stats.anchorsExpected = plan.expected;
    stats.addressesMissing = plan.missing.length;
    let outcome = "ok";
    if (settings.readdAnchors && plan.missing.length > 0) {
      if (!iface) {
        log.error(`[supervisor] ${plan.missing.length} anchor(s) missing but no IPv6 default route interface (set NETRUN_IPV6_IFACE)`);
        outcome = "no_ipv6_iface";
      } else {
        const take = plan.missing.slice(0, settings.readdBatch);
        const res = await ipBatch(readdBatchText(take, iface, { deprecate: settings.deprecateAnchors }), "readd");
        stats.addressesReadded += take.length;
        stats.lastReaddAt = iso();
        log.warn(
          `[supervisor] re-added ${take.length} missing anchor IPv6 address(es) on ${iface} ` +
            `(of ${plan.missing.length}; ip -batch exit ${res.code}), e.g. ${take.slice(0, 3).join(", ")}`
        );
      }
    }
    if (settings.deprecateAnchors) {
      const take = plan.pendingDeprecate.slice(0, settings.deprecateBatch);
      stats.anchorsPendingDeprecate = plan.pendingDeprecate.length - take.length;
      if (take.length > 0) {
        const res = await ipBatch(deprecateBatchText(take), "deprecate");
        stats.anchorsDeprecated += take.length;
        log.log(
          `[supervisor] deprecated ${take.length} anchor(s) (preferred_lft 0: never the node's own source address); ` +
            `${stats.anchorsPendingDeprecate} to go; ip -batch exit ${res.code}`
        );
      }
    } else {
      stats.anchorsPendingDeprecate = null;
    }
    return outcome;
  }

  async function writeStatus() {
    const body = `${JSON.stringify({ ...status(), writtenAt: iso() }, null, 2)}\n`;
    try {
      if (writeFile) {
        await writeFile(statusFile, body);
        return;
      }
      await fsp.mkdir(path.dirname(statusFile), { recursive: true });
      const tmp = `${statusFile}.tmp`;
      await fsp.writeFile(tmp, body);
      await fsp.rename(tmp, statusFile);
    } catch (err) {
      log.warn(`[supervisor] cannot write ${statusFile}: ${(err && err.message) || err}`);
    }
  }

  function tick() {
    if (!settings.enabled) return Promise.resolve({ skipped: true, outcome: "disabled" });
    if (inFlight) return inFlight;
    inFlight = (async () => {
      const started = now();
      stats.lastRunAt = iso(started);
      let outcome;
      try {
        if (await busy()) {
          outcome = "generation_in_progress";
        } else if (await bootRestoreRunning()) {
          outcome = "boot_restore_running";
        } else {
          const inv = await readCfgs();
          if (!inv || !inv.ok) {
            outcome = "cfg_read_failed";
          } else {
            const respawn = await respawnPhase(inv.cfgs);
            const addresses = await addressPhase(inv.cfgs);
            outcome = respawn !== "ok" ? respawn : addresses !== "ok" ? addresses : "ok";
          }
        }
      } catch (err) {
        outcome = `error:${(err && err.message) || err}`;
        log.error(`[supervisor] tick failed: ${(err && err.message) || err}`);
      }
      stats.lastOutcome = outcome;
      stats.lastDurationMs = now() - started;
      await writeStatus();
      return { skipped: false, outcome };
    })().finally(() => {
      inFlight = null;
    });
    return inFlight;
  }

  function start() {
    if (timers) return;
    log.log(
      `[supervisor] enabled=${settings.enabled} interval=${settings.intervalSec}s first_in=${settings.firstDelaySec}s ` +
        `max_respawns_per_hour=${settings.maxRespawnsPerHour} readd_anchors=${settings.readdAnchors} ` +
        `deprecate_anchors=${settings.deprecateAnchors}`
    );
    timers = [];
    if (!settings.enabled) return;
    const first = setTimeout(() => {
      tick();
      const every = setInterval(() => tick(), settings.intervalSec * 1000);
      if (typeof every.unref === "function") every.unref();
      timers.push(every);
    }, settings.firstDelaySec * 1000);
    if (typeof first.unref === "function") first.unref();
    timers.push(first);
  }

  function stop() {
    for (const t of timers || []) {
      clearTimeout(t);
      clearInterval(t);
    }
    timers = null;
  }

  function status() {
    return {
      enabled: settings.enabled,
      intervalSec: settings.intervalSec,
      maxRespawnsPerHour: settings.maxRespawnsPerHour,
      readdAnchors: settings.readdAnchors,
      deprecateAnchors: settings.deprecateAnchors,
      ...stats,
      lastRespawns: [...stats.lastRespawns],
      pendingDown: [...state.downSince.keys()].sort((a, b) => a - b),
      unsupervised: [...unsupervised],
      seenServing: [...state.seen].sort((a, b) => a - b),
      failedCfgs: [...state.failed.entries()]
        .map(([sp, f]) => ({ startPort: sp, at: iso(f.at), reason: f.reason, respawns: f.respawns }))
        .sort((a, b) => a.startPort - b.startPort),
    };
  }

  return { start, stop, tick, status, settings: () => ({ ...settings }) };
}

module.exports = {
  createSupervisor,
  readSettings,
  parseIfInet6Rows,
  hexToIpv6,
  presentPrefixes,
  planAnchors,
  planRespawns,
  readBootTimeMs,
  readdBatchText,
  deprecateBatchText,
  IFA_F_DEPRECATED,
  IFA_F_NODAD,
};
