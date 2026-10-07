"use strict";

// Audit RES-13 (node part) — the stale-listener ("ghost") firewall moves into
// the agent. Until now an orchestrator SSH timer (scripts/reconcile_node_ghosts.sh,
// every 30 min, `active` nodes only, a fixed 20000-60000 window) was the only
// thing that blocked re-spawned listeners nobody owns and the only remover of
// stale drops after a reboot: reapplyPergbBlocks (accounting.js) only ADDS.
//
//   POST /firewall/desired  (X-API-KEY)
//   { livePorts:    [int]        every port (socks AND http) that must serve:
//                                rows in available / reserved / sold /
//                                expired_grace / allocated_pergb + in-flight
//                                allocations,
//     pergbBlocked: [int]        ports to drop on purpose (per-GB accounts not
//                                active, node_blocked_at rows); a socks port's
//                                paired http port (socks - 10000) is added like
//                                /accounts/{port}/disable does,
//     windows: [[lo, hi], ...]   the node's port windows (socks + http), or
//     window: [lo, hi]           the socks window; its http mirror
//                                [lo - 10000, hi - 10000] is implied unless
//                                httpMirror: false,
//     computedAt: ISO string     optional: when the orchestrator read its DB,
//     dryRun: bool, force: bool }
//
// Applied (one nft -f on inet proxy_accounting pergb_blocked):
//   block   every listener inside the windows that is NOT in livePorts (a
//           ghost), plus pergbBlocked;
//   unblock every blocked port in livePorts that is not in pergbBlocked.
// Never blocked, and their blocks are LIFTED (the 2026-10-07 incident: the
// SSH reconcile firewalled a batch that was still being generated, so every
// retry failed validation against the same drops): the ports of an in-flight
// generation (the generation lock: socks range + http mirror). Never a ghost:
// a listener of a cfg written in the last NODE_AGENT_FIREWALL_FRESH_SEC (1800)
// or after computedAt - 5 min (a batch the orchestrator's snapshot cannot know
// yet), ports below 1024, the agent's own port. Blocks on other ports are left
// alone. A push that would block more than NODE_AGENT_FIREWALL_MAX_NEW_BLOCKS
// (3000) NEW ports, or names no live port while listeners exist, is refused
// (409) unless force: a broken payload must not firewall a node's whole stock.
//
// The accepted push is persisted (NODE_AGENT_FIREWALL_STATE_FILE,
// /var/lib/netrun/desired.json) with the ghost set it found, and re-applied at
// agent start (after reapplyPergbBlocks) and every NODE_AGENT_FIREWALL_REAPPLY_SEC
// (900): pergbBlocked and the PUSHED ghosts are re-asserted (a reboot restores
// whatever ruleset snapshot was saved), stale blocks on live ports are removed
// — a re-apply never declares new ghosts (only a fresh push does), so a batch
// generated after the push is never blocked from a stale list. Accounting's
// pergb_blocked.list follows (unblocked ports out, pergbBlocked in).
// /generate lifts the blocks on the batch it is about to generate (liftPorts);
// when its kill-on-rebind sweep did not finish, the ports an old occupant still
// listens on are passed as `exclude` and keep their blocks (and list entries).
// NODE_AGENT_FIREWALL_DESIRED=0 turns the endpoint, the re-apply and the lift off.
//
// Per-port account toggles win over an older desired state (audit follow-up):
// POST /accounts/{port}/disable|enable goes through recordAccountToggle, which
// records { blocked, atMs } for the port (and, like accounting.js, its http
// pair port - 10000) in memory and in NODE_AGENT_FIREWALL_TOGGLES_FILE
// (desired.toggles.json next to the state file) before the 200. Every plan
// overlays them: a disabled port stays in pergbBlocked, an enabled one is
// treated as live and never blocked, so neither the 15-min re-apply nor the
// boot re-apply can undo a toggle made after the last push, and the accounting
// list is never pruned / refilled against one. A push drops the toggles older
// than its snapshot (computedAt, else its arrival, minus 5 min: the
// orchestrator's rows already carry them) and keeps the newer ones; a
// generation lift drops the toggles of its batch. The toggle itself (nft +
// list, accounting.js) runs outside the firewall's apply chain, so a slow push
// never delays the disable ack; a toggle that lands while a plan is being
// applied is re-checked right before nft -f and inside the list update.
//
// Ephemeral-range guard (NODE_AGENT_FIREWALL_EPHEMERAL_GUARD, default on): the
// `tcp dport @pergb_blocked drop` rule also drops the SYN-ACKs of upstream
// connections whose ephemeral source port is a blocked port (the 2026-10-07
// 5-7 % failure incident). A push that would ADD blocks inside
// net.ipv4.ip_local_port_range is refused (409 ephemeral_overlap) unless
// force; a re-apply only warns (it re-asserts what the kernel already had).

const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const hygieneLib = require("./hygiene.js");

const NFT_TABLE = "proxy_accounting";
const NFT_SET = "pergb_blocked";
const HTTP_OFFSET = 10000;
const STATE_VERSION = 1;
const DEFAULT_STATE_FILE = "/var/lib/netrun/desired.json";
const DEFAULT_REAPPLY_SEC = 900;
const DEFAULT_FRESH_SEC = 1800;
const DEFAULT_MAX_NEW_BLOCKS = 3000;
const COMPUTED_AT_MARGIN_MS = 5 * 60_000;
const MAX_LIST = 300_000;
const NFT_CHUNK = 500;
const SAMPLE = 20;
const TOGGLES_VERSION = 1;
const MAX_TOGGLES = 70_000;
const EPHEMERAL_RANGE_PATH = "/proc/sys/net/ipv4/ip_local_port_range";

function execCapture(cmd, args, { timeoutMs = 30_000 } = {}) {
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

function intEnv(raw, def, min) {
  const n = Number(raw);
  if (raw === undefined || raw === null || String(raw).trim() === "" || !Number.isFinite(n)) return def;
  return Math.max(min, Math.floor(n));
}

// desired.json -> desired.toggles.json (any other name: <name>.toggles.json).
function defaultTogglesFile(stateFile) {
  return `${String(stateFile).replace(/\.json$/i, "")}.toggles.json`;
}

function readSettings(env = process.env) {
  const stateFile = String(env.NODE_AGENT_FIREWALL_STATE_FILE || DEFAULT_STATE_FILE);
  return {
    enabled: hygieneLib.envSwitch(env.NODE_AGENT_FIREWALL_DESIRED),
    stateFile,
    togglesFile: String(env.NODE_AGENT_FIREWALL_TOGGLES_FILE || defaultTogglesFile(stateFile)),
    reapplySec: intEnv(env.NODE_AGENT_FIREWALL_REAPPLY_SEC, DEFAULT_REAPPLY_SEC, 60),
    freshSec: intEnv(env.NODE_AGENT_FIREWALL_FRESH_SEC, DEFAULT_FRESH_SEC, 0),
    maxNewBlocks: intEnv(env.NODE_AGENT_FIREWALL_MAX_NEW_BLOCKS, DEFAULT_MAX_NEW_BLOCKS, 0),
    ephemeralGuard: hygieneLib.envSwitch(env.NODE_AGENT_FIREWALL_EPHEMERAL_GUARD),
  };
}

// "1024\t8000" (the /proc file) -> [1024, 8000], else null.
function parseEphemeralRange(text) {
  const m = /^\s*(\d+)\s+(\d+)\s*$/.exec(String(text || ""));
  if (!m) return null;
  const lo = Number(m[1]);
  const hi = Number(m[2]);
  return isPort(lo) && isPort(hi) && lo <= hi ? [lo, hi] : null;
}

function readEphemeralRangeProc() {
  try {
    return parseEphemeralRange(fs.readFileSync(EPHEMERAL_RANGE_PATH, "utf-8"));
  } catch {
    return null; // no /proc (macOS tests): unknown, the guard stays quiet
  }
}

// Per-port toggles (Map port -> { blocked, atMs, ... }) as they act on nft:
// each covers the port and its http pair (accounting.js _enforceBlock), the
// newest toggle wins where two cover one port. keep(t) filters the toggles.
function expandToggles(toggles, keep = () => true) {
  const out = new Map();
  for (const [p, t] of toggles || []) {
    if (!keep(t)) continue;
    for (const q of withHttpMirror([p])) {
      const prev = out.get(q);
      if (!prev || prev.atMs <= t.atMs) out.set(q, t);
    }
  }
  return out;
}

// The plan inputs with the toggles laid over them: a disabled port is
// pay-per-GB blocked, an enabled one is live and not blocked.
function overlayToggles(live, pergb, expanded) {
  const outLive = new Set(live);
  const outPergb = new Set(pergb);
  for (const [q, t] of expanded) {
    if (t.blocked) {
      outPergb.add(q);
    } else {
      outPergb.delete(q);
      outLive.add(q);
    }
  }
  return { live: outLive, pergb: outPergb };
}

const isPort = (p) => Number.isInteger(p) && p >= 1 && p <= 65535;

function portList(raw, field) {
  if (raw === undefined || raw === null) return { ok: true, ports: [] };
  if (!Array.isArray(raw)) return { ok: false, error: `${field}_not_an_array` };
  if (raw.length > MAX_LIST) return { ok: false, error: `${field}_too_long` };
  const out = [];
  for (let i = 0; i < raw.length; i += 1) {
    const p = Number(raw[i]);
    if (!isPort(p)) return { ok: false, error: `${field}_bad_port:${i}` };
    out.push(p);
  }
  return { ok: true, ports: out };
}

function windowPair(raw) {
  if (!Array.isArray(raw) || raw.length !== 2) return null;
  const lo = Number(raw[0]);
  const hi = Number(raw[1]);
  if (!isPort(lo) || !isPort(hi) || lo > hi) return null;
  return [lo, hi];
}

// Request body -> { ok, error, desired: { livePorts, pergbBlocked, windows, computedAtMs } }.
function parseDesiredBody(body) {
  const b = body && typeof body === "object" ? body : null;
  if (!b) return { ok: false, error: "body_not_an_object" };
  if (b.livePorts === undefined && b.live_ports === undefined) return { ok: false, error: "livePorts_required" };
  const live = portList(b.livePorts ?? b.live_ports, "livePorts");
  if (!live.ok) return live;
  const pergb = portList(b.pergbBlocked ?? b.pergb_blocked, "pergbBlocked");
  if (!pergb.ok) return pergb;
  const windows = [];
  if (b.windows !== undefined) {
    if (!Array.isArray(b.windows) || b.windows.length === 0 || b.windows.length > 16) return { ok: false, error: "windows_invalid" };
    for (const w of b.windows) {
      const pair = windowPair(w);
      if (!pair) return { ok: false, error: "windows_invalid" };
      windows.push(pair);
    }
  } else if (b.window !== undefined) {
    const pair = windowPair(b.window);
    if (!pair) return { ok: false, error: "window_invalid" };
    windows.push(pair);
    const mirror = b.httpMirror ?? b.http_mirror;
    if (mirror !== false && pair[1] - HTTP_OFFSET >= 1) {
      windows.push([Math.max(1, pair[0] - HTTP_OFFSET), pair[1] - HTTP_OFFSET]);
    }
  } else {
    return { ok: false, error: "window_required" };
  }
  let computedAtMs = null;
  const ca = b.computedAt ?? b.computed_at;
  if (ca !== undefined && ca !== null && ca !== "") {
    computedAtMs = Date.parse(String(ca));
    if (!Number.isFinite(computedAtMs)) return { ok: false, error: "computedAt_invalid" };
  }
  return {
    ok: true,
    desired: { livePorts: live.ports, pergbBlocked: pergb.ports, windows, computedAtMs },
  };
}

// A pay-per-GB socks port drags its paired http port along (accounting.js _httpFor).
function withHttpMirror(ports) {
  const out = new Set();
  for (const p of ports) {
    out.add(p);
    if (p - HTTP_OFFSET >= 1) out.add(p - HTTP_OFFSET);
  }
  return out;
}

// Ports of an in-flight generation from its lock record: the range, plus the
// http mirror (socks - 10000) of a dual batch. A record without proxyCount /
// proxiesType (an older agent's lock): 1500 ports with the mirror — the
// largest batch; such locks are short-lived.
function inFlightFromLock(lock) {
  const out = new Set();
  if (!lock || typeof lock !== "object") return out;
  const sp = Number(lock.startPort);
  if (!isPort(sp)) return out;
  const n = Number(lock.proxyCount);
  const count = Number.isInteger(n) && n > 0 ? Math.min(n, 10000) : 1500;
  const type = lock.proxiesType === undefined || lock.proxiesType === null ? "dual" : String(lock.proxiesType);
  for (let p = sp; p < sp + count && p <= 65535; p += 1) {
    out.add(p);
    if (type === "dual" && p - HTTP_OFFSET >= 1) out.add(p - HTTP_OFFSET);
  }
  return out;
}

// `nft list set inet proxy_accounting pergb_blocked` -> Set of ports.
function parseSetElements(text) {
  const out = new Set();
  const s = String(text || "");
  const i = s.indexOf("elements");
  if (i < 0) return out;
  const open = s.indexOf("{", i);
  const close = s.indexOf("}", open);
  if (open < 0 || close < 0) return out;
  for (const m of s.slice(open + 1, close).matchAll(/\d+/g)) {
    const p = Number(m[0]);
    if (isPort(p)) out.add(p);
  }
  return out;
}

const inWindows = (windows) => (p) => windows.some(([lo, hi]) => p >= lo && p <= hi);
const sorted = (it) => [...it].sort((a, b) => a - b);

// The pure core. mode "push": ghosts = listeners in the windows that are not
// live / in flight / fresh / protected. mode "reapply": ghosts = the pushed
// ghost set minus the same exclusions (never new ones). Returns sorted arrays.
function planFirewall({
  mode,
  listening = new Set(),
  current = new Set(),
  live = new Set(),
  pergb = new Set(),
  windows = [],
  inFlight = new Set(),
  fresh = new Set(),
  protectedPorts = new Set(),
  ghostPorts = new Set(),
}) {
  const inWin = inWindows(windows);
  const excluded = (p) => inFlight.has(p) || fresh.has(p) || protectedPorts.has(p) || p < 1024;
  const ghosts = new Set();
  const source = mode === "push" ? listening : ghostPorts;
  for (const p of source) {
    if (live.has(p) || excluded(p)) continue;
    if (mode === "push" && !inWin(p)) continue;
    ghosts.add(p);
  }
  const pergbWanted = new Set();
  for (const p of pergb) if (!inFlight.has(p) && !protectedPorts.has(p)) pergbWanted.add(p);
  const want = new Set([...ghosts, ...pergbWanted]);
  const add = [...want].filter((p) => !current.has(p));
  const remove = [...current].filter((p) => inFlight.has(p) || (live.has(p) && !pergb.has(p)));
  const skippedInFlight = [...new Set([...source, ...pergb])].filter((p) => inFlight.has(p));
  return {
    ghosts: sorted(ghosts),
    pergbWanted: sorted(pergbWanted),
    add: sorted(add),
    remove: sorted(remove),
    skippedInFlight: sorted(skippedInFlight),
  };
}

function nftBatchText({ add = [], remove = [] }) {
  const lines = [];
  for (let i = 0; i < remove.length; i += NFT_CHUNK) {
    lines.push(`destroy element inet ${NFT_TABLE} ${NFT_SET} { ${remove.slice(i, i + NFT_CHUNK).join(", ")} }`);
  }
  for (let i = 0; i < add.length; i += NFT_CHUNK) {
    lines.push(`add element inet ${NFT_TABLE} ${NFT_SET} { ${add.slice(i, i + NFT_CHUNK).join(", ")} }`);
  }
  return lines.length ? `${lines.join("\n")}\n` : "";
}

function summarize(list) {
  return { count: list.length, sample: list.slice(0, SAMPLE) };
}

// ── the service ──────────────────────────────────────────────────────────

function createFirewall({
  env = process.env,
  run = execCapture,
  readCfgs = async () => ({ ok: true, cfgs: [] }),
  readLock = async () => null, // the live generation lock record, or null
  ensureInfra = async () => {},
  updateBlockedList = async () => {}, // (fn(Set) -> void) persisted by accounting.js
  protectedPorts = [],
  now = () => Date.now(),
  log = console,
  tmpDir = os.tmpdir(),
  readEphemeralRange = readEphemeralRangeProc, // -> [lo, hi] | null
} = {}) {
  const settings = readSettings(env);
  const protectedSet = new Set(protectedPorts.filter(isPort));
  let lastApply = null;
  let timer = null;
  let tail = Promise.resolve();
  let summary; // undefined = not read yet, null = no desired state

  // Per-port account toggles: port -> { blocked, atMs, seq }. seq orders them
  // within this process (a plan knows which toggles it already saw).
  const toggles = new Map();
  let toggleSeq = 0;
  let togglesTail = Promise.resolve();
  try {
    const raw = JSON.parse(fs.readFileSync(settings.togglesFile, "utf-8"));
    if (raw && raw.version === TOGGLES_VERSION && raw.toggles && typeof raw.toggles === "object") {
      for (const [k, v] of Object.entries(raw.toggles)) {
        const p = Number(k);
        const atMs = Number(v && v.atMs);
        if (isPort(p) && v && typeof v.blocked === "boolean" && Number.isFinite(atMs)) toggles.set(p, { blocked: v.blocked, atMs, seq: 0 });
      }
    }
  } catch {
    // no toggles recorded yet
  }

  // One write at a time; a burst of toggles (an account's whole port list)
  // shares the write that has not started yet — it takes its snapshot when it
  // starts, so every caller's toggle is in the file once its promise resolves.
  let toggleWriteQueued = null;
  function persistToggles() {
    if (toggleWriteQueued) return toggleWriteQueued;
    const run = togglesTail.then(async () => {
      toggleWriteQueued = null;
      const body = {
        version: TOGGLES_VERSION,
        toggles: Object.fromEntries(
          [...toggles].sort((a, b) => a[0] - b[0]).map(([p, t]) => [String(p), { blocked: t.blocked, atMs: t.atMs, at: new Date(t.atMs).toISOString() }])
        ),
      };
      await fsp.mkdir(path.dirname(settings.togglesFile), { recursive: true });
      const tmp = `${settings.togglesFile}.tmp`;
      await fsp.writeFile(tmp, `${JSON.stringify(body)}\n`, { mode: 0o600 });
      await fsp.rename(tmp, settings.togglesFile);
    });
    toggleWriteQueued = run;
    togglesTail = run.catch(() => {});
    return run;
  }

  // Toggles a plan made at planSeq has not seen yet.
  const newerThan = (planSeq) => (t) => t.seq > planSeq;

  function summarize_(state) {
    return state
      ? {
          receivedAt: state.receivedAt,
          computedAt: state.computedAt || null,
          windows: state.windows,
          livePorts: (state.livePorts || []).length,
          pergbBlocked: (state.pergbBlocked || []).length,
          ghostPorts: (state.ghostPorts || []).length,
        }
      : null;
  }

  // Ports of `ports` inside the ephemeral range (the guard), or null when the
  // guard is off / the range is unknown.
  function ephemeralHits(ports) {
    if (!settings.ephemeralGuard) return null;
    let range = null;
    try {
      range = readEphemeralRange();
    } catch {
      range = null;
    }
    if (!range) return null;
    const [lo, hi] = range;
    return { range: `${lo} ${hi}`, hits: sorted([...ports].filter((p) => p >= lo && p <= hi)) };
  }

  // One apply at a time (push vs the periodic re-apply vs a generation lift).
  function serialized(fn) {
    const runIt = tail.then(fn);
    tail = runIt.catch(() => {});
    return runIt;
  }

  async function readState() {
    let state = null;
    try {
      const raw = JSON.parse(await fsp.readFile(settings.stateFile, "utf-8"));
      if (raw && raw.version === STATE_VERSION) state = raw;
    } catch {
      state = null;
    }
    summary = summarize_(state);
    return state;
  }

  async function writeState(state) {
    await fsp.mkdir(path.dirname(settings.stateFile), { recursive: true });
    const tmp = `${settings.stateFile}.tmp`;
    await fsp.writeFile(tmp, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    await fsp.rename(tmp, settings.stateFile);
    summary = summarize_(state);
  }

  async function currentBlocked() {
    const res = await run("nft", ["list", "set", "inet", NFT_TABLE, NFT_SET], { timeoutMs: 30_000 });
    if (res.code !== 0) {
      // No set yet (never blocked anything): nothing is blocked.
      if (/No such file|does not exist|not found/i.test(String(res.stderr || ""))) return { ok: true, ports: new Set() };
      return { ok: false, error: String(res.stderr || "").trim().slice(0, 200) || `exit ${res.code}` };
    }
    return { ok: true, ports: parseSetElements(res.stdout) };
  }

  async function listening() {
    const res = await run("ss", ["-Hltn"], { timeoutMs: 30_000 });
    if (res.code !== 0) return { ok: false, error: String(res.stderr || "").trim().slice(0, 200) || `exit ${res.code}` };
    return { ok: true, ports: hygieneLib.parseListeningPorts(res.stdout) };
  }

  // Ports a generation lift kept (an old occupant still listened on them;
  // `exclude`): while that generation holds the lock they are NOT in-flight —
  // a push or re-apply in that window keeps their drops instead of lifting
  // them. Cleared once no generation holds the lock, and by the next lift.
  let liftKept = new Set();

  async function inFlightPorts() {
    let ports;
    try {
      ports = inFlightFromLock(await readLock());
    } catch {
      ports = new Set();
    }
    if (ports.size === 0) {
      liftKept = new Set();
      return ports;
    }
    for (const p of liftKept) ports.delete(p);
    return ports;
  }

  // After nft -f: a toggle that landed while it ran (seq > planSeq) may have
  // been overwritten by the plan's own add / destroy of the same port (the
  // accounting nft call and ours race). Put its intent back.
  async function reassertLate(applied, planSeq, label) {
    const late = expandToggles(toggles, newerThan(planSeq));
    if (late.size === 0) return;
    const add = applied.remove.filter((p) => late.has(p) && late.get(p).blocked);
    const remove = applied.add.filter((p) => late.has(p) && !late.get(p).blocked);
    if (add.length === 0 && remove.length === 0) return;
    const res = await applyNft({ add, remove });
    log.warn(`[firewall] ${label}: ${add.length + remove.length} port(s) toggled during nft -f re-asserted${res.ok ? "" : ` — FAILED: ${res.error}`}`);
  }

  // Ports of cfgs written at/after cutoffMs (a batch the push cannot know).
  async function freshPorts(cutoffMs) {
    const out = new Set();
    const inv = await readCfgs();
    for (const c of (inv && inv.cfgs) || []) {
      if (!Number.isFinite(c.mtimeMs) || c.mtimeMs < cutoffMs) continue;
      for (const p of [...(c.socksPorts || []), ...(c.httpPorts || [])]) out.add(p);
      out.add(c.startPort);
    }
    return out;
  }

  async function applyNft(plan) {
    if (plan.add.length === 0 && plan.remove.length === 0) return { ok: true };
    if (plan.add.length > 0) await ensureInfra();
    let dir = null;
    try {
      dir = fs.mkdtempSync(path.join(tmpDir, "netrun-firewall-"));
      const file = path.join(dir, "desired.nft");
      fs.writeFileSync(file, nftBatchText(plan));
      const res = await run("nft", ["-f", file], { timeoutMs: 60_000 });
      return res.code === 0 ? { ok: true } : { ok: false, error: String(res.stderr || "").trim().slice(0, 300) || `exit ${res.code}` };
    } catch (err) {
      return { ok: false, error: String((err && err.message) || err) };
    } finally {
      if (dir) {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      }
    }
  }

  // A toggle that landed after the plan (seq > planSeq) wins over it: never
  // add a block on a port enabled since, never remove one disabled since.
  function dropOvertaken(plan, planSeq) {
    const late = expandToggles(toggles, newerThan(planSeq));
    if (late.size === 0) return plan;
    return {
      ...plan,
      add: plan.add.filter((p) => !(late.has(p) && !late.get(p).blocked)),
      remove: plan.remove.filter((p) => !(late.has(p) && late.get(p).blocked)),
    };
  }

  // Accounting's pergb_blocked.list follows the plan: unblocked ports out,
  // pay-per-GB ports in — except a port toggled after the plan (checked when
  // the list update actually runs, behind any toggle queued before it).
  async function syncAccountingList(plan, pergb, live, planSeq) {
    const unblock = new Set(plan.remove);
    for (const p of live) if (!pergb.has(p)) unblock.add(p);
    await updateBlockedList((list) => {
      const late = expandToggles(toggles, newerThan(planSeq));
      for (const p of [...list]) if (unblock.has(p) && !(late.has(p) && late.get(p).blocked)) list.delete(p);
      for (const p of plan.pergbWanted) if (!(late.has(p) && !late.get(p).blocked)) list.add(p);
    });
  }

  function report(kind, extra) {
    const r = { kind, at: new Date(now()).toISOString(), ...extra };
    if (!extra.dryRun) lastApply = r;
    return r;
  }

  // POST /firewall/desired. -> { status: 200|400|409|500, body }
  function push(body) {
    if (!settings.enabled) return Promise.resolve({ status: 404, body: { success: false, error: "firewall_desired_disabled" } });
    return serialized(async () => {
      const parsed = parseDesiredBody(body);
      if (!parsed.ok) return { status: 400, body: { success: false, error: "invalid_desired", detail: parsed.error } };
      const { desired } = parsed;
      const dryRun = Boolean(body && body.dryRun);
      const force = Boolean(body && body.force);
      const [ls, cur] = await Promise.all([listening(), currentBlocked()]);
      if (!ls.ok) return { status: 500, body: { success: false, error: "ss_failed", detail: ls.error } };
      if (!cur.ok) return { status: 500, body: { success: false, error: "nft_list_failed", detail: cur.error } };
      const inFlight = await inFlightPorts();
      const nowMs = now();
      let cutoff = nowMs - settings.freshSec * 1000;
      if (Number.isFinite(desired.computedAtMs)) cutoff = Math.min(cutoff, desired.computedAtMs - COMPUTED_AT_MARGIN_MS);
      const fresh = await freshPorts(cutoff);
      // Toggles newer than the orchestrator's snapshot win over the payload;
      // older ones are in the snapshot already (dropped once this push is in).
      const snapshotCutoff = (Number.isFinite(desired.computedAtMs) ? desired.computedAtMs : nowMs) - COMPUTED_AT_MARGIN_MS;
      const planSeq = toggleSeq;
      const kept = expandToggles(toggles, (t) => t.atMs > snapshotCutoff);
      const { live, pergb } = overlayToggles(new Set(desired.livePorts), withHttpMirror(desired.pergbBlocked), kept);
      const plan = planFirewall({
        mode: "push",
        listening: ls.ports,
        current: cur.ports,
        live,
        pergb,
        windows: desired.windows,
        inFlight,
        fresh,
        protectedPorts: protectedSet,
      });
      const listenersInWindows = [...ls.ports].filter(inWindows(desired.windows)).length;
      const base = {
        dryRun,
        windows: desired.windows,
        listenersInWindows,
        ghosts: summarize(plan.ghosts),
        pergbBlocked: summarize(plan.pergbWanted),
        added: summarize(plan.add),
        removed: summarize(plan.remove),
        skippedInFlight: summarize(plan.skippedInFlight),
        freshExempt: fresh.size,
        alreadyBlocked: cur.ports.size,
        togglesKept: kept.size,
      };
      const eph = ephemeralHits(plan.add);
      if (eph) base.ipLocalPortRange = eph.range;
      let refusal = null;
      let extra = {};
      if (!force && desired.livePorts.length === 0 && plan.ghosts.length > 0) refusal = "empty_live_ports";
      else if (!force && plan.add.length > settings.maxNewBlocks) refusal = "too_many_blocks";
      else if (!force && eph && eph.hits.length > 0) {
        refusal = "ephemeral_overlap";
        extra = { ipLocalPortRange: eph.range, overlappingAdds: summarize(eph.hits) };
      }
      if (refusal) {
        log.warn(
          `[firewall] push refused (${refusal}): would add ${plan.add.length} block(s), ${plan.ghosts.length} ghost(s)` +
            `${refusal === "ephemeral_overlap" ? `, ${eph.hits.length} inside ip_local_port_range ${eph.range} (their drops would also drop upstream SYN-ACKs)` : ""}` +
            "; force:true overrides"
        );
        return { status: 409, body: { success: false, error: refusal, maxNewBlocks: settings.maxNewBlocks, ...extra, report: base } };
      }
      if (dryRun) return { status: 200, body: { success: true, applied: false, report: report("push", base) } };
      const applied = dropOvertaken(plan, planSeq);
      const nft = await applyNft(applied);
      if (nft.ok) await reassertLate(applied, planSeq, "push");
      if (!nft.ok) {
        log.error(`[firewall] push: nft -f failed: ${nft.error}`);
        return { status: 500, body: { success: false, error: "nft_failed", detail: nft.error, report: report("push", { ...base, ok: false }) } };
      }
      await syncAccountingList(plan, pergb, live, planSeq);
      await writeState({
        version: STATE_VERSION,
        receivedAt: new Date(nowMs).toISOString(),
        computedAt: Number.isFinite(desired.computedAtMs) ? new Date(desired.computedAtMs).toISOString() : null,
        windows: desired.windows,
        livePorts: sorted(new Set(desired.livePorts)),
        pergbBlocked: sorted(desired.pergbBlocked),
        ghostPorts: plan.ghosts,
      });
      // The persisted snapshot carries every toggle older than its cutoff now
      // (after writeState: a crash in between keeps the toggles, never the
      // reverse). The newer ones stay and keep overriding it.
      let pruned = 0;
      for (const [p, t] of [...toggles]) {
        if (t.atMs <= snapshotCutoff && t.seq <= planSeq) {
          toggles.delete(p);
          pruned += 1;
        }
      }
      if (pruned) await persistToggles().catch((err) => log.error(`[firewall] toggles not persisted: ${(err && err.message) || err}`));
      log.log(
        `[firewall] push applied: +${plan.add.length} block(s) (${plan.ghosts.length} ghost(s), ${plan.pergbWanted.length} pergb), ` +
          `-${plan.remove.length} stale; ${plan.skippedInFlight.length} in-flight port(s) left open; ` +
          `${toggles.size} account toggle(s) newer than the snapshot kept`
      );
      return { status: 200, body: { success: true, applied: true, report: report("push", { ...base, ok: true }) } };
    });
  }

  // Boot / periodic: re-assert the persisted push. Never declares new ghosts.
  // Every account toggle recorded since the push lays over it (the last
  // per-port intent wins, however old the push is).
  function reapply(reason = "periodic") {
    if (!settings.enabled) return Promise.resolve({ skipped: true, reason: "disabled" });
    return serialized(async () => {
      const state = await readState();
      if (!state) return { skipped: true, reason: "no_desired_state" };
      const cur = await currentBlocked();
      if (!cur.ok) {
        log.error(`[firewall] re-apply (${reason}): nft list failed: ${cur.error}`);
        return report("reapply", { reason, ok: false, error: cur.error });
      }
      const receivedMs = Date.parse(state.receivedAt);
      const fresh = await freshPorts(Number.isFinite(receivedMs) ? receivedMs - COMPUTED_AT_MARGIN_MS : 0);
      const inFlight = await inFlightPorts();
      const planSeq = toggleSeq;
      const { live, pergb } = overlayToggles(new Set(state.livePorts || []), withHttpMirror(state.pergbBlocked || []), expandToggles(toggles));
      const plan = planFirewall({
        mode: "reapply",
        current: cur.ports,
        live,
        pergb,
        windows: state.windows || [],
        inFlight,
        fresh,
        protectedPorts: protectedSet,
        ghostPorts: new Set(state.ghostPorts || []),
      });
      const applied = dropOvertaken(plan, planSeq);
      const nft = await applyNft(applied);
      if (nft.ok) await reassertLate(applied, planSeq, `re-apply (${reason})`);
      if (!nft.ok) {
        log.error(`[firewall] re-apply (${reason}): nft -f failed: ${nft.error}`);
        return report("reapply", { reason, ok: false, error: nft.error });
      }
      await syncAccountingList(plan, pergb, live, planSeq);
      if (plan.add.length || plan.remove.length) {
        log.log(`[firewall] re-apply (${reason}): +${plan.add.length} block(s), -${plan.remove.length} stale block(s)`);
      }
      const out = {
        reason,
        ok: true,
        added: summarize(plan.add),
        removed: summarize(plan.remove),
        skippedInFlight: summarize(plan.skippedInFlight),
      };
      // Never refused (the kernel had these blocks before), only reported.
      const eph = ephemeralHits(new Set([...plan.ghosts, ...plan.pergbWanted]));
      if (eph && eph.hits.length > 0) {
        out.ephemeralOverlap = { ipLocalPortRange: eph.range, blockedInRange: summarize(eph.hits) };
        log.warn(
          `[firewall] re-apply (${reason}): ${eph.hits.length} blocked port(s) inside ip_local_port_range ${eph.range} — ` +
            "their drops also drop upstream SYN-ACKs; lower the range (apply_capacity_tuning.sh --only sysctl)"
        );
      }
      return report("reapply", out);
    });
  }

  // /generate: the ports of the batch about to be generated are never blocked —
  // lift what is there (a ghost / pay-per-GB block of the old occupant, an
  // earlier failed attempt) and drop them from the persisted lists and toggles.
  // exclude: ports an old occupant still listens on (the kill-on-rebind sweep
  // did not finish) — their drops, list entries and toggles stay.
  function liftPorts(ports, reason = "generation", { exclude = null } = {}) {
    if (!settings.enabled) return Promise.resolve({ skipped: true });
    const want = new Set((ports || []).filter(isPort));
    const kept = [];
    for (const p of exclude || []) {
      if (want.delete(p)) kept.push(p);
    }
    liftKept = new Set(kept);
    if (kept.length) {
      log.warn(`[firewall] lift (${reason}): ${kept.length} port(s) still have a listener — their blocks stay, e.g. ${sorted(kept).slice(0, 5).join(",")}`);
    }
    if (want.size === 0) return Promise.resolve({ lifted: 0, kept: kept.length });
    return serialized(async () => {
      const cur = await currentBlocked();
      if (!cur.ok) return { lifted: 0, error: cur.error, kept: kept.length };
      const remove = sorted([...cur.ports].filter((p) => want.has(p)));
      if (remove.length) {
        const nft = await applyNft({ add: [], remove });
        if (!nft.ok) {
          log.error(`[firewall] lift (${reason}): nft -f failed: ${nft.error}`);
          return { lifted: 0, error: nft.error, kept: kept.length };
        }
      }
      await updateBlockedList((list) => {
        for (const p of [...list]) if (want.has(p)) list.delete(p);
      });
      let toggled = 0;
      for (const p of [...toggles.keys()]) {
        if (want.has(p)) {
          toggles.delete(p);
          toggled += 1;
        }
      }
      if (toggled) await persistToggles().catch((err) => log.error(`[firewall] toggles not persisted: ${(err && err.message) || err}`));
      const state = await readState();
      if (state) {
        const prune = (arr) => (arr || []).filter((p) => !want.has(p));
        const next = { ...state, ghostPorts: prune(state.ghostPorts), pergbBlocked: prune(state.pergbBlocked) };
        if (next.ghostPorts.length !== (state.ghostPorts || []).length || next.pergbBlocked.length !== (state.pergbBlocked || []).length) {
          await writeState(next);
        }
      }
      if (remove.length) log.log(`[firewall] lift (${reason}): unblocked ${remove.length} port(s) of the batch, e.g. ${remove.slice(0, 5).join(",")}`);
      return { lifted: remove.length, sample: remove.slice(0, SAMPLE), kept: kept.length };
    });
  }

  // POST /accounts/{port}/disable|enable: apply = the accounting call (nft +
  // pergb_blocked.list). The toggle is recorded first (every plan from now on
  // sees it) and persisted before the answer; the accounting call runs outside
  // the apply chain, so a push / re-apply in progress never delays the ack.
  async function recordAccountToggle(port, blocked, apply) {
    const p = Number(port);
    if (!settings.enabled || !isPort(p)) return apply();
    toggleSeq += 1;
    toggles.set(p, { blocked: Boolean(blocked), atMs: now(), seq: toggleSeq });
    if (toggles.size > MAX_TOGGLES) {
      const oldest = [...toggles].sort((a, b) => a[1].atMs - b[1].atMs).slice(0, toggles.size - MAX_TOGGLES);
      for (const [q] of oldest) toggles.delete(q);
    }
    const persisted = persistToggles().catch((err) => {
      log.error(`[firewall] account toggle of port ${p} not persisted: ${(err && err.message) || err}`);
    });
    try {
      return await apply();
    } finally {
      await persisted;
    }
  }

  function start() {
    if (!settings.enabled || timer) return;
    timer = setInterval(() => {
      reapply("periodic").catch((err) => log.error(`[firewall] re-apply failed: ${(err && err.message) || err}`));
    }, settings.reapplySec * 1000);
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  // /health: from memory (the state file is read at start and on every apply).
  function status() {
    return {
      enabled: settings.enabled,
      reapplySec: settings.reapplySec,
      desired: summary || null,
      lastApply,
      accountToggles: toggles.size,
      ephemeralGuard: settings.ephemeralGuard,
    };
  }

  // GET /firewall/desired: re-read, plus a ghost sample.
  async function statusFull() {
    const state = settings.enabled ? await readState() : null;
    const out = status();
    if (state && out.desired) out.desired = { ...out.desired, ghostSample: (state.ghostPorts || []).slice(0, 100) };
    return out;
  }

  return { push, reapply, liftPorts, recordAccountToggle, start, stop, status, statusFull, settings: () => ({ ...settings }) };
}

module.exports = {
  createFirewall,
  readSettings,
  parseDesiredBody,
  planFirewall,
  inFlightFromLock,
  parseEphemeralRange,
  expandToggles,
  overlayToggles,
  defaultTogglesFile,
  parseSetElements,
  withHttpMirror,
  nftBatchText,
};
