"use strict";

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const PROXY_ROOT = path.normalize(process.env.NODE_AGENT_PROXY_ROOT || "/opt/netrun/proxyserver");
const PROXY_CFG_DIR = path.join(PROXY_ROOT, "3proxy");
const PROXY_BIN = path.join(PROXY_ROOT, "3proxy", "bin", "3proxy");
const NFT_TABLE = "proxy_accounting";
const COUNTER_NAME_RE = /^proxy_(\d+)_(in6|in|out)$/;
// Grace before force-killing a 3proxy on disable. 3proxy treats SIGTERM as a
// GRACEFUL shutdown — it stops accepting NEW connections but lets in-flight
// ones run to completion. For pay-per-GB enforcement that let an active
// download stream unbounded past the quota (revenue leak). We give SIGTERM a
// short window to exit cleanly, then SIGKILL any survivor to sever the live
// session. Overridable for tests via NODE_AGENT_DISABLE_GRACE_MS.
const DISABLE_GRACE_MS = Number(process.env.NODE_AGENT_DISABLE_GRACE_MS || 2000);
// Audit the active grace per node (phased rollout: un-patched nodes don't
// force-kill, patched ones do — make each node's setting visible in the log).
console.log(`[accounting] disable force-kill grace: DISABLE_GRACE_MS=${DISABLE_GRACE_MS}`);

// Per-port disable "generation" token. disablePort and enablePort both bump it;
// the deferred force-kill captures the token when armed and aborts if it has
// since changed. Closes the critical race where an enablePort (rebuy / watchdog
// reactivation) lands inside the grace window — without the guard the stale
// SIGKILL would re-resolve the port's pids and kill the proxy the user JUST
// paid to bring back. Bounded by the finite set of ports.
const _disableGen = new Map();
function _bumpDisableGen(port) {
  const next = (_disableGen.get(port) || 0) + 1;
  _disableGen.set(port, next);
  return next;
}

class PortNotFoundError extends Error {
  constructor(port) {
    super(`port_not_found: ${port}`);
    this.name = "PortNotFoundError";
    this.code = "PORT_NOT_FOUND";
    this.port = port;
  }
}

class NftablesError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "NftablesError";
    this.code = "NFTABLES_ERROR";
    this.detail = detail;
  }
}

class ProcessSpawnError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "ProcessSpawnError";
    this.code = "PROCESS_SPAWN_ERROR";
    this.detail = detail;
  }
}

function execCapture(cmd, args, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let child;
    try {
      child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (err) {
      resolve({ code: -1, stdout: "", stderr: String(err && err.message || err), spawnError: err });
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
      resolve({ code: -1, stdout, stderr: stderr || String(err && err.message || err), spawnError: err });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: typeof code === "number" ? code : -1, stdout, stderr });
    });
  });
}

function configPathForPort(port) {
  return path.join(PROXY_CFG_DIR, `3proxy_${port}.cfg`);
}

// Audit WI-5 (H16) — a disabled port whose cfg stays as `3proxy_<port>.cfg`
// gets respawned by the reboot restore scripts (which glob `3proxy_*.cfg`),
// silently reviving a depleted/disabled pay-per-GB port. Demoting renames the
// cfg to `3proxy_<port>.cfg.disabled` (NOT matched by the glob); enablePort
// promotes it back to the live name.
function disabledConfigPathForPort(port) {
  return path.join(PROXY_CFG_DIR, `3proxy_${port}.cfg.disabled`);
}

function _demoteCfg(cfg, portNum) {
  // Rename the live cfg out of the restore glob. ENOENT = a concurrent disable
  // already moved it (no-op); anything else is a real failure.
  try {
    fs.renameSync(cfg, disabledConfigPathForPort(portNum));
  } catch (err) {
    if (err && err.code === "ENOENT") return false;
    throw new ProcessSpawnError("cfg_disable_rename_failed", String((err && err.message) || err));
  }
  return true;
}

async function findRunningPids(port) {
  const pattern = `3proxy_${port}.cfg`;
  const result = await execCapture("pgrep", ["-f", pattern]);
  if (result.code === 0) {
    return result.stdout
      .split(/\s+/)
      .map((s) => s.trim())
      .filter((s) => /^\d+$/.test(s))
      .map(Number);
  }
  if (result.code === 1) {
    return [];
  }
  throw new ProcessSpawnError("pgrep_failed", result.stderr || `exit ${result.code}`);
}

// Wave PERGB-METER-CACHE — collapse the per-cycle dump storm. The orchestrator
// polls /accounting in 100-port chunks, so ONE poll cycle of a ~5k-port node
// fires ~50 separate getCountersForPorts() calls, each previously running a
// full `nft -j list counters table` dump (~1.1s at 12k counters) — i.e. ~50
// dumps per cycle, which pinned a CPU core continuously. A targeted per-counter
// read via `nft -f` is actually SLOWER (per-statement overhead — measured), so
// we keep the single bulk dump but CACHE it across the chunks of one cycle.
// Cycles are delimited by the request GAP: chunks arrive back-to-back while the
// next cycle is >=1 poll interval later, so a gap longer than
// COUNTERS_CACHE_GAP_MS forces a fresh dump. That makes cross-cycle reuse (which
// would zero a cycle's deltas) impossible regardless of the poll interval.
// Concurrent chunks coalesce onto one in-flight dump. Billing-safe: every chunk
// in a cycle reads ONE consistent counter snapshot and the orchestrator's
// per-port delta math is unchanged.
const COUNTERS_CACHE_GAP_MS = Number(process.env.NODE_AGENT_COUNTERS_CACHE_GAP_MS || 2000);
const COUNTERS_CACHE_MAX_MS = Number(process.env.NODE_AGENT_COUNTERS_CACHE_MAX_MS || 8000);
// Wave FLEET-HEALTH (SPD-05) — the dump costs ~1.1 s at 12k counters and grows
// to 36k counters on an 18k-proxy node; under generation load the old 5 s
// execCapture default SIGKILLed it and the whole poll cycle failed. 20 s by
// default, NODE_AGENT_NFT_DUMP_TIMEOUT_MS to tune (min 5 s).
// Coupling: the first /accounting chunk of a cycle sends nothing until the dump
// is parsed, so the orchestrator's TRAFFIC_POLL_REQUEST_TIMEOUT_SEC (default
// 10) must stay ABOVE this / 1000 + parse time (30 recommended) — otherwise a
// 10-20 s dump still fails the cycle as a client read timeout.
const NFT_DUMP_TIMEOUT_MS = Math.max(5000, Number(process.env.NODE_AGENT_NFT_DUMP_TIMEOUT_MS || 20000) || 20000);
// The cache holds the dump already PARSED into Map(port -> {in, out, in6}):
// every chunk of a cycle is a few Map lookups instead of a regex pass over all
// 36k items (the old per-chunk rescan was O(chunks x counters) per cycle).
let _countersCache = { at: 0, byPort: null };
let _countersInFlight = null;
let _lastCounterReqAt = 0;
let _counterParseCount = 0;

// Overridable exec seam for unit tests (asserts the dump timeout).
let _dumpExec = execCapture;

async function _fetchAllCounterItems() {
  const result = await _dumpExec("nft", ["-j", "list", "counters", "table", "inet", NFT_TABLE], {
    timeoutMs: NFT_DUMP_TIMEOUT_MS,
  });
  if (result.code !== 0) {
    throw new NftablesError("nft_list_counters_failed", result.stderr || `exit ${result.code}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout || "{}");
  } catch (err) {
    throw new NftablesError("nft_json_parse_failed", String(err && err.message || err));
  }
  return Array.isArray(parsed && parsed.nftables) ? parsed.nftables : [];
}

// Overridable fetcher seam for unit tests (default = real nft dump).
let _counterItemsFetcher = _fetchAllCounterItems;

// One pass over the dump: Map(port -> { in, out, in6 }) of our named counters.
// Pure + exported for tests.
function parseCounterItems(items) {
  _counterParseCount += 1;
  const byPort = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    if (!item || typeof item !== "object") continue;
    const counter = item.counter;
    if (!counter || typeof counter !== "object") continue;
    if (counter.family !== "inet" || counter.table !== NFT_TABLE) continue;
    const m = COUNTER_NAME_RE.exec(String(counter.name || ""));
    if (!m) continue;
    const port = Number(m[1]);
    let bucket = byPort.get(port);
    if (!bucket) {
      bucket = { in: 0, out: 0, in6: 0 };
      byPort.set(port, bucket);
    }
    bucket[m[2]] = Number(counter.bytes) || 0;
  }
  return byPort;
}

async function _getCachedCounterMap() {
  const now = Date.now();
  const newCycle = now - _lastCounterReqAt > COUNTERS_CACHE_GAP_MS;
  _lastCounterReqAt = now;
  const fresh =
    !newCycle &&
    _countersCache.byPort !== null &&
    now - _countersCache.at < COUNTERS_CACHE_MAX_MS;
  if (fresh) return _countersCache.byPort;
  if (_countersInFlight) return _countersInFlight;
  _countersInFlight = (async () => {
    try {
      const byPort = parseCounterItems(await _counterItemsFetcher());
      _countersCache = { at: Date.now(), byPort };
      return byPort;
    } finally {
      _countersInFlight = null;
    }
  })();
  return _countersInFlight;
}

// Test seam (Wave PERGB-METER-CACHE).
function _resetCountersCache() {
  _countersCache = { at: 0, byPort: null };
  _countersInFlight = null;
  _lastCounterReqAt = 0;
  _counterParseCount = 0;
}
function _setCounterItemsFetcher(fn) {
  _counterItemsFetcher = typeof fn === "function" ? fn : _fetchAllCounterItems;
}
// Test seams (Wave FLEET-HEALTH SPD-05).
function _setDumpExec(fn) {
  _dumpExec = typeof fn === "function" ? fn : execCapture;
}
function _counterParses() {
  return _counterParseCount;
}

async function getCountersForPorts(ports) {
  const requested = new Set(
    (ports || [])
      .map((p) => Number(p))
      .filter((p) => Number.isInteger(p) && p > 0)
  );
  if (requested.size === 0) return {};

  const byPort = await _getCachedCounterMap();

  const out = {};
  for (const port of requested) {
    const b = byPort.get(port);
    if (!b) continue;
    // Wave PERGB-METER-FIX — _in = client->proxy upload, _out = proxy->client
    // download (BILLABLE), both family-agnostic (client-port rules). The legacy
    // v6-egress `in6` counter is retired (it captured ~0 under dual-stack); on a
    // not-yet-reaccounted node it's still parsed into b.in6 but no longer summed
    // (it was egress-IPv6 garbage), so we read b.in alone.
    out[String(port)] = {
      bytes_in: b.in,
      bytes_out: b.out,
    };
  }
  return out;
}

// ── PERGB-NFT-ENFORCE — firewall-level pay-per-GB quota block ───────────────
// disablePort/enablePort historically renamed the per-port 3proxy_<port>.cfg
// and SIGKILLed its process. On block-config nodes only the block-START port
// owns a per-port cfg; every mid-block port has none, so the old path was a
// silent no-op (PORT_NOT_FOUND -> 404): a depleted pay-per-GB account kept
// serving past quota (revenue leak) and the orchestrator looped re-enabling it
// forever. We add enforcement that works for ANY port: one
// `tcp dport @pergb_blocked drop` rule on the proxy_accounting input chain,
// toggled by set membership. Validated live (block -> egress dies instantly,
// unblock -> restored). Best-effort + idempotent; membership is persisted and
// re-applied on boot (reapplyPergbBlocks) so a reboot can't silently un-block.
const NFT_BLOCK_SET = "pergb_blocked";
const HTTP_PORT_OFFSET = 10000; // paired http port = socks port - 10000
const BLOCKED_LIST_FILE = path.join(PROXY_ROOT, "pergb_blocked.list");

function _httpFor(portNum) {
  const h = portNum - HTTP_PORT_OFFSET;
  return h > 0 ? h : null;
}

function _readBlockedList() {
  try {
    return new Set(
      fs
        .readFileSync(BLOCKED_LIST_FILE, "utf-8")
        .split(/\s+/)
        .filter((s) => /^\d+$/.test(s))
        .map(Number)
    );
  } catch {
    return new Set();
  }
}

function _writeBlockedList(set) {
  try {
    fs.writeFileSync(
      BLOCKED_LIST_FILE,
      [...set].sort((a, b) => a - b).join("\n") + "\n"
    );
  } catch (err) {
    console.error(
      `[accounting] failed to persist ${BLOCKED_LIST_FILE}: ${(err && err.message) || err}`
    );
  }
}

// Idempotently ensure our block set + the single drop rule sit on top of the
// proxy_accounting input chain (the table/chain are created by the proxy
// accounting setup; we only add our set + one rule).
// Wave PERGB-METER-CACHE — the block-drop rule + chain/set/table are static for
// a process lifetime: once present they persist until an nftables flush (reboot
// -> agent restart -> this flag resets). The old code re-listed the ENTIRE input
// chain (~38k rules at 5k ports) on EVERY _enforceBlock call just to regex-check
// the one drop rule, and a block/unblock storm turned that O(ruleset) scan into a
// continuous CPU sink. Ensure once per process, then skip the expensive
// `nft list chain`. The flag latches only once the drop rule is confirmed present
// (or freshly inserted ok), so a transient insert failure is retried next call.
// Set membership (which ports are blocked) is managed separately and NOT gated,
// so enforcement stays correct.
let _blockInfraEnsured = false;
// Overridable exec seam for the block path's nft calls (unit tests stub nft,
// which is absent in the test env).
let _nftExec = execCapture;
function _setNftExec(fn) {
  _nftExec = typeof fn === "function" ? fn : execCapture;
  _blockInfraEnsured = false;
}

async function ensurePergbBlockInfra() {
  if (_blockInfraEnsured) return;
  await _nftExec("nft", ["add", "table", "inet", NFT_TABLE]);
  await _nftExec("nft", [
    "add", "chain", "inet", NFT_TABLE, "input",
    "{", "type", "filter", "hook", "input", "priority", "filter", ";", "policy", "accept", ";", "}",
  ]);
  await _nftExec("nft", [
    "add", "set", "inet", NFT_TABLE, NFT_BLOCK_SET,
    "{", "type", "inet_service", ";", "}",
  ]);
  const cur = await _nftExec("nft", ["list", "chain", "inet", NFT_TABLE, "input"]);
  if (new RegExp("@" + NFT_BLOCK_SET + "[\\s\\S]*drop").test(cur.stdout || "")) {
    _blockInfraEnsured = true;
    return;
  }
  const ins = await _nftExec("nft", [
    "insert", "rule", "inet", NFT_TABLE, "input",
    "tcp", "dport", "@" + NFT_BLOCK_SET, "drop",
  ]);
  if (ins.code === 0) _blockInfraEnsured = true;
}

// Returns execCapture's result ({code, stdout, stderr}); never throws.
async function _nftSetElement(op, portNum) {
  return _nftExec("nft", [
    op, "element", "inet", NFT_TABLE, NFT_BLOCK_SET, "{", String(portNum), "}",
  ]);
}

// Wave FLEET-HEALTH (RES-08 hardening) — `add element` with one self-heal: the
// infra latch survives an nftables flush/restart that drops our set, so on a
// failed add re-ensure the table/set/drop rule once and retry.
async function _nftAddBlockElement(portNum) {
  const first = await _nftSetElement("add", portNum);
  if (first.code === 0) return first;
  _blockInfraEnsured = false;
  await ensurePergbBlockInfra();
  return _nftSetElement("add", portNum);
}

// Apply (blocked=true) or lift (blocked=false) the firewall block for a port +
// its paired http port. The blocked list is ALWAYS persisted (reapplyPergbBlocks
// re-asserts it on boot).
// Wave FLEET-HEALTH (RES-08 hardening) — a block that did not land THROWS
// NftablesError("nft_block_failed") after the list write: the 200 of
// POST /accounts/{port}/disable is what the orchestrator stamps
// node_blocked_at on (and never re-sends), so it must mean the drop is in the
// kernel. Unblock stays best-effort: `delete element` on a never-blocked port
// fails with ENOENT, which must not turn every enable into a 500.
async function _enforceBlock(portNum, blocked) {
  const http = _httpFor(portNum);
  const ports = http ? [portNum, http] : [portNum];
  const failures = [];
  try {
    await ensurePergbBlockInfra();
    for (const p of ports) {
      if (blocked) {
        const res = await _nftAddBlockElement(p);
        if (!res || res.code !== 0) {
          failures.push(`add ${p}: ${String((res && res.stderr) || "").trim() || `exit ${res ? res.code : "?"}`}`);
        }
      } else {
        await _nftSetElement("delete", p);
      }
    }
    if (blocked && !_blockInfraEnsured) failures.push("drop rule not confirmed");
  } catch (err) {
    failures.push(String((err && err.message) || err));
  }
  const list = _readBlockedList();
  for (const p of ports) {
    if (blocked) list.add(p);
    else list.delete(p);
  }
  _writeBlockedList(list);
  if (blocked && failures.length > 0) {
    const detail = failures.join("; ").slice(0, 500);
    console.error(`[accounting] nft block port ${portNum} failed: ${detail}`);
    throw new NftablesError("nft_block_failed", detail);
  }
}

// Re-assert every persisted block. Call on agent startup: a reboot clears the
// in-memory nft set and respawns all 3proxy from cfg, which would otherwise
// silently un-block depleted pay-per-GB accounts. Best-effort (boot must not
// fail); failed adds are counted and logged.
async function reapplyPergbBlocks() {
  const list = _readBlockedList();
  if (list.size === 0) return { reapplied: 0, failed: 0 };
  let failed = 0;
  let healed = false;
  try {
    await ensurePergbBlockInfra();
    for (const p of list) {
      // Self-heal at most once per reapply: with nft broken, thousands of
      // persisted ports must not each re-run the infra setup.
      let res = await _nftSetElement("add", p);
      if ((!res || res.code !== 0) && !healed) {
        healed = true;
        _blockInfraEnsured = false;
        await ensurePergbBlockInfra();
        res = await _nftSetElement("add", p);
      }
      if (!res || res.code !== 0) failed += 1;
    }
  } catch (err) {
    console.error(`[accounting] reapplyPergbBlocks failed: ${(err && err.message) || err}`);
  }
  if (failed > 0) {
    console.error(`[accounting] reapplyPergbBlocks: ${failed}/${list.size} block(s) did not apply`);
  }
  console.log(`[accounting] reapplied ${list.size - failed} pergb firewall block(s)`);
  return { reapplied: list.size - failed, failed };
}

// Block a pay-per-GB port: firewall-drop it (works for every port, incl.
// mid-block) THEN best-effort tear down its per-port cfg/process (block-START
// ports). A missing per-port cfg is no longer an error — the nft drop is the
// enforcement, so the account converges instead of 404-looping.
// A BATCH cfg (one 3proxy serving up to ~1500 ports) is named after its START
// port, so configPathForPort(start) finds it as if it were a per-port cfg.
function _isBatchCfg(cfgPath) {
  try {
    const text = fs.readFileSync(cfgPath, "utf-8");
    return (text.match(/^[ \t]*socks[ \t]/gm) || []).length > 1;
  } catch {
    return false;
  }
}

async function disablePort(port) {
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum <= 0) {
    throw new PortNotFoundError(port);
  }
  // Wave FLEET-HEALTH (RES-08 hardening) — a failed nft block is held until the
  // per-port cfg teardown below has run (a single-port 3proxy is still killed),
  // then thrown: the route answers 500 disable_failed instead of a 200 the
  // orchestrator would stamp node_blocked_at on and never retry.
  let nftError = null;
  try {
    await _enforceBlock(portNum, true);
  } catch (err) {
    nftError = err;
  }
  // Security audit 2026-10-02 — disabling a batch's START port used to SIGTERM
  // the whole batch (every other customer in it lost the proxy) AND demote its
  // cfg, so a reboot never brought the batch back. For a batch the nft drop is
  // the whole enforcement; the shared process and cfg are never touched.
  if (_isBatchCfg(configPathForPort(portNum))) {
    if (nftError) throw nftError;
    return { action: "blocked_nft_only", port: portNum, batch: true };
  }
  let result;
  try {
    result = await _disablePortCfg(portNum);
  } catch (err) {
    if (err && err.code === "PORT_NOT_FOUND") {
      if (nftError) throw nftError;
      return { action: "blocked_nft_only", port: portNum };
    }
    throw nftError || err;
  }
  if (nftError) throw nftError;
  return result;
}

async function _disablePortCfg(port) {
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum <= 0) {
    throw new PortNotFoundError(port);
  }
  // Bump FIRST so any in-flight force-kill from a prior disable of this port
  // (or a stale one superseded by a since-then enablePort) is invalidated.
  const gen = _bumpDisableGen(portNum);
  const cfg = configPathForPort(portNum);
  const cfgExists = fs.existsSync(cfg);
  const pids = await findRunningPids(portNum);

  if (pids.length === 0) {
    if (!cfgExists) {
      const counters = await getCountersForPorts([portNum]).catch(() => ({}));
      if (!counters[String(portNum)]) {
        throw new PortNotFoundError(portNum);
      }
      return { action: "already_disabled" };
    }
    // Audit WI-5 (H16) — no live proxy, but the cfg is still in the restore
    // glob; a reboot would revive this disabled port. Demote so restore skips it.
    _demoteCfg(cfg, portNum);
    return { action: "already_disabled", cfgDisabled: true };
  }

  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch (err) {
      if (err && err.code !== "ESRCH") {
        throw new ProcessSpawnError("kill_failed", String(err && err.message || err));
      }
    }
  }
  // Audit WI-5 (H16) — demote the cfg so a reboot's restore glob skips this
  // port, even while the async force-kill below is still draining survivors.
  if (cfgExists) {
    _demoteCfg(cfg, portNum);
  }
  // SIGTERM is graceful — 3proxy keeps an already-established connection (e.g.
  // a large download) alive, which defeats pay-per-GB quota enforcement. After
  // a short grace, force-kill any survivor. We RE-RESOLVE the pids for THIS
  // port at kill time (not the captured list) so we never SIGKILL a recycled
  // PID — pgrep on `3proxy_<port>.cfg` only matches a 3proxy still serving this
  // exact port. The generation guard aborts if an enablePort/disablePort for
  // this port ran in the meantime, so we never kill a freshly RE-ENABLED proxy
  // (rebuy / watchdog reactivation inside the grace window). Fire-and-forget +
  // unref so the disable ack returns now and the timer never keeps the agent
  // (or a test) alive on its own.
  if (DISABLE_GRACE_MS >= 0) {
    const timer = setTimeout(() => {
      if (_disableGen.get(portNum) !== gen) {
        return; // superseded by a later enable/disable — do NOT kill.
      }
      findRunningPids(portNum)
        .then((survivors) => {
          if (_disableGen.get(portNum) !== gen) {
            return; // re-check after the async pgrep hop.
          }
          let killed = 0;
          for (const pid of survivors) {
            try {
              process.kill(pid, "SIGKILL");
              killed += 1;
            } catch (_err) {
              // Already exited after the graceful SIGTERM — nothing to force.
            }
          }
          if (killed > 0) {
            console.log(
              `[accounting.disablePort] force-killed ${killed} survivor(s) on port ${portNum} after ${DISABLE_GRACE_MS}ms grace`
            );
          }
        })
        .catch((err) => {
          // A money-path enforcement primitive must NOT fail silently: the HTTP
          // ack already returned "killed", so a swallowed error here means the
          // survivor streams on with nobody the wiser. Log loudly; the next
          // poll-cycle disable retry is the backstop.
          console.error(
            `[accounting.disablePort] force-kill check failed on port ${portNum}: ${
              (err && err.message) || err
            }`
          );
        });
    }, DISABLE_GRACE_MS);
    if (typeof timer.unref === "function") timer.unref();
  }
  return { action: "killed", pids };
}

// Unblock a pay-per-GB port: lift the firewall drop THEN best-effort re-spawn
// its per-port cfg (block-START ports). A missing per-port cfg is no longer an
// error — lifting the nft drop is what restores a mid-block port.
async function enablePort(port) {
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum <= 0) {
    throw new PortNotFoundError(port);
  }
  await _enforceBlock(portNum, false);
  try {
    return await _enablePortCfg(portNum);
  } catch (err) {
    if (err && err.code === "PORT_NOT_FOUND") {
      return { action: "unblocked_nft_only", port: portNum };
    }
    throw err;
  }
}

async function _enablePortCfg(port) {
  const portNum = Number(port);
  if (!Number.isInteger(portNum) || portNum <= 0) {
    throw new PortNotFoundError(port);
  }
  // Invalidate any pending force-kill from a recent disablePort of this port:
  // re-enabling means we must NOT let a stale SIGKILL drop the proxy we're
  // about to (re)spawn. Bump before spawning so the timer's generation check
  // fails even if it fires mid-spawn.
  _bumpDisableGen(portNum);
  const cfg = configPathForPort(portNum);
  // Audit WI-5 (H16) — promote a previously-demoted cfg back to the live name
  // so spawn, the reboot restore glob, and pgrep all agree on `3proxy_<port>.cfg`.
  const disabledCfg = disabledConfigPathForPort(portNum);
  if (!fs.existsSync(cfg) && fs.existsSync(disabledCfg)) {
    fs.renameSync(disabledCfg, cfg);
  }
  if (!fs.existsSync(cfg)) {
    throw new PortNotFoundError(portNum);
  }

  const pids = await findRunningPids(portNum);
  if (pids.length > 0) {
    return { action: "already_enabled", pids };
  }

  if (!fs.existsSync(PROXY_BIN)) {
    throw new ProcessSpawnError("3proxy_binary_missing", PROXY_BIN);
  }

  let child;
  try {
    child = spawn(PROXY_BIN, [cfg], {
      detached: true,
      stdio: "ignore",
    });
  } catch (err) {
    throw new ProcessSpawnError("3proxy_spawn_failed", String(err && err.message || err));
  }
  const pid = child.pid;
  child.unref();
  return { action: "started", pid };
}

module.exports = {
  getCountersForPorts,
  disablePort,
  enablePort,
  PortNotFoundError,
  NftablesError,
  ProcessSpawnError,
  // Exposed for the generation-guard unit test (no pgrep dependency).
  _bumpDisableGen,
  _disableGen,
  DISABLE_GRACE_MS,
  // Audit WI-5 (H16) — cfg demote/promote lifecycle, exported for unit tests.
  configPathForPort,
  disabledConfigPathForPort,
  _demoteCfg,
  // PERGB-NFT-ENFORCE — firewall block lifecycle (agent-startup reapply hook +
  // exported for unit tests).
  reapplyPergbBlocks,
  ensurePergbBlockInfra,
  _enforceBlock,
  _setNftExec,
  _readBlockedList,
  _isBatchCfg,
  // Metering-cache test hooks (accounting.meter_cache.test.js).
  _resetCountersCache,
  _setCounterItemsFetcher,
  // Wave FLEET-HEALTH (SPD-05) — parse-once map + dump timeout seams.
  parseCounterItems,
  _fetchAllCounterItems,
  _setDumpExec,
  _counterParses,
  NFT_DUMP_TIMEOUT_MS,
  _writeBlockedList,
  _httpFor,
  BLOCKED_LIST_FILE,
  NFT_BLOCK_SET,
};
