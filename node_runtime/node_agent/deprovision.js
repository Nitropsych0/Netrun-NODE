"use strict";

// Wave NODE-DEPROVISION — remove a specific set of socks ports' footprint
// (3proxy listener + per-port cfg block + nft accounting rules/counters) from
// this node WITHOUT disturbing the OTHER ports that share the same batch cfg.
//
// Why this exists: proxies are generated in BATCHES — one `3proxy_<startPort>.cfg`
// = one 3proxy process serving a contiguous-ish range of ~200-500 socks ports.
// A cfg mixes `available` + `invalid` + customer (`sold`/`allocated_pergb`)
// ports. There was no way to drop the dead/surplus ones; the node footprint
// (listeners + ~6 nft objects/port) only ever grew, eventually overloading the
// 2-core nodes (load 30 with ~2 connections — pure nft input-chain traversal).
//
// Safety model: the ORCHESTRATOR decides WHICH ports are safe to remove (it owns
// the DB: never sends a sold/allocated_pergb/reserved/committed port). This module
// is a dumb, idempotent executor: given a flat port list, it groups them by the
// cfg that actually contains them, and per affected cfg either
//   - drops the WHOLE cfg (all its ports are in the remove list) → kill + unlink, no respawn, or
//   - REWRITES the cfg keeping the surviving blocks → kill + respawn (the kept
//     ports, incl. customers, take a brief reconnect blip of ~grace duration).
// Then it removes each removed port's nft rules (by handle, via the per-rule
// `comment "proxy_<port>_<kind>"`) + named counters, and persists the ruleset.
//
// cfg per-port block (exact format, verified on prod):
//   flush
//   users <login>:CL:<password>
//   <blank>
//   allow * *
//   deny *
//   socks -6 -a -p<PORT>  -i<bcip> -e<ipv6>
//   proxy -6 -n -a -p<PORT-10000> -i<bcip> -e<ipv6>
// The leading header (daemon/nserver/auth/global users) precedes the first `flush`.
//
// Pay-per-GB v2 (lane L9):
//   - option A shield (pergb_shield.js): a per-GB shared port is never
//     deprovisioned — dropped from the request (reported in skipped_shared);
//     a request of shared ports only is refused (409 pergb_shared_port);
//   - AMENDMENT A1 (pergb_pool.js): on a per-GB node a dropped batch hands its
//     pool /64s back to RADIUS (release_nets, 24 h cool-down) — every /64 its
//     cfg and its address list named, minus any /64 something per-piece still
//     names (a fresh, complete scan). A rewritten (mixed) batch keeps its list,
//     so its removed ports' /64s stay reserved until the batch itself goes.

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const egress = require("./egress.js");
const proxySpawn = require("./proxy_spawn.js");
const { withProcessLock } = require("./process_lock.js");
const pergbShield = require("./pergb_shield.js");
const pergbPool = require("./pergb_pool.js");

const PROXY_ROOT = path.normalize(process.env.NODE_AGENT_PROXY_ROOT || "/opt/netrun/proxyserver");
const PROXY_CFG_DIR = path.join(PROXY_ROOT, "3proxy");
const PROXY_BIN = path.join(PROXY_ROOT, "3proxy", "bin", "3proxy");
const NFT_TABLE = "proxy_accounting";
const NFTABLES_PERSIST = process.env.NODE_AGENT_NFT_PERSIST || "/etc/nftables.conf";
// Audit 2026-10-08 — the ruleset reaches the file only through
// netrun-nft-persist (atomic temp + rename under the lock every writer shares,
// .prev kept): the installed copy, else the repo's.
const NFT_PERSIST_HELPERS = [
  process.env.NODE_AGENT_NFT_PERSIST_BIN,
  "/usr/local/sbin/netrun-nft-persist",
  path.join(__dirname, "..", "..", "scripts", "netrun-nft-persist.sh"),
];
// HTTPS frontend reconciler (scripts/netrun-https.sh, installed by followup).
const HTTPS_SYNC_BIN = process.env.NODE_AGENT_HTTPS_SYNC_BIN || "/usr/local/sbin/netrun-https";
const HTTP_PORT_OFFSET = 10000; // paired http port = socks port - 10000
// SIGTERM grace before SIGKILL when tearing down a batch process. Kept SHORT:
// the removed ports are surplus/dead (no customer session to drain) and a mixed
// cfg's kept customer ports reconnect to the respawn either way — a long grace
// only multiplies across every affected cfg (a 250-port spread can touch dozens
// of cfgs), which is what timed out the first prod run at 1500ms × N.
const KILL_GRACE_MS = Number(process.env.NODE_AGENT_DEPROV_GRACE_MS || 300);
// After SIGKILL: how long to wait for the process to be gone (polled every 50 ms).
const KILL_WAIT_MS = Number(process.env.NODE_AGENT_DEPROV_KILL_WAIT_MS || 5000);
const CFG_NAME_RE = /^3proxy_(\d+)\.cfg$/;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Self-contained exec helper (mirrors accounting.js; intentionally NOT shared so
// this never perturbs the money-path module). Never throws — returns {code,stdout,stderr}.
function execCapture(cmd, args, { timeoutMs = 8000, env = undefined } = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let child;
    try {
      child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...(env ? { env } : {}) });
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

function safeUnlink(p) {
  try { fs.unlinkSync(p); return true; }
  catch (err) { if (err && err.code === "ENOENT") return false; throw err; }
}

// Parse a 3proxy batch cfg into { header, blocks }.
//   header = every line before the first `flush` (daemon/nserver/global auth/users).
//   blocks = one per port, each starting at a `flush` line through (excluding) the
//            next `flush`; carries its socksPort / httpPort / egress ipv6.
// A block with no socks port (malformed/trailer) keeps socksPort=null and is
// always PRESERVED (we only ever drop blocks we positively identified as targets).
function parseCfg(text) {
  const lines = text.split(/\r?\n/);
  const firstFlush = lines.findIndex((l) => l.trim() === "flush");
  if (firstFlush === -1) return { header: lines, blocks: [] };
  const header = lines.slice(0, firstFlush);
  const blocks = [];
  let cur = null;
  for (let i = firstFlush; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() === "flush") {
      if (cur) blocks.push(cur);
      cur = { lines: [l], socksPort: null, httpPort: null, ipv6: null };
      continue;
    }
    if (!cur) continue; // defensive (shouldn't happen: header ends at firstFlush)
    cur.lines.push(l);
    if (/^socks\b/.test(l)) {
      const pm = /-p(\d+)\b/.exec(l);
      const em = /-e(\S+)/.exec(l);
      if (pm) cur.socksPort = Number(pm[1]);
      if (em) cur.ipv6 = em[1];
    } else if (/^proxy\b/.test(l)) {
      const pm = /-p(\d+)\b/.exec(l);
      if (pm) cur.httpPort = Number(pm[1]);
    }
  }
  if (cur) blocks.push(cur);
  return { header, blocks };
}

// Pure planner (no fs/exec — unit-testable). Given a cfg's text and the set of
// socks ports to remove, returns which blocks stay vs go and the rewritten cfg
// body (header + surviving blocks). A block is removed ONLY if its socks port is
// positively in removeSet — header and any unparseable block are always kept, so
// a parse miss can never silently drop a customer port.
function planRewrite(text, removeSet) {
  const { header, blocks } = parseCfg(text);
  const removeBlocks = [];
  const keepBlocks = [];
  for (const b of blocks) {
    if (b.socksPort != null && removeSet.has(b.socksPort)) removeBlocks.push(b);
    else keepBlocks.push(b);
  }
  const wholeBatch = blocks.length > 0 && keepBlocks.length === 0;
  let newText = null;
  if (removeBlocks.length > 0 && !wholeBatch) {
    const kept = [...header];
    for (const b of keepBlocks) for (const l of b.lines) kept.push(l);
    newText = kept.join("\n");
    if (!newText.endsWith("\n")) newText += "\n";
  }
  return { header, blocks, keepBlocks, removeBlocks, wholeBatch, newText };
}

async function findCfgPids(startPort) {
  // pgrep on the cfg basename — matches the running 3proxy regardless of the
  // /root vs /opt path prefix (both are the same inode via symlink).
  const res = await execCapture("pgrep", ["-f", `3proxy_${startPort}\\.cfg`]);
  if (res.code === 0) {
    return res.stdout.split(/\s+/).map((s) => s.trim()).filter((s) => /^\d+$/.test(s)).map(Number);
  }
  return []; // code 1 = none; anything else: treat as none (best-effort teardown)
}

// SIGTERM → grace → SIGKILL survivors. Returns only once the process is gone, so
// a rewrite can respawn without two daemons fighting over the same ports.
async function killCfgProcess(startPort) {
  const pids = await findCfgPids(startPort);
  if (pids.length === 0) return { killed: 0 };
  for (const pid of pids) { try { process.kill(pid, "SIGTERM"); } catch {} }
  await sleep(KILL_GRACE_MS);
  let survivors = await findCfgPids(startPort);
  for (const pid of survivors) { try { process.kill(pid, "SIGKILL"); } catch {} }
  const forceKilled = survivors.length;
  // Audit N2 review (correctness#1) — a SIGKILLed 3proxy (thousands of
  // threads) can take a moment to go: wait, bounded, until pgrep no longer sees
  // it, so the spawn helper's idempotency check never takes the dying process
  // for the running batch and skips the respawn.
  const deadline = Date.now() + KILL_WAIT_MS;
  while (survivors.length && Date.now() < deadline) {
    await sleep(50);
    survivors = await findCfgPids(startPort);
  }
  return { killed: pids.length, forceKilled, stillAlive: survivors.length };
}

// Audit RES-11 — through the node's spawn helper (own systemd scope; the
// direct detached start where the helper is absent).
// After a kill, "already-running" / "already-listening" means the helper saw
// the old process, not a new one: a failure, never an ok.
async function spawnCfg(cfgPath, { afterKill = false } = {}) {
  const res = await proxySpawn.spawn3proxyCfg(cfgPath, { bin: PROXY_BIN });
  if (!res.ok) throw new Error(`respawn_failed:${res.detail || res.outcome}`);
  if (afterKill && /^already/.test(String(res.outcome || ""))) throw new Error(`respawn_failed:${res.outcome}_after_kill`);
  return res.pid;
}

// Remove the nft footprint of the given SOCKS ports. Accounting is MAP-based
// (Wave PERGB-NFT-MAP): the input/output chains run `counter name tcp dport map
// @cmap_in|@cmap_out`, so each port is a MAP ELEMENT `<key> : "proxy_<port>_<kind>"`
// pointing at a named counter — there is NO per-port rule. We dump the two
// counter maps, pick the elements whose counter name carries a target socks port,
// delete those elements (by key), then delete the now-unreferenced named counters.
// Element-before-counter ordering matters (a counter referenced by a live map
// element can't be dropped). One batched `nft -f`; per-statement best-effort
// fallback if the atomic apply aborts on a stale element from a concurrent change.
const COUNTER_MAPS = ["cmap_in", "cmap_out"];

async function nftCleanup(ports) {
  const want = new Set(ports.map(Number).filter((p) => Number.isInteger(p) && p > 0));
  if (want.size === 0) return { elements: 0, counters: 0 };

  const elementDeletes = []; // { map, key }
  const counterNames = new Set();

  for (const mapName of COUNTER_MAPS) {
    const dump = await execCapture("nft", ["list", "map", "inet", NFT_TABLE, mapName], { timeoutMs: 30000 });
    if (dump.code !== 0) continue;
    // elements look like: `<key> : "proxy_<socksPort>_<kind>"` (many per line)
    for (const m of (dump.stdout || "").matchAll(/(\d+)\s*:\s*"proxy_(\d+)_(in6|in|out)"/g)) {
      const port = Number(m[2]);
      if (want.has(port)) {
        elementDeletes.push({ map: mapName, key: m[1] });
        counterNames.add(`proxy_${port}_${m[3]}`);
      }
    }
  }
  // Target the named counters directly too — covers a legacy in6 counter or one
  // whose map element a prior partial run already removed.
  for (const p of want) for (const k of ["in", "out", "in6"]) counterNames.add(`proxy_${p}_${k}`);

  if (elementDeletes.length === 0 && counterNames.size === 0) return { elements: 0, counters: 0 };

  // Use `destroy` (nft >= 1.0.0), the idempotent form of `delete`: a missing
  // object is a no-op instead of aborting the whole `nft -f` transaction. That
  // keeps the apply ONE fast atomic batch even when a prior partial run already
  // removed some of these elements/counters (the slow per-statement fallback that
  // dragged the first prod retry to ~48s is gone). Elements are destroyed before
  // counters so a counter is unreferenced by the time we drop it.
  const lines = [];
  for (const e of elementDeletes) lines.push(`destroy element inet ${NFT_TABLE} ${e.map} { ${e.key} }`);
  for (const name of counterNames) lines.push(`destroy counter inet ${NFT_TABLE} ${name}`);

  const batchPath = path.join(PROXY_ROOT, `.deprov_nft_${process.pid}.batch`);
  fs.writeFileSync(batchPath, lines.join("\n") + "\n");
  const applied = await execCapture("nft", ["-f", batchPath], { timeoutMs: 60000 });
  safeUnlink(batchPath);
  return {
    elements: elementDeletes.length,
    counters: counterNames.size,
    ok: applied.code === 0,
    error: applied.code === 0 ? undefined : (applied.stderr || "").slice(0, 200),
  };
}

// Main entry. ports = flat list of SOCKS ports to remove (the orchestrator has
// already excluded every customer-held port). Idempotent: a port not found in any
// cfg is reported under skipped (already gone), not an error.
async function deprovisionPorts(rawPorts, { shield = pergbShield.defaultShield(), pool = pergbPool.defaultAccess(), log = console } = {}) {
  const askedSet = new Set((rawPorts || []).map(Number).filter((p) => Number.isInteger(p) && p > 0));
  const result = { ok: true, requested: askedSet.size, removed_ports: [], skipped_ports: [], cfgs: [] };
  if (askedSet.size === 0) return result;

  // Pay-per-GB v2 (option A) — the per-GB shared ports are never touched.
  let shared = new Set();
  try {
    shared = await shield.sharedPorts();
  } catch (err) {
    log.error(`[deprovision] per-GB shield unavailable: ${(err && err.message) || err}`);
  }
  const sharedAsked = [...askedSet].filter((p) => shared.has(p)).sort((a, b) => a - b);
  if (sharedAsked.length) {
    result.skipped_shared = sharedAsked;
    if (sharedAsked.length === askedSet.size) {
      return { ...result, ok: false, httpStatus: 409, error: "pergb_shared_port", detail: "every requested port is a per-GB shared port" };
    }
  }
  const removeSet = new Set([...askedSet].filter((p) => !shared.has(p)));
  // AMENDMENT A1 — /64s of dropped batches, handed back to the per-GB pool
  // below (only on a per-GB node: elsewhere the response is as before).
  const pergbCandidates = new Set();
  const pergbOn = pergbPool.poolPresent(pool);

  let files;
  try {
    files = fs.readdirSync(PROXY_CFG_DIR).filter((f) => CFG_NAME_RE.test(f));
  } catch (err) {
    return { ok: false, error: "cfg_dir_unreadable", detail: String((err && err.message) || err) };
  }

  const remaining = new Set(removeSet);

  for (const file of files) {
    if (remaining.size === 0) break;
    const cfgPath = path.join(PROXY_CFG_DIR, file);
    let text;
    try { text = fs.readFileSync(cfgPath, "utf-8"); } catch { continue; }

    const plan = planRewrite(text, removeSet);
    const { removeBlocks, keepBlocks, wholeBatch } = plan;
    if (removeBlocks.length === 0) continue; // cfg untouched

    const startPort = Number(CFG_NAME_RE.exec(file)[1]);
    const rec = {
      cfg: file, startPort, removed: removeBlocks.length, kept: keepBlocks.length,
      mode: wholeBatch ? "drop" : "rewrite", ok: false,
    };

    try {
      // Audit RES-11 — kill + unlink / kill + respawn as ONE step of the shared
      // process lock: the supervisor must never see this batch "dead" between
      // the kill and the unlink (and start it again with no cfg left).
      await withProcessLock(async () => {
        if (wholeBatch) {
          await killCfgProcess(startPort);
          // read before the unlinks: every /64 the batch held
          if (pergbOn) {
            for (const k of pergbPool.collectFileNets([cfgPath, cfgPath + ".disabled", path.join(PROXY_ROOT, `ipv6_${startPort}.list`)])) {
              pergbCandidates.add(k);
            }
          }
          safeUnlink(cfgPath);
          safeUnlink(cfgPath + ".disabled");
          // Drop ALL of the generator's per-start-port state for this instance,
          // not just the cfg. The generator keys these files by instance_id =
          // start_port (proxyyy_automated.sh): a stale/partial ipv6_<port>.list
          // (or users list) left behind makes the NEXT generate at this start_port
          // REUSE it and emit an inconsistent batch — proxies.list has N entries
          // but the cfg/map only 1 port, so the node-agent hangs forever waiting
          // for N listeners to come up (observed on the 2026-06-30 recovery node).
          safeUnlink(path.join(PROXY_ROOT, `proxy-startup_${startPort}.sh`));
          safeUnlink(path.join(PROXY_ROOT, `ipv6_${startPort}.list`));
          safeUnlink(path.join(PROXY_ROOT, `random_users_${startPort}.list`));
          safeUnlink(path.join(PROXY_ROOT, `running_server_${startPort}.info`));
        } else {
          // Rewrite atomically: header + surviving blocks → temp → fsync rename.
          const body = plan.newText;
          // Sanity: the rewrite MUST still contain every kept socks port (guards a
          // parse bug from silently dropping a customer port).
          const stillHas = new Set();
          for (const m of body.matchAll(/^socks\b.*?-p(\d+)\b/gm)) stillHas.add(Number(m[1]));
          for (const b of keepBlocks) {
            if (b.socksPort != null && !stillHas.has(b.socksPort)) {
              throw new Error(`rewrite_sanity_failed_missing_${b.socksPort}`);
            }
          }
          const tmp = cfgPath + ".deprov.tmp";
          // Audit 2026-10-08 — a cfg holds customer logins / passwords: 0600.
          fs.writeFileSync(tmp, body, { mode: 0o600 });
          fs.chmodSync(tmp, 0o600);
          fs.renameSync(tmp, cfgPath);
          const kill = await killCfgProcess(startPort);
          if (kill.stillAlive) throw new Error("respawn_failed:old_process_still_running");
          rec.respawnPid = await spawnCfg(cfgPath, { afterKill: kill.killed > 0 });
        }
      });
      for (const b of removeBlocks) {
        remaining.delete(b.socksPort);
        result.removed_ports.push(b.socksPort);
      }
      rec.ok = true;
    } catch (err) {
      rec.ok = false;
      rec.error = String((err && err.message) || err);
      result.ok = false;
    }
    result.cfgs.push(rec);
  }

  for (const p of remaining) result.skipped_ports.push(p);

  // nft cleanup over the FULL requested set (not just what we removed from a cfg
  // this run): a port whose listener a PRIOR partial run already dropped is now
  // 'skipped' here, but its nft rules/counters may still be orphaned — clean them
  // too. Idempotent (best-effort handle/counter deletes). Then persist so a reboot
  // can't restore the removed footprint.
  const allRequested = [...removeSet];
  if (allRequested.length > 0) {
    result.nft = await nftCleanup(allRequested);
    // Wave IPV6-ROTATION — a removed port must not keep a rotated egress or a
    // per-connection mode: the next generate on it is someone else's proxy.
    // Before the dump below, so the saved ruleset no longer maps it. Never
    // fails the deprovision (a restart drops ports without a cfg anyway).
    try {
      result.egress = await egress.forgetPorts(allRequested);
    } catch (err) {
      result.egress = { ok: false, error: String((err && err.message) || err) };
    }
    result.persist = await persistRuleset();
  }
  // AMENDMENT A1 — after egress.forgetPorts (the egress state no longer
  // names the removed ports' anchors). Never fails the deprovision: a /64
  // that is not handed back stays reserved, i.e. out of per-GB's reach.
  if (pergbCandidates.size) {
    const dropped = result.cfgs.filter((c) => c.ok && c.mode === "drop").map((c) => c.startPort);
    result.pergb_release = await pergbPool.releaseUnusedNets(pergbCandidates, {
      access: pool,
      proxyRoot: PROXY_ROOT,
      ref: pergbPool.newRef("deprovision", dropped[0] || ""),
      log,
    });
  }
  // HTTPS frontend: haproxy still binds the removed HTTP ports until its
  // frontends are rewritten — release them now, so a later generate that reuses
  // this port range can bind. Best-effort (the 5-min sync timer is the backstop).
  if (result.cfgs.some((c) => c.ok) && fs.existsSync(HTTPS_SYNC_BIN)) {
    // The script's own lock wait stays under the timeout: a SIGKILLed bash
    // leaves its `flock -w` child holding our pipes until that wait ends.
    const sync = await execCapture(HTTPS_SYNC_BIN, ["sync"], {
      timeoutMs: 120000,
      env: { ...process.env, NETRUN_HTTPS_LOCK_WAIT_SEC: "90" },
    });
    result.https_sync = { code: sync.code };
  }
  return result;
}

// Save the live ruleset for a reboot. Never throws; { ok, code, detail }.
async function persistRuleset({ helpers = NFT_PERSIST_HELPERS, target = NFTABLES_PERSIST, exec = execCapture } = {}) {
  const helper = helpers.find((p) => p && fs.existsSync(p));
  const res = helper
    ? await exec("bash", [helper, "save"], { timeoutMs: 180000, env: { ...process.env, NETRUN_NFT_CONF: target } })
    : await exec(
        "bash",
        [
          "-c",
          't="$(mktemp "$(dirname "$1")/.nftables.conf.XXXXXX")" || exit 1; ' +
            'if nft list ruleset > "$t" && [ -s "$t" ]; then mv -f "$t" "$1"; else rm -f "$t"; exit 1; fi',
          "_",
          target,
        ],
        { timeoutMs: 60000 }
      );
  return { ok: res.code === 0, code: res.code, detail: res.code === 0 ? null : String(res.stderr || "").trim().slice(0, 300) };
}

module.exports = {
  deprovisionPorts,
  persistRuleset,
  // exported for unit tests
  parseCfg,
  planRewrite,
  nftCleanup,
  killCfgProcess,
  PROXY_CFG_DIR,
  NFT_TABLE,
};
