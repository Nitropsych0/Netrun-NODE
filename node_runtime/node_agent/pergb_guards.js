"use strict";

// Pay-per-GB v2 — node guards (plan D12, §3.4), every 2 s:
//
// - admission, from the per-GB slice's cgroup (memory.current against
//   memory.high — the throttle point, 85 % of MemoryMax — else memory.max,
//   and pids.current against pids.max): soft close at 90 % (new connections
//   refused for accounts holding > 20 % of the live per-GB sessions), hard
//   close at 100 % (refused for everyone), back to soft below 90 % and open
//   below 80 %;
// - the per-GB log filesystem below 10 % free, or the meter more than 30 s
//   behind → admission closed (3proxy drops log lines it cannot write: an
//   unmetered connection must never be let in);
// - IPv4 local ports on the egress IPv4(s): distinct local ports of every
//   TCP socket (all states, TIME_WAIT included) inside ip_local_port_range;
//   RADIUS refuses new IPv4-destination connections at ≥ 60 % and takes them
//   again at ≤ 50 %;
// - the RADIUS probe every 5 s (an Access-Request for netrun-svcprobe
//   towards a canary destination); on 2 failures in a row:
//   `systemctl reset-failed netrun-radius.socket netrun-radius.service` and
//   `systemctl restart netrun-radius.socket` (at most once per 30 s), and
//   radius.alive=false;
// - the clock (timedatectl NTPSynchronized), every 60 s.
// Admission is pushed to RADIUS every tick (it is in memory only there: a
// RADIUS restart opens it until the next push).

const fs = require("fs");
const path = require("path");

const SOFT_PCT = 90;
const HARD_PCT = 100;
const REOPEN_PCT = 80;
const SOFT_SHARE = 0.2;
const IPV4_CLOSE_PCT = 60;
const IPV4_REOPEN_PCT = 50;
const LOGFS_MIN_FREE_PCT = 10;
const METER_MAX_LAG_SEC = 30;
const PROBE_FAILURES = 2;
const RECOVER_EVERY_MS = 30000;

// memory level with hysteresis: "open" | "soft" | "hard"
function nextLevel(prev, pct) {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return prev || "open";
  if (pct >= HARD_PCT) return "hard";
  if (prev === "hard") return pct >= SOFT_PCT ? "hard" : pct >= REOPEN_PCT ? "soft" : "open";
  if (prev === "soft") return pct >= REOPEN_PCT ? "soft" : "open";
  return pct >= SOFT_PCT ? "soft" : "open";
}

function nextIpv4Open(prevOpen, pct) {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return prevOpen;
  if (prevOpen) return pct < IPV4_CLOSE_PCT;
  return pct <= IPV4_REOPEN_PCT;
}

// "1024\t8000" -> [1024, 8000]
function parsePortRange(text) {
  const m = /^\s*(\d+)\s+(\d+)\s*$/.exec(String(text || ""));
  if (!m) return null;
  const lo = Number(m[1]);
  const hi = Number(m[2]);
  return lo >= 1 && hi >= lo && hi <= 65535 ? [lo, hi] : null;
}

// `ss -Htan src <ip> ...` text -> distinct local ports of <ip> in [lo, hi]
function countLocalPorts(text, ip, lo, hi) {
  const ports = new Set();
  for (const raw of String(text || "").split("\n")) {
    const toks = raw.trim().split(/\s+/);
    for (const tok of toks) {
      const m = /^\[?([0-9.]+)(?:%[^\]:]*)?\]?:(\d+)$/.exec(tok);
      if (!m) continue;
      if (m[1] === ip) {
        const p = Number(m[2]);
        if (p >= lo && p <= hi) ports.add(p);
      }
      break; // the first endpoint is the local one
    }
  }
  return ports.size;
}

function readNumber(text) {
  const s = String(text || "").trim();
  if (s === "max" || s === "") return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

// deps: { ctl, run, now, log, readFile(path) -> text, statfs(path) -> {bavail,
// bsize, blocks}, settings: { cgroupRoot, sliceCgroup, logDir, portRangeFile },
// enable() -> enable.json | null, egressIpv4s() -> [ip], meterLagSec() ->
// number, liveSessions() -> Promise<Map accountId -> n>, probe() ->
// Promise<{ok, verdict, ms}> | null (not configured), radiusStatus() ->
// Promise<object> }
function createGuards(deps) {
  const now = deps.now || Date.now;
  const log = deps.log || console;
  const readFile = deps.readFile || ((p) => fs.readFileSync(p, "utf-8"));
  const settings = {
    cgroupRoot: "/sys/fs/cgroup",
    sliceCgroup: "/netrun.slice/netrun-pergb.slice",
    logDir: "/var/log/netrun-pergb",
    portRangeFile: "/proc/sys/net/ipv4/ip_local_port_range",
    ...(deps.settings || {}),
  };
  const st = {
    level: "open",
    memPct: null,
    pidsPct: null,
    budgetPct: null,
    memory: null,
    pids: null,
    logFsFreePct: null,
    meterLagSec: null,
    diskClosed: false,
    lagClosed: false,
    admissionOpen: true,
    softAccounts: [],
    ipv4Open: true,
    ipv4PortsPct: null,
    ipv4AddrOpen: new Map(), // ip -> open (hysteresis per egress IPv4, A7)
    ipv4: [],
    radiusAlive: null,
    probe: { last: null, failures: 0, ok: 0, fail: 0, lastOkAt: null, recoveries: 0, lastRecoverAt: null },
    clockSynced: null,
    clockCheckedAt: 0,
    pushed: { admission: null, ipv4: null, error: null, at: null },
    lastTickAt: null,
  };

  function readCg(name) {
    try {
      return readFile(path.join(settings.cgroupRoot, settings.sliceCgroup, name));
    } catch {
      return null;
    }
  }

  function memoryPct() {
    const cur = readNumber(readCg("memory.current"));
    let limit = readNumber(readCg("memory.high"));
    if (limit === null) limit = readNumber(readCg("memory.max"));
    if (limit === null) {
      const e = deps.enable ? deps.enable() : null;
      if (e && Number(e.sliceMemMax) > 0) limit = Math.floor(Number(e.sliceMemMax) * 0.85);
    }
    st.memory = { current: cur, budget: limit };
    return cur !== null && limit ? (cur / limit) * 100 : null;
  }

  function pidsPct() {
    const cur = readNumber(readCg("pids.current"));
    const max = readNumber(readCg("pids.max"));
    st.pids = { current: cur, max };
    return cur !== null && max ? (cur / max) * 100 : null;
  }

  function logFsFreePct() {
    try {
      const s = (deps.statfs || fs.statfsSync)(settings.logDir);
      return s.blocks > 0 ? (s.bavail / s.blocks) * 100 : null;
    } catch {
      return null;
    }
  }

  async function ipv4PortsPct() {
    const ips = deps.egressIpv4s ? deps.egressIpv4s() : [];
    let range = null;
    try {
      range = parsePortRange(readFile(settings.portRangeFile));
    } catch {}
    if (!range || !ips.length) {
      st.ipv4 = [];
      return null;
    }
    const [lo, hi] = range;
    const size = hi - lo + 1;
    const per = [];
    for (const ip of ips) {
      const r = await deps.run("ss", ["-Htan", "src", ip, "and", "sport", "ge", `:${lo}`, "and", "sport", "le", `:${hi}`], { timeoutMs: 15000 });
      if (r.code !== 0) {
        per.push({ ip, ports: null, pct: null, error: String(r.stderr || "").trim().slice(0, 120) });
        continue;
      }
      const n = countLocalPorts(r.stdout, ip, lo, hi);
      per.push({ ip, ports: n, pct: Math.round((n / size) * 1000) / 10 });
    }
    for (const p of per) {
      const prev = st.ipv4AddrOpen.has(p.ip) ? st.ipv4AddrOpen.get(p.ip) : true;
      st.ipv4AddrOpen.set(p.ip, nextIpv4Open(prev, p.pct));
    }
    for (const ip of [...st.ipv4AddrOpen.keys()]) if (!ips.includes(ip)) st.ipv4AddrOpen.delete(ip);
    st.ipv4 = per.map((p) => ({ ...p, range: [lo, hi], open: st.ipv4AddrOpen.get(p.ip) }));
    const pcts = per.map((p) => p.pct).filter((v) => v !== null);
    return pcts.length ? Math.max(...pcts) : null;
  }

  async function softAccountsNow() {
    if (!deps.liveSessions) return [];
    let counts;
    try {
      counts = await deps.liveSessions();
    } catch {
      return [];
    }
    let total = 0;
    for (const n of counts.values()) total += n;
    if (!total) return [];
    const out = [];
    for (const [id, n] of counts) if (n / total > SOFT_SHARE) out.push(Number(id));
    return out.sort((a, b) => a - b);
  }

  async function clock() {
    if (now() - st.clockCheckedAt < 60000) return;
    st.clockCheckedAt = now();
    const r = await deps.run("timedatectl", ["show", "-p", "NTPSynchronized", "--value"], { timeoutMs: 5000 });
    const v = String((r && r.stdout) || "").trim().toLowerCase();
    st.clockSynced = r && r.code === 0 ? v === "yes" : null;
  }

  async function tick() {
    st.lastTickAt = now();
    st.memPct = memoryPct();
    st.pidsPct = pidsPct();
    const parts = [st.memPct, st.pidsPct].filter((v) => v !== null);
    st.budgetPct = parts.length ? Math.max(...parts) : null;
    const prevLevel = st.level;
    st.level = nextLevel(st.level, st.budgetPct);
    if (st.level !== prevLevel) log.log(`[pergb-guards] admission level ${prevLevel} -> ${st.level} (budget ${st.budgetPct === null ? "?" : st.budgetPct.toFixed(1)} %)`);
    st.logFsFreePct = logFsFreePct();
    st.diskClosed = st.logFsFreePct !== null && st.logFsFreePct < LOGFS_MIN_FREE_PCT;
    st.meterLagSec = deps.meterLagSec ? deps.meterLagSec() : null;
    st.lagClosed = st.meterLagSec !== null && st.meterLagSec > METER_MAX_LAG_SEC;
    st.admissionOpen = !(st.level === "hard" || st.diskClosed || st.lagClosed);
    st.softAccounts = st.admissionOpen && st.level === "soft" ? await softAccountsNow() : [];
    try {
      st.ipv4PortsPct = await ipv4PortsPct();
    } catch (e) {
      st.ipv4PortsPct = null;
    }
    const wasOpen = st.ipv4Open;
    // open while any egress IPv4 has ports left; RADIUS gets the per-address
    // verdicts too (addrs) to pick only among the open ones (A7)
    st.ipv4Open = st.ipv4AddrOpen.size ? [...st.ipv4AddrOpen.values()].some(Boolean) : nextIpv4Open(st.ipv4Open, st.ipv4PortsPct);
    if (wasOpen !== st.ipv4Open) log.log(`[pergb-guards] IPv4 admission ${st.ipv4Open ? "reopened" : "closed"} (${st.ipv4PortsPct} % of local ports)`);
    try {
      await clock();
    } catch {}
    // push (both are in memory only in RADIUS: every tick)
    try {
      await deps.ctl.call("admission", { open: st.admissionOpen, softAccounts: st.softAccounts });
      await deps.ctl.call("ipv4_admission", { open: st.ipv4Open, addrs: Object.fromEntries(st.ipv4AddrOpen) });
      st.pushed = { admission: st.admissionOpen, ipv4: st.ipv4Open, error: null, at: new Date(now()).toISOString() };
    } catch (e) {
      st.pushed = { ...st.pushed, error: e.code || e.message };
    }
    return status();
  }

  async function recover(reason) {
    if (st.probe.lastRecoverAt && now() - st.probe.lastRecoverAt < RECOVER_EVERY_MS) return false;
    st.probe.lastRecoverAt = now();
    st.probe.recoveries += 1;
    log.error(`[pergb-guards] RADIUS probe failed ${st.probe.failures}x (${reason}): reset-failed + restart netrun-radius.socket`);
    await deps.run("systemctl", ["reset-failed", "netrun-radius.socket", "netrun-radius.service"], { timeoutMs: 30000 });
    await deps.run("systemctl", ["restart", "netrun-radius.socket"], { timeoutMs: 60000 });
    return true;
  }

  async function probeTick() {
    let r = null;
    try {
      r = deps.probe ? await deps.probe() : null;
    } catch (e) {
      r = { ok: false, verdict: "error", error: e.message };
    }
    if (r === null) {
      // no probe configured (no canary / password yet): ctl liveness only
      try {
        await deps.ctl.call("status", {});
        st.radiusAlive = true;
      } catch {
        st.radiusAlive = false;
      }
      st.probe.last = { verdict: "not_configured", at: new Date(now()).toISOString() };
      return st.radiusAlive;
    }
    st.probe.last = { ...r, at: new Date(now()).toISOString() };
    if (r.ok) {
      st.probe.ok += 1;
      st.probe.failures = 0;
      st.probe.lastOkAt = new Date(now()).toISOString();
      st.radiusAlive = true;
      return true;
    }
    st.probe.fail += 1;
    st.probe.failures += 1;
    if (st.probe.failures >= PROBE_FAILURES) {
      st.radiusAlive = false;
      await recover(r.verdict);
    }
    return false;
  }

  function status() {
    return {
      memPct: st.memPct === null ? null : Math.round(st.memPct * 10) / 10,
      pidsPct: st.pidsPct === null ? null : Math.round(st.pidsPct * 10) / 10,
      budgetPct: st.budgetPct === null ? null : Math.round(st.budgetPct * 10) / 10,
      level: st.level,
      memory: st.memory,
      pids: st.pids,
      ipv4PortsPct: st.ipv4PortsPct,
      ipv4: st.ipv4,
      ipv4AdmissionOpen: st.ipv4Open,
      logFsFreePct: st.logFsFreePct === null ? null : Math.round(st.logFsFreePct * 10) / 10,
      meterLagSec: st.meterLagSec,
      admissionOpen: st.admissionOpen,
      softAccounts: st.softAccounts,
      closedBy: [st.level === "hard" ? "memory" : null, st.diskClosed ? "log_fs" : null, st.lagClosed ? "meter_lag" : null].filter(Boolean),
      clockSynced: st.clockSynced,
      radiusAlive: st.radiusAlive,
      probe: { ...st.probe },
      pushed: st.pushed,
      lastTickAt: st.lastTickAt ? new Date(st.lastTickAt).toISOString() : null,
    };
  }

  return { tick, probeTick, status, recover, _state: st };
}

module.exports = {
  SOFT_PCT,
  HARD_PCT,
  REOPEN_PCT,
  IPV4_CLOSE_PCT,
  IPV4_REOPEN_PCT,
  LOGFS_MIN_FREE_PCT,
  METER_MAX_LAG_SEC,
  nextLevel,
  nextIpv4Open,
  parsePortRange,
  countLocalPorts,
  createGuards,
};
