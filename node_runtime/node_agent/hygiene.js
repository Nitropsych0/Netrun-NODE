"use strict";

// Incident 2026-10-07 (Chicago, 2 vCPU / 4 GB, ~10 batch cfgs x 1500 dual
// proxies) — after a reboot every batch ran TWICE: once from
// netrun-3proxy-restore.service
//   /opt/netrun/proxyserver/3proxy/bin/3proxy /opt/netrun/proxyserver/3proxy/3proxy_<sp>.cfg
// and once from a leftover generator crontab line
//   @reboot bash /root/proxyserver/proxy-startup_<sp>.sh
//   -> /root/proxyserver/3proxy/bin/3proxy /root/proxyserver/3proxy/3proxy_<sp>.cfg
// (/root/proxyserver is a symlink to /opt/netrun/proxyserver). 19 3proxy for
// ~10 cfgs: MemAvailable 1.5 GB -> 0.46 GB, /health past the Vultr watchdog's
// 5 s timeout, two watchdog reboots (each one recreated the duplicates), and
// the duplicates split accepts on the same ports via SO_REUSEPORT.
//
// Why the cron lines survived: the agent's post-/generate cleanup removed
// `<PROXY_ROOT>/proxy-startup_<sp>.sh` = /opt/netrun/proxyserver/... by exact
// string, but the generator (`cd ~`) writes /root/proxyserver/... — it never
// matched. Those scripts also REWRITE the batch cfg from the ipv6/users lists
// before starting 3proxy, at every boot.
//
// Two jobs. Everything with a side effect goes through `run` (crontab / ps /
// ss / systemctl), `kill`, `realpath`, `readFile`, `sleep`, `now` and
// `isGenerationBusy`, so tests drive the real code against a fake host.
//
//   cron hygiene — drop every crontab line that runs a generator
//     proxy-startup_*.sh (any directory); every other line is kept verbatim;
//     the crontab is written back only when something changed. Only while
//     netrun-3proxy-restore AND netrun-ipv6-restore are enabled: without them
//     the @reboot line is the only thing that brings the batch (and its IPv6
//     addresses) back after a reboot (NODE_AGENT_CRON_HYGIENE=force skips
//     that check).
//
//   3proxy dedupe — group the running 3proxy processes by the realpath of
//     their cfg argument; for a cfg with more than one process keep ONE (the
//     oldest whose cfg argument is under preferRoot = the agent's PROXY_ROOT,
//     the path the agent and the boot restore use; else the oldest), SIGTERM
//     the rest and SIGKILL any survivor after graceMs. Never the last process
//     of a cfg; never a cfg none of whose probe ports listens (start port +
//     first socks port of the cfg — a boot still binding is left alone);
//     nothing at all while a /generate holds the generation lock.
//
// Both run at start (dedupe after firstDedupeDelayMs, so the boot restore has
// finished) and every NODE_AGENT_HYGIENE_INTERVAL_SEC (600) on unref'd timers.
// The steady state costs one `ps` and one `crontab -l` per tick.

const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const { parseCfgSummary } = require("./cfg_status.js");

const DEFAULT_INTERVAL_SEC = 600;
const MIN_INTERVAL_SEC = 60;
const FIRST_DEDUPE_DELAY_MS = 60_000;
// SIGTERM is graceful for 3proxy (it keeps established connections); a
// duplicate still alive after this is SIGKILLed.
const KILL_GRACE_MS = 3000;
// The boot path that replaces the generator's @reboot lines.
const BOOT_UNITS = ["netrun-3proxy-restore.service", "netrun-ipv6-restore.service"];
const LISTEN_PROBE_CHUNK = 256;

const CFG_BASENAME_RE = /^3proxy_(\d+)\.cfg$/;
// A generator start-up script as a word of a crontab line: proxy-startup_<id>.sh
// with any (or no) directory in front. `my-proxy-startup_1.sh` and
// `proxy-startup_1.sh.bak` are other files.
const STARTUP_SCRIPT_RE = /(?:^|[\s/"'=;&|(])(proxy-startup_[A-Za-z0-9_.-]*\.sh)(?=$|[\s"';&|)<>])/;

// Self-contained exec helper (same shape as egress.js / deprovision.js). Never
// throws — returns { code, stdout, stderr }; a spawn failure is code -1.
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

function errText(err) {
  return String((err && err.message) || err);
}

function stderrOf(res) {
  return String((res && res.stderr) || "").trim().slice(0, 200) || `exit ${res ? res.code : "?"}`;
}

// "0" / "off" / "false" / "no" = off; unset or empty = the default; anything
// else = on.
function envSwitch(raw, def = true) {
  if (raw === undefined || raw === null) return def;
  const v = String(raw).trim().toLowerCase();
  if (!v) return def;
  return !["0", "off", "false", "no"].includes(v);
}

function readSettings(env = process.env) {
  const cronRaw = String(env.NODE_AGENT_CRON_HYGIENE ?? "").trim().toLowerCase();
  const sec = Number(env.NODE_AGENT_HYGIENE_INTERVAL_SEC);
  return {
    dedupe: envSwitch(env.NODE_AGENT_DEDUPE_3PROXY),
    cronHygiene: cronRaw === "force" ? "force" : envSwitch(cronRaw) ? "on" : "off",
    intervalSec: Number.isFinite(sec) && sec > 0 ? Math.max(MIN_INTERVAL_SEC, Math.floor(sec)) : DEFAULT_INTERVAL_SEC,
  };
}

// ── pure helpers ─────────────────────────────────────────────────────────

// The generator start-up script (basename) a crontab line runs, or null.
// Comment lines never count.
function cronLineStartupScript(line) {
  const text = String(line || "").replace(/\r$/, "");
  if (/^\s*#/.test(text)) return null;
  const m = STARTUP_SCRIPT_RE.exec(text);
  return m ? m[1] : null;
}

// crontab text -> { changed, text, removed: [lines], kept }. A line goes when
// it runs a generator start-up script and match(scriptBasename, line) agrees;
// every other line (comments, env lines, blanks) is kept byte for byte.
function planCronCleanup(text, match = () => true) {
  const src = String(text || "");
  const lines = src.split("\n");
  if (src.endsWith("\n")) lines.pop();
  const kept = [];
  const removed = [];
  for (const line of lines) {
    const script = cronLineStartupScript(line);
    if (script && match(script, line)) removed.push(line);
    else kept.push(line);
  }
  if (removed.length === 0) return { changed: false, text: src, removed, kept: kept.length };
  return { changed: true, text: kept.length ? `${kept.join("\n")}\n` : "", removed, kept: kept.length };
}

// match() for one start port's script, in any directory (the post-/generate
// cleanup).
function startupScriptMatcher(startupScriptPath) {
  const name = path.basename(String(startupScriptPath || ""));
  return (script) => Boolean(name) && script === name;
}

// `ps -eo pid=,etimes=,args=` -> the real 3proxy processes that run a
// 3proxy_<sp>.cfg: [{ pid, ageSec, args, cfgArg, startPort }]. argv[0] must BE
// 3proxy — the restore unit's `bash -c 'setsid .../3proxy <cfg>'` wrapper,
// `pgrep -f 3proxy_<sp>.cfg` and a zombie `[3proxy] <defunct>` are not. A
// relative cfg argument is skipped (its realpath depends on the process cwd).
function parsePsProcesses(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\S.*?)\s*$/.exec(raw);
    if (!m) continue;
    const argv = m[3].split(/\s+/);
    if (path.basename(argv[0]) !== "3proxy") continue;
    const cfgArg = argv.slice(1).find((a) => CFG_BASENAME_RE.test(path.basename(a)));
    if (!cfgArg || !path.isAbsolute(cfgArg)) continue;
    out.push({
      pid: Number(m[1]),
      ageSec: Number(m[2]),
      args: m[3],
      cfgArg: path.normalize(cfgArg),
      startPort: Number(CFG_BASENAME_RE.exec(path.basename(cfgArg))[1]),
    });
  }
  return out;
}

// processes carrying `key` (the realpath of their cfg) -> one plan per cfg
// that runs more than once: { key, startPort, keep, kill: [...] }. keep = the
// oldest process whose cfg argument is under preferRoot, else the oldest one
// (equal age: the lower pid). kill never contains keep.
function planDedupe(procs, { preferRoot = null } = {}) {
  const byKey = new Map();
  for (const p of Array.isArray(procs) ? procs : []) {
    if (!p || !p.key || !Number.isInteger(p.pid) || p.pid <= 0) continue;
    if (!byKey.has(p.key)) byKey.set(p.key, []);
    byKey.get(p.key).push(p);
  }
  const root = preferRoot ? `${path.normalize(String(preferRoot)).replace(/\/+$/, "")}/` : null;
  const olderFirst = (a, b) => (b.ageSec || 0) - (a.ageSec || 0) || a.pid - b.pid;
  const plans = [];
  for (const [key, list] of byKey) {
    if (list.length < 2) continue;
    const sorted = [...list].sort(olderFirst);
    const preferred = root ? sorted.filter((p) => p.cfgArg.startsWith(root)) : [];
    const keep = (preferred.length > 0 ? preferred : sorted)[0];
    plans.push({ key, startPort: keep.startPort, keep, kill: sorted.filter((p) => p !== keep) });
  }
  plans.sort((a, b) => a.startPort - b.startPort || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return plans;
}

// `ss -ltnH ...` -> Set of local ports (the local address is the 4th column).
function parseListeningPorts(text) {
  const out = new Set();
  for (const raw of String(text || "").split("\n")) {
    const fields = raw.trim().split(/\s+/);
    if (fields.length < 2) continue;
    const local = fields.length >= 4 ? fields[3] : fields[fields.length - 1];
    const port = Number(String(local || "").split(":").pop());
    if (Number.isInteger(port) && port > 0 && port <= 65535) out.add(port);
  }
  return out;
}

// ── the service ──────────────────────────────────────────────────────────

function createHygiene({
  env = process.env,
  run = execCapture,
  kill = (pid, signal) => process.kill(pid, signal),
  realpath = (p) => fsp.realpath(p),
  readFile = (p) => fsp.readFile(p, "utf-8"),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  isGenerationBusy = async () => false,
  preferRoot = null,
  graceMs = KILL_GRACE_MS,
  firstDedupeDelayMs = FIRST_DEDUPE_DELAY_MS,
  bootUnits = BOOT_UNITS,
  tmpDir = os.tmpdir(),
  log = console,
} = {}) {
  const settings = readSettings(env);
  const stats = {
    duplicatesReaped: 0,
    lastReapAt: null,
    lastDedupeAt: null,
    lastDedupeOutcome: null,
    cronLinesRemoved: 0,
    lastCronAt: null,
    lastCronOutcome: null,
  };
  let cronTail = Promise.resolve();
  let tickInFlight = null;
  let timers = null;
  let lastCronWarning = null;

  const iso = () => new Date(now()).toISOString();

  // A throwing lock probe counts as busy: never act on an unknown lock.
  async function busy() {
    try {
      return Boolean(await isGenerationBusy());
    } catch {
      return true;
    }
  }

  // One crontab read-modify-write at a time (periodic sweep vs the
  // post-/generate cleanup).
  function withCronLock(fn) {
    const next = cronTail.then(fn);
    cronTail = next.catch(() => {});
    return next;
  }

  async function bootUnitsEnabled() {
    const res = await run("systemctl", ["is-enabled", ...bootUnits], { timeoutMs: 8000 });
    const states = String(res.stdout || "").split("\n").map((s) => s.trim()).filter(Boolean);
    return states.length === bootUnits.length && states.every((s) => s === "enabled");
  }

  // Remove the crontab lines whose generator start-up script satisfies
  // match(scriptBasename, line). Returns { ok, skipped, outcome, removed,
  // error, stderrTail }; outcome is one of unchanged | removed | no_crontab |
  // crontab_unavailable | boot_restore_units_not_enabled | error.
  function removeCronLines(match = () => true) {
    return withCronLock(async () => {
      const done = (outcome, extra = {}) => {
        const out = { ok: true, skipped: false, outcome, removed: [], error: null, stderrTail: "", ...extra };
        stats.lastCronAt = iso();
        stats.lastCronOutcome = outcome;
        stats.cronLinesRemoved += out.removed.length;
        return out;
      };
      const listed = await run("crontab", ["-l"], { timeoutMs: 8000 });
      if (listed.code !== 0) {
        if (/no crontab/i.test(String(listed.stderr || ""))) return done("no_crontab");
        if (listed.code === -1 && /ENOENT/.test(String(listed.stderr || ""))) {
          return done("crontab_unavailable", { skipped: true });
        }
        return done("error", { ok: false, error: "crontab_list_failed", stderrTail: stderrOf(listed) });
      }
      const plan = planCronCleanup(listed.stdout, match);
      if (!plan.changed) return done("unchanged");
      if (settings.cronHygiene !== "force" && !(await bootUnitsEnabled())) {
        return done("boot_restore_units_not_enabled", { skipped: true, pending: plan.removed.length });
      }
      let dir = null;
      try {
        dir = fs.mkdtempSync(path.join(tmpDir, "netrun-cron-"));
        const file = path.join(dir, "crontab");
        fs.writeFileSync(file, plan.text, { mode: 0o600 });
        const wrote = await run("crontab", [file], { timeoutMs: 8000 });
        if (wrote.code !== 0) {
          return done("error", { ok: false, error: "crontab_write_failed", stderrTail: stderrOf(wrote) });
        }
      } catch (err) {
        return done("error", { ok: false, error: `crontab_write_failed:${errText(err)}` });
      } finally {
        if (dir) {
          try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
        }
      }
      for (const line of plan.removed) log.log(`[hygiene] cron: removed ${JSON.stringify(line)}`);
      return done("removed", { removed: plan.removed });
    });
  }

  // The periodic sweep: every generator start-up line goes.
  async function cronHygiene() {
    if (settings.cronHygiene === "off") return { ok: true, skipped: true, outcome: "disabled", removed: [] };
    if (await busy()) {
      stats.lastCronAt = iso();
      stats.lastCronOutcome = "generation_in_progress";
      return { ok: true, skipped: true, outcome: "generation_in_progress", removed: [] };
    }
    const res = await removeCronLines(() => true);
    if (res.removed.length > 0) {
      log.log(
        `[hygiene] cron: removed ${res.removed.length} generator proxy-startup line(s); ` +
          "netrun-3proxy-restore starts the batches at boot"
      );
    }
    if (res.outcome === "boot_restore_units_not_enabled") {
      if (lastCronWarning !== res.outcome) {
        log.warn(
          `[hygiene] cron: ${res.pending} generator proxy-startup line(s) kept: ${bootUnits.join(" / ")} ` +
            "not both enabled (they are then the only boot path); NODE_AGENT_CRON_HYGIENE=force removes them anyway"
        );
      }
    } else if (!res.ok) {
      log.error(`[hygiene] cron: ${res.error}: ${res.stderrTail}`);
    }
    lastCronWarning = res.outcome;
    return res;
  }

  async function listProcesses() {
    const res = await run("ps", ["-eo", "pid=,etimes=,args="], { timeoutMs: 8000 });
    if (res.code !== 0) return { ok: false, error: stderrOf(res), procs: [] };
    return { ok: true, error: null, procs: parsePsProcesses(res.stdout) };
  }

  // key = realpath(dir of the cfg argument) + basename: /root/proxyserver/...
  // and /opt/netrun/proxyserver/... are the same file. A directory that no
  // longer resolves keeps its normalized path.
  async function withKeys(procs) {
    const dirs = new Map();
    const out = [];
    for (const p of procs) {
      const dir = path.dirname(p.cfgArg);
      if (!dirs.has(dir)) {
        let real = dir;
        try {
          real = await realpath(dir);
        } catch {
          real = dir;
        }
        dirs.set(dir, real);
      }
      out.push({ ...p, key: path.join(dirs.get(dir), path.basename(p.cfgArg)) });
    }
    return out;
  }

  // Start port + the cfg's first socks port (after a /deprovision rewrite the
  // start port's block may be gone while the batch still serves).
  async function probePortsOf(plan) {
    const ports = [plan.startPort];
    try {
      const probe = parseCfgSummary(await readFile(plan.key)).probePort;
      if (Number.isInteger(probe) && probe > 0 && !ports.includes(probe)) ports.push(probe);
    } catch {
      // unreadable cfg: the start port alone decides
    }
    return ports;
  }

  async function listListening(ports) {
    const list = [...new Set(ports)];
    const out = new Set();
    for (let i = 0; i < list.length; i += LISTEN_PROBE_CHUNK) {
      const filter = list.slice(i, i + LISTEN_PROBE_CHUNK).map((p) => `sport = :${p}`).join(" or ");
      const res = await run("ss", ["-ltnH", filter], { timeoutMs: 8000 });
      if (res.code !== 0) return { ok: false, error: stderrOf(res), ports: out };
      for (const p of parseListeningPorts(res.stdout)) out.add(p);
    }
    return { ok: true, error: null, ports: out };
  }

  async function dedupe() {
    if (!settings.dedupe) return { ok: true, skipped: true, outcome: "disabled", reaped: [] };
    const finish = (outcome, extra = {}) => {
      stats.lastDedupeAt = iso();
      stats.lastDedupeOutcome = outcome;
      return { ok: !outcome.endsWith("_failed"), skipped: false, outcome, reaped: [], ...extra };
    };
    if (await busy()) return { ...finish("generation_in_progress"), skipped: true };

    const snap = await listProcesses();
    if (!snap.ok) {
      log.error(`[hygiene] dedupe: ps failed (${snap.error}); nothing killed`);
      return finish("ps_failed");
    }
    const plans = planDedupe(await withKeys(snap.procs), { preferRoot });
    if (plans.length === 0) return finish("ok");

    const portsByKey = new Map();
    for (const plan of plans) portsByKey.set(plan.key, await probePortsOf(plan));
    const listening = await listListening([...portsByKey.values()].flat());
    if (!listening.ok) {
      log.error(`[hygiene] dedupe: ss failed (${listening.error}); nothing killed`);
      return finish("ss_failed");
    }
    const actionable = [];
    for (const plan of plans) {
      const ports = portsByKey.get(plan.key);
      if (ports.some((p) => listening.ports.has(p))) {
        actionable.push(plan);
      } else {
        log.warn(
          `[hygiene] dedupe: ${plan.key} runs ${plan.kill.length + 1} times but none of port(s) ` +
            `${ports.join(",")} listens; left alone`
        );
      }
    }
    if (actionable.length === 0) return finish("ok");

    // Re-check right before signalling: a /generate may have started since the
    // snapshot, and a pid may have exited (or been recycled) meanwhile.
    if (await busy()) return { ...finish("generation_in_progress"), skipped: true };
    const fresh = await listProcesses();
    if (!fresh.ok) {
      log.error(`[hygiene] dedupe: ps failed (${fresh.error}); nothing killed`);
      return finish("ps_failed");
    }
    const live = new Map(fresh.procs.map((p) => [p.pid, p]));
    const stillSame = (p, table = live) => {
      const q = table.get(p.pid);
      return Boolean(q) && q.args === p.args;
    };

    const victims = [];
    for (const plan of actionable) {
      const { keep } = plan;
      if (!stillSame(keep)) {
        log.warn(`[hygiene] dedupe: ${plan.key}: pid ${keep.pid} to keep is gone; left alone this round`);
        continue;
      }
      log.log(
        `[hygiene] dedupe: ${plan.key} (start port ${plan.startPort}) runs ${plan.kill.length + 1} times; ` +
          `keeping pid ${keep.pid} (${keep.cfgArg}, up ${keep.ageSec}s)`
      );
      for (const v of plan.kill) {
        if (!stillSame(v)) continue;
        try {
          kill(v.pid, "SIGTERM");
        } catch (err) {
          if (!(err && err.code === "ESRCH")) log.error(`[hygiene] dedupe: SIGTERM pid ${v.pid} failed: ${errText(err)}`);
          continue;
        }
        log.log(`[hygiene] dedupe: SIGTERM pid ${v.pid} (${v.cfgArg}, up ${v.ageSec}s), duplicate of pid ${keep.pid}`);
        victims.push({ ...v, keepPid: keep.pid });
      }
    }

    if (victims.length > 0) {
      await sleep(graceMs);
      const after = await listProcesses();
      if (!after.ok) {
        log.error(`[hygiene] dedupe: ps failed after SIGTERM (${after.error}); no SIGKILL this round`);
      } else {
        const table = new Map(after.procs.map((p) => [p.pid, p]));
        for (const v of victims) {
          if (!stillSame(v, table)) continue;
          try {
            kill(v.pid, "SIGKILL");
            log.log(`[hygiene] dedupe: SIGKILL pid ${v.pid}: still alive ${graceMs} ms after SIGTERM`);
          } catch (err) {
            if (!(err && err.code === "ESRCH")) log.error(`[hygiene] dedupe: SIGKILL pid ${v.pid} failed: ${errText(err)}`);
          }
        }
      }
      stats.duplicatesReaped += victims.length;
      stats.lastReapAt = iso();
      log.log(
        `[hygiene] dedupe: reaped ${victims.length} duplicate 3proxy process(es); ` +
          `${stats.duplicatesReaped} since agent start`
      );
    }
    return finish("ok", {
      reaped: victims.map((v) => ({ pid: v.pid, cfg: v.cfgArg, startPort: v.startPort, keptPid: v.keepPid })),
    });
  }

  // One tick at a time; a failing half never stops the other.
  function tick({ cron = true, dedupe: doDedupe = true } = {}) {
    if (tickInFlight) return tickInFlight;
    tickInFlight = (async () => {
      const out = { cron: null, dedupe: null };
      try {
        if (cron) {
          try {
            out.cron = await cronHygiene();
          } catch (err) {
            log.error(`[hygiene] cron failed: ${errText(err)}`);
          }
        }
        if (doDedupe) {
          try {
            out.dedupe = await dedupe();
          } catch (err) {
            log.error(`[hygiene] dedupe failed: ${errText(err)}`);
          }
        }
        return out;
      } finally {
        tickInFlight = null;
      }
    })();
    return tickInFlight;
  }

  // Cron hygiene now, the first dedupe after firstDedupeDelayMs, then both
  // every intervalSec. Unref'd: never keeps a test process (or a stopping
  // agent) alive.
  function start() {
    if (timers) return;
    log.log(
      `[hygiene] dedupe_3proxy=${settings.dedupe ? "on" : "off"} cron_hygiene=${settings.cronHygiene} ` +
        `interval=${settings.intervalSec}s first_dedupe_in=${Math.round(firstDedupeDelayMs / 1000)}s`
    );
    timers = [];
    if (!settings.dedupe && settings.cronHygiene === "off") return;
    if (settings.cronHygiene !== "off") tick({ cron: true, dedupe: false });
    if (settings.dedupe) {
      const first = setTimeout(() => tick({ cron: false, dedupe: true }), firstDedupeDelayMs);
      if (typeof first.unref === "function") first.unref();
      timers.push(first);
    }
    const every = setInterval(() => tick(), settings.intervalSec * 1000);
    if (typeof every.unref === "function") every.unref();
    timers.push(every);
  }

  function stop() {
    for (const t of timers || []) clearTimeout(t);
    timers = null;
  }

  // /health: hygiene (duplicatesReaped / lastReapAt also go top-level).
  function status() {
    return {
      dedupe3proxy: settings.dedupe,
      cronHygiene: settings.cronHygiene,
      intervalSec: settings.intervalSec,
      ...stats,
    };
  }

  return {
    start,
    stop,
    tick,
    dedupe,
    cronHygiene,
    removeCronLines,
    status,
    settings: () => ({ ...settings }),
  };
}

module.exports = {
  createHygiene,
  readSettings,
  envSwitch,
  // exported for unit tests (pure, no exec / fs)
  cronLineStartupScript,
  planCronCleanup,
  startupScriptMatcher,
  parsePsProcesses,
  planDedupe,
  parseListeningPorts,
  BOOT_UNITS,
  DEFAULT_INTERVAL_SEC,
  FIRST_DEDUPE_DELAY_MS,
  KILL_GRACE_MS,
};
