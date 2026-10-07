"use strict";

// Wave FLEET-HEALTH — bounded retention for the per-job directories under
// JOBS_ROOT (/opt/netrun/jobs). Every /generate leaves one directory behind
// (job.json, proxies.list, map.csv, stdout/stderr logs) and nothing ever
// removed them: the live Chicago node carried 1500 of them, and every /jobs
// call and every "reuse a running instance" check reads ALL their job.json.
//
// Kept (never deleted):
//   - the `keep` newest jobs (by updatedAt / finishedAt / startedAt /
//     createdAt, falling back to the directory mtime) — the same order /jobs
//     lists them in;
//   - the job of the live generation lock (the generation running right now);
//   - every job whose status is queued/running and that was updated within
//     `staleMs` (a generation in progress, even one the lock no longer names);
//   - for every start port that still has a cfg on disk (3proxy_<p>.cfg or
//     .cfg.disabled), the newest READY job of that start port: /generate's
//     "instance already running → reuse its proxies.list" path and /reconcile
//     read exactly that job.
// Anything that is not a plain job directory (the .generation.lock file,
// hidden entries, names outside the job-id alphabet) is never touched.
//
// NODE_AGENT_JOBS_KEEP (default 200) sets `keep`; 0 disables pruning.

const fsp = require("fs/promises");
const path = require("path");

const DEFAULT_KEEP = 200;
const JOB_DIR_NAME_RE = /^[a-zA-Z0-9_-]+$/;
const LIVE_STATUSES = new Set(["queued", "running"]);
const READY_STATUSES = new Set(["ready", "success", "completed"]);

function keepFromEnv(raw) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return DEFAULT_KEEP;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 0; // 0 / negative / garbage-as-0 = pruning off
  return Math.floor(n);
}

function jobSortMs(entry) {
  const meta = entry && entry.meta;
  if (meta) {
    for (const key of ["updatedAt", "finishedAt", "startedAt", "createdAt"]) {
      const t = Date.parse(String(meta[key] || ""));
      if (Number.isFinite(t) && t > 0) return t;
    }
  }
  return Number.isFinite(entry && entry.mtimeMs) ? entry.mtimeMs : 0;
}

function statusOf(meta) {
  return String((meta && meta.status) || "").trim().toLowerCase();
}

// Pure planner. entries = [{ name, meta|null, mtimeMs }]; returns
// { keep: [names], remove: [names] } (remove is oldest-first).
function planJobPrune(entries, {
  keep = DEFAULT_KEEP,
  nowMs = Date.now(),
  staleMs = 30 * 60 * 1000,
  lockJobId = null,
  cfgStartPorts = new Set(),
} = {}) {
  const list = (Array.isArray(entries) ? entries : []).filter(
    (e) => e && typeof e.name === "string" && JOB_DIR_NAME_RE.test(e.name)
  );
  if (!(keep > 0) || list.length <= keep) {
    return { keep: list.map((e) => e.name), remove: [] };
  }
  const sorted = [...list].sort((a, b) => jobSortMs(b) - jobSortMs(a) || (a.name < b.name ? -1 : 1));
  const protectedNames = new Set(sorted.slice(0, keep).map((e) => e.name));
  if (lockJobId) protectedNames.add(String(lockJobId));

  const newestReadyByPort = new Map();
  for (const e of sorted) {
    const st = statusOf(e.meta);
    if (LIVE_STATUSES.has(st)) {
      const updated = jobSortMs(e);
      if (updated > 0 && nowMs - updated <= staleMs) protectedNames.add(e.name);
    }
    if (READY_STATUSES.has(st)) {
      const sp = Number(e.meta && e.meta.params && e.meta.params.startPort);
      if (Number.isInteger(sp) && sp > 0 && !newestReadyByPort.has(sp)) newestReadyByPort.set(sp, e.name);
    }
  }
  const ports = cfgStartPorts instanceof Set ? cfgStartPorts : new Set(cfgStartPorts || []);
  for (const [sp, name] of newestReadyByPort) {
    if (ports.has(sp)) protectedNames.add(name);
  }

  const keepNames = [];
  const remove = [];
  for (const e of sorted) {
    if (protectedNames.has(e.name)) keepNames.push(e.name);
    else remove.push(e.name);
  }
  remove.reverse(); // oldest first
  return { keep: keepNames, remove };
}

async function readJson(p) {
  try {
    return JSON.parse(await fsp.readFile(p, "utf-8"));
  } catch {
    return null;
  }
}

async function cfgStartPortsOnDisk(cfgDir) {
  const out = new Set();
  let names = [];
  try {
    names = await fsp.readdir(cfgDir);
  } catch {
    return out;
  }
  for (const n of names) {
    const m = /^3proxy_(\d+)\.cfg(?:\.disabled)?$/.exec(n);
    if (m) out.add(Number(m[1]));
  }
  return out;
}

// Filesystem side. Returns { ok, scanned, removed: [names], kept, error? }.
// Never throws; never deletes outside jobsRoot.
async function pruneJobDirs({
  jobsRoot,
  cfgDir,
  keep = DEFAULT_KEEP,
  staleMs = 30 * 60 * 1000,
  lockJobId = null,
  nowMs = Date.now(),
} = {}) {
  const result = { ok: true, scanned: 0, removed: [], kept: 0 };
  if (!(keep > 0) || !jobsRoot) return result;
  const root = path.resolve(jobsRoot);
  let dirents;
  try {
    dirents = await fsp.readdir(root, { withFileTypes: true });
  } catch (err) {
    return { ...result, ok: false, error: String((err && err.message) || err) };
  }
  const candidates = dirents.filter((d) => d.isDirectory() && JOB_DIR_NAME_RE.test(d.name));
  result.scanned = candidates.length;
  if (candidates.length <= keep) {
    result.kept = candidates.length;
    return result;
  }
  const entries = [];
  for (const d of candidates) {
    const dir = path.join(root, d.name);
    let mtimeMs = 0;
    try {
      mtimeMs = (await fsp.stat(dir)).mtimeMs;
    } catch {
      continue; // vanished meanwhile
    }
    entries.push({ name: d.name, meta: await readJson(path.join(dir, "job.json")), mtimeMs });
  }
  const plan = planJobPrune(entries, {
    keep,
    nowMs,
    staleMs,
    lockJobId,
    cfgStartPorts: cfgDir ? await cfgStartPortsOnDisk(cfgDir) : new Set(),
  });
  result.kept = plan.keep.length;
  for (const name of plan.remove) {
    const dir = path.resolve(root, name);
    const rel = path.relative(root, dir);
    if (!rel || rel.startsWith("..") || path.isAbsolute(rel) || rel.includes(path.sep)) continue;
    try {
      await fsp.rm(dir, { recursive: true, force: true });
      result.removed.push(name);
    } catch (err) {
      result.ok = false;
      result.error = String((err && err.message) || err);
    }
  }
  return result;
}

module.exports = {
  DEFAULT_KEEP,
  keepFromEnv,
  planJobPrune,
  pruneJobDirs,
  // exported for tests
  cfgStartPortsOnDisk,
};
