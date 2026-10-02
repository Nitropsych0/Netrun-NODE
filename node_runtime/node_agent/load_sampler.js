"use strict";

// Wave NODE-LOAD-GUARD — cheap CPU / memory / socket sampling for the
// orchestrator's load guard (a node stays on sale only while it can serve).
// Reads /proc every SAMPLE_MS and keeps a 5-minute ring; no child processes
// (a busy node runs ~7000 listeners, `ss` would cost far more than /proc).
// The orchestrator decides; this only reports.

const fs = require("fs");
const os = require("os");

const SAMPLE_MS = Number(process.env.NODE_AGENT_LOAD_SAMPLE_MS || 5000);
const WINDOW_MS = 5 * 60 * 1000;

function parseProcStat(text) {
  const line = String(text || "").split("\n").find((l) => l.startsWith("cpu "));
  if (!line) return null;
  const v = line.trim().split(/\s+/).slice(1).map(Number);
  if (v.length < 4 || v.some((x) => !Number.isFinite(x))) return null;
  // user nice system idle iowait irq softirq steal (guest is inside user).
  const idle = v[3] + (v[4] || 0);
  const total = v.slice(0, 8).reduce((a, b) => a + b, 0);
  return { idle, total };
}

function cpuPctBetween(a, b) {
  if (!a || !b) return null;
  const dt = b.total - a.total;
  if (dt <= 0) return null;
  return Math.max(0, Math.min(100, (100 * (dt - (b.idle - a.idle))) / dt));
}

function parseMeminfo(text) {
  const kv = {};
  for (const l of String(text || "").split("\n")) {
    const m = l.match(/^(\w+):\s+(\d+)/);
    if (m) kv[m[1]] = Number(m[2]);
  }
  if (!kv.MemTotal || kv.MemAvailable === undefined) return null;
  return Math.round((1000 * (kv.MemTotal - kv.MemAvailable)) / kv.MemTotal) / 10;
}

function parseSockstatTcp(text) {
  const m = String(text || "").match(/^TCP6?:\s+inuse\s+(\d+)/m);
  return m ? Number(m[1]) : 0;
}

function round1(x) {
  return x === null || x === undefined ? null : Math.round(x * 10) / 10;
}

function createSampler({ readFile = (p) => fs.readFileSync(p, "utf-8"), now = () => Date.now() } = {}) {
  const samples = []; // { at, cpu: {idle,total} }

  function read(p) {
    try {
      return readFile(p);
    } catch {
      return null;
    }
  }

  function tick() {
    const cpu = parseProcStat(read("/proc/stat"));
    if (!cpu) return;
    const at = now();
    samples.push({ at, cpu });
    while (samples.length > 2 && samples[0].at < at - WINDOW_MS - SAMPLE_MS) samples.shift();
  }

  // Per-interval CPU% for consecutive samples within the last `ms`.
  function intervals(ms) {
    const out = [];
    const since = now() - ms;
    for (let i = 1; i < samples.length; i += 1) {
      if (samples[i - 1].at < since) continue;
      const pct = cpuPctBetween(samples[i - 1].cpu, samples[i].cpu);
      if (pct !== null) out.push(pct);
    }
    return out;
  }

  function avgOver(ms) {
    const first = samples.find((s) => s.at >= now() - ms);
    const last = samples[samples.length - 1];
    return first && last && first !== last ? cpuPctBetween(first.cpu, last.cpu) : null;
  }

  function snapshot() {
    const last5 = intervals(WINDOW_MS);
    const first = samples.find((s) => s.at >= now() - WINDOW_MS);
    const last = samples[samples.length - 1];
    const windowSec = first && last ? Math.round((last.at - first.at) / 1000) : 0;
    const tcp = parseSockstatTcp(read("/proc/net/sockstat")) + parseSockstatTcp(read("/proc/net/sockstat6"));
    return {
      cpuPct: round1(intervals(SAMPLE_MS * 1.5).slice(-1)[0] ?? null),
      cpuAvg1m: round1(avgOver(60 * 1000)),
      cpuAvg5m: round1(avgOver(WINDOW_MS)),
      // The LOWEST interval in the window: >80 means it never dipped below
      // 80 % for the whole window — «CPU > 80 % for 5 minutes».
      cpuMin5m: round1(last5.length ? Math.min(...last5) : null),
      windowSec,
      load1: round1(os.loadavg()[0]),
      ncpu: os.cpus().length,
      memUsedPct: parseMeminfo(read("/proc/meminfo")),
      tcpInuse: tcp,
      sampledAt: last ? new Date(last.at).toISOString() : null,
    };
  }

  let timer = null;
  function start() {
    if (timer) return;
    tick();
    timer = setInterval(tick, SAMPLE_MS);
    if (timer.unref) timer.unref();
  }

  return { tick, snapshot, start, _samples: samples };
}

module.exports = {
  createSampler,
  parseProcStat,
  cpuPctBetween,
  parseMeminfo,
  parseSockstatTcp,
  SAMPLE_MS,
  WINDOW_MS,
};
