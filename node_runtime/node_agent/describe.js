"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const https = require("https");
const pergbShield = require("./pergb_shield.js");

const AGENT_VERSION = "1.0.0";

const GEO_CACHE_TTL_MS = 60 * 60 * 1000;
let _geoCache = null;
let _geoCacheAt = 0;

async function buildDescribe({
  healthSnapshot,
  jobsRoot,
  proxyRoot,
  egressRotation = false,
  firewallDesired = false,
  supervisor = false,
  httpsHostnames = false,
  shield = pergbShield.defaultShield(),
} = {}) {
  const ipv6 = healthSnapshot?.ipv6 || null;
  const ipv6Egress = healthSnapshot?.ipv6Egress || null;
  const dns = healthSnapshot?.dns || null;
  // Pay-per-GB v2 (lane L9) — what per-GB takes from the box (its slice's
  // memory budget; option A: its shared ports on the primary IPv4).
  let pergb = NO_PERGB;
  try {
    pergb = await shield.capacityBudget();
  } catch {
    pergb = NO_PERGB;
  }

  return {
    agent_version: AGENT_VERSION,
    node_runtime_commit: getGitCommit(),
    capacity: estimateCapacity({ pergb }),
    capacity_model: describeCapacityModel({ pergb }),
    // Kept at 1 / 1500 (Wave CAPACITY-18K): the agent serialises /generate
    // behind ONE generation lock (a 2nd parallel job only gets node_busy), and
    // a bigger batch saves almost no RAM (per-process overhead is ~1.5-7.5 MiB
    // per 1500 proxies) while 0.9.3 scans its per-process user list linearly
    // on every auth. Filling 18k = 12 sequential batches.
    max_parallel_jobs: 1,
    max_batch_size: 1500,
    generator_script: getGeneratorScriptPath(),
    geo_code: await detectGeoCode().catch(() => null),
    ipv6: ipv6,
    ipv6_egress: ipv6Egress,
    dns: dns,
    api_key_required: Boolean(String(process.env.NODE_AGENT_API_KEY || "").trim()),
    jobs_root: jobsRoot || process.env.NODE_AGENT_JOBS_ROOT || "/opt/netrun/jobs",
    proxy_root: proxyRoot || process.env.NODE_AGENT_PROXY_ROOT || "/opt/netrun/proxyserver",
    supports: {
      describe: true,
      accounting: true,
      enroll: true,
      // Wave IPV6-ROTATION — true once egress.js has its nft NAT table up;
      // false on a node without nft NAT (POST /egress/* then answers 503).
      egress_rotation: Boolean(egressRotation),
      // Audit RES-13 — POST /firewall/desired (desired-state ghost firewall).
      firewall_desired: Boolean(firewallDesired),
      // Audit RES-11 — dead-batch respawn + anchor re-add (/health supervisor).
      supervisor: Boolean(supervisor),
      // Audit FO-08 — POST /https/hostnames (SNI certificates for the node's
      // DNS names); false when NODE_AGENT_HTTPS_HOSTNAMES=0.
      https_hostnames: Boolean(httpsHostnames),
    },
  };
}

function getGitCommit() {
  try {
    return execSync("git rev-parse HEAD", {
      encoding: "utf-8",
      cwd: __dirname,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .trim()
      .slice(0, 12);
  } catch {
    return null;
  }
}

// Wave CAPACITY-18K — RAM model from the node capacity study
// (docs/wave_node_capacity_report.md §3, 3proxy 0.9.3 disassembly):
//   - a dual proxy = 2 listener threads x ~42 KB (kernel stack 16 + task_struct
//     ~10 + user stack 8-12 + socket ~4 + heap 1-2) + ~3 KB address/route/nft/
//     user ~= 87 KB -> budget 100 KB (was 0.5 MB, 5x too high: Delhi held 12k
//     proxies on a 4 GB box that the old model capped at 5000);
//   - one 3proxy process per batch: ~1.5 MiB, +6 MiB on legacy batches that
//     still carry nscache/nscache6 65536 -> budget the legacy 7.5 MiB at an
//     average batch of 1000 (prod batches average 304-1360);
//   - base reserve: OS ~350 + agent ~150 + unbound ~150 (32m/64m caches) +
//     haproxy ~100 + ~1000 live connections x 150 KB = 900 MB;
//   - 15 % of MemTotal kept free.
// MemTotal, not MemAvailable: `capacity` is what the BOX holds (read once at
// enroll), and must not shrink as the node fills. The result is capped by the
// port ceiling: dual pairs (http = socks - 10000) with every port in
// 8100-65535 on one IPv4 = 27 436 (report §3, "port ceiling proof").
const CAPACITY_MODEL = Object.freeze({
  perProxyKb: 100,
  perProcessMb: 7.5,
  avgBatchSize: 1000,
  baseReserveMb: 900,
  freePct: 15,
  minCapacity: 100,
  portCeiling: 27436,
});
const CAPACITY_FALLBACK = 5000;
// Pay-per-GB v2 (lane L9) — per-GB on the node takes its own budget out of the
// per-piece model: the netrun-pergb.slice MemoryMax (enable.json sliceMemMax,
// default 1536M; RADIUS, both 3proxy-pergb processes and the per-GB haproxy
// live inside it) comes off the usable RAM, and with option A (shared ports on
// the primary IPv4) each shared port costs at most one dual pair — its socks
// or its http side — so the port ceiling drops by the shared port count.
const NO_PERGB = Object.freeze({ enabled: false, memMb: 0, ports: 0, option: null });

function parseMemTotalMb(meminfoText) {
  const m = /^MemTotal:\s+(\d+)\s+kB/m.exec(String(meminfoText || ""));
  if (!m) return null;
  const mb = Number(m[1]) / 1024;
  return Number.isFinite(mb) && mb > 0 ? mb : null;
}

function capacityFromMemTotalMb(memTotalMb, model = CAPACITY_MODEL, pergb = NO_PERGB) {
  const pergbMb = pergb && pergb.enabled ? Math.max(0, Number(pergb.memMb) || 0) : 0;
  const pergbPorts = pergb && pergb.enabled ? Math.max(0, Number(pergb.ports) || 0) : 0;
  const usableMb = memTotalMb * (1 - model.freePct / 100) - model.baseReserveMb - pergbMb;
  const perProxyMb = model.perProxyKb / 1024 + model.perProcessMb / model.avgBatchSize;
  const ramLimit = Math.floor(Math.max(0, usableMb) / perProxyMb);
  return Math.max(model.minCapacity, Math.min(model.portCeiling - pergbPorts, ramLimit));
}

function readMeminfo() {
  return fs.readFileSync("/proc/meminfo", "utf-8");
}

// `meminfoText` is injectable for tests; production reads /proc/meminfo.
// `pergb`: the per-GB budget (pergb_shield.capacityBudget()), none by default.
function estimateCapacity({ meminfoText, pergb = NO_PERGB } = {}) {
  try {
    const text = meminfoText === undefined ? readMeminfo() : meminfoText;
    const memTotalMb = parseMemTotalMb(text);
    if (memTotalMb === null) return CAPACITY_FALLBACK;
    return capacityFromMemTotalMb(memTotalMb, CAPACITY_MODEL, pergb);
  } catch {
    return CAPACITY_FALLBACK;
  }
}

function describeCapacityModel({ meminfoText, pergb = NO_PERGB } = {}) {
  let memTotalMb = null;
  try {
    memTotalMb = parseMemTotalMb(meminfoText === undefined ? readMeminfo() : meminfoText);
  } catch {
    memTotalMb = null;
  }
  const on = Boolean(pergb && pergb.enabled);
  return {
    ...CAPACITY_MODEL,
    memTotalMb: memTotalMb === null ? null : Math.round(memTotalMb),
    // Pay-per-GB v2 — additive: what per-GB took out of the model.
    pergbReserveMb: on ? Math.max(0, Number(pergb.memMb) || 0) : 0,
    pergbSharedPorts: on ? Math.max(0, Number(pergb.ports) || 0) : 0,
    pergbOption: on ? pergb.option || null : null,
  };
}

function getGeneratorScriptPath() {
  const candidates = [
    "/opt/netrun/node_runtime/soft/generator/proxyyy_automated.sh",
    "/opt/netrun/node_runtime/generator/proxyyy_automated.sh",
    path.resolve(__dirname, "..", "soft", "generator", "proxyyy_automated.sh"),
    path.resolve(__dirname, "..", "generator", "proxyyy_automated.sh"),
    path.resolve(__dirname, "..", "..", "node_runtime", "soft", "generator", "proxyyy_automated.sh"),
    path.resolve(__dirname, "..", "..", "node_runtime", "generator", "proxyyy_automated.sh"),
    path.resolve(__dirname, "..", "..", "soft", "generator", "proxyyy_automated.sh"),
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      // continue
    }
  }
  return null;
}

async function detectGeoCode() {
  const now = Date.now();
  if (_geoCache !== null && now - _geoCacheAt < GEO_CACHE_TTL_MS) {
    return _geoCache;
  }
  try {
    const country = await new Promise((resolve, reject) => {
      const req = https.get("https://ipapi.co/country", { timeout: 4000 }, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`ipapi status ${res.statusCode}`));
          return;
        }
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => resolve(body.trim()));
      });
      req.on("error", reject);
      req.on("timeout", () => req.destroy(new Error("timeout")));
    });
    if (/^[A-Z]{2}$/.test(country)) {
      _geoCache = country;
      _geoCacheAt = now;
      return country;
    }
    return null;
  } catch {
    return null;
  }
}

module.exports = {
  buildDescribe,
  estimateCapacity,
  capacityFromMemTotalMb,
  parseMemTotalMb,
  describeCapacityModel,
  CAPACITY_MODEL,
};
