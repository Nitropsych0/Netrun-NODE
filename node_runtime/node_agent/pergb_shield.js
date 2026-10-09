"use strict";

// Pay-per-GB v2 (plan §3.9, lane L9) — what per-piece code must know about
// the per-GB shared ports, read from /etc/netrun-pergb/enable.json (the last
// accepted POST /pergb/enable params, written by pergb_runtime.js).
//
// Option A (the default; enable.json has no dedicated IPv4): the shared range
// [base, base+count-1] is served on the node's PRIMARY IPv4, next to per-piece:
//   - /accounts/{port}/disable|enable of a shared port -> 409 pergb_shared_port
//     (and a per-piece socks port never drags a shared http mirror into the
//     drop set);
//   - /deprovision never touches a shared port (409 when only shared ones
//     were asked);
//   - the desired-state firewall never calls a shared port a ghost and never
//     keeps it in pergbBlocked: `tcp dport @pergb_blocked drop` would drop
//     every per-GB customer on that port.
// Option B (enable.json carries a dedicated per-GB IPv4 that is not the
// primary one): per-GB lives on its own address, so the port numbers may
// coincide with per-piece ones (10000-10999 = per-piece http mirrors):
//   - the pay-per-GB drop rule is scoped to the primary IPv4
//     (`ip daddr <primary> tcp dport @pergb_blocked drop`; per-piece listens
//     on the primary IPv4 only, so this is the same rule for per-piece);
//   - the firewall ignores listeners bound to the per-GB IPv4;
//   - nothing is refused.
// In both: the per-GB 3proxy loopback listeners 127.0.0.3 / 127.0.0.4 are
// never per-piece (D3) and the ghost firewall ignores them.
// When in doubt (the primary IPv4 cannot be found) the node is treated as
// option A: a shield too many costs a refused per-piece block, a shield too
// few would drop per-GB customers.

const fs = require("fs");
const net = require("net");
const { spawn } = require("child_process");

const DEFAULT_ENABLE_FILE = "/etc/netrun-pergb/enable.json";
const PERGB_LOOPBACK = Object.freeze(["127.0.0.3", "127.0.0.4"]);
const PRIMARY_TTL_MS = 10 * 60_000;
const DEFAULT_SLICE_MEM_MB = 1536; // netrun-pergb.slice MemoryMax default (NETRUN_PERGB_MEM_MAX)
const NFT_TABLE = "proxy_accounting";
const NFT_SET = "pergb_blocked";

function execCapture(cmd, args, { timeoutMs = 5000 } = {}) {
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
      try { child.kill("SIGKILL"); } catch {}
    }, timeoutMs);
    child.stdout.on("data", (d) => { stdout += d.toString("utf-8"); });
    child.stderr.on("data", (d) => { stderr += d.toString("utf-8"); });
    const done = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    };
    child.on("error", (err) => { stderr = stderr || String((err && err.message) || err); done(-1); });
    child.on("close", (code) => done(typeof code === "number" ? code : -1));
  });
}

const isIpv4 = (v) => typeof v === "string" && net.isIPv4(v.trim());
const isPort = (p) => Number.isInteger(p) && p >= 1 && p <= 65535;

// `ip -4 route get 1.1.1.1` -> the source address (the node's primary IPv4,
// the same one netrun-https's public_ipv4 uses), or null.
function parseRouteGetSrc(text) {
  const m = /\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b/.exec(String(text || ""));
  return m && isIpv4(m[1]) ? m[1] : null;
}

// "1536M" / "2G" / 1610612736 (bytes, as systemd reads a plain number) -> MiB, or null.
function parseSizeMb(v) {
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return v / (1024 * 1024);
  const m = /^\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*$/i.exec(String(v === undefined || v === null ? "" : v));
  if (!m) return null;
  const n = Number(m[1]);
  const mult = { "": 1 / (1024 * 1024), K: 1 / 1024, M: 1, G: 1024, T: 1024 * 1024 }[m[2].toUpperCase()];
  const mb = n * mult;
  return Number.isFinite(mb) && mb > 0 ? mb : null;
}

const firstOf = (obj, keys) => {
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  return undefined;
};

// enable.json object -> the parts the shields use. Field names follow I6
// (base, count, egressIpv4, sliceMemMax) with the obvious aliases; `enabled:
// false` means per-GB is off on this node.
function parseEnable(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { state: "error", error: "enable.json is not an object" };
  if (raw.enabled === false) return { state: "off", reason: "enabled_false" };
  const base = Number(firstOf(raw, ["base", "portBase", "port_base"]));
  const countRaw = firstOf(raw, ["count", "portCount", "port_count"]);
  const count = countRaw === undefined ? 1000 : Number(countRaw);
  if (!isPort(base) || !Number.isInteger(count) || count < 1 || !isPort(base + count - 1)) {
    return { state: "error", error: `bad shared range base=${JSON.stringify(raw.base)} count=${JSON.stringify(countRaw)}` };
  }
  // A dedicated per-GB IPv4 (option B): an explicit field, else egressIpv4
  // when it is not the primary (decided once the primary is known).
  const explicit = firstOf(raw, ["pergbIpv4", "dedicatedIpv4", "pergb_ipv4", "ipv4"]);
  const egress = firstOf(raw, ["egressIpv4", "egress_ipv4"]);
  const candidate = isIpv4(explicit) ? explicit.trim() : isIpv4(egress) ? egress.trim() : null;
  const primary = firstOf(raw, ["primaryIpv4", "primary_ipv4"]);
  return {
    state: "on",
    base,
    count,
    last: base + count - 1,
    candidateIpv4: candidate,
    primaryIpv4: isIpv4(primary) ? primary.trim() : null,
    sliceMemMb: parseSizeMb(firstOf(raw, ["sliceMemMax", "slice_mem_max", "memMax"])),
  };
}

function createShield({ env = process.env, run = execCapture, now = () => Date.now(), log = console } = {}) {
  const file = () => String(env.NETRUN_PERGB_ENABLE_FILE || DEFAULT_ENABLE_FILE);
  let cache = null; // { sig, file, value }
  let primaryCache = null; // { at, value }
  let lastNote = null;

  function readEnable() {
    const f = file();
    let st;
    try {
      st = fs.statSync(f);
    } catch (err) {
      cache = null;
      if (err && err.code === "ENOENT") return { state: "off", reason: "no_enable_file" };
      return { state: "error", error: `stat ${f}: ${err.message || err}` };
    }
    const sig = `${st.ino}:${st.size}:${st.mtimeMs}`;
    if (cache && cache.sig === sig && cache.file === f) return cache.value;
    let value;
    try {
      value = parseEnable(JSON.parse(fs.readFileSync(f, "utf-8")));
    } catch (err) {
      value = { state: "error", error: `read ${f}: ${err.message || err}` };
    }
    cache = { sig, file: f, value };
    return value;
  }

  async function primaryIpv4(enable) {
    if (isIpv4(env.NETRUN_PRIMARY_IPV4)) return env.NETRUN_PRIMARY_IPV4.trim();
    if (enable && enable.primaryIpv4) return enable.primaryIpv4;
    // a failed detection is retried after a minute, a found one after ten
    if (primaryCache && now() - primaryCache.at < (primaryCache.value ? PRIMARY_TTL_MS : 60_000)) return primaryCache.value;
    const res = await run("ip", ["-4", "route", "get", "1.1.1.1"], { timeoutMs: 5000 });
    const value = res && res.code === 0 ? parseRouteGetSrc(res.stdout) : null;
    primaryCache = { at: now(), value };
    return value;
  }

  // -> { state: "off" | "error" | "on", option: "A" | "B" | null, base, last,
  //      count, dedicatedIpv4, primaryIpv4, error }
  async function info() {
    const e = readEnable();
    if (e.state !== "on") return { ...e, option: null, dedicatedIpv4: null, primaryIpv4: null };
    const primary = await primaryIpv4(e);
    let option = "A";
    let dedicated = null;
    if (e.candidateIpv4 && primary && e.candidateIpv4 !== primary) {
      option = "B";
      dedicated = e.candidateIpv4;
    }
    const note = `${option}:${dedicated || ""}:${primary || ""}`;
    if (note !== lastNote) {
      lastNote = note;
      if (e.candidateIpv4 && !primary) {
        log.error(`[pergb-shield] per-GB IPv4 ${e.candidateIpv4} but the primary IPv4 is unknown: option A shields stay on`);
      }
    }
    return { ...e, option, dedicatedIpv4: dedicated, primaryIpv4: primary };
  }

  // Option A: the shared ports (Set); otherwise empty.
  async function sharedPorts() {
    const i = await info();
    const out = new Set();
    if (i.state === "on" && i.option === "A") for (let p = i.base; p <= i.last; p += 1) out.add(p);
    return out;
  }

  async function isSharedPort(port) {
    const i = await info();
    const p = Number(port);
    return i.state === "on" && i.option === "A" && p >= i.base && p <= i.last;
  }

  // Listeners the ghost firewall never judges: the per-GB loopback and, with
  // option B, the per-GB IPv4.
  async function ignoredListenAddrs() {
    const out = new Set(PERGB_LOOPBACK);
    const i = await info();
    if (i.state === "on" && i.option === "B" && i.dedicatedIpv4) out.add(i.dedicatedIpv4);
    return out;
  }

  // The pay-per-GB drop rule as the input chain must hold it.
  async function dropRule() {
    const i = await info();
    if (i.state === "on" && i.option === "B" && i.primaryIpv4) {
      const text = `ip daddr ${i.primaryIpv4} tcp dport @${NFT_SET} drop`;
      return { text, args: ["ip", "daddr", i.primaryIpv4, "tcp", "dport", `@${NFT_SET}`, "drop"], scoped: true, primaryIpv4: i.primaryIpv4 };
    }
    return { text: `tcp dport @${NFT_SET} drop`, args: ["tcp", "dport", `@${NFT_SET}`, "drop"], scoped: false, primaryIpv4: null };
  }

  // What per-GB takes from the per-piece capacity model (describe.js):
  // the slice's memory budget, and with option A the shared ports (each one
  // can cost at most one dual pair: its socks or its http side).
  async function capacityBudget() {
    const i = await info();
    if (i.state !== "on") return { enabled: false, memMb: 0, ports: 0, option: null };
    return {
      enabled: true,
      memMb: Math.round(i.sliceMemMb || DEFAULT_SLICE_MEM_MB),
      ports: i.option === "A" ? i.count : 0,
      option: i.option,
    };
  }

  return { info, readEnable, sharedPorts, isSharedPort, ignoredListenAddrs, dropRule, capacityBudget, primaryIpv4: () => primaryIpv4(readEnable()) };
}

let defaultInstance = null;
function defaultShield() {
  if (!defaultInstance) defaultInstance = createShield();
  return defaultInstance;
}

// A per-GB 3proxy process line (`ps` args): its own binary
// /opt/netrun/pergb/bin/3proxy-pergb and cfgs /opt/netrun/pergb/cfg/
// pergb_<sp>.cfg (D3) — never a per-piece batch instance.
function isPergbProcessCmd(cmd) {
  const s = String(cmd || "");
  return /(^|\/)3proxy-pergb(\s|$)/.test(s) || /\/pergb_\d+\.cfg\b/.test(s);
}

class PergbSharedPortError extends Error {
  constructor(port) {
    super(`pergb_shared_port: ${port}`);
    this.name = "PergbSharedPortError";
    this.code = "PERGB_SHARED_PORT";
    this.port = port;
  }
}

module.exports = {
  createShield,
  defaultShield,
  PergbSharedPortError,
  isPergbProcessCmd,
  parseEnable,
  parseRouteGetSrc,
  parseSizeMb,
  PERGB_LOOPBACK,
  DEFAULT_ENABLE_FILE,
  DEFAULT_SLICE_MEM_MB,
  NFT_TABLE,
  NFT_SET,
  // the default instance, for callers that do not inject one
  info: () => defaultShield().info(),
  sharedPorts: () => defaultShield().sharedPorts(),
  isSharedPort: (p) => defaultShield().isSharedPort(p),
  ignoredListenAddrs: () => defaultShield().ignoredListenAddrs(),
  dropRule: () => defaultShield().dropRule(),
  capacityBudget: () => defaultShield().capacityBudget(),
};
