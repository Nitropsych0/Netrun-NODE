"use strict";

// Wave FLEET-HEALTH (RES-10) — per-cfg serving status and IPv6 address
// coverage for GET /health, so the orchestrator's health model can tell
// "agent up, every batch listening, every egress address on the box" from
// "agent up but a batch is dead / its /64 addresses are gone" without ever
// calling /reconcile.
//
// Pure helpers (parse a cfg, parse the kernel's address list, fold the
// pieces into a verdict) plus two small caches:
//   - createCfgInventory: re-parses a 3proxy_<start>.cfg only when its
//     mtime/size changed (a batch cfg is ~1500 blocks; /health is polled);
//   - createCoverageProbe: expected (cfg -e addresses) vs present (kernel)
//     IPv6 addresses, recomputed at most every ttlMs (default 60 s).

const fsp = require("fs/promises");
const path = require("path");

const CFG_FILE_RE = /^3proxy_(\d+)\.cfg$/;
const IF_INET6_PATH = "/proc/net/if_inet6";

// IPv6 text -> 32 lowercase hex digits (the /proc/net/if_inet6 spelling), or
// null. Accepts compressed / leading-zero-less groups and an optional /len.
function ipv6ToHex(text) {
  let s = String(text || "").trim().toLowerCase();
  if (!s) return null;
  const slash = s.indexOf("/");
  if (slash >= 0) s = s.slice(0, slash);
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!/^[0-9a-f:]+$/.test(s)) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    groups = [...left, ...new Array(fill).fill("0"), ...right];
  } else {
    groups = left;
  }
  if (groups.length !== 8) return null;
  let out = "";
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out += g.padStart(4, "0");
  }
  return out;
}

// One 3proxy cfg -> what /health needs from it. probePort = the first socks
// port in the file (first proxy/http port for an http-only cfg): after a
// /deprovision rewrite the block of the file's start port may be gone while
// the batch still serves, so the file name alone is not a listening probe.
//
// Audit FP-01 — also the cfg's resolvers (`nserver` lines) and the egress
// family flags of its service lines (-6 / -64 / -46 / -4; none = 3proxy's
// default, IPv4), for /health's static checks: third-party DNS left over from
// the 2026-05 geo seed, and a batch that can leave over IPv4 while the node is
// in ipv6_only egress mode (the dual-stack self-check never ran).
//
// probeAddr: the listen address (-i) of the probe line. An http-only cfg on a
// node with the HTTPS front binds 127.0.0.1:<port> while haproxy holds
// <public-ip>:<port>: a bare port probe would read haproxy's frontend as the
// batch listening (cfgListening below matches the address for such a cfg).
function parseCfgSummary(text) {
  const socksPorts = [];
  const httpPorts = [];
  const egress = new Set();
  const nservers = [];
  const modeFlags = new Set();
  let socksAddr;
  let httpAddr;
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    const ns = /^nserver\s+(\S+)/.exec(line);
    if (ns) {
      nservers.push(ns[1]);
      continue;
    }
    const isSocks = /^socks\s/.test(line);
    const isHttp = /^proxy\s/.test(line);
    if (!isSocks && !isHttp) continue;
    const pm = /(?:^|\s)-p(\d+)(?:\s|$)/.exec(line);
    if (pm) {
      (isSocks ? socksPorts : httpPorts).push(Number(pm[1]));
      const im = /(?:^|\s)-i(\S+)/.exec(line);
      if (isSocks && socksAddr === undefined) socksAddr = im ? im[1] : null;
      if (isHttp && httpAddr === undefined) httpAddr = im ? im[1] : null;
    }
    const em = /(?:^|\s)-e(\S+)/.exec(line);
    if (em && em[1].includes(":")) egress.add(em[1]);
    const fm = /(?:^|\s)(-64|-46|-6|-4)(?=\s|$)/.exec(line);
    modeFlags.add(fm ? fm[1] : "none");
  }
  const primary = socksPorts.length ? socksPorts : httpPorts;
  const probeAddr = socksPorts.length ? socksAddr : httpAddr;
  return {
    probePort: primary.length ? primary[0] : null,
    probeAddr: probeAddr || null,
    httpOnly: socksPorts.length === 0 && httpPorts.length > 0,
    count: primary.length,
    socksPorts,
    httpPorts,
    egress: [...egress],
    nservers,
    modeFlags: [...modeFlags].sort(),
  };
}

// "[2001:db8::1]" / "127.0.0.1%lo" / "::FFFF:1.2.3.4" -> the bare lowercase address.
function normalizeListenAddr(addr) {
  // The zone first: ss prints a device-bound socket as "[::1]%lo".
  return String(addr || "").trim().replace(/%.*$/, "").replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
}

const WILDCARD_ADDRS = new Set(["", "*", "0.0.0.0", "::"]);

function listenKey(addr, port) {
  return `${normalizeListenAddr(addr)}:${port}`;
}

// `ss -ltn` text -> Set of "<addr>:<port>" of the listeners (local column).
function parseListenKeys(text) {
  const out = new Set();
  for (const raw of String(text || "").split(/\r?\n/)) {
    const fields = raw.trim().split(/\s+/);
    if (fields.length < 2) continue;
    const local = fields.length >= 4 ? fields[3] : fields[fields.length - 1];
    const m = /^(.*):(\d+)$/.exec(String(local || ""));
    if (!m) continue;
    const port = Number(m[2]);
    if (Number.isInteger(port) && port > 0 && port <= 65535) out.add(listenKey(m[1], port));
  }
  return out;
}

// Is the cfg's probe listener up? An http-only cfg bound to a specific
// address is matched on address:port (keys), so haproxy's frontend on the
// same port number never counts; every other cfg on the port (ports).
function cfgListening(c, ports, keys = null) {
  const probe = Number.isInteger(c && c.probePort) && c.probePort > 0 ? c.probePort : c && c.startPort;
  if (keys && c && c.httpOnly && c.probeAddr && !WILDCARD_ADDRS.has(normalizeListenAddr(c.probeAddr))) {
    return keys.has(listenKey(c.probeAddr, probe));
  }
  return Boolean(ports && ports.has(probe));
}

// A resolver that is not the node's own unbound (127.0.0.0/8, ::1, localhost;
// an optional :port).
function isLocalResolver(addr) {
  const a = String(addr || "").trim().toLowerCase().replace(/^\[(.*)\](?::\d+)?$/, "$1");
  if (a === "::1" || a === "localhost") return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$/.test(a);
}

// Static per-cfg checks for /health (cfgs = createCfgInventory().read().cfgs):
//   legacyDns: cfgs whose nserver lines name third-party resolvers;
//   egressFamily: with an expected flag (ipv6_only -> "-6"), cfgs whose
//     service lines carry anything else (-64 / -46 / -4 / none = IPv4 egress
//     possible). expectedFlag null (dualstack / unknown) checks nothing.
function staticCfgChecks(cfgs, { expectedFlag = null, sample = 20 } = {}) {
  const legacy = [];
  const family = [];
  for (const c of Array.isArray(cfgs) ? cfgs : []) {
    const bad = (c.nservers || []).filter((a) => !isLocalResolver(a));
    if (bad.length) legacy.push({ startPort: c.startPort, nservers: [...new Set(bad)].slice(0, 4) });
    if (expectedFlag && (c.modeFlags || []).some((f) => f !== expectedFlag)) {
      family.push({ startPort: c.startPort, flags: c.modeFlags });
    }
  }
  return {
    cfgsLegacyDns: { count: legacy.length, items: legacy.slice(0, sample) },
    cfgsEgressFamily: expectedFlag
      ? { expectedFlag, mismatched: family.length, items: family.slice(0, sample) }
      : { expectedFlag: null, mismatched: null, items: [] },
  };
}

// /proc/net/if_inet6: "<32 hex> <ifindex> <plen> <scope> <flags> <ifname>".
// Returns Set of hex addresses (optionally only those on `iface`).
function parseIfInet6(text, { iface = null } = {}) {
  const out = new Set();
  for (const raw of String(text || "").split(/\r?\n/)) {
    const f = raw.trim().split(/\s+/);
    if (f.length < 1 || !/^[0-9a-f]{32}$/i.test(f[0])) continue;
    if (iface && f[5] !== iface) continue;
    out.add(f[0].toLowerCase());
  }
  return out;
}

// `ip -6 addr show [dev X]` / `ip -6 -o addr show` text -> Set of hex addresses.
function parseIpAddrShow(text) {
  const out = new Set();
  for (const m of String(text || "").matchAll(/\binet6\s+([0-9a-fA-F:]+)(?:\/\d+)?/g)) {
    const hex = ipv6ToHex(m[1]);
    if (hex) out.add(hex);
  }
  return out;
}

// expected = iterable of IPv6 strings (cfg -e values; duplicates collapse);
// present = Set of hex. -> { expected, present, missing, missingSample }.
function computeAddressCoverage(expectedAddrs, presentHex, { sample = 10 } = {}) {
  const seen = new Set();
  const missingSample = [];
  let present = 0;
  let missing = 0;
  for (const addr of expectedAddrs || []) {
    const hex = ipv6ToHex(addr);
    if (!hex || seen.has(hex)) continue;
    seen.add(hex);
    if (presentHex && presentHex.has(hex)) {
      present += 1;
    } else {
      missing += 1;
      if (missingSample.length < sample) missingSample.push(String(addr));
    }
  }
  return { expected: seen.size, present, missing, missingSample };
}

// Fold the cfg inventory, the running 3proxy instances and the listening-port
// probe into the per-cfg list. cfgs = [{ startPort, cfgPath, probePort, count }],
// instances = collectRunningInstances().instances, listeningPorts = Set|array.
// When the port probe failed (portsOk false) `listening` and `cfgsDown` are
// null (unknown), never "down".
// listeningKeys (Set of "<addr>:<port>", optional): address-aware probe for
// http-only cfgs (cfgListening).
function computeCfgStatus({ cfgs, instances, listeningPorts, listeningKeys = null, portsOk = true, maxItems = 500 } = {}) {
  const portSet =
    listeningPorts instanceof Set
      ? listeningPorts
      : new Set(Array.isArray(listeningPorts) ? listeningPorts.map(Number) : []);
  const pidsByStart = new Map();
  for (const inst of Array.isArray(instances) ? instances : []) {
    const sp = Number(inst && inst.startPort);
    const pid = Number(inst && inst.pid);
    if (!Number.isInteger(sp) || sp <= 0 || !Number.isInteger(pid) || pid <= 0) continue;
    if (!pidsByStart.has(sp)) pidsByStart.set(sp, []);
    pidsByStart.get(sp).push(pid);
  }
  const items = [];
  const withoutProcess = [];
  let down = 0;
  for (const c of Array.isArray(cfgs) ? cfgs : []) {
    const startPort = Number(c && c.startPort);
    if (!Number.isInteger(startPort) || startPort <= 0) continue;
    const pids = (pidsByStart.get(startPort) || []).sort((a, b) => a - b);
    const listening = portsOk ? cfgListening({ ...c, startPort }, portSet, listeningKeys) : null;
    if (listening === false) down += 1;
    if (pids.length === 0) withoutProcess.push({ startPort, cfgPath: c.cfgPath || null });
    items.push({
      startPort,
      count: Number.isInteger(c.count) ? c.count : null,
      listening,
      pid: pids.length ? pids[0] : null,
    });
  }
  items.sort((a, b) => a.startPort - b.startPort);
  return {
    cfgs: items.slice(0, Math.max(0, maxItems)),
    cfgsTotal: items.length,
    cfgsTruncated: items.length > maxItems,
    cfgsDown: portsOk ? down : null,
    cfgsWithoutProcess: withoutProcess.sort((a, b) => a.startPort - b.startPort),
  };
}

// Active cfg files (3proxy_<start>.cfg; *.cfg.disabled are off on purpose),
// parsed once per (mtime, size, inode). The inode is part of the key: the
// spawn helper's DNS fix-forward rewrites a cfg (tmp + mv: a new inode) and
// keeps its mtime, and the rewrite may keep the size too.
function createCfgInventory({ cfgDir, fs: fsImpl = fsp } = {}) {
  const cache = new Map(); // name -> { mtimeMs, size, ino, summary }
  async function read() {
    let names;
    try {
      names = await fsImpl.readdir(cfgDir);
    } catch (err) {
      if (err && err.code === "ENOENT") {
        cache.clear();
        return { ok: true, cfgs: [] };
      }
      return { ok: false, error: String((err && err.message) || err), cfgs: [] };
    }
    const live = new Set();
    const cfgs = [];
    for (const name of names) {
      const m = CFG_FILE_RE.exec(name);
      if (!m) continue;
      const cfgPath = path.join(cfgDir, name);
      let st;
      try {
        st = await fsImpl.stat(cfgPath);
      } catch {
        continue; // removed meanwhile
      }
      live.add(name);
      let hit = cache.get(name);
      if (!hit || hit.mtimeMs !== st.mtimeMs || hit.size !== st.size || hit.ino !== st.ino) {
        let text = "";
        try {
          text = await fsImpl.readFile(cfgPath, "utf-8");
        } catch {
          continue;
        }
        hit = { mtimeMs: st.mtimeMs, size: st.size, ino: st.ino, summary: parseCfgSummary(text) };
        cache.set(name, hit);
      }
      cfgs.push({
        startPort: Number(m[1]),
        cfgPath,
        probePort: hit.summary.probePort,
        probeAddr: hit.summary.probeAddr,
        httpOnly: hit.summary.httpOnly,
        count: hit.summary.count,
        egress: hit.summary.egress,
        nservers: hit.summary.nservers,
        modeFlags: hit.summary.modeFlags,
        socksPorts: hit.summary.socksPorts,
        httpPorts: hit.summary.httpPorts,
        mtimeMs: st.mtimeMs,
      });
    }
    for (const name of [...cache.keys()]) if (!live.has(name)) cache.delete(name);
    cfgs.sort((a, b) => a.startPort - b.startPort);
    return { ok: true, cfgs };
  }
  return { read };
}

// Expected (distinct -e addresses of the active cfgs) vs present (kernel)
// IPv6 addresses, cached for ttlMs. readCfgs() -> { ok, cfgs }, readPresent()
// -> Set of hex. Concurrent callers share one computation.
function createCoverageProbe({
  ttlMs = 60_000,
  readCfgs,
  readPresent = async () => parseIfInet6(await fsp.readFile(IF_INET6_PATH, "utf-8")),
  now = () => Date.now(),
} = {}) {
  let cached = null;
  let inFlight = null;
  async function compute() {
    const at = now();
    try {
      const inv = await readCfgs();
      if (!inv || !inv.ok) {
        return { ok: false, error: (inv && inv.error) || "cfg_read_failed", expected: null, present: null, missing: null, checkedAt: new Date(at).toISOString() };
      }
      const expected = [];
      for (const c of inv.cfgs) for (const a of c.egress || []) expected.push(a);
      const presentHex = await readPresent();
      return {
        ok: true,
        error: null,
        ...computeAddressCoverage(expected, presentHex),
        source: IF_INET6_PATH,
        checkedAt: new Date(at).toISOString(),
      };
    } catch (err) {
      return { ok: false, error: String((err && err.message) || err), expected: null, present: null, missing: null, checkedAt: new Date(at).toISOString() };
    }
  }
  async function get() {
    if (cached && now() - cached.atMs < ttlMs) return cached.value;
    if (inFlight) return inFlight;
    inFlight = (async () => {
      try {
        const value = await compute();
        cached = { atMs: now(), value };
        return value;
      } finally {
        inFlight = null;
      }
    })();
    return inFlight;
  }
  function invalidate() {
    cached = null;
  }
  return { get, invalidate };
}

module.exports = {
  ipv6ToHex,
  parseCfgSummary,
  normalizeListenAddr,
  listenKey,
  parseListenKeys,
  cfgListening,
  isLocalResolver,
  staticCfgChecks,
  parseIfInet6,
  parseIpAddrShow,
  computeAddressCoverage,
  computeCfgStatus,
  createCfgInventory,
  createCoverageProbe,
  IF_INET6_PATH,
};
