"use strict";

// VPN (owner 2026-10-15) — the node side of the VPN product: VLESS + REALITY on
// Xray-core, one subscription for every VPN node, clients are the usual apps
// (Happ, v2rayNG, Streisand, …) fed by the subscription link.
//
// The orchestrator drives it over the agent's TLS listener (:8086, X-API-KEY):
//   POST /vpn/enable   {entries:[ipv4…], port?, dest, serverNames?, flow?}
//                      -> {publicKey, shortIds, serverNames, flow, port, entries}
//   POST /vpn/disable
//   PUT  /vpn/users    {users:[{id: uuid, email}]}  the full desired set
//   GET  /vpn/usage?ack=<seq>                       traffic batches since ack
//   POST /vpn/kill     {emails:[…]}                 drop live connections
//   GET  /vpn/status
//
// Entries: the node's FREE IPv4s (owner: «берутся все свободные ипв4 ноды» —
// the Vultr secondary addresses the proxies do not use). Each gets its own
// inbound on <ip>:443 and its own freedom outbound marked MARK_BASE+1+i; the
// table inet netrun_vpn SNATs that mark to the same address, so a user leaves
// from the IPv4 he connected to (IPv6 leaves from the node's own IPv6). The
// addresses are added live (`ip addr add <ip>/32`) and persisted in a netplan
// drop-in (pergb_ipv4.ensureAddresses, never `netplan apply`).
//
// Users are applied without a restart (`xray api adu` / `rmu`); a removed user
// keeps no live connection: the access log (tmpfs, read and dropped every few
// seconds, destinations discarded) maps every inbound connection to its user,
// and `ss -K` closes the removed users' ones.
//
// Traffic: `xray api statsquery -pattern user>>> -reset` every meterSec into
// numbered batches (/var/lib/netrun-vpn/meter.json) that the orchestrator
// reads and acknowledges (GET /vpn/usage?ack=). Xray runs with
// XRAY_BUF_SPLICE=disable: with splice a long download is counted only when
// its connection closes (measured 2026-10-15), without it as it flows.
//
// The guard (chain vpn of table inet netrun_vpn, uid netrun-vpn only): no
// private/loopback/link-local/multicast destinations, none of the node's own
// addresses (DNS to the node's resolver excepted), no SMTP (25), established
// traffic passes. Torrents are blocked in Xray (sniffed protocol bittorrent).
//
// Files: /etc/netrun-vpn/{enable.json, keys.json, users.json, xray.json,
// ipv4s.json, nft.conf}, /var/lib/netrun-vpn/meter.json,
// /run/netrun-vpn/access.log (written by Xray as netrun-vpn).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");

const ipv4Lib = require("./pergb_ipv4.js");

const UNIT = "netrun-vpn-xray.service";
const NFT_TABLE = "netrun_vpn";
const MARK_BASE = 0x00566e00;
const DEFAULT_PORT = 443;
const DEFAULT_FLOW = "xtls-rprx-vision";
const FLOWS = new Set(["xtls-rprx-vision", ""]);
const MAX_ENTRIES = 16;
const MAX_USERS = 20000;
const ENABLE_VERSION = 1;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$/;
const SHORT_ID_RE = /^[0-9a-f]{2,16}$/;
// IPv4 / IPv6 destinations no VPN user may reach
const DENY_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"];
const DENY_V6 = ["::1", "fe80::/10", "fc00::/7", "ff00::/8"];

function flag(v, dflt) {
  if (v === undefined || v === null || v === "") return dflt;
  return !/^(0|off|false|no)$/i.test(String(v));
}

function readSettings(env = process.env) {
  const etcDir = String(env.NETRUN_VPN_ETC_DIR || "/etc/netrun-vpn");
  return {
    etcDir,
    libDir: String(env.NETRUN_VPN_LIB_DIR || "/var/lib/netrun-vpn"),
    runDir: String(env.NETRUN_VPN_RUN_DIR || "/run/netrun-vpn"),
    bin: String(env.NETRUN_VPN_BIN || "/opt/netrun/vpn/bin/xray"),
    binSha: String(env.NETRUN_VPN_BIN_SHA256 || "/opt/netrun/vpn/bin/xray.sha256"),
    pinnedSha: String(env.NETRUN_VPN_PINNED_SHA256 || path.resolve(__dirname, "../../deploy/node/bin/xray.sha256")),
    // below the proxy ports (>= 10000; a high one sat in proxy_accounting's
    // pergb_blocked set and was dropped even on lo — Chicago 2026-10-15)
    api: String(env.NETRUN_VPN_API || "127.0.0.1:8087"),
    uid: Number(env.NETRUN_VPN_UID || 65532),
    group: String(env.NETRUN_VPN_GROUP || "netrun-vpn"),
    meterSec: Math.max(2, Number(env.NETRUN_VPN_METER_SEC || 10)),
    logSec: Math.max(1, Number(env.NETRUN_VPN_LOG_SEC || 3)),
    maxBatches: Math.max(10, Number(env.NETRUN_VPN_MAX_BATCHES || 2000)),
    netplanDir: String(env.NETRUN_VPN_NETPLAN_DIR || "/etc/netplan"),
    chown: flag(env.NETRUN_VPN_CHOWN, true),
    systemctl: String(env.NETRUN_VPN_SYSTEMCTL || "systemctl"),
  };
}

// ── pure helpers (exported for the tests) ─────────────────────────

// "host" | "host:port" -> { host, port } | null
function parseDest(v) {
  const s = String(v || "").trim();
  const m = /^([^:\s]+)(?::(\d{1,5}))?$/.exec(s);
  if (!m || !HOST_RE.test(m[1])) return null;
  const port = m[2] ? Number(m[2]) : 443;
  if (!(port >= 1 && port <= 65535)) return null;
  return { host: m[1].toLowerCase(), port };
}

// The enable body -> { ok, params } | { ok: false, error, detail }
function validateEnable(body) {
  const b = body && typeof body === "object" ? body : {};
  const bad = (detail) => ({ ok: false, error: "bad_params", detail });
  const entries = Array.isArray(b.entries) ? [...new Set(b.entries.map((x) => String(x).trim()))] : [];
  if (!entries.length) return bad("entries: at least one IPv4 is required");
  if (entries.length > MAX_ENTRIES) return bad(`entries: at most ${MAX_ENTRIES}`);
  for (const ip of entries) if (!net.isIPv4(ip)) return bad(`entries: not an IPv4: ${ip}`);
  const port = b.port === undefined || b.port === null ? DEFAULT_PORT : Number(b.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return bad("port: 1..65535");
  const dest = parseDest(b.dest);
  if (!dest) return bad("dest: host or host:port of a real TLS 1.3 site");
  let serverNames = Array.isArray(b.serverNames) && b.serverNames.length ? b.serverNames.map((x) => String(x).trim().toLowerCase()) : [dest.host];
  serverNames = [...new Set(serverNames)];
  for (const n of serverNames) if (!HOST_RE.test(n)) return bad(`serverNames: not a hostname: ${n}`);
  const flow = b.flow === undefined || b.flow === null ? DEFAULT_FLOW : String(b.flow);
  if (!FLOWS.has(flow)) return bad(`flow: one of ${[...FLOWS].map((f) => JSON.stringify(f)).join(", ")}`);
  // the node's primary IPv4 serves the proxies: an entry only when asked for
  const allowPrimary = b.allowPrimary === true;
  return { ok: true, params: { entries, port, dest: `${dest.host}:${dest.port}`, serverNames, flow, allowPrimary } };
}

// The users body -> { ok, users } | { ok: false, error, detail }; one email per user
function validateUsers(body) {
  const list = body && Array.isArray(body.users) ? body.users : null;
  if (!list) return { ok: false, error: "bad_params", detail: "users: an array is required" };
  if (list.length > MAX_USERS) return { ok: false, error: "bad_params", detail: `users: at most ${MAX_USERS}` };
  const seen = new Set();
  const users = [];
  for (const u of list) {
    const id = String((u && u.id) || "").toLowerCase();
    const email = String((u && u.email) || "");
    if (!UUID_RE.test(id)) return { ok: false, error: "bad_params", detail: `users: not a uuid: ${id.slice(0, 40)}` };
    if (!EMAIL_RE.test(email)) return { ok: false, error: "bad_params", detail: `users: bad email: ${email.slice(0, 70)}` };
    if (seen.has(email)) return { ok: false, error: "bad_params", detail: `users: repeated email: ${email}` };
    seen.add(email);
    users.push({ id, email });
  }
  users.sort((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0));
  return { ok: true, users };
}

// What changes between two user lists (by email; a new id is a remove + add)
function diffUsers(prev, next) {
  const before = new Map((prev || []).map((u) => [u.email, u.id]));
  const after = new Map((next || []).map((u) => [u.email, u.id]));
  const add = [];
  const remove = [];
  for (const [email, id] of after) if (before.get(email) !== id) add.push({ email, id });
  for (const [email, id] of before) if (after.get(email) !== id) remove.push(email);
  return { add, remove };
}

function inboundTag(i) {
  return `vpn-in-${i}`;
}

function outboundTag(i) {
  return `vpn-out-${i}`;
}

function markOf(i) {
  return MARK_BASE + 1 + i;
}

function clientsOf(users, flow) {
  return users.map((u) => ({ id: u.id, email: u.email, flow, level: 0 }));
}

// The Xray config for these params, keys and users.
function renderConfig({ params, keys, users, settings, ownIps }) {
  const { entries, port, dest, serverNames, flow } = params;
  const deny = [...DENY_V4, ...DENY_V6, ...(ownIps || []).map(normalizeCidr)];
  return {
    log: { loglevel: "warning", access: path.join(settings.runDir, "access.log"), dnsLog: false },
    api: { tag: "api", listen: settings.api, services: ["HandlerService", "StatsService"] },
    stats: {},
    policy: {
      levels: { 0: { handshake: 4, connIdle: 300, uplinkOnly: 1, downlinkOnly: 1, statsUserUplink: true, statsUserDownlink: true } },
      system: {},
    },
    inbounds: entries.map((ip, i) => ({
      tag: inboundTag(i),
      listen: ip,
      port,
      protocol: "vless",
      settings: { clients: clientsOf(users, flow), decryption: "none" },
      streamSettings: {
        network: "tcp",
        security: "reality",
        realitySettings: { show: false, dest, xver: 0, serverNames, privateKey: keys.privateKey, shortIds: keys.shortIds },
      },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true },
    })),
    outbounds: [
      ...entries.map((ip, i) => ({ tag: outboundTag(i), protocol: "freedom", settings: { domainStrategy: "AsIs" }, streamSettings: { sockopt: { mark: markOf(i) } } })),
      { tag: "block", protocol: "blackhole" },
    ],
    routing: {
      domainStrategy: "AsIs",
      rules: [
        { type: "field", protocol: ["bittorrent"], outboundTag: "block" },
        { type: "field", ip: deny, outboundTag: "block" },
        { type: "field", port: "25", network: "tcp", outboundTag: "block" },
        ...entries.map((ip, i) => ({ type: "field", inboundTag: [inboundTag(i)], outboundTag: outboundTag(i) })),
      ],
    },
  };
}

// An IPv6 address -> 8 x 16-bit words (null when not IPv6)
function v6words(a) {
  if (!net.isIPv6(a)) return null;
  let [head, tail] = a.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
  const words = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  return words.length === 8 ? words.map((w) => parseInt(w, 16)) : null;
}

// "2001:db8::5/64" -> "2001:db8::/64", "198.51.100.7/24" -> "198.51.100.0/24"
// (nft and Xray want network addresses); a bare address is returned as is.
function normalizeCidr(cidr) {
  const [a, l] = String(cidr).split("/");
  if (l === undefined) return a;
  const len = Number(l);
  if (net.isIPv4(a)) {
    const n = a.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
    const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
    const v = (n & mask) >>> 0;
    return `${[v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(".")}/${len}`;
  }
  const w = v6words(a);
  if (!w) return cidr;
  const out = w.map((word, i) => {
    const bits = Math.max(0, Math.min(16, len - i * 16));
    return bits === 16 ? word : bits === 0 ? 0 : word & ((0xffff << (16 - bits)) & 0xffff);
  });
  // compress the longest zero run
  let best = [-1, 0];
  for (let i = 0; i < 8; ) {
    if (out[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && out[j] === 0) j += 1;
    if (j - i > best[1] && j - i > 1) best = [i, j - i];
    i = j;
  }
  const hex = out.map((x) => x.toString(16));
  let text;
  if (best[0] < 0) text = hex.join(":");
  else text = `${hex.slice(0, best[0]).join(":")}::${hex.slice(best[0] + best[1]).join(":")}`;
  return `${text}/${len}`;
}

// The node's own addresses for the guard: every IPv4 (/32), the IPv6 networks
// of its interfaces and the locally routed IPv6 prefixes (the BGP /48: `ip -6
// route show table local type local` / blackhole), as network addresses.
function parseOwnAddresses(addrText, routeText) {
  const v4 = new Set();
  const v6 = new Set();
  for (const m of String(addrText || "").matchAll(/\binet (\d+\.\d+\.\d+\.\d+)\/\d+/g)) if (!m[1].startsWith("127.")) v4.add(m[1]);
  for (const m of String(addrText || "").matchAll(/\binet6 ([0-9a-f:]+)\/(\d+)/gi)) {
    const a = m[1].toLowerCase();
    if (a === "::1" || a.startsWith("fe80")) continue;
    const plen = Number(m[2]);
    v6.add(plen >= 128 ? a : normalizeCidr(`${a}/${plen}`));
  }
  for (const line of String(routeText || "").split("\n")) {
    const tok = line.trim().split(/\s+/);
    const cand = ["local", "blackhole", "unreachable", "prohibit"].includes(tok[0]) ? tok[1] : tok[0];
    const m = /^([0-9a-f:]+)\/(\d+)$/i.exec(cand || "");
    if (!m || !net.isIPv6(m[1])) continue;
    const plen = Number(m[2]);
    if (plen < 16 || plen > 64 || /^(fe80|ff)/i.test(m[1])) continue;
    v6.add(normalizeCidr(`${m[1].toLowerCase()}/${plen}`));
  }
  return { v4: [...v4].sort(), v6: [...v6].sort() };
}

// nft -f text: the guard (uid only) and the per-entry SNAT. Replaces the table atomically.
function renderNft({ entries, uid, own }) {
  const lines = [];
  lines.push(`table inet ${NFT_TABLE} {}`);
  lines.push(`delete table inet ${NFT_TABLE}`);
  lines.push(`table inet ${NFT_TABLE} {`);
  lines.push("  chain output {");
  lines.push("    type filter hook output priority 0; policy accept;");
  lines.push(`    meta skuid ${uid} jump vpn`);
  lines.push("  }");
  lines.push("  chain vpn {");
  lines.push("    ct state established,related accept");
  lines.push("    ip daddr 127.0.0.1 udp dport 53 accept");
  lines.push("    ip daddr 127.0.0.1 tcp dport 53 accept");
  lines.push("    ip6 daddr ::1 udp dport 53 accept");
  lines.push("    ip6 daddr ::1 tcp dport 53 accept");
  lines.push(`    ip daddr { ${[...DENY_V4, ...(own.v4 || [])].join(", ")} } reject`);
  lines.push(`    ip6 daddr { ${[...DENY_V6, ...(own.v6 || [])].join(", ")} } reject with icmpv6 port-unreachable`);
  lines.push("    tcp dport 25 reject with tcp reset");
  lines.push("  }");
  lines.push("  chain postrouting {");
  lines.push("    type nat hook postrouting priority srcnat; policy accept;");
  entries.forEach((ip, i) => lines.push(`    meta nfproto ipv4 meta mark 0x${markOf(i).toString(16).padStart(8, "0")} snat ip to ${ip}`));
  lines.push("  }");
  lines.push("}");
  return `${lines.join("\n")}\n`;
}

// `xray api statsquery` JSON -> { email: { up, down } } (only non-zero)
function parseStats(text) {
  let j;
  try {
    j = JSON.parse(String(text || "").trim() || "{}");
  } catch {
    return null;
  }
  const out = {};
  for (const s of (j && j.stat) || []) {
    const m = /^user>>>(.+)>>>traffic>>>(uplink|downlink)$/.exec(String(s.name || ""));
    const v = Number(s.value || 0);
    if (!m || !(v > 0)) continue;
    const u = out[m[1]] || (out[m[1]] = { up: 0, down: 0 });
    if (m[2] === "uplink") u.up += v;
    else u.down += v;
  }
  return out;
}

// Access log lines -> [{ ip, port, email }] (the destination is never kept)
function parseAccess(text) {
  const out = [];
  const re = /\bfrom (?:tcp:|udp:)?(\[[0-9a-f:.]+\]|[0-9.]+):(\d+) accepted\b.*?\bemail: (\S+)/gi;
  for (const m of String(text || "").matchAll(re)) {
    out.push({ ip: m[1].replace(/^\[|\]$/g, ""), port: Number(m[2]), email: m[3] });
  }
  return out;
}

// `xray x25519` output -> { privateKey, publicKey }
function parseX25519(text) {
  const t = String(text || "");
  const priv = /Private ?key:\s*(\S+)/i.exec(t);
  const pub = /(?:Public ?key|Password \(PublicKey\)|Password):\s*(\S+)/i.exec(t);
  return priv && pub ? { privateKey: priv[1], publicKey: pub[1] } : null;
}

// `ss -Htn state established` lines -> Set("ip|port") of the peers on `port`
function parseSsPeers(text, port) {
  const out = new Set();
  for (const line of String(text || "").split("\n")) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const local = cols[cols.length - 2];
    const peer = cols[cols.length - 1];
    const lm = /:(\d+)$/.exec(local);
    const pm = /^\[?([0-9a-f:.]+?)\]?:(\d+)$/i.exec(peer);
    if (!lm || !pm || Number(lm[1]) !== port) continue;
    out.add(`${pm[1].replace(/^::ffff:/i, "")}|${pm[2]}`);
  }
  return out;
}

// ── runtime ───────────────────────────────────────────────────────

// deps: { settings?, env?, run(cmd, args, opts) -> {code, stdout, stderr}, log?, now? }
function createVpn(deps = {}) {
  const settings = { ...readSettings(deps.env || process.env), ...(deps.settings || {}) };
  const log = deps.log || console;
  const run = deps.run || require("./pergb_runtime.js").execCapture;
  const now = deps.now || (() => Date.now());
  const P = {
    enable: path.join(settings.etcDir, "enable.json"),
    keys: path.join(settings.etcDir, "keys.json"),
    users: path.join(settings.etcDir, "users.json"),
    config: path.join(settings.etcDir, "xray.json"),
    nft: path.join(settings.etcDir, "nft.conf"),
    ipv4s: path.join(settings.etcDir, "ipv4s.json"),
    meter: path.join(settings.libDir, "meter.json"),
    access: path.join(settings.runDir, "access.log"),
    accessOld: path.join(settings.runDir, "access.log.1"),
  };
  const conns = new Map(); // "ip|port" -> { email, at }
  let meter = null;
  let applied = null; // the users Xray runs with (null: unknown -> restart applies the file)
  let timers = [];
  let lastMeterAt = null;
  let lastMeterError = null;
  let lastLogError = null;
  let busy = Promise.resolve();

  function serial(fn) {
    const next = busy.then(fn, fn);
    busy = next.catch(() => {});
    return next;
  }

  function readJson(p, dflt) {
    try {
      return JSON.parse(fs.readFileSync(p, "utf-8"));
    } catch {
      return dflt;
    }
  }

  function writeAtomic(p, text, mode, group = false) {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const tmp = `${p}.tmp`;
    fs.writeFileSync(tmp, text, { mode });
    fs.chmodSync(tmp, mode);
    if (group && settings.chown) {
      try {
        fs.chownSync(tmp, 0, gidOf(settings.group));
      } catch (e) {
        log.error(`[vpn] chown ${p}: ${e.message}`);
      }
    }
    fs.renameSync(tmp, p);
  }

  function gidOf(name) {
    const text = fs.readFileSync("/etc/group", "utf-8");
    const line = text.split("\n").find((l) => l.startsWith(`${name}:`));
    if (!line) throw new Error(`no group ${name}`);
    return Number(line.split(":")[2]);
  }

  function enableState() {
    return readJson(P.enable, { version: ENABLE_VERSION, enabled: false });
  }

  function usersFile() {
    const j = readJson(P.users, { users: [] });
    return Array.isArray(j.users) ? j.users : [];
  }

  function loadMeter() {
    if (meter) return meter;
    const j = readJson(P.meter, null);
    meter = j && Number.isInteger(j.seq) && Array.isArray(j.batches) ? j : { seq: 0, batches: [] };
    return meter;
  }

  function saveMeter() {
    writeAtomic(P.meter, `${JSON.stringify(meter)}\n`, 0o600);
  }

  function installed() {
    return fs.existsSync(settings.bin) && fs.existsSync(settings.etcDir);
  }

  function sha256File(p) {
    return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
  }

  // the installed binary is the pinned one -> null | error code
  function binaryCheck() {
    if (!installed()) return "vpn_not_installed";
    let pinned = null;
    try {
      pinned = fs.readFileSync(settings.pinnedSha, "utf-8").trim().split(/\s+/)[0];
    } catch {
      return null; // no pin in this checkout (tests)
    }
    try {
      if (sha256File(settings.bin) !== pinned) return "binary_hash_mismatch";
    } catch {
      return "vpn_not_installed";
    }
    return null;
  }

  async function ensureKeys() {
    const k = readJson(P.keys, null);
    if (k && k.privateKey && k.publicKey && Array.isArray(k.shortIds) && k.shortIds.length) return k;
    const r = await run(settings.bin, ["x25519"], { timeoutMs: 10000 });
    const pair = r.code === 0 ? parseX25519(r.stdout) : null;
    if (!pair) throw new Error(`xray x25519 failed: ${String(r.stderr || r.stdout).trim().slice(0, 200)}`);
    const keys = { ...pair, shortIds: [crypto.randomBytes(4).toString("hex"), crypto.randomBytes(8).toString("hex")], createdAt: new Date(now()).toISOString() };
    writeAtomic(P.keys, `${JSON.stringify(keys, null, 2)}\n`, 0o600);
    return keys;
  }

  async function primaryIpv4() {
    const r = await run("ip", ["-4", "route", "get", "1.1.1.1"], { timeoutMs: 10000 });
    const m = /\bsrc (\d+\.\d+\.\d+\.\d+)/.exec(String((r && r.stdout) || ""));
    return r && r.code === 0 && m ? m[1] : null;
  }

  async function ownAddresses() {
    const a = await run("ip", ["-o", "addr", "show"], { timeoutMs: 10000 });
    const r = await run("ip", ["-6", "route", "show", "type", "blackhole"], { timeoutMs: 10000 });
    const l = await run("ip", ["-6", "route", "show", "table", "local", "type", "local"], { timeoutMs: 10000 });
    return parseOwnAddresses(a.stdout, `${r.stdout || ""}\n${l.stdout || ""}`);
  }

  async function applyNft(entries) {
    const own = await ownAddresses();
    const text = renderNft({ entries, uid: settings.uid, own });
    writeAtomic(P.nft, text, 0o600);
    const r = await run("nft", ["-f", P.nft], { timeoutMs: 15000 });
    if (r.code !== 0) throw new Error(`nft: ${String(r.stderr || r.stdout).trim().slice(0, 300)}`);
    return own;
  }

  function writeConfig(params, keys, users, own) {
    const ownIps = [...own.v4, ...own.v6];
    const cfg = renderConfig({ params, keys, users, settings, ownIps });
    const text = `${JSON.stringify(cfg, null, 2)}\n`;
    let cur = null;
    try {
      cur = fs.readFileSync(P.config, "utf-8");
    } catch {}
    if (cur === text) return false;
    writeAtomic(P.config, text, 0o640, true);
    return true;
  }

  async function systemctl(args, timeoutMs = 30000) {
    return run(settings.systemctl, args, { timeoutMs });
  }

  async function active() {
    const r = await systemctl(["is-active", UNIT], 10000);
    return r.code === 0 && String(r.stdout).trim() === "active";
  }

  // `xray api <cmd> --server=… <rest>` (Go flags stop at the first positional)
  async function api(args, timeoutMs = 10000) {
    const [cmd, ...rest] = args;
    return run(settings.bin, ["api", cmd, `--server=${settings.api}`, ...rest], { timeoutMs });
  }

  // the API answers (after a start/restart)
  async function waitApi(ms = 10000) {
    const until = now() + ms;
    while (now() < until) {
      const r = await api(["statsquery", "-pattern", "netrun-probe"], 3000);
      if (r.code === 0) return true;
      await new Promise((res) => setTimeout(res, 300));
    }
    return false;
  }

  async function restart() {
    const r = await systemctl(["restart", UNIT]);
    if (r.code !== 0) throw new Error(`systemctl restart ${UNIT}: ${String(r.stderr || "").trim().slice(0, 200)}`);
    if (!(await waitApi())) throw new Error("xray api not answering after restart");
    applied = usersFile();
  }

  async function enable(body) {
    const v = validateEnable(body);
    if (!v.ok) return { status: 400, body: { success: false, error: v.error, detail: v.detail } };
    const bin = binaryCheck();
    if (bin) return { status: 409, body: { success: false, error: bin } };
    const params = v.params;
    const primary = await primaryIpv4();
    if (primary && params.entries.includes(primary) && !params.allowPrimary) {
      return { status: 409, body: { success: false, error: "primary_ipv4", detail: `${primary} is the node's primary IPv4 (the proxies'); pass allowPrimary to use it` } };
    }
    const ip = await ipv4Lib.ensureAddresses(params.entries.filter((a) => a !== primary), {
      run,
      log,
      settings: { netplanDir: settings.netplanDir, statePath: P.ipv4s, dropinName: "61-netrun-vpn.yaml", dropinTitle: "VPN entry IPv4s (node_agent/vpn_runtime.js, POST /vpn/enable)" },
    });
    if (!ip.ok) return { status: 409, body: { success: false, error: ip.error, detail: ip.detail } };
    const keys = await ensureKeys();
    const prev = enableState();
    const state = { version: ENABLE_VERSION, enabled: true, params, iface: ip.iface, enabledAt: prev.enabledAt || new Date(now()).toISOString(), updatedAt: new Date(now()).toISOString() };
    writeAtomic(P.enable, `${JSON.stringify(state, null, 2)}\n`, 0o600);
    const own = await applyNft(params.entries);
    const changed = writeConfig(params, keys, usersFile(), own);
    await systemctl(["enable", UNIT]);
    if (changed || !(await active())) await restart();
    startLoops();
    log.log(`[vpn] enabled on ${params.entries.join(",")}:${params.port} (dest ${params.dest})`);
    return { status: 200, body: { success: true, ...publicParams(params, keys) } };
  }

  function publicParams(params, keys) {
    return { publicKey: keys.publicKey, shortIds: keys.shortIds, serverNames: params.serverNames, flow: params.flow, port: params.port, entries: params.entries, dest: params.dest };
  }

  async function disable() {
    await systemctl(["disable", "--now", UNIT]);
    await run("nft", ["delete", "table", "inet", NFT_TABLE], { timeoutMs: 10000 });
    await ipv4Lib.ensureAddresses([], { run, log, settings: { netplanDir: settings.netplanDir, statePath: P.ipv4s, dropinName: "61-netrun-vpn.yaml" } });
    const state = { ...enableState(), enabled: false, updatedAt: new Date(now()).toISOString() };
    writeAtomic(P.enable, `${JSON.stringify(state, null, 2)}\n`, 0o600);
    stopLoops();
    applied = null;
    conns.clear();
    log.log("[vpn] disabled");
    return { status: 200, body: { success: true } };
  }

  async function putUsers(body) {
    const v = validateUsers(body);
    if (!v.ok) return { status: 400, body: { success: false, error: v.error, detail: v.detail } };
    const st = enableState();
    writeAtomic(P.users, `${JSON.stringify({ users: v.users, updatedAt: new Date(now()).toISOString() })}\n`, 0o600);
    if (!st.enabled) return { status: 200, body: { success: true, users: v.users.length, applied: false } };
    const keys = await ensureKeys();
    const own = await ownAddresses();
    writeConfig(st.params, keys, v.users, own);
    if (!(await active())) {
      await restart();
      return { status: 200, body: { success: true, users: v.users.length, applied: true, restarted: true } };
    }
    const d = diffUsers(applied || [], v.users);
    let restarted = false;
    try {
      if (applied === null) throw new Error("applied users unknown");
      await applyDiff(st.params, d);
    } catch (e) {
      log.error(`[vpn] user diff via api failed (${e.message}) — restarting with the full list`);
      await restart();
      restarted = true;
    }
    applied = v.users;
    const killed = d.remove.length ? await killEmails(d.remove) : 0;
    return { status: 200, body: { success: true, users: v.users.length, added: d.add.length, removed: d.remove.length, killed, restarted } };
  }

  async function applyDiff(params, d) {
    const tags = params.entries.map((_ip, i) => inboundTag(i));
    for (let i = 0; i < d.remove.length; i += 200) {
      const chunk = d.remove.slice(i, i + 200);
      for (const tag of tags) {
        const r = await api(["rmu", `-tag=${tag}`, ...chunk], 30000);
        if (r.code !== 0 && !/not found/i.test(String(r.stderr || r.stdout))) throw new Error(`rmu ${tag}: ${String(r.stderr || r.stdout).trim().slice(0, 200)}`);
      }
    }
    if (d.add.length) {
      const file = path.join(settings.etcDir, `adu-${process.pid}.json`);
      const doc = { inbounds: tags.map((tag) => ({ tag, port: params.port, protocol: "vless", settings: { clients: clientsOf(d.add, params.flow), decryption: "none" } })) };
      writeAtomic(file, JSON.stringify(doc), 0o600);
      try {
        const r = await api(["adu", file], 60000);
        if (r.code !== 0) throw new Error(`adu: ${String(r.stderr || r.stdout).trim().slice(0, 200)}`);
      } finally {
        try {
          fs.unlinkSync(file);
        } catch {}
      }
    }
  }

  // close the live connections of these users -> how many were closed
  async function killEmails(emails) {
    const want = new Set(emails);
    const st = enableState();
    const port = (st.params && st.params.port) || DEFAULT_PORT;
    let killed = 0;
    for (const [key, c] of conns) {
      if (!want.has(c.email)) continue;
      const [ip, p] = key.split("|");
      const dst = net.isIPv6(ip) ? `[${ip}]` : ip;
      const r = await run("ss", ["-K", "-H", "-t", "-n", "state", "established", "(", "sport", "=", `:${port}`, "and", "dst", dst, "and", "dport", "=", `:${p}`, ")"], { timeoutMs: 10000 });
      if (r.code === 0 && String(r.stdout).trim()) killed += String(r.stdout).trim().split("\n").length;
      conns.delete(key);
    }
    return killed;
  }

  async function kill(body) {
    const emails = body && Array.isArray(body.emails) ? body.emails.map(String).filter((e) => EMAIL_RE.test(e)) : [];
    if (!emails.length) return { status: 400, body: { success: false, error: "bad_params", detail: "emails: a non-empty array" } };
    await readAccessLog();
    return { status: 200, body: { success: true, killed: await killEmails(emails) } };
  }

  async function usage(q) {
    const m = loadMeter();
    const ack = Number(q && q.ack);
    if (Number.isInteger(ack) && ack > 0) {
      const before = m.batches.length;
      m.batches = m.batches.filter((b) => b.seq > ack);
      if (m.batches.length !== before) saveMeter();
    }
    const limit = Math.min(500, Math.max(1, Number((q && q.limit) || 200)));
    return { status: 200, body: { success: true, seq: m.seq, pending: m.batches.length, batches: m.batches.slice(0, limit), lastMeterAt, lastMeterError } };
  }

  // one stats read -> a new batch when anything moved
  async function meterTick() {
    const st = enableState();
    if (!st.enabled) return null;
    const r = await api(["statsquery", "-pattern", "user>>>", "-reset"], 10000);
    if (r.code !== 0) {
      lastMeterError = String(r.stderr || r.stdout).trim().slice(0, 200);
      return null;
    }
    const users = parseStats(r.stdout);
    if (users === null) {
      lastMeterError = "unparsable statsquery output";
      return null;
    }
    lastMeterAt = new Date(now()).toISOString();
    lastMeterError = null;
    if (!Object.keys(users).length) return null;
    const m = loadMeter();
    m.seq += 1;
    m.batches.push({ seq: m.seq, at: lastMeterAt, users });
    // the orchestrator away for long: fold the oldest batches together (no byte is lost)
    while (m.batches.length > settings.maxBatches) {
      const [a, b] = m.batches.splice(0, 2);
      const merged = { seq: b.seq, at: b.at, users: { ...a.users } };
      for (const [e, u] of Object.entries(b.users)) {
        const t = merged.users[e] || (merged.users[e] = { up: 0, down: 0 });
        t.up += u.up;
        t.down += u.down;
      }
      m.batches.unshift(merged);
    }
    saveMeter();
    return m.seq;
  }

  // rotate the access log, map connections to users, forget the rest
  async function readAccessLog() {
    let size = 0;
    try {
      size = fs.statSync(P.access).size;
    } catch {
      return 0;
    }
    if (!size) return 0;
    try {
      fs.renameSync(P.access, P.accessOld);
    } catch (e) {
      lastLogError = e.message;
      return 0;
    }
    await api(["restartlogger"], 5000);
    let text = "";
    try {
      text = fs.readFileSync(P.accessOld, "utf-8");
    } finally {
      try {
        fs.unlinkSync(P.accessOld);
      } catch {}
    }
    const t = now();
    let n = 0;
    for (const c of parseAccess(text)) {
      conns.set(`${c.ip}|${c.port}`, { email: c.email, at: t });
      n += 1;
    }
    lastLogError = null;
    return n;
  }

  // drop the mappings of connections that are gone (a minute's grace: the
  // log can name a connection before ss lists it)
  async function pruneConns() {
    const st = enableState();
    const port = (st.params && st.params.port) || DEFAULT_PORT;
    const r = await run("ss", ["-H", "-t", "-n", "state", "established", "(", "sport", "=", `:${port}`, ")"], { timeoutMs: 15000 });
    if (r.code !== 0) return;
    const live = parseSsPeers(r.stdout, port);
    const graceFrom = now() - 60000;
    for (const [key, c] of conns) if (!live.has(key) && c.at < graceFrom) conns.delete(key);
  }

  function every(ms, fn, name) {
    const t = setInterval(() => {
      fn().catch((e) => log.error(`[vpn] ${name}: ${(e && e.message) || e}`));
    }, ms);
    if (typeof t.unref === "function") t.unref();
    timers.push(t);
  }

  function startLoops() {
    if (timers.length) return;
    every(settings.meterSec * 1000, meterTick, "meter");
    every(settings.logSec * 1000, readAccessLog, "access log");
    every(10 * 60 * 1000, pruneConns, "prune");
  }

  function stopLoops() {
    for (const t of timers) clearInterval(t);
    timers = [];
  }

  // agent start: an enabled node gets its addresses, guard and Xray back
  async function start() {
    const st = enableState();
    if (!st.enabled || !installed()) return { enabled: false };
    try {
      const primary = await primaryIpv4();
      await ipv4Lib.ensureAddresses(
        st.params.entries.filter((a) => a !== primary),
        { run, log, settings: { netplanDir: settings.netplanDir, statePath: P.ipv4s, dropinName: "61-netrun-vpn.yaml" } }
      );
      const own = await applyNft(st.params.entries);
      const keys = await ensureKeys();
      // a new agent may render another config (a deploy): Xray must run it
      const changed = writeConfig(st.params, keys, usersFile(), own);
      if (changed || !(await active())) await restart();
      else applied = usersFile();
    } catch (e) {
      log.error(`[vpn] start: ${(e && e.message) || e}`);
    }
    startLoops();
    return { enabled: true };
  }

  async function status() {
    const st = enableState();
    const keys = readJson(P.keys, null);
    const m = loadMeter();
    let version = null;
    if (installed()) {
      const r = await run(settings.bin, ["version"], { timeoutMs: 5000 });
      const vm = /Xray (\S+)/.exec(String(r.stdout || ""));
      version = vm ? vm[1] : null;
    }
    return {
      success: true,
      installed: installed(),
      binary: installed() ? binaryCheck() || "ok" : null,
      version,
      enabled: !!st.enabled,
      active: st.enabled ? await active() : false,
      params: st.enabled && keys ? publicParams(st.params, keys) : null,
      users: usersFile().length,
      applied: applied ? applied.length : null,
      conns: conns.size,
      meter: { seq: m.seq, pending: m.batches.length, lastMeterAt, lastMeterError },
      accessLogError: lastLogError,
    };
  }

  return {
    settings,
    paths: P,
    enable: (b) => serial(() => enable(b)),
    disable: () => serial(() => disable()),
    putUsers: (b) => serial(() => putUsers(b)),
    kill: (b) => serial(() => kill(b)),
    usage,
    status,
    start,
    meterTick,
    readAccessLog,
    pruneConns,
    stopLoops,
    get conns() {
      return conns;
    },
  };
}

// The agent's TLS listener: /vpn/* -> { status, body } | null (not a VPN route)
async function handleRoute(vpn, method, pathname, query, body) {
  if (pathname !== "/vpn" && !pathname.startsWith("/vpn/")) return null;
  if (method === "GET" && pathname === "/vpn/status") return { status: 200, body: await vpn.status() };
  if (method === "POST" && pathname === "/vpn/enable") return vpn.enable(body);
  if (method === "POST" && pathname === "/vpn/disable") return vpn.disable();
  if (method === "PUT" && pathname === "/vpn/users") return vpn.putUsers(body);
  if (method === "GET" && pathname === "/vpn/usage") return vpn.usage(query);
  if (method === "POST" && pathname === "/vpn/kill") return vpn.kill(body);
  return { status: 404, body: { success: false, error: "not_found" } };
}

module.exports = {
  UNIT,
  NFT_TABLE,
  MARK_BASE,
  readSettings,
  normalizeCidr,
  parseDest,
  validateEnable,
  validateUsers,
  diffUsers,
  renderConfig,
  renderNft,
  parseOwnAddresses,
  parseStats,
  parseAccess,
  parseX25519,
  parseSsPeers,
  inboundTag,
  outboundTag,
  markOf,
  createVpn,
  handleRoute,
};
