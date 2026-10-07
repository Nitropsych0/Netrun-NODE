"use strict";

// Wave IPV6-ROTATION — change the outgoing IPv6 of single proxies without
// touching 3proxy (docs/wave_ipv6_rotation_plan.md, section 1).
//
// Why not a cfg change: one 3proxy process serves a whole batch (up to 1500
// ports of many customers, per-piece and pay-per-GB alike) and every cfg writer
// restarts it, which cuts every live session in the batch. SIGUSR1 is no way
// out either: 0.9.3 frees its config before re-opening the cfg path, and a
// /root path is unreadable after `setuid 65535` → a batch with no listeners.
//
// So each port keeps binding its upstream sockets to the `-e` address of its
// `socks` line (the ANCHOR; the paired http port shares it) and an nftables
// SNAT rewrites the source of NEW connections:
//
//   table ip6 netrun_egress {
//     set dyn_anchors     anchors of ports in per_connection mode
//     map static_egress   anchor -> current address
//     chain dyn           snat to numgen random mod K map { pool }
//     chain post          nat postrouting: @dyn_anchors -> dyn, else the map
//     chain forward_guard filter forward: drop anything to the node's /64
//     chain exit_guard    filter input: unsolicited inbound to an exit address
//                         is dropped (EGRESS_EXIT_GUARD, see "Exit guard")
//   }
//
// Only the first packet of a connection is NATed and conntrack carries the
// rest, so a change never moves a live session and never touches another
// port; a map miss leaves the packet alone (egress = anchor). Pay-per-GB
// metering is keyed by the client-facing port and does not notice.
//
// Proxy NDP, not NIC addresses. The addresses this module provisions
// (current / pool / draining) are never put on the interface: on a node that
// already carries ~16k anchors every `ip address add|del` costs the kernel
// O(n) (measured on a production node, kernel 6.8: 1000 adds ≈ 35 s, 200
// deletes ≈ 4.4 s — over the orchestrator's 30 s node timeout for one call).
// Instead each one is a proxy neighbour entry (`ip -6 neigh add proxy <a> dev
// <if>`; 1000 in one batch ≈ 0.37 s, 1000 deletes ≈ 0.19 s): the kernel
// answers the router's neighbour solicitations for it (proxy_ndp,
// proxy_delay 0, forwarding: egressSysctls), and a reply
// to it is de-NATed back to the anchor by conntrack in PREROUTING, before
// routing, so it never has to be a local address. Unsolicited packets to such
// an address (a drained one, a scan) would be FORWARDED — forwarding is on
// and the /64 is on-link — back out to the router; chain forward_guard drops them (the
// node forwards for nobody).
//
// Exit guard (chain exit_guard, input hook). Every anchor is a local address
// of the node's /64, so without a filter a port scan of a customer's exit
// IPv6 finds sshd on :22 and the agent on :8085 — a server, not a home line —
// and every closed port answers RST. A home router drops what nobody asked
// for; so does this chain, for every address of the /64 except the node's
// own (primary) address(es), which keep admin access over IPv6:
//   iif lo accept                  local traffic (a local connection to an
//                                  anchor travels over lo with that daddr)
//   ip6 daddr != <the /64> accept  link-local, multicast (router NS/RA, and
//                                  DHCPv6 replies, which go to link-local),
//                                  other prefixes
//   ip6 daddr <primary> accept     the host's own address (parsePrimaryAddrs)
//   ct state established,related accept   replies to upstream connections
//                                  (TCP, SOCKS UDP ASSOCIATE, unbound's
//                                  recursion, the agent's probes), de-NATed
//                                  replies to rotated / pool addresses
//   icmpv6 type echo-request drop  no ping answers on exit addresses
//   meta l4proto ipv6-icmp accept  NDP (incl. the unicast NS for proxy
//                                  entries, which ip6_forward() hands to
//                                  ip6_input()), PMTU, errors
//   drop                           SYN to any port, unsolicited UDP
// Priority filter - 10: before the proxy_accounting input chain (priority 0),
// whose per-port meter matches `tcp dport` only (IPv6 too), so a scan of
// [exit]:<a customer's port> is dropped before it is metered as theirs.
// The primary set is recomputed at init and on every GC tick (a change →
// one full rebuild); element deltas never touch chains.
//
// Owned here: the table, $PROXY_ROOT/egress_state.json, the proxy entries
// for the addresses above, the egress interface's proxy-NDP sysctls (also
// persisted in /etc/sysctl.d/99-netrun-egress.conf) and, once, the NIC
// copies of addresses an older version of this module added (moved to proxy
// entries at start). Anchors are never added or removed.
//
// nft consistency: every change is ONE `nft -f` transaction, so the kernel
// holds either the old or the new ruleset, never a mix. Changes go out as
// element deltas computed from the state we last applied; if the kernel no
// longer matches that (someone flushed or reloaded nftables), the delta's
// `delete element` of a missing key aborts the whole transaction and we fall
// back to a full rebuild (`add table` + `delete table` + definition — also one
// transaction, correct whatever the kernel held). If that fails too, the state
// is rolled back to what the kernel still has. `destroy element` would hide a
// drift instead of repairing it (and needs a recent nft and kernel anyway).
// The GC tick also checks that the table still exists (`nft flush ruleset`,
// `systemctl restart nftables`) and rebuilds it from the state if not.
//
// Address count: every extra address is one more proxy entry (and one more
// solicited-node multicast group: the kernel joins it so the router's
// solicitations reach the node) on an interface that already carries up to
// ~18k anchors. So a port keeps at most ONE draining address (rotating it
// again ends the older drain at once), an idle per-connection pool is kept
// for EGRESS_POOL_REFRESH_SEC before it drains (switching modes back and forth
// reuses it instead of adding EGRESS_POOL_SIZE each time), and the node holds
// at most EGRESS_MAX_EXTRA_ADDRS current + pool + draining addresses.
//
// Boot: other writers save the whole ruleset (`nft list ruleset >
// /etc/nftables.conf`), this table included, and its proxy entries are gone
// after a reboot. A drop-in on nftables.service (written at start, see
// nftDropinText) deletes the table right after the boot load, so ports leave
// from their anchors (and the exit guard is off) until init() rebuilds it.

const fs = require("fs");
const path = require("path");
const net = require("net");
const crypto = require("crypto");
const { spawn } = require("child_process");

const DEFAULT_PROXY_ROOT = "/opt/netrun/proxyserver";
const STATE_FILENAME = "egress_state.json";
const STATE_VERSION = 1;
const TABLE = "netrun_egress";
const MAX_PORTS_PER_CALL = 1000;
const MAX_DRAIN_SEC = 7 * 24 * 3600;
const GC_INTERVAL_MS = 30 * 1000;
// Elements per nft statement: short lines without a statement per element.
const NFT_CHUNK = 256;
// Live cfgs and pay-per-GB single-port cfgs parked as `.disabled` (their
// addresses stay on the NIC and the port may come back).
const CFG_FILE_RE = /^3proxy_(\d+)\.cfg(\.disabled)?$/;
const IFACE_RE = /^[A-Za-z0-9_.-]{1,32}$/;
const MODES = new Set(["static", "per_connection"]);
const DEFAULT_MAX_EXTRA_ADDRS = 40000;
const DEFAULT_NFT_DROPIN = "/etc/systemd/system/nftables.service.d/netrun-egress.conf";
const DEFAULT_SYSCTL_CONF = "/etc/sysctl.d/99-netrun-egress.conf";
const DEFAULT_PROC_SYS = "/proc/sys";
// More candidate primary addresses than this → none (parsePrimaryAddrs): the
// /64 then carries something unexpected, and the guard must not open it all.
const MAX_PRIMARY_ADDRS = 8;

const ERR_PORT_NOT_FOUND = "port_not_found";
const ERR_ANCHOR_NOT_FOUND = "anchor_not_found";
const ERR_ADDRESS_ADD_FAILED = "address_add_failed";
const ERR_ADDRESS_BUDGET = "address_budget_exceeded";
const ERR_NFT_FAILED = "nft_failed";

class EgressUnavailableError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "EgressUnavailableError";
    this.code = "EGRESS_UNAVAILABLE";
  }
}

class BadRequestError extends Error {
  constructor(detail) {
    super(detail);
    this.name = "BadRequestError";
    this.code = "BAD_REQUEST";
  }
}

// ── IPv6 text ────────────────────────────────────────────────────────────

// IPv6 text -> 8 16-bit groups, or null. cfgs carry non-canonical text (the
// generator writes leading zeros), so every address is parsed before it is
// compared or stored. Zone ids are refused: a link-local address is never an
// egress address.
function ipv6Groups(text) {
  let s = String(text == null ? "" : text).trim().toLowerCase();
  if (!s || s.includes("%") || !net.isIPv6(s)) return null;
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const o = tail.split(".").map(Number);
    s = `${s.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (part) => (part === "" ? [] : part.split(":").map((h) => parseInt(h, 16)));
  const left = parse(halves[0]);
  const right = halves.length === 2 ? parse(halves[1]) : [];
  const fill = 8 - left.length - right.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  const groups = halves.length === 2 ? [...left, ...new Array(fill).fill(0), ...right] : left;
  if (groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  return groups;
}

// RFC 5952 text: lower case, no leading zeros, the longest run (>= 2) of zero
// groups as "::", the first one on a tie.
function formatIpv6(groups) {
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLen).join(":")}`;
}

function normalizeIpv6(text) {
  const groups = ipv6Groups(text);
  return groups ? formatIpv6(groups) : null;
}

function prefixFromGroups(groups) {
  const head = groups.slice(0, 4);
  return { groups: head, text: `${formatIpv6([...head, 0, 0, 0, 0])}/64` };
}

// "2001:db8:1:2::/64" or a bare address -> { groups (first 4), text }. Only a
// /64: a new address is the prefix + 64 random bits.
function parsePrefix(text) {
  const m = /^([^/\s]+)(?:\/(\d{1,3}))?$/.exec(String(text || "").trim());
  if (!m || (m[2] !== undefined && Number(m[2]) !== 64)) return null;
  const groups = ipv6Groups(m[1]);
  return groups ? prefixFromGroups(groups) : null;
}

function inPrefix(addr, prefix) {
  const groups = ipv6Groups(addr);
  return Boolean(groups) && prefix.groups.every((g, i) => groups[i] === g);
}

// `count` fresh addresses: the prefix + 64 bits from crypto.randomBytes, none
// in `taken`. A suffix below 2^32 is redrawn so an address never looks like a
// hand-made ::1 / ::a host — it stays like the generator's random suffixes.
function generateAddresses(prefix, count, taken, randomBytes = crypto.randomBytes) {
  const out = [];
  const seen = new Set();
  let attempts = 0;
  while (out.length < count) {
    attempts += 1;
    if (attempts > count * 4 + 64) throw new Error("address_generation_exhausted");
    const b = randomBytes(8);
    const suffix = [b.readUInt16BE(0), b.readUInt16BE(2), b.readUInt16BE(4), b.readUInt16BE(6)];
    if (suffix[0] === 0 && suffix[1] === 0) continue;
    const addr = formatIpv6([...prefix.groups, ...suffix]);
    if (taken.has(addr) || seen.has(addr)) continue;
    seen.add(addr);
    out.push(addr);
  }
  return out;
}

// ── cfg anchors and `ip` output ──────────────────────────────────────────

// socks lines of one cfg -> Map port -> raw `-e` token (null when absent).
// Keyed on the socks line's -p/-e only: older cfgs carry other allow/flush
// lines, single-port cfgs have no `flush` at all, and the paired `proxy` line
// repeats the same -e.
function parseCfgAnchors(text) {
  const out = new Map();
  for (const line of String(text || "").split(/\r?\n/)) {
    if (!/^\s*socks\s/.test(line)) continue;
    const pm = /\s-p(\d+)\b/.exec(line);
    if (!pm) continue;
    const port = Number(pm[1]);
    if (out.has(port)) continue;
    const em = /\s-e(\S+)/.exec(line);
    out.set(port, em ? em[1] : null);
  }
  return out;
}

function parseDefaultRouteDev(text) {
  for (const line of String(text || "").split("\n")) {
    const m = /\bdev\s+(\S+)/.exec(line);
    if (m && IFACE_RE.test(m[1])) return m[1];
  }
  return null;
}

// `ip -6 -o addr show` -> [{ addr (canonical), plen, scope, flags }] in order.
function parseIpAddrShow(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    const m = /\binet6\s+([0-9a-fA-F:.]+)\/(\d+)\s*(.*)$/.exec(line);
    if (!m) continue;
    const addr = normalizeIpv6(m[1]);
    if (!addr) continue;
    const scope = /\bscope\s+(\S+)/.exec(m[3]);
    out.push({ addr, plen: Number(m[2]), scope: scope ? scope[1] : null, flags: m[3] });
  }
  return out;
}

// `ip -6 neigh show proxy dev <if>` -> Set of canonical addresses. One entry
// per line, the address first ("2001:db8::5 proxy"; without a dev filter
// "2001:db8::5 dev eth0 proxy").
function parseNeighProxy(text) {
  const out = new Set();
  for (const line of String(text || "").split("\n")) {
    const addr = normalizeIpv6(line.trim().split(/\s+/)[0]);
    if (addr) out.add(addr);
  }
  return out;
}

// The node's own (primary) address(es) inside `prefix`, for the exit guard,
// from `ip -6 -o addr show dev <if> scope global`: a global address whose
// prefix length is not 128 and that is not flagged nodad or dadfailed, minus
// `exclude` (the cfg anchors and this module's addresses). Not the prefix
// length alone: netrun-ipv6-restore re-adds every anchor as a /64 at boot.
// Every anchor is added with nodad (the generator's /128s, the restore's
// /64s); the host's own address (SLAAC, netplan) never is, and an anchor
// that lacks the flag (an older restore script) is still a cfg anchor.
// Sorted, so the rebuild text is stable. Returns { addrs, candidates }:
// more than MAX_PRIMARY_ADDRS candidates → addrs [] (fail closed).
// On a full node ~16k anchor lines go by with one regex each: the prefix
// length and the flags are checked before any address is parsed.
function parsePrimaryAddrs(text, prefix, exclude = new Set()) {
  const found = new Set();
  for (const line of String(text || "").split("\n")) {
    const m = /\binet6\s+([0-9a-fA-F:.]+)\/(\d+)\s*(.*)$/.exec(line);
    if (!m || m[2] === "128") continue;
    // `-o` output: the flags end where the lifetimes' "\" begins
    const flags = m[3].split("\\")[0];
    if (!/\bscope global\b/.test(flags) || /\b(?:nodad|dadfailed)\b/.test(flags)) continue;
    const addr = normalizeIpv6(m[1]);
    if (!addr || !inPrefix(addr, prefix) || exclude.has(addr)) continue;
    found.add(addr);
  }
  const all = [...found].sort();
  return { addrs: all.length > MAX_PRIMARY_ADDRS ? [] : all, candidates: all.length };
}

// ── proxy-NDP sysctls ────────────────────────────────────────────────────

// What proxy NDP needs, in the order it is applied:
// - <if>.proxy_ndp: answer the router's (multicast) neighbour solicitations
//   for the proxy entries of the interface;
// - all.proxy_ndp: its unicast solicitations — the reachability probes it
//   sends before trusting a stale entry — are addressed to the proxied
//   address itself, so they take the forwarding path, and ip6_forward()
//   hands them to neighbour discovery only when the "all" value is on (it
//   does not look at the interface's). Without it every probe goes
//   unanswered and the router drops the entry and re-resolves, a hiccup on
//   every reachability cycle. Proxy entries are per device, so this answers
//   for nothing else;
// - <if>.proxy_delay 0: answer at once (the default delays the answer to a
//   multicast solicitation by up to 0.8 s);
// - forwarding: neighbour discovery answers for proxy entries only on a
//   forwarding interface, and ip6_forward() — the unicast probes above —
//   drops everything unless "all" forwards. The installers already turn
//   all.forwarding on; a write of 1 over a 1 is never made (ensureSysctls).
function egressSysctls(iface) {
  return [
    { key: ["net", "ipv6", "conf", "all", "proxy_ndp"], want: "1" },
    { key: ["net", "ipv6", "conf", iface, "proxy_ndp"], want: "1" },
    { key: ["net", "ipv6", "neigh", iface, "proxy_delay"], want: "0" },
    { key: ["net", "ipv6", "conf", "all", "forwarding"], want: "1", forwarding: true },
    { key: ["net", "ipv6", "conf", iface, "forwarding"], want: "1", forwarding: true },
  ];
}

function acceptRaKey(iface) {
  return ["net", "ipv6", "conf", iface, "accept_ra"];
}

// sysctl.conf name: dot-separated, a dot inside a component (eth0.100)
// written as "/" (sysctl.d(5), sysctl(8)).
function sysctlName(parts) {
  return parts.map((p) => p.replace(/\./g, "/")).join(".");
}

// /etc/sysctl.d/99-netrun-egress.conf, so the settings survive a reboot (the
// agent sets them at start anyway). `acceptRa`: the agent had to switch the
// interface to accept_ra=2 before turning forwarding on (see ensureSysctls);
// that line comes before the forwarding ones, as sysctl applies the file in
// order.
function sysctlConfText(iface, { acceptRa = false } = {}) {
  const lines = [
    "# NETRUN IPv6 egress rotation (node-agent egress.js). Rotated and per-connection",
    `# addresses are not added to ${iface}: the kernel answers the router's neighbour`,
    `# solicitations for them (proxy NDP; \`ip -6 neigh show proxy dev ${iface}\`).`,
    "# Written by the agent at start when it differs; edits are overwritten.",
  ];
  let raDone = !acceptRa;
  for (const s of egressSysctls(iface)) {
    if (s.forwarding && !raDone) {
      lines.push(`${sysctlName(acceptRaKey(iface))} = 2`);
      raDone = true;
    }
    lines.push(`${sysctlName(s.key)} = ${s.want}`);
  }
  lines.push("");
  return lines.join("\n");
}

// ── state ────────────────────────────────────────────────────────────────

// pool_idle_since: when the last per_connection port left a non-empty pool
// (null while a port uses it, or with no pool).
function emptyState() {
  return { version: STATE_VERSION, ports: {}, pool: [], pool_refreshed_at: null, pool_idle_since: null, draining: [] };
}

function cloneState(s) {
  const ports = {};
  for (const [k, v] of Object.entries(s.ports)) ports[k] = { ...v };
  return {
    version: STATE_VERSION,
    ports,
    pool: s.pool.slice(),
    pool_refreshed_at: s.pool_refreshed_at,
    pool_idle_since: s.pool_idle_since || null,
    draining: s.draining.map((d) => ({ ...d })),
  };
}

function serializeState(s) {
  return `${JSON.stringify(s)}\n`;
}

function hasPerConnection(s) {
  return Object.values(s.ports).some((e) => e.mode === "per_connection");
}

// What a port's NEW connections leave from: null = its anchor, "pool" = a
// random pool member, else the address.
function egressOf(entry) {
  if (!entry) return null;
  if (entry.mode === "per_connection") return "pool";
  return entry.current || null;
}

// `port`: the port whose current address this was (absent for pool members
// and journal entries) — a port keeps at most one draining address.
function addDraining(s, addr, untilMs, port = null) {
  if (!addr) return;
  const until = new Date(untilMs).toISOString();
  const cur = s.draining.find((d) => d.addr === addr);
  if (!cur) s.draining.push(port ? { addr, until, port } : { addr, until });
  else if (Date.parse(cur.until) < untilMs) cur.until = until;
}

// A pool nobody uses starts its idle clock; one in use (or none) has none.
function markPoolIdle(s, nowMs) {
  if (s.pool.length === 0 || hasPerConnection(s)) s.pool_idle_since = null;
  else if (!s.pool_idle_since) s.pool_idle_since = new Date(nowMs).toISOString();
}

// The addresses nft maps to (currents and the pool).
function activeAddressesOf(s) {
  const out = new Set();
  for (const e of Object.values(s.ports)) if (e.current) out.add(e.current);
  for (const a of s.pool) out.add(a);
  return out;
}

// Every address this module provisions (a proxy entry each).
function addressesOf(s) {
  const out = activeAddressesOf(s);
  for (const d of s.draining) out.add(d.addr);
  return [...out];
}

// Loose validation of a loaded file: addresses normalised, unreadable entries
// dropped — one bad entry must not take the node's whole state down.
function sanitizeState(raw) {
  const s = emptyState();
  if (!raw || typeof raw !== "object") return s;
  for (const [key, v] of Object.entries(raw.ports || {})) {
    const port = Number(key);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !v || !MODES.has(v.mode)) continue;
    const anchor = normalizeIpv6(v.anchor);
    if (!anchor) continue;
    const current = v.mode === "static" && v.current ? normalizeIpv6(v.current) : null;
    // a static entry without a current address says nothing the anchor
    // doesn't (files from before static-means-forget kept such entries)
    if (v.mode === "static" && !current) continue;
    s.ports[String(port)] = { anchor, current, mode: v.mode };
  }
  s.pool = [...new Set((Array.isArray(raw.pool) ? raw.pool : []).map(normalizeIpv6).filter(Boolean))];
  if (typeof raw.pool_refreshed_at === "string" && Number.isFinite(Date.parse(raw.pool_refreshed_at))) {
    s.pool_refreshed_at = raw.pool_refreshed_at;
  }
  if (s.pool.length && typeof raw.pool_idle_since === "string" && Number.isFinite(Date.parse(raw.pool_idle_since))) {
    s.pool_idle_since = raw.pool_idle_since;
  }
  // files written before the per-port drain cap carry no `port`
  for (const d of Array.isArray(raw.draining) ? raw.draining : []) {
    const addr = normalizeIpv6(d && d.addr);
    const until = Date.parse(d && d.until);
    const port = d && Number.isInteger(d.port) && d.port >= 1 && d.port <= 65535 ? d.port : null;
    if (addr && Number.isFinite(until)) addDraining(s, addr, until, port);
  }
  return s;
}

// ── pure planners ────────────────────────────────────────────────────────

// Per-port verdicts of one call, before any address exists. A state entry
// whose anchor no longer matches the cfg is stale (the port was regenerated
// for someone else): it is replaced, and its address drains.
function planCall(state, { op, mode = null, ports, anchors }) {
  const steps = ports.map((port) => {
    const info = anchors.get(port) || null;
    const raw = state.ports[String(port)] || null;
    const entry = raw && (!info || info.anchor === raw.anchor) ? raw : null;
    let error = null;
    if (op !== "reset") {
      if (!info) error = ERR_PORT_NOT_FOUND;
      else if (!info.anchor) error = ERR_ANCHOR_NOT_FOUND;
    }
    const anchor = info ? info.anchor : raw ? raw.anchor : null;
    return { port, raw, entry, anchor, error, wantsAddress: op === "rotate" && !error };
  });
  const wantsPool = op === "mode" && mode === "per_connection" && state.pool.length === 0
    && steps.some((s) => !s.error);
  return { steps, wantsPool };
}

// The state after a call and its response items. `freshByPort` / `freshPool`
// hold only addresses that are really provisioned; a port without one fails
// with address_add_failed (address_budget_exceeded when `refused` / the
// `poolRefused` budget kept it from getting one) and keeps its old state.
function applyCall(state, plan, ctx) {
  const {
    op, mode = null, freshByPort = new Map(), freshPool = [], refused = new Set(), poolRefused = false, nowMs, drainSec,
  } = ctx;
  const next = cloneState(state);
  if (next.pool.length === 0 && freshPool.length > 0) {
    next.pool = freshPool.slice();
    next.pool_refreshed_at = new Date(nowMs).toISOString();
  }
  const retired = [];
  const items = [];
  for (const step of plan.steps) {
    const was = step.entry;
    const item = {
      port: step.port,
      ok: false,
      anchor: step.anchor,
      mode: was ? was.mode : null,
      old_ipv6: egressOf(was),
      new_ipv6: egressOf(was),
      error: step.error,
    };
    if (!item.error) {
      let entry = null;
      if (op === "rotate") {
        const addr = freshByPort.get(step.port);
        if (addr) entry = { anchor: step.anchor, current: addr, mode: "static" };
        else item.error = refused.has(step.port) ? ERR_ADDRESS_BUDGET : ERR_ADDRESS_ADD_FAILED;
      } else if (op === "mode") {
        // static: back to the anchor until the next rotate — the port has
        // nothing left to remember, so the entry goes (like reset)
        if (mode === "per_connection" && next.pool.length === 0) {
          item.error = poolRefused ? ERR_ADDRESS_BUDGET : ERR_ADDRESS_ADD_FAILED;
        } else if (mode === "per_connection") entry = { anchor: step.anchor, current: null, mode };
      }
      if (!item.error) {
        if (step.raw && step.raw.current) {
          retired.push({ addr: step.raw.current, untilMs: nowMs + drainSec * 1000, port: step.port });
        }
        if (entry) next.ports[String(step.port)] = entry;
        else delete next.ports[String(step.port)];
        item.ok = true;
        item.mode = entry ? entry.mode : null;
        item.new_ipv6 = egressOf(entry);
      }
    }
    items.push(item);
  }
  // One draining address per port: a port retiring its current again ends
  // the older drain now (the GC deletes it), so frequent rotations (timer,
  // rotation link) never pile proxy entries up. Sessions older than
  // the last rotation on that port are the ones cut.
  if (retired.length) {
    const ports = new Set(retired.map((r) => r.port));
    const nowIso = new Date(nowMs).toISOString();
    for (const d of next.draining) {
      if (d.port && ports.has(d.port) && Date.parse(d.until) > nowMs) d.until = nowIso;
    }
    for (const r of retired) addDraining(next, r.addr, r.untilMs, r.port);
  }
  // The pool is node-wide: when its last port leaves it is kept idle (a
  // switch back reuses it) and drains later (retireIdlePool).
  markPoolIdle(next, nowMs);
  return { state: next, items };
}

// Startup: drop the ports whose cfg block or anchor is gone (deprovisioned,
// or regenerated for someone else). Their listener went with the cfg, so the
// address drains at once. A pool left without ports goes idle.
function reconcileWithCfgs(state, anchors, { nowMs }) {
  const next = cloneState(state);
  const dropped = [];
  for (const [key, e] of Object.entries(state.ports)) {
    const info = anchors.get(Number(key));
    if (info && info.anchor === e.anchor) continue;
    if (e.current) addDraining(next, e.current, nowMs);
    delete next.ports[key];
    dropped.push(Number(key));
  }
  markPoolIdle(next, nowMs);
  return { state: next, dropped };
}

// An idle pool (no per_connection port since pool_idle_since) drains once it
// has been idle for `idleSec`; null = nothing to do. Pool members always
// drain for the default time: the pool is node-wide, not one caller's.
function retireIdlePool(state, { nowMs, idleSec, drainSec }) {
  if (state.pool.length === 0 || hasPerConnection(state) || !state.pool_idle_since) return null;
  if (Date.parse(state.pool_idle_since) + idleSec * 1000 > nowMs) return null;
  const next = cloneState(state);
  for (const a of next.pool) addDraining(next, a, nowMs + drainSec * 1000);
  next.pool = [];
  next.pool_refreshed_at = null;
  next.pool_idle_since = null;
  return next;
}

// Address budget: how many of `want` fresh addresses fit under `max` extra
// addresses (currents + pool + draining not yet due). Over it, the drains due
// soonest end now (the GC deletes them) to make room; what still does not fit
// is refused. `state` is returned as is when nothing had to be cut.
function fitBudget(state, want, { max, nowMs }) {
  if (want <= 0) return { state, allowed: 0, cut: 0 };
  const live = activeAddressesOf(state);
  const draining = state.draining.filter((d) => Date.parse(d.until) > nowMs && !live.has(d.addr));
  const over = live.size + draining.length + want - max;
  if (over <= 0) return { state, allowed: want, cut: 0 };
  const victims = draining
    .slice()
    .sort((a, b) => Date.parse(a.until) - Date.parse(b.until))
    .slice(0, over);
  const cut = new Set(victims.map((d) => d.addr));
  const next = cloneState(state);
  const nowIso = new Date(nowMs).toISOString();
  for (const d of next.draining) if (cut.has(d.addr)) d.until = nowIso;
  const allowed = Math.max(0, Math.min(want, max - live.size - (draining.length - victims.length)));
  return { state: next, allowed, cut: victims.length };
}

// Startup, after the re-add: nft must never map to an address nothing
// answers for (no proxy entry, not on the NIC: replies would go nowhere), so
// whatever could not be re-added is forgotten — a port then leaves from its
// anchor. `present`: anything with has(addr).
function dropMissing(state, present) {
  const next = cloneState(state);
  const lost = [];
  for (const e of Object.values(next.ports)) {
    if (e.current && !present.has(e.current)) {
      lost.push(e.current);
      e.current = null;
    }
  }
  next.pool = next.pool.filter((a) => present.has(a) || (lost.push(a), false));
  if (next.pool.length === 0) {
    next.pool_refreshed_at = null;
    next.pool_idle_since = null;
  }
  next.draining = next.draining.filter((d) => present.has(d.addr));
  return { state: next, lost };
}

// How many fresh members a pool refresh asks for: the oldest
// ceil(size * fraction) are replaced and any shortfall below `size` is filled.
function poolRefreshNeed(pool, size, fraction) {
  const out = Math.min(pool.length, Math.ceil(size * fraction));
  return size - Math.min(pool.length - out, size);
}

// The pool after a refresh that got `fresh` (oldest first in, oldest first
// out). Fewer fresh than asked for → fewer old members leave, so a failed add
// never shrinks the pool.
function refreshPoolMembers(pool, size, fraction, fresh) {
  const out = Math.min(pool.length, Math.ceil(size * fraction));
  let kept = pool.slice(out);
  const keepMax = Math.max(0, size - fresh.length);
  if (kept.length > keepMax) kept = kept.slice(kept.length - keepMax);
  const room = Math.max(0, size - kept.length - fresh.length);
  const back = pool.slice(0, out).slice(Math.max(0, out - room));
  const next = [...back, ...kept, ...fresh];
  const keep = new Set(next);
  return { pool: next, retired: pool.filter((a) => !keep.has(a)) };
}

// GC: a due draining address is deleted where it is provisioned — its proxy
// entry (`proxies`: Set) and, for an address the version before proxy NDP
// left on the NIC (`nic`: address -> the prefix length it carries there), the
// NIC address too. A protected address (an anchor, a current, a pool member)
// is in use again: it leaves the draining list and is never deleted. A due
// address provisioned nowhere is just forgotten.
function planGc(state, { nowMs, proxies, nic = new Map(), protectedAddrs }) {
  const keep = [];
  const deletes = [];
  for (const d of state.draining) {
    if (protectedAddrs.has(d.addr)) continue;
    if (Date.parse(d.until) > nowMs) { keep.push(d); continue; }
    const proxy = proxies.has(d.addr);
    const plen = nic.get(d.addr);
    if (proxy || plen !== undefined) deletes.push({ addr: d.addr, proxy, plen, entry: d });
  }
  return { keep, deletes };
}

// The `ip -6 -batch` lines that carry out planGc's deletes.
function gcBatchLines(deletes, iface) {
  const lines = [];
  for (const d of deletes) {
    if (d.proxy) lines.push(`neigh del proxy ${d.addr} dev ${iface}`);
    if (d.plen !== undefined) lines.push(`address del ${d.addr}/${d.plen} dev ${iface}`);
  }
  return lines;
}

// ── nft text ─────────────────────────────────────────────────────────────

// What the kernel table must hold for a state. Ports in ascending order, so
// the text is deterministic; two ports sharing an anchor (never generated, but
// one bad map key would abort a whole transaction) → the lower port wins.
function desiredNft(state) {
  const staticMap = new Map();
  const dyn = new Set();
  const ports = Object.keys(state.ports).map(Number).sort((a, b) => a - b);
  for (const port of ports) {
    const e = state.ports[String(port)];
    if (e.mode === "per_connection") dyn.add(e.anchor);
    else if (e.current && !staticMap.has(e.anchor)) staticMap.set(e.anchor, e.current);
  }
  return { staticMap, dyn, pool: state.pool.slice() };
}

function chunk(list, n) {
  const out = [];
  for (let i = 0; i < list.length; i += n) out.push(list.slice(i, i + n));
  return out;
}

function poolRule(pool) {
  return `snat to numgen random mod ${pool.length} map { ${pool.map((a, i) => `${i} : ${a}`).join(", ")} }`;
}

function elementsBlock(list) {
  if (list.length === 0) return [];
  return ["\t\telements = {", ...list.map((x, i) => `\t\t\t${x}${i < list.length - 1 ? "," : ""}`), "\t\t}"];
}

// chain exit_guard (see the header). `primary`: canonical addresses inside
// the /64 that keep inbound access (none → no such rule).
function exitGuardLines(prefix, primary) {
  const lines = [
    "\tchain exit_guard {",
    "\t\ttype filter hook input priority filter - 10; policy accept;",
    "\t\tiif \"lo\" accept",
    `\t\tip6 daddr != ${prefix} accept`,
  ];
  if (primary.length === 1) lines.push(`\t\tip6 daddr ${primary[0]} accept`);
  else if (primary.length > 1) lines.push(`\t\tip6 daddr { ${primary.join(", ")} } accept`);
  lines.push(
    "\t\tct state established,related accept",
    "\t\ticmpv6 type echo-request drop",
    "\t\tmeta l4proto ipv6-icmp accept",
    "\t\tdrop",
    "\t}",
  );
  return lines;
}

// The whole table as one transaction: `add table` makes the `delete` safe on
// a node that has none yet. `prefix`: the node's /64 text ("2001:db8::/64"),
// for the forward guard (chain forward_guard; see the header) and the exit
// guard (chain exit_guard, unless `exitGuard` is false; `primary`: the
// node's own addresses it lets in).
function nftRebuildScript(state, prefix, { exitGuard = true, primary = [] } = {}) {
  if (!parsePrefix(prefix)) throw new TypeError(`nftRebuildScript: bad /64 prefix ${prefix}`);
  for (const a of primary) {
    if (normalizeIpv6(a) !== a) throw new TypeError(`nftRebuildScript: bad primary address ${a}`);
  }
  const d = desiredNft(state);
  return [
    `add table ip6 ${TABLE}`,
    `delete table ip6 ${TABLE}`,
    `table ip6 ${TABLE} {`,
    "\tset dyn_anchors {",
    "\t\ttype ipv6_addr",
    ...elementsBlock([...d.dyn]),
    "\t}",
    "\tmap static_egress {",
    "\t\ttype ipv6_addr : ipv6_addr",
    ...elementsBlock([...d.staticMap].map(([k, v]) => `${k} : ${v}`)),
    "\t}",
    "\tchain dyn {",
    ...(d.pool.length ? [`\t\t${poolRule(d.pool)}`] : []),
    "\t}",
    "\tchain post {",
    "\t\ttype nat hook postrouting priority srcnat; policy accept;",
    "\t\tip6 saddr @dyn_anchors goto dyn",
    "\t\tsnat to ip6 saddr map @static_egress",
    "\t}",
    "\tchain forward_guard {",
    "\t\ttype filter hook forward priority filter; policy accept;",
    `\t\tip6 daddr ${prefix} drop`,
    "\t}",
    ...(exitGuard ? exitGuardLines(prefix, primary) : []),
    "}",
    "",
  ].join("\n");
}

// The element delta from `before` to `after` as one transaction (null = the
// table does not change). A changed map value is delete + add: `add element`
// of an existing key with another value is refused by the kernel.
function nftDiffScript(before, after) {
  const a = desiredNft(before);
  const b = desiredNft(after);
  const delMap = [...a.staticMap].filter(([k, v]) => b.staticMap.get(k) !== v).map(([k]) => k);
  const addMap = [...b.staticMap].filter(([k, v]) => a.staticMap.get(k) !== v);
  const delDyn = [...a.dyn].filter((k) => !b.dyn.has(k));
  const addDyn = [...b.dyn].filter((k) => !a.dyn.has(k));
  const poolChanged = a.pool.length !== b.pool.length || a.pool.some((x, i) => x !== b.pool[i]);
  const lines = [];
  for (const part of chunk(delMap, NFT_CHUNK)) {
    lines.push(`delete element ip6 ${TABLE} static_egress { ${part.join(", ")} }`);
  }
  for (const part of chunk(delDyn, NFT_CHUNK)) {
    lines.push(`delete element ip6 ${TABLE} dyn_anchors { ${part.join(", ")} }`);
  }
  for (const part of chunk(addMap, NFT_CHUNK)) {
    lines.push(`add element ip6 ${TABLE} static_egress { ${part.map(([k, v]) => `${k} : ${v}`).join(", ")} }`);
  }
  for (const part of chunk(addDyn, NFT_CHUNK)) {
    lines.push(`add element ip6 ${TABLE} dyn_anchors { ${part.join(", ")} }`);
  }
  if (poolChanged) {
    lines.push(`flush chain ip6 ${TABLE} dyn`);
    if (b.pool.length) lines.push(`add rule ip6 ${TABLE} dyn ${poolRule(b.pool)}`);
  }
  return lines.length ? `${lines.join("\n")}\n` : null;
}

// The nftables.service drop-in. install_node_v2.sh and node_followup_v2.sh
// write the same text (egress.test.js keeps them equal). `-`: a missing table
// is not a failure. ExecStartPost runs when the unit starts (boot, `systemctl
// restart`), never on `systemctl reload`.
function nftDropinText(nftBin) {
  return [
    "# NETRUN IPv6 egress rotation (node-agent egress.js; install_node_v2.sh, node_followup_v2.sh).",
    "# A saved ruleset may hold table ip6 netrun_egress, whose addresses are gone after a",
    "# reboot: drop it after the boot load. Proxies leave from their anchors until the agent",
    "# rebuilds the table from egress_state.json.",
    "[Service]",
    `ExecStartPost=-${nftBin} delete table ip6 ${TABLE}`,
    "",
  ].join("\n");
}

// ── HTTP bodies ──────────────────────────────────────────────────────────

function parseCallBody(body, { op, defaultDrainSec }) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new BadRequestError("body must be a JSON object");
  }
  const { ports } = body;
  if (!Array.isArray(ports)) throw new BadRequestError("ports must be an array of socks ports");
  if (ports.length > MAX_PORTS_PER_CALL) throw new BadRequestError(`at most ${MAX_PORTS_PER_CALL} ports per call`);
  for (const p of ports) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new BadRequestError(`bad port: ${JSON.stringify(p)}`);
  }
  let drainSec = defaultDrainSec;
  if (body.drain_sec !== undefined && body.drain_sec !== null) {
    if (!Number.isInteger(body.drain_sec) || body.drain_sec < 0 || body.drain_sec > MAX_DRAIN_SEC) {
      throw new BadRequestError(`drain_sec must be an integer 0..${MAX_DRAIN_SEC}`);
    }
    drainSec = body.drain_sec;
  }
  let mode = null;
  if (op === "mode") {
    if (!MODES.has(body.mode)) throw new BadRequestError('mode must be "per_connection" or "static"');
    mode = body.mode;
  }
  return { ports: [...new Set(ports)], drainSec, mode };
}

// `?ports=a,b` -> unique ports; absent/empty -> null (every port with state).
function parsePortsQuery(raw) {
  if (raw === null || raw === undefined || String(raw).trim() === "") return null;
  const parts = String(raw).split(",").map((s) => s.trim()).filter(Boolean);
  if (parts.length > MAX_PORTS_PER_CALL) throw new BadRequestError(`at most ${MAX_PORTS_PER_CALL} ports per call`);
  const ports = parts.map((s) => (/^\d{1,5}$/.test(s) ? Number(s) : NaN));
  const bad = parts.find((s, i) => !(ports[i] >= 1 && ports[i] <= 65535));
  if (bad !== undefined) throw new BadRequestError(`bad port: ${JSON.stringify(bad)}`);
  return [...new Set(ports)];
}

const ROUTES = {
  "GET /egress": "get",
  "POST /egress/rotate": "rotate",
  "POST /egress/mode": "mode",
  "POST /egress/reset": "reset",
};

// ── side effects ─────────────────────────────────────────────────────────

// Self-contained exec helper (same shape as deprovision/accounting: never
// throws, returns {code, stdout, stderr}; a spawn failure is code -1).
function execCapture(cmd, args, { timeoutMs = 30000 } = {}) {
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

// tmp + fsync + rename (+ directory fsync): a crash leaves the old file or
// the new one, never a torn one. A failed write removes its tmp: a partial
// one left by ENOSPC would hold the space the next write (or the nft
// rollback's script file) needs.
function writeFileAtomic(filePath, text) {
  const tmp = `${filePath}.tmp`;
  const buf = Buffer.from(text, "utf-8");
  try {
    const fd = fs.openSync(tmp, "w");
    try {
      let off = 0;
      while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, filePath);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
  try {
    const dfd = fs.openSync(path.dirname(filePath), "r");
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch {
    // directory fsync is not supported everywhere; the rename is already atomic
  }
}

function envInt(raw, def, min, max) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return def;
  const n = Number(raw);
  return Number.isInteger(n) && n >= min && n <= max ? n : def;
}

function envFraction(raw, def) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return def;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 && n <= 1 ? n : def;
}

function readConfig(env) {
  const dropin = String(env.EGRESS_NFT_DROPIN || "").trim();
  const sysctlConf = String(env.EGRESS_SYSCTL_CONF || "").trim();
  return {
    proxyRoot: path.normalize(env.NODE_AGENT_PROXY_ROOT || DEFAULT_PROXY_ROOT),
    drainSec: envInt(env.EGRESS_DRAIN_SEC, 600, 0, MAX_DRAIN_SEC),
    poolSize: envInt(env.EGRESS_POOL_SIZE, 1024, 1, 65536),
    poolRefreshSec: envInt(env.EGRESS_POOL_REFRESH_SEC, 600, 30, 7 * 24 * 3600),
    poolRefreshFraction: envFraction(env.EGRESS_POOL_REFRESH_FRACTION, 0.25),
    maxExtraAddrs: envInt(env.EGRESS_MAX_EXTRA_ADDRS, DEFAULT_MAX_EXTRA_ADDRS, 1, 10000000),
    prefix: String(env.NODE_EGRESS_PREFIX || "").trim() || null,
    // "off" = do not write the nftables.service drop-in (tests, non-systemd)
    nftDropin: dropin === "off" ? null : path.normalize(dropin || DEFAULT_NFT_DROPIN),
    // "off" = do not persist the proxy-NDP sysctls (tests, the netns smoke)
    sysctlConf: sysctlConf === "off" ? null : path.normalize(sysctlConf || DEFAULT_SYSCTL_CONF),
    // where the sysctls are read and written; only tests point it elsewhere
    procSys: path.normalize(String(env.EGRESS_PROC_SYS || "").trim() || DEFAULT_PROC_SYS),
    // "off" = no chain exit_guard (anything else, unset included, = on)
    exitGuard: String(env.EGRESS_EXIT_GUARD || "").trim().toLowerCase() !== "off",
  };
}

// The absolute path of an executable on PATH (plus the sbin dirs a service's
// PATH may lack), or null. The drop-in needs one: systemd does not search PATH.
function findExecutable(name, envPath = process.env.PATH) {
  const dirs = [...String(envPath || "").split(":"), "/usr/sbin", "/sbin", "/usr/bin", "/bin"];
  for (const dir of dirs) {
    if (!dir || !path.isAbsolute(dir)) continue;
    const file = path.join(dir, name);
    try {
      fs.accessSync(file, fs.constants.X_OK);
      if (fs.statSync(file).isFile()) return file;
    } catch {
      // not here
    }
  }
  return null;
}

// One in-process async mutex: every mutation, GC and pool refresh runs alone.
// They never touch cfgs, so no cfg lock is involved.
function createMutex() {
  let tail = Promise.resolve();
  return function withLock(fn) {
    const run = tail.then(() => fn());
    tail = run.catch(() => {});
    return run;
  };
}

function errText(err) {
  return String((err && err.message) || err);
}

function stderrOf(res) {
  return String(res.stderr || "").trim().slice(0, 200) || `exit ${res.code}`;
}

// ── the service ──────────────────────────────────────────────────────────

// Everything with a side effect goes through `run` (ip / nft / systemctl),
// `writeState`, `now`, `randomBytes`, `findBin` and the EGRESS_PROC_SYS /
// EGRESS_SYSCTL_CONF paths, so tests drive the real code against a fake host.
function createEgressService({
  env = process.env,
  run = execCapture,
  writeState = writeFileAtomic,
  now = () => Date.now(),
  randomBytes = crypto.randomBytes,
  findBin = findExecutable,
  log = console,
} = {}) {
  const cfg = readConfig(env);
  const cfgDir = path.join(cfg.proxyRoot, "3proxy");
  const statePath = path.join(cfg.proxyRoot, STATE_FILENAME);
  const withLock = createMutex();
  const cfgCache = new Map();

  let state = emptyState();
  let diskText = null; // what egress_state.json holds — skips no-op writes
  let ready = false;
  let reason = "not_initialised";
  let iface = null;
  let prefix = null;
  let initPromise = null;
  let timers = null;
  let tmpSeq = 0;
  // Addresses of the state still on the NIC from the version before proxy
  // NDP (address -> prefix length): init could not move them (their proxy
  // entry or their delete failed). They still work there; the GC deletes
  // the NIC copy too once they are due. Rebuilt by every init.
  let nicLeftovers = new Map();
  // The exit guard's primary address(es) (parsePrimaryAddrs), as the last
  // table written holds them; recomputed by init and every GC tick.
  let primary = [];
  let primaryNote = null; // the last detection result logged

  function rebuildScript(s) {
    return nftRebuildScript(s, prefix.text, { exitGuard: cfg.exitGuard, primary });
  }

  function markUnavailable(why) {
    if (why !== reason || ready) log.error(`[egress] unavailable: ${why}`);
    ready = false;
    reason = why;
    return false;
  }

  // Map port -> { anchor, cfg } over every cfg (live first, so a port that is
  // also in a .disabled leftover takes the live anchor) + the set of every
  // anchor, including duplicates. Parsed cfgs are cached by inode/size/mtime.
  function readAnchors() {
    let files;
    try {
      files = fs.readdirSync(cfgDir).filter((f) => CFG_FILE_RE.test(f));
    } catch (err) {
      if (err && err.code === "ENOENT") files = [];
      else throw err;
    }
    files.sort((a, b) => (a.endsWith(".disabled") - b.endsWith(".disabled")) || a.localeCompare(b));
    const byPort = new Map();
    const all = new Set();
    const seen = new Set();
    for (const f of files) {
      const p = path.join(cfgDir, f);
      let st;
      try { st = fs.statSync(p); } catch { continue; }
      const sig = `${st.ino}:${st.size}:${st.mtimeMs}`;
      let parsed = cfgCache.get(p);
      if (!parsed || parsed.sig !== sig) {
        let text;
        try { text = fs.readFileSync(p, "utf-8"); } catch { continue; }
        parsed = { sig, ports: new Map() };
        for (const [port, raw] of parseCfgAnchors(text)) parsed.ports.set(port, raw ? normalizeIpv6(raw) : null);
        cfgCache.set(p, parsed);
      }
      seen.add(p);
      for (const [port, anchor] of parsed.ports) {
        if (anchor) all.add(anchor);
        if (!byPort.has(port)) byPort.set(port, { anchor, cfg: f });
      }
    }
    for (const k of [...cfgCache.keys()]) if (!seen.has(k)) cfgCache.delete(k);
    return { byPort, all };
  }

  function tmpFile(ext) {
    tmpSeq += 1;
    return path.join(cfg.proxyRoot, `.egress_${process.pid}_${tmpSeq}.${ext}`);
  }

  async function runWithFile(ext, text, cmd, args, timeoutMs) {
    const file = tmpFile(ext);
    try {
      fs.writeFileSync(file, text);
    } catch (err) {
      return { code: -1, stdout: "", stderr: `tmp_write_failed: ${errText(err)}` };
    }
    try {
      return await run(cmd, [...args, file], { timeoutMs });
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  }

  async function applyNft(script) {
    const res = await runWithFile("nft", script, "nft", ["-f"], 120000);
    return { ok: res.code === 0, detail: String(res.stderr || "").trim().slice(0, 300) || `exit ${res.code}` };
  }

  // -force: one failed line (a proxy entry that is already gone, a NIC
  // address that is) must not stop the rest of the batch.
  function ipBatch(lines) {
    return runWithFile("ip", `${lines.join("\n")}\n`, "ip", ["-6", "-force", "-batch"], 120000);
  }

  // The interface's own addresses (address -> prefix length): ~40 ms with
  // 16k addresses, so only once per call — for the uniqueness of new
  // addresses and for init's move off the NIC.
  async function listIface() {
    const res = await run("ip", ["-6", "-o", "addr", "show", "dev", iface], { timeoutMs: 30000 });
    if (res.code !== 0) throw new Error(`ip_addr_show_failed: ${stderrOf(res)}`);
    const out = new Map();
    for (const a of parseIpAddrShow(res.stdout)) out.set(a.addr, a.plen);
    return out;
  }

  async function listProxies() {
    const res = await run("ip", ["-6", "neigh", "show", "proxy", "dev", iface], { timeoutMs: 30000 });
    if (res.code !== 0) throw new Error(`ip_neigh_show_failed: ${stderrOf(res)}`);
    return parseNeighProxy(res.stdout);
  }

  function proxyAddLines(addrs) {
    return addrs.map((a) => `neigh add proxy ${a} dev ${iface}`);
  }

  // Provisioned BEFORE nft ever maps to them (an address nobody answers for
  // swallows every reply). Adding an entry that exists succeeds. Returns the
  // subset that is really there.
  async function addProxies(addrs) {
    if (addrs.length === 0) return new Set();
    const res = await ipBatch(proxyAddLines(addrs));
    if (res.code === 0) return new Set(addrs);
    log.error(`[egress] ip neigh add proxy: ${stderrOf(res)}`);
    try {
      const list = await listProxies();
      return new Set(addrs.filter((a) => list.has(a)));
    } catch {
      return new Set();
    }
  }

  // Proxy NDP (egressSysctls), read from and written to /proc/sys. Only what
  // differs is written: writing forwarding=1, even over a 1, makes the kernel
  // drop at once every default route learned from router advertisements on
  // an interface whose accept_ra is not 2 — and with forwarding on,
  // accept_ra=1 ignores advertisements. So an egress interface that takes
  // RAs now (accept_ra=1, not forwarding yet) is switched to accept_ra=2
  // BEFORE any forwarding write (accept_ra 0 — static, or a userspace RA
  // client such as systemd-networkd — is left alone, and so is an interface
  // that already forwards: it ignores RAs today). Each write is read back.
  // Returns { ok, changed: ["name=value"], pinnedRa } or { ok: false,
  // reason }.
  function ensureSysctls() {
    const file = (key) => path.join(cfg.procSys, ...key);
    const read = (key) => fs.readFileSync(file(key), "utf-8").trim();
    const changed = [];
    let pinnedRa = false;
    const set = (key, value) => {
      fs.writeFileSync(file(key), `${value}\n`);
      const got = read(key);
      if (got !== value) throw new Error(`${sysctlName(key)} reads ${got} after writing ${value}`);
      changed.push(`${sysctlName(key)}=${value}`);
    };
    try {
      const ifaceForwarding = ["net", "ipv6", "conf", iface, "forwarding"];
      let takesRa = read(acceptRaKey(iface)) === "1" && read(ifaceForwarding) !== "1";
      for (const { key, want, forwarding } of egressSysctls(iface)) {
        if (read(key) === want) continue;
        if (forwarding && takesRa) {
          set(acceptRaKey(iface), "2");
          pinnedRa = true;
          takesRa = false;
        }
        set(key, want);
      }
    } catch (err) {
      return { ok: false, reason: `sysctl_failed: ${errText(err)}`, changed };
    }
    return { ok: true, changed, pinnedRa };
  }

  // sysctlConfText in EGRESS_SYSCTL_CONF, written only when missing or
  // different. The accept_ra line, once the agent needed it, is kept.
  function persistSysctls(pinnedRa) {
    const file = cfg.sysctlConf;
    if (!file) return { changed: false, skipped: "off" };
    if (!fs.existsSync(path.dirname(file))) return { changed: false, skipped: "no_sysctl_d" };
    let current = null;
    try { current = fs.readFileSync(file, "utf-8"); } catch {}
    const raLine = `${sysctlName(acceptRaKey(iface))} = 2`;
    const acceptRa = pinnedRa || (current !== null && current.split("\n").includes(raLine));
    const text = sysctlConfText(iface, { acceptRa });
    if (current === text) return { changed: false };
    writeFileAtomic(file, text);
    log.log(`[egress] wrote ${file}`);
    return { changed: true };
  }

  // Upgrade from the version that put these addresses on the NIC: each one
  // already got its proxy entry (init's re-add), and only then leaves the NIC,
  // deleted with the prefix length it carries — so a port never loses its
  // address in between and nothing is left twice. An anchor is never
  // deleted; an address whose proxy entry is missing stays on the NIC (it
  // works there). Returns how many left; the rest go to nicLeftovers.
  async function moveOffNic(addrs, nic, proxies, anchors) {
    const onNic = addrs.filter((a) => nic.has(a) && !anchors.has(a));
    const moving = onNic.filter((a) => proxies.has(a));
    let still = nic;
    if (moving.length) {
      const res = await ipBatch(moving.map((a) => `address del ${a}/${nic.get(a)} dev ${iface}`));
      if (res.code === 0) {
        const gone = new Set(moving);
        still = new Map([...nic].filter(([a]) => !gone.has(a)));
      } else {
        log.error(`[egress] ip address del (move to proxy NDP): ${stderrOf(res)}`);
        try { still = await listIface(); } catch { still = nic; }
      }
    }
    nicLeftovers = new Map(onNic.filter((a) => still.has(a)).map((a) => [a, still.get(a)]));
    const moved = onNic.length - nicLeftovers.size;
    if (moved) log.log(`[egress] moved ${moved} address(es) off ${iface} to proxy NDP`);
    if (nicLeftovers.size) log.error(`[egress] ${nicLeftovers.size} address(es) still on ${iface}; the GC deletes them once drained`);
    return moved;
  }

  function persist(s) {
    const text = serializeState(s);
    if (text === diskText) return;
    writeState(statePath, text);
    diskText = text;
  }

  function loadState() {
    let text;
    try {
      text = fs.readFileSync(statePath, "utf-8");
    } catch (err) {
      if (err && err.code === "ENOENT") return { state: emptyState(), text: null };
      throw new Error(`state_read_failed: ${errText(err)}`);
    }
    try {
      return { state: sanitizeState(JSON.parse(text)), text };
    } catch (err) {
      const aside = `${statePath}.corrupt-${now()}`;
      try { fs.renameSync(statePath, aside); } catch {}
      log.error(`[egress] ${statePath} unreadable (${errText(err)}); moved to ${aside}, starting empty`);
      return { state: emptyState(), text: null };
    }
  }

  async function detectNetwork() {
    const route = await run("ip", ["-6", "route", "show", "default"], { timeoutMs: 10000 });
    if (route.code !== 0) {
      return { ok: false, reason: `ip_failed: ${stderrOf(route)}` };
    }
    const dev = parseDefaultRouteDev(route.stdout);
    if (!dev) return { ok: false, reason: "no_default_ipv6_route" };
    if (cfg.prefix) {
      const p = parsePrefix(cfg.prefix);
      return p ? { ok: true, iface: dev, prefix: p, listing: null } : { ok: false, reason: `bad_NODE_EGRESS_PREFIX: ${cfg.prefix}` };
    }
    const list = await run("ip", ["-6", "-o", "addr", "show", "dev", dev, "scope", "global"], { timeoutMs: 30000 });
    if (list.code !== 0) return { ok: false, reason: `ip_failed: ${stderrOf(list)}` };
    const first = parseIpAddrShow(list.stdout).find((a) => a.scope === "global" && !/\bdadfailed\b/.test(a.flags));
    if (!first) return { ok: false, reason: `no_global_ipv6_on_${dev}` };
    // the listing serves init's primary detection too (one listing, not two)
    return { ok: true, iface: dev, prefix: prefixFromGroups(ipv6Groups(first.addr)), listing: list.stdout };
  }

  // The exit guard's primary address(es) now: from `listing` (`ip -6 -o addr
  // show dev <if> scope global` the caller already has) or one listing (~40 ms
  // next to 16k anchors). `exclude`: the cfg anchors and this module's
  // addresses. null when the listing fails (the caller keeps what it has).
  // A changed result is logged once.
  async function detectPrimary(exclude, listing = null) {
    let text = listing;
    if (text === null) {
      const res = await run("ip", ["-6", "-o", "addr", "show", "dev", iface, "scope", "global"], { timeoutMs: 30000 });
      if (res.code !== 0) {
        log.error(`[egress] exit guard: ip_addr_show_failed: ${stderrOf(res)}; keeping ${primary.join(",") || "no"} primary address`);
        return null;
      }
      text = res.stdout;
    }
    const found = parsePrimaryAddrs(text, prefix, exclude);
    const note = `${found.addrs.join(",")}/${found.candidates}`;
    if (note !== primaryNote) {
      primaryNote = note;
      if (found.candidates > MAX_PRIMARY_ADDRS) {
        log.error(
          `[egress] exit guard: ${found.candidates} candidate primary addresses on ${iface} (over ${MAX_PRIMARY_ADDRS}); `
          + "letting none in — IPv6 admin access to the node's own address is filtered too"
        );
      } else if (found.addrs.length === 0) {
        log.error(`[egress] exit guard: no primary address of ${prefix.text} on ${iface}; every address of the /64 is filtered`);
      } else {
        log.log(`[egress] exit guard: primary ${found.addrs.join(", ")}`);
      }
    }
    return found.addrs;
  }

  // The cfg anchors and every address this module provisions: never primary.
  function notPrimary(anchorsAll, s) {
    return new Set([...anchorsAll, ...addressesOf(s), ...nicLeftovers.keys()]);
  }

  // Startup: proxy-NDP sysctls (set, verified, persisted) → load → drop ports
  // whose cfg/anchor is gone → re-add the proxy entry of every current, pool
  // and draining address (one -force batch; after a plain restart they are
  // all still there) → move the ones an older version left on the NIC off it
  // → the exit guard's primary address(es) → rebuild the table (exit guard
  // included). A node without nft NAT (or whose sysctls cannot be set) stays
  // up with the module unavailable — and without the exit guard; the GC tick
  // retries.
  function init() {
    if (ready) return Promise.resolve(true);
    if (initPromise) return initPromise;
    initPromise = withLock(async () => {
      if (ready) return true;
      const net0 = await detectNetwork();
      if (!net0.ok) return markUnavailable(net0.reason);
      iface = net0.iface;
      prefix = net0.prefix;
      const sys = ensureSysctls();
      if (!sys.ok) return markUnavailable(sys.reason);
      if (sys.changed.length) log.log(`[egress] set ${sys.changed.join(" ")}`);
      try {
        persistSysctls(sys.pinnedRa);
      } catch (err) {
        // the running kernel has them; the next start writes the file again
        log.error(`[egress] ${cfg.sysctlConf}: ${errText(err)}`);
      }
      let loaded;
      try {
        loaded = loadState();
      } catch (err) {
        return markUnavailable(errText(err));
      }
      const nowMs = now();
      const index = readAnchors();
      const rec = reconcileWithCfgs(loaded.state, index.byPort, { nowMs });
      let s = rec.state;
      if (rec.dropped.length) log.log(`[egress] dropped ${rec.dropped.length} port(s) whose cfg/anchor is gone`);
      // A damaged file listing an anchor must not make us add (or later own) it.
      s.draining = s.draining.filter((d) => !index.all.has(d.addr));
      const addrs = addressesOf(s);
      nicLeftovers = new Map();
      if (addrs.length) {
        let nic;
        let proxies;
        try {
          nic = await listIface();
          await ipBatch(proxyAddLines(addrs));
          proxies = await listProxies();
        } catch (err) {
          return markUnavailable(errText(err));
        }
        await moveOffNic(addrs, nic, proxies, index.all);
        // answered for: a proxy entry, or (not moved) still on the NIC
        const present = new Set([...proxies, ...addrs.filter((a) => nic.has(a))]);
        const kept = dropMissing(s, present);
        if (kept.lost.length) {
          log.error(`[egress] ${kept.lost.length} address(es) not re-added; their ports leave from the anchor`);
        }
        s = kept.state;
      }
      if (cfg.exitGuard) {
        const found = await detectPrimary(notPrimary(index.all, s), net0.listing);
        if (found) primary = found;
      }
      const res = await applyNft(rebuildScript(s));
      if (!res.ok) return markUnavailable(`nft_failed: ${res.detail}`);
      state = s;
      diskText = loaded.text;
      try {
        persist(s);
      } catch (err) {
        // memory and the kernel agree; the next change writes the file again
        log.error(`[egress] state write failed: ${errText(err)}`);
      }
      ready = true;
      reason = null;
      log.log(
        `[egress] ready: iface=${iface} prefix=${prefix.text} ports=${Object.keys(s.ports).length} `
        + `pool=${s.pool.length} draining=${s.draining.length} `
        + `exit_guard=${cfg.exitGuard ? `on primary=${primary.join(",") || "none"}` : "off"}`
      );
      return true;
    }).finally(() => {
      initPromise = null;
    });
    return initPromise;
  }

  // Fresh addresses for a change: generated against everything already in
  // use (the NIC's addresses, every proxy entry on the interface, the cfg
  // anchors, the state), journaled as draining-now BEFORE `ip` runs (a crash
  // after the add leaves them for the GC instead of leaking them), then
  // provisioned as proxy entries.
  async function provision(before, count, cfgAnchors, nowMs) {
    let nic;
    let proxies;
    try {
      nic = await listIface();
      proxies = await listProxies();
    } catch (err) {
      log.error(`[egress] ${errText(err)}`);
      return { journal: null, fresh: [], present: new Set() };
    }
    const taken = new Set([...nic.keys(), ...proxies, ...cfgAnchors, ...addressesOf(before)]);
    for (const e of Object.values(before.ports)) taken.add(e.anchor);
    const fresh = generateAddresses(prefix, count, taken, randomBytes);
    const journal = cloneState(before);
    for (const a of fresh) addDraining(journal, a, nowMs);
    try {
      persist(journal);
    } catch (err) {
      throw new EgressUnavailableError(`state_write_failed: ${errText(err)}`);
    }
    return { journal, fresh, present: await addProxies(fresh) };
  }

  // nft first, then the file. A failed nft leaves the kernel as it was (each
  // transaction is atomic) and memory falls back to `fallback` (what the file
  // holds). A failed write puts nft back to `fallback` too, so a restart,
  // which rebuilds from the file, never contradicts what callers were told.
  // If that rollback fails as well, the kernel still maps `next` (e.g. a
  // fresh address the file only lists as draining): memory keeps `next`, so
  // nothing the kernel maps is ever garbage-collected, and the module stops
  // until init() rebuilds kernel and memory from the file (the GC tick
  // retries it).
  async function commit(before, next, fallback) {
    const script = nftDiffScript(before, next);
    if (script !== null) {
      let res = await applyNft(script);
      if (!res.ok) {
        log.error(`[egress] nft delta refused (${res.detail}); rebuilding the table`);
        res = await applyNft(rebuildScript(next));
      }
      if (!res.ok) {
        log.error(`[egress] nft rebuild failed: ${res.detail}`);
        await applyNft(rebuildScript(fallback));
        state = fallback;
        return { ok: false, detail: res.detail };
      }
    }
    try {
      persist(next);
    } catch (err) {
      if (script !== null) {
        const rb = await applyNft(rebuildScript(fallback));
        if (!rb.ok) {
          log.error(`[egress] nft rollback after a failed state write failed: ${rb.detail}`);
          state = next;
          markUnavailable(`state_write_failed: ${errText(err)}; nft_rollback_failed`);
          throw new EgressUnavailableError(`state_write_failed: ${errText(err)}`);
        }
      }
      state = fallback;
      throw new EgressUnavailableError(`state_write_failed: ${errText(err)}`);
    }
    state = next;
    return { ok: true };
  }

  async function callLocked(op, ports, { mode = null, drainSec = cfg.drainSec, anchors = null } = {}) {
    if (!ready) throw new EgressUnavailableError(reason);
    const nowMs = now();
    const before = state;
    const index = anchors ? { byPort: anchors, all: new Set() } : readAnchors();
    const plan = planCall(before, { op, mode, ports, anchors: index.byPort });
    const wanting = plan.steps.filter((s) => s.wantsAddress).map((s) => s.port);
    const poolWant = plan.wantsPool ? cfg.poolSize : 0;
    // `base` = `before` with the drains due soonest ended now when the call
    // would take the node over EGRESS_MAX_EXTRA_ADDRS; ports (or a pool) that
    // still do not fit are refused with address_budget_exceeded.
    const fit = fitBudget(before, wanting.length + poolWant, { max: cfg.maxExtraAddrs, nowMs });
    const base = fit.state;
    const portsWanting = wanting.slice(0, Math.min(wanting.length, fit.allowed));
    const refused = new Set(wanting.slice(portsWanting.length));
    const poolCount = Math.min(poolWant, fit.allowed - portsWanting.length);
    if (refused.size || poolCount < poolWant || fit.cut) {
      log.error(
        `[egress] address budget ${cfg.maxExtraAddrs}: ${fit.cut} drain(s) ended early, `
        + `${refused.size} port(s) refused, pool ${poolCount}/${poolWant}`
      );
    }
    const count = portsWanting.length + poolCount;
    let prov = { journal: null, fresh: [], present: new Set() };
    if (count > 0) prov = await provision(base, count, index.all, nowMs);
    const freshByPort = new Map();
    portsWanting.forEach((port, i) => {
      if (prov.present.has(prov.fresh[i])) freshByPort.set(port, prov.fresh[i]);
    });
    const freshPool = prov.fresh.slice(portsWanting.length).filter((a) => prov.present.has(a));
    const { state: next, items } = applyCall(base, plan, {
      op, mode, freshByPort, freshPool, refused, poolRefused: poolWant > 0 && poolCount === 0, nowMs, drainSec,
    });
    // Whatever was generated but is not in use (a failed add the listing may
    // have missed) drains now: the GC removes its proxy entry if it exists
    // after all.
    const used = new Set(addressesOf(next));
    for (const a of prov.fresh) if (!used.has(a)) addDraining(next, a, nowMs);
    const outcome = await commit(before, next, prov.journal || before);
    if (!outcome.ok) {
      const failed = items.map((it) => {
        if (!it.ok) return it;
        const step = plan.steps.find((s) => s.port === it.port);
        const mode = step.entry ? step.entry.mode : null;
        return { ...it, ok: false, mode, new_ipv6: it.old_ipv6, error: ERR_NFT_FAILED };
      });
      return { ok: false, items: failed };
    }
    return { ok: items.every((it) => it.ok), items };
  }

  function rotate(ports, { drainSec } = {}) {
    return withLock(() => callLocked("rotate", ports, { drainSec }));
  }

  function setMode(ports, mode, { drainSec } = {}) {
    if (!MODES.has(mode)) return Promise.reject(new BadRequestError(`bad mode: ${mode}`));
    return withLock(() => callLocked("mode", ports, { mode, drainSec }));
  }

  function reset(ports, { drainSec } = {}) {
    return withLock(() => callLocked("reset", ports, { drainSec }));
  }

  // /deprovision: the ports are gone (their listener and every session with
  // them), so their addresses drain at once. The next generate on such a port
  // is someone else's proxy and must start from its own anchor.
  function forgetPorts(rawPorts) {
    const ports = [...new Set((rawPorts || []).map(Number).filter((p) => Number.isInteger(p) && p > 0))];
    return withLock(async () => {
      if (!ready) return { ok: true, forgotten: 0, skipped: reason };
      const known = ports.filter((p) => state.ports[String(p)]);
      if (known.length === 0) return { ok: true, forgotten: 0 };
      const res = await callLocked("reset", known, { drainSec: 0, anchors: new Map() });
      return { ok: res.ok, forgotten: res.items.filter((it) => it.ok).length };
    });
  }

  // init, then refill a pool that could not be re-added (otherwise its ports
  // would leave from their anchors until the next refresh tick).
  function initAndFill() {
    return init().then((ok) => {
      if (!ok || !hasPerConnection(state) || state.pool.length >= cfg.poolSize) return ok;
      return refreshPool().then(() => ok);
    });
  }

  // The table can vanish under us: `nft flush ruleset`, `systemctl restart
  // nftables` (its ExecStop flushes the ruleset, the boot drop-in deletes the
  // table). Nothing would map then — rotated ports leave from their anchors —
  // and no exit guard would filter, until the next change, so the GC tick
  // looks for the table (one short `nft list chain`: exit_guard while the
  // guard is on, else post and only while the state maps something) and
  // rebuilds it. With the guard on, the tick first re-detects the primary
  // address(es) (one `ip -6 -o addr show ... scope global`): a change (a new
  // SLAAC address, a renumbered node) is one full rebuild — element deltas
  // never touch chains. A failed rebuild leaves the kernel's guard as it was,
  // so the old primary is kept and the next tick tries again.
  async function ensureTable() {
    const was = primary;
    let changed = false;
    if (cfg.exitGuard) {
      // without the cfg anchors an unflagged /64 anchor could pass for the
      // host's own address: an unreadable cfg dir keeps the primary as it is
      let anchorsAll = null;
      try {
        anchorsAll = readAnchors().all;
      } catch (err) {
        log.error(`[egress] exit guard: cfg anchors unreadable (${errText(err)}); keeping the primary address`);
      }
      const found = anchorsAll ? await detectPrimary(notPrimary(anchorsAll, state)) : null;
      changed = Boolean(found) && found.join(",") !== primary.join(",");
      if (changed) primary = found;
    }
    if (changed) {
      log.log(`[egress] exit guard primary ${was.join(",") || "none"} -> ${primary.join(",") || "none"}; rebuilding the table`);
    } else {
      const d = desiredNft(state);
      if (!cfg.exitGuard && d.staticMap.size === 0 && d.dyn.size === 0 && d.pool.length === 0) return;
      const chain = cfg.exitGuard ? "exit_guard" : "post";
      const res = await run("nft", ["list", "chain", "ip6", TABLE, chain], { timeoutMs: 30000 });
      if (res.code === 0) return;
      log.error(`[egress] table ip6 ${TABLE} is gone (${stderrOf(res)}); rebuilding it`);
    }
    const rb = await applyNft(rebuildScript(state));
    if (!rb.ok) {
      log.error(`[egress] nft rebuild failed: ${rb.detail}`);
      primary = was;
    }
  }

  // Proxy NDP can vanish under us too: the kernel drops a device's proxy
  // entries when it goes down (and on a carrier loss), and a re-created
  // interface starts with proxy_ndp off. Nothing would answer for those
  // addresses then and every reply to a rotated port would be lost, so the
  // tick re-checks the sysctls and the entries of every current, pool and not
  // yet due draining address (one listing, only while there is one) and puts
  // back what is missing. Returns the listing (with what was re-added) for
  // the GC, or null.
  async function ensureProxyNdp(nowMs) {
    const want = new Set(activeAddressesOf(state));
    for (const d of state.draining) if (Date.parse(d.until) > nowMs) want.add(d.addr);
    if (want.size === 0) return null;
    const sys = ensureSysctls();
    if (!sys.ok) log.error(`[egress] ${sys.reason}`);
    if (sys.changed.length) log.error(`[egress] proxy-NDP sysctls had changed; set ${sys.changed.join(" ")}`);
    let have;
    try {
      have = await listProxies();
    } catch (err) {
      log.error(`[egress] ${errText(err)}`);
      return null;
    }
    const missing = [...want].filter((a) => !have.has(a));
    if (missing.length === 0) return have;
    log.error(`[egress] ${missing.length} proxy entr${missing.length === 1 ? "y" : "ies"} missing on ${iface}; re-adding`);
    const res = await ipBatch(proxyAddLines(missing));
    if (res.code !== 0) {
      log.error(`[egress] ip neigh add proxy: ${stderrOf(res)}`);
      return null;
    }
    for (const a of missing) have.add(a);
    return have;
  }

  function gcTick() {
    if (!ready) return initAndFill().then(() => ({ deleted: 0 }));
    return withLock(async () => {
      if (!ready) return { deleted: 0 };
      await ensureTable();
      const nowMs = now();
      let proxies = await ensureProxyNdp(nowMs);
      const idle = retireIdlePool(state, { nowMs, idleSec: cfg.poolRefreshSec, drainSec: cfg.drainSec });
      if (idle) {
        log.log(`[egress] per-connection pool idle for ${cfg.poolRefreshSec}s: ${state.pool.length} address(es) drain`);
        await commit(state, idle, state);
      }
      if (state.draining.length === 0) return { deleted: 0 };
      if (!state.draining.some((d) => Date.parse(d.until) <= nowMs)) return { deleted: 0 };
      try {
        if (!proxies) proxies = await listProxies();
      } catch (err) {
        log.error(`[egress] gc: ${errText(err)}`);
        return { deleted: 0 };
      }
      const protectedAddrs = new Set([...readAnchors().all, ...state.pool]);
      for (const e of Object.values(state.ports)) {
        protectedAddrs.add(e.anchor);
        if (e.current) protectedAddrs.add(e.current);
      }
      const plan = planGc(state, { nowMs, proxies, nic: nicLeftovers, protectedAddrs });
      // what is still there after the batch (nothing, when it succeeded)
      let stillProxied = new Set();
      let stillNic = new Map();
      if (plan.deletes.length) {
        const res = await ipBatch(gcBatchLines(plan.deletes, iface));
        if (res.code !== 0) {
          log.error(`[egress] gc: ${stderrOf(res)}`);
          try { stillProxied = await listProxies(); } catch { stillProxied = proxies; }
          if (plan.deletes.some((d) => d.plen !== undefined)) {
            try { stillNic = await listIface(); } catch { stillNic = nicLeftovers; }
          }
        }
      }
      const left = (d) => (d.proxy && stillProxied.has(d.addr)) || (d.plen !== undefined && stillNic.has(d.addr));
      for (const d of plan.deletes) {
        if (d.plen !== undefined && !stillNic.has(d.addr)) nicLeftovers.delete(d.addr);
      }
      const next = cloneState(state);
      next.draining = [...plan.keep, ...plan.deletes.filter(left).map((d) => d.entry)];
      await commit(state, next, state);
      return { deleted: plan.deletes.filter((d) => !left(d)).length };
    });
  }

  // An idle pool (no per_connection port) is neither refreshed nor refilled:
  // the GC tick drains it once it has been idle for EGRESS_POOL_REFRESH_SEC.
  function refreshPool() {
    return withLock(async () => {
      if (!ready || !hasPerConnection(state)) return { refreshed: 0 };
      const nowMs = now();
      const need = poolRefreshNeed(state.pool, cfg.poolSize, cfg.poolRefreshFraction);
      if (need === 0 && state.pool.length <= cfg.poolSize) return { refreshed: 0 };
      const before = state;
      // over the budget: fewer fresh members, so fewer old ones leave
      const fit = fitBudget(before, need, { max: cfg.maxExtraAddrs, nowMs });
      const count = Math.min(need, fit.allowed);
      let prov = { journal: null, fresh: [], present: new Set() };
      if (count > 0) prov = await provision(fit.state, count, readAnchors().all, nowMs);
      const fresh = prov.fresh.filter((a) => prov.present.has(a));
      const { pool, retired } = refreshPoolMembers(before.pool, cfg.poolSize, cfg.poolRefreshFraction, fresh);
      const next = cloneState(fit.state);
      next.pool = pool;
      if (fresh.length || retired.length) next.pool_refreshed_at = new Date(nowMs).toISOString();
      for (const a of retired) addDraining(next, a, nowMs + cfg.drainSec * 1000);
      for (const a of prov.fresh) if (!prov.present.has(a)) addDraining(next, a, nowMs);
      const outcome = await commit(before, next, prov.journal || before);
      return { refreshed: outcome.ok ? fresh.length : 0, ok: outcome.ok };
    });
  }

  // An entry whose port now has another anchor (regenerated) is reported as
  // nothing, like a call treats it; one whose cfg is gone is what the node
  // still holds until the next start.
  function view(ports) {
    const { byPort } = readAnchors();
    const list = ports || Object.keys(state.ports).map(Number).sort((a, b) => a - b);
    const items = list.map((port) => {
      const e = state.ports[String(port)];
      const info = byPort.get(port);
      if (e && (!info || info.anchor === e.anchor)) return { port, anchor: e.anchor, current: e.current, mode: e.mode };
      return { port, anchor: info ? info.anchor : null, current: null, mode: null };
    });
    return {
      items,
      pool: { size: state.pool.length, refreshed_at: state.pool_refreshed_at, idle_since: state.pool_idle_since },
      draining: state.draining.length,
      prefix: prefix ? prefix.text : null,
      iface,
    };
  }

  function unavailable(sendJson, res) {
    sendJson(res, 503, { ok: false, error: "egress_unavailable", detail: reason || "not_initialised" });
  }

  // Routes /egress and /egress/{rotate,mode,reset}; returns false for any
  // other path so the server's 404 answers it.
  async function handleHttp(req, res, url, { sendJson, parseJsonBody, ensureAuthorized }) {
    const route = ROUTES[`${req.method} ${url.pathname}`];
    if (!route) return false;
    if (!ensureAuthorized(req)) {
      sendJson(res, 401, { success: false, error: "unauthorized" });
      return true;
    }
    try {
      if (route === "get") {
        const ports = parsePortsQuery(url.searchParams.get("ports"));
        if (initPromise) await initPromise;
        if (!ready) unavailable(sendJson, res);
        else sendJson(res, 200, view(ports));
        return true;
      }
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        throw new BadRequestError(errText(err));
      }
      const call = parseCallBody(body, { op: route, defaultDrainSec: cfg.drainSec });
      if (initPromise) await initPromise;
      if (!ready) {
        unavailable(sendJson, res);
        return true;
      }
      let result;
      if (route === "rotate") result = await rotate(call.ports, call);
      else if (route === "mode") result = await setMode(call.ports, call.mode, call);
      else result = await reset(call.ports, call);
      sendJson(res, 200, result);
    } catch (err) {
      if (err && err.code === "BAD_REQUEST") {
        sendJson(res, 400, { ok: false, error: "bad_request", detail: err.message });
      } else if (err && err.code === "EGRESS_UNAVAILABLE") {
        sendJson(res, 503, { ok: false, error: "egress_unavailable", detail: err.message });
      } else {
        sendJson(res, 500, { ok: false, error: "egress_failed", detail: errText(err) });
      }
    }
    return true;
  }

  // The nftables.service drop-in that deletes a saved copy of the table at
  // boot (nftDropinText). Written only when missing or different, and only on
  // a systemd host with nft; then a best-effort daemon-reload so a manual
  // `systemctl restart nftables` uses it too (the next boot reads it anyway).
  async function ensureBootDropin() {
    const file = cfg.nftDropin;
    if (!file) return { changed: false, skipped: "off" };
    if (!fs.existsSync(path.dirname(path.dirname(file)))) return { changed: false, skipped: "no_systemd" };
    const nftBin = findBin("nft");
    if (!nftBin) return { changed: false, skipped: "no_nft" };
    const text = nftDropinText(nftBin);
    let current = null;
    try { current = fs.readFileSync(file, "utf-8"); } catch {}
    if (current === text) return { changed: false };
    fs.mkdirSync(path.dirname(file), { recursive: true });
    writeFileAtomic(file, text);
    log.log(`[egress] wrote ${file}`);
    const res = await run("systemctl", ["daemon-reload"], { timeoutMs: 60000 });
    if (res.code !== 0) log.error(`[egress] systemctl daemon-reload: ${stderrOf(res)}`);
    return { changed: true };
  }

  // Returns the start-up promise (the agent does not wait for it; tests do).
  function start() {
    if (timers) return Promise.resolve(ready);
    const dropin = ensureBootDropin().catch((err) => {
      log.error(`[egress] nftables.service drop-in: ${errText(err)}`);
    });
    const initialised = initAndFill().catch((err) => {
      log.error(`[egress] init failed: ${errText(err)}`);
      return false;
    });
    const started = Promise.all([dropin, initialised]).then(([, ok]) => ok);
    // Both ticks are no-ops when there is nothing to do; unref'd so they
    // never keep a test process (or a stopping agent) alive.
    const gc = setInterval(() => {
      gcTick().catch((err) => log.error(`[egress] gc failed: ${errText(err)}`));
    }, GC_INTERVAL_MS);
    const pool = setInterval(() => {
      refreshPool().catch((err) => log.error(`[egress] pool refresh failed: ${errText(err)}`));
    }, cfg.poolRefreshSec * 1000);
    gc.unref();
    pool.unref();
    timers = [gc, pool];
    return started;
  }

  function stop() {
    for (const t of timers || []) clearInterval(t);
    timers = null;
  }

  return {
    init,
    start,
    stop,
    rotate,
    setMode,
    reset,
    forgetPorts,
    gcTick,
    refreshPool,
    ensureBootDropin,
    view,
    handleHttp,
    isAvailable: () => ready,
    // Audit N2 follow-up — every address this module provisions (currents,
    // pool, draining) or still has on the NIC (leftovers of the NIC era): the
    // supervisor's orphan-anchor GC never deletes one. null until init has
    // run (the GC then deletes nothing).
    ownedAddresses: () => (ready ? new Set([...addressesOf(state), ...nicLeftovers.keys()]) : null),
    // exit_guard: EGRESS_EXIT_GUARD; primary: what chain exit_guard lets in
    status: () => ({
      available: ready, reason, iface, prefix: prefix ? prefix.text : null, exit_guard: cfg.exitGuard, primary: primary.slice(),
    }),
    snapshot: () => cloneState(state),
    config: () => ({ ...cfg }),
  };
}

// The agent's one instance, created on first use (requiring this module has
// no side effects — deprovision.js and the tests load it freely).
let defaultInstance = null;
function defaultService() {
  if (!defaultInstance) defaultInstance = createEgressService();
  return defaultInstance;
}

module.exports = {
  createEgressService,
  start: () => defaultService().start(),
  isAvailable: () => defaultService().isAvailable(),
  ownedAddresses: () => defaultService().ownedAddresses(),
  handleHttp: (...args) => defaultService().handleHttp(...args),
  forgetPorts: (ports) => defaultService().forgetPorts(ports),
  // exported for unit tests (pure, no fs / exec)
  normalizeIpv6,
  ipv6Groups,
  formatIpv6,
  parsePrefix,
  inPrefix,
  generateAddresses,
  parseCfgAnchors,
  parseDefaultRouteDev,
  parseIpAddrShow,
  parseNeighProxy,
  parsePrimaryAddrs,
  egressSysctls,
  sysctlConfText,
  emptyState,
  sanitizeState,
  serializeState,
  planCall,
  applyCall,
  reconcileWithCfgs,
  dropMissing,
  retireIdlePool,
  fitBudget,
  poolRefreshNeed,
  refreshPoolMembers,
  planGc,
  gcBatchLines,
  desiredNft,
  nftRebuildScript,
  nftDiffScript,
  nftDropinText,
  findExecutable,
  parseCallBody,
  parsePortsQuery,
  writeFileAtomic,
  TABLE,
  MAX_PORTS_PER_CALL,
  MAX_PRIMARY_ADDRS,
};
