"use strict";

// Pay-per-GB v2 — live per-GB sockets and exact kills (plan §3.7).
//
// Where per-GB sockets are: the two 3proxy-pergb units run in
//   /netrun.slice/netrun-pergb.slice/netrun-pergb-3proxy@<sp>.service
// (pergb_runtime.SLICE_CGROUP / cgroupPath; the dash nests the slice), and
// `ss ... cgroup <path>` lists exactly their sockets. Each per-GB session has
//   - an accepted loopback socket 127.0.0.3|4:<port> <- 127.0.0.1:<c> (from
//     the per-GB haproxy), and
//   - an outbound socket from the address RADIUS handed out: a tagged IPv6
//     of the node's /48 (I3) or the egress IPv4.
// Attribution:
//   - IPv6: the outbound socket's local address -> its /64 must not be a
//     per-piece one (excluded) -> the tag MAC must be valid -> decode -> list
//     -> account. A per-piece proxy on RADIUS (A13-I) has a /64 of its own
//     (pieceOf): a socket there belongs to that piece list only when its tag
//     decodes to that list; kills of a piece target only its sockets;
//   - IPv4: the loopback tuple of the accepted socket -> the base login the
//     meter saw in that session's records (pergb_meter sessions) -> account.
//     A session without any record yet holds < 2·L' and is killed on the
//     tick its first record appears (the enforcer repeats kills every tick
//     while an account is blocked).
// SOCKS5 UDP (owner 2026-10-14, per-GB too): an association's egress is a UDP
// socket bound to the address RADIUS handed out (tagged IPv6, attributed like
// a TCP one), unconnected — `ss -Hua` lists it as UNCONN with no peer. It is
// killed by its local address and port (`ss -K` aborts it: 3proxy's relay
// read fails, the association ends and its TCP control closes). UDP sockets
// carry no byte counters: the enforcer bounds one at 2·L'.
// Kills: `ss -K` with the exact 4-tuples (UDP: local address + port), 256 per
// call, inside the unit's cgroup. 3proxy then tears down the other side. A node whose ss has no
// `cgroup` filter (iproute2 < 5.9) falls back to the address filters only,
// which is still exact: no per-piece socket uses a pool address outside
// `excluded` with a valid tag, nor 127.0.0.3/4.

const net = require("net");

const KILL_CHUNK = 256;
const LOOPBACK_LISTEN = new Set(["127.0.0.3", "127.0.0.4"]);

// "[2001:db8::1]:443" | "127.0.0.4%lo:31000" | "[::ffff:127.0.0.1]:40000" -> { ip, port } | null
function parseEndpoint(token) {
  const m = /^(.*):(\d+|\*)$/.exec(String(token || ""));
  if (!m || m[2] === "*") return null;
  let ip = m[1];
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  ip = ip.replace(/%[^\]]*$/, "");
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) ip = ip.slice(7);
  if (!net.isIP(ip)) return null;
  return { ip: ip.toLowerCase(), port: Number(m[2]) };
}

function infoNumber(info, key) {
  const m = new RegExp(`\\b${key}:(\\d+)`).exec(info);
  return m ? Number(m[1]) : null;
}

// `ss -Htni state established ...` text -> [{ local, lport, peer, pport, sent, received }].
// The state column is absent (a state filter is given); -i puts tcp_info on
// the next, indented line.
function parseSs(text) {
  const out = [];
  let last = null;
  for (const raw of String(text || "").split("\n")) {
    if (!raw.trim()) continue;
    if (/^\s/.test(raw)) {
      if (last) {
        const sent = infoNumber(raw, "bytes_sent");
        const acked = infoNumber(raw, "bytes_acked");
        const received = infoNumber(raw, "bytes_received");
        last.sent = sent !== null ? sent : acked !== null ? acked : last.sent;
        last.received = received !== null ? received : last.received;
      }
      continue;
    }
    const eps = [];
    for (const tok of raw.trim().split(/\s+/)) {
      const ep = parseEndpoint(tok);
      if (ep) eps.push(ep);
      if (eps.length === 2) break;
    }
    if (eps.length < 2) {
      last = null;
      continue;
    }
    last = { local: eps[0].ip, lport: eps[0].port, peer: eps[1].ip, pport: eps[1].port, sent: 0, received: 0 };
    out.push(last);
  }
  return out;
}

// `ss -Huan ...` text -> [{ local, lport, peer, pport, proto: "udp" }]. The
// state column is present (UNCONN / ESTAB); an unconnected socket's peer is
// `*:*` / `[::]:*` (peer null). A wildcard-bound socket (`*:5353`) is skipped.
function parseSsUdp(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    if (!raw.trim() || /^\s/.test(raw)) continue;
    const toks = raw.trim().split(/\s+/);
    let local = null;
    let peer = null;
    let i = 0;
    for (; i < toks.length; i++) {
      local = parseEndpoint(toks[i]);
      if (local) break;
    }
    if (!local) continue;
    if (i + 1 < toks.length) peer = parseEndpoint(toks[i + 1]);
    out.push({ local: local.ip, lport: local.port, peer: peer ? peer.ip : null, pport: peer ? peer.port : null, proto: "udp", sent: null, received: null });
  }
  return out;
}

function tupleKey(localIp, port, clientIp, clientPort) {
  return `${localIp}:${port}<${clientIp}:${clientPort}`;
}

function bracket(ip) {
  return ip.includes(":") ? `[${ip}]` : ip;
}

// ss filter tokens for a set of exact 4-tuples: ( src L and dst P ) or ...
function tupleFilter(socks) {
  const toks = ["("];
  socks.forEach((s, i) => {
    if (i > 0) toks.push("or");
    toks.push("(", "src", `${bracket(s.local)}:${s.lport}`, "and", "dst", `${bracket(s.peer)}:${s.pport}`, ")");
  });
  toks.push(")");
  return toks;
}

// ss filter tokens for UDP sockets by their local address: ( src L or ... )
function udpFilter(socks) {
  const toks = ["("];
  socks.forEach((s, i) => {
    if (i > 0) toks.push("or");
    toks.push("src", `${bracket(s.local)}:${s.lport}`);
  });
  toks.push(")");
  return toks;
}

// Classify sockets (one unit's or the fallback listing).
//   ctx: { tagger (pergb_tag createTagger | null), excluded (Set of subnet
//   ids), pieceOf(subnetId) -> { listId, accountId } | null (A13-I: the /64s
//   of per-piece proxies on RADIUS), tupleLogin(key) -> base login | null,
//   listAccount(listId) -> accountId | null, loginAccount(login) -> accountId | null }
// -> { v6: [...], v4: [...], loopUnknown: n, other: n }
function classify(socks, ctx) {
  const v6 = [];
  const v4 = [];
  let loopUnknown = 0;
  let other = 0;
  for (const s of socks) {
    if (s.proto === "udp" && !s.local.includes(":")) {
      // IPv4 UDP: the relay's client side (the public address), RADIUS, DNS —
      // an association's egress is always the IPv6 (netrun-radius)
      other += 1;
      continue;
    }
    if (LOOPBACK_LISTEN.has(s.local)) {
      const key = tupleKey(s.local, s.lport, s.peer, s.pport);
      const login = ctx.tupleLogin ? ctx.tupleLogin(key) : null;
      if (!login) {
        loopUnknown += 1;
        continue;
      }
      const accountId = ctx.loginAccount ? ctx.loginAccount(login) : null;
      v4.push({ ...s, key, login, accountId });
      continue;
    }
    if (s.local.includes(":") && ctx.tagger) {
      const d = ctx.tagger.decodeAddress(s.local);
      if (!d) {
        other += 1;
        continue;
      }
      const piece = ctx.pieceOf ? ctx.pieceOf(d.subnetId) : null;
      if (piece) {
        // a piece's /64 is exclusive: only its own tagged address is its socket
        if (!d.valid || d.listId !== piece.listId) {
          other += 1;
          continue;
        }
        const listAcct = ctx.listAccount ? ctx.listAccount(d.listId) : null;
        const accountId = listAcct === null || listAcct === undefined ? (piece.accountId === undefined ? null : piece.accountId) : listAcct;
        v6.push({ ...s, listId: d.listId, subnetId: d.subnetId, accountId, piece: true });
        continue;
      }
      if (ctx.excluded && ctx.excluded.has(d.subnetId)) {
        other += 1;
        continue;
      }
      if (!d.valid) {
        other += 1;
        continue;
      }
      const accountId = ctx.listAccount ? ctx.listAccount(d.listId) : null;
      v6.push({ ...s, listId: d.listId, subnetId: d.subnetId, accountId });
      continue;
    }
    other += 1;
  }
  return { v6, v4, loopUnknown, other };
}

// target: { accountId } | { listId } (+ logins: Set of base logins for a list kill)
function selectTargets(classified, target) {
  const pick6 = (s) =>
    target.listId !== undefined && target.listId !== null ? s.listId === target.listId : s.accountId === target.accountId;
  const pick4 = (s) =>
    target.listId !== undefined && target.listId !== null
      ? Boolean(target.logins && target.logins.has(s.login))
      : s.accountId === target.accountId;
  return { v6: classified.v6.filter(pick6), v4: classified.v4.filter(pick4) };
}

// deps: { run(cmd, args, {timeoutMs}) -> {code, stdout, stderr}, units() ->
// [{ unit, cgroup }], fallbackFilter() -> ss filter tokens (the pool prefix
// and 127.0.0.3/4) | null, ctx() -> classify ctx, log }
function createKiller(deps) {
  const run = deps.run;
  const log = deps.log || console;
  let cgroupSupport = null; // null = not probed yet
  let lastListing = null;
  const stats = { kills6: 0, kills4: 0, calls: 0, errors: 0, lastError: null, mode: null };

  async function probeCgroup() {
    if (cgroupSupport !== null) return cgroupSupport;
    const r = await run("ss", ["-Htn", "state", "established", "cgroup", "/"], { timeoutMs: 10000 });
    cgroupSupport = r.code === 0 && !/error|unknown|expected/i.test(String(r.stderr || ""));
    stats.mode = cgroupSupport ? "cgroup" : "fallback";
    if (!cgroupSupport) log.error(`[pergb-kill] ss has no cgroup filter (V11): address filters only (${String(r.stderr || "").trim().slice(0, 120)})`);
    return cgroupSupport;
  }

  // All per-GB sockets: [{ ...socket, unit, cgroup }]
  async function listSockets() {
    const out = [];
    if (await probeCgroup()) {
      for (const u of deps.units()) {
        const r = await run("ss", ["-Htni", "state", "established", "cgroup", u.cgroup], { timeoutMs: 20000 });
        if (r.code !== 0) {
          stats.errors += 1;
          stats.lastError = `ss cgroup ${u.cgroup}: ${String(r.stderr || "").trim().slice(0, 200)}`;
          continue;
        }
        for (const s of parseSs(r.stdout)) out.push({ ...s, unit: u.unit, cgroup: u.cgroup });
        const ru = await run("ss", ["-Huan", "cgroup", u.cgroup], { timeoutMs: 20000 });
        if (ru.code !== 0) {
          stats.errors += 1;
          stats.lastError = `ss -u cgroup ${u.cgroup}: ${String(ru.stderr || "").trim().slice(0, 200)}`;
          continue;
        }
        for (const s of parseSsUdp(ru.stdout)) out.push({ ...s, unit: u.unit, cgroup: u.cgroup });
      }
    } else {
      const filter = deps.fallbackFilter ? deps.fallbackFilter() : null;
      if (filter) {
        const r = await run("ss", ["-Htni", "state", "established", ...filter], { timeoutMs: 20000 });
        if (r.code === 0) for (const s of parseSs(r.stdout)) out.push({ ...s, unit: null, cgroup: null });
        else {
          stats.errors += 1;
          stats.lastError = `ss: ${String(r.stderr || "").trim().slice(0, 200)}`;
        }
        const ru = await run("ss", ["-Huan", ...filter], { timeoutMs: 20000 });
        if (ru.code === 0) for (const s of parseSsUdp(ru.stdout)) out.push({ ...s, unit: null, cgroup: null });
        else {
          stats.errors += 1;
          stats.lastError = `ss -u: ${String(ru.stderr || "").trim().slice(0, 200)}`;
        }
      }
    }
    lastListing = { at: Date.now(), count: out.length };
    return out;
  }

  // One classified view of every live per-GB socket (the enforcer and the
  // guards share it per tick).
  async function snapshot() {
    const socks = await listSockets();
    return classify(socks, deps.ctx());
  }

  async function killSockets(list) {
    let killed = 0;
    // group by cgroup (null in fallback mode) and protocol
    const groups = new Map();
    for (const s of list) {
      const udp = s.proto === "udp";
      const k = `${udp ? "u" : "t"}|${s.cgroup || ""}`;
      if (!groups.has(k)) groups.set(k, { udp, cg: s.cgroup || "", socks: [] });
      groups.get(k).socks.push(s);
    }
    for (const { udp, cg, socks } of groups.values()) {
      for (let i = 0; i < socks.length; i += KILL_CHUNK) {
        const chunk = socks.slice(i, i + KILL_CHUNK);
        const args = udp ? ["-K", "-Huan"] : ["-K", "-Htn", "state", "established"];
        if (cg) args.push("cgroup", cg, "and");
        args.push(...(udp ? udpFilter(chunk) : tupleFilter(chunk)));
        stats.calls += 1;
        const r = await run("ss", args, { timeoutMs: 20000 });
        if (r.code !== 0) {
          stats.errors += 1;
          stats.lastError = `ss -K: ${String(r.stderr || "").trim().slice(0, 200)}`;
          log.error(`[pergb-kill] ${stats.lastError}`);
          continue;
        }
        // ss -K prints the sockets it closed
        const closed = (udp ? parseSsUdp(r.stdout) : parseSs(r.stdout)).length;
        killed += closed || 0;
      }
    }
    return killed;
  }

  // Kill one account's or one list's live sessions. target: { accountId } |
  // { listId, logins: Set }. -> { killed6, killed4, pending4 }
  async function kill(target, view = null) {
    const v = view || (await snapshot());
    const sel = selectTargets(v, target);
    const killed6 = sel.v6.length ? await killSockets(sel.v6) : 0;
    const killed4 = sel.v4.length ? await killSockets(sel.v4) : 0;
    stats.kills6 += killed6;
    stats.kills4 += killed4;
    return { killed6, killed4, pending4: v.loopUnknown, matched6: sel.v6.length, matched4: sel.v4.length };
  }

  return {
    probeCgroup,
    listSockets,
    snapshot,
    kill,
    killSockets,
    status() {
      return { ...stats, cgroupFilter: cgroupSupport, lastListing };
    },
    _resetProbe() {
      cgroupSupport = null;
    },
  };
}

module.exports = {
  KILL_CHUNK,
  parseEndpoint,
  parseSs,
  parseSsUdp,
  tupleKey,
  tupleFilter,
  udpFilter,
  classify,
  selectTargets,
  createKiller,
};
