"use strict";

// Pay-per-GB v2 — quota enforcement on the node (plan D5, §3.7).
//
// Every tick, after the meter ingested the logs:
// 1. cum(account) = Σ (up + down) of the account's base logins in the meter's
//    current epoch (login -> account from RADIUS `logins`).
// 2. The local limit: `limit.bytes` when `limit.epoch` equals the meter
//    epoch (an absolute figure in this node's counter space), otherwise
//    cum_at_receipt + `limit.allowance` (the orchestrator has not seen this
//    epoch yet: it grants an allowance from where the counters were when the
//    limit arrived).
// 3. Near-limit mode when limit − cum < H, H = max(256 MiB, 30 s × the
//    account's rate over the last 15 s): unlogged = Σ over the account's live
//    sockets of min(sent, L') + min(received, L') (L' = logdump + 64 KiB, the
//    most a live connection can hold unlogged per direction; IPv6 sessions by
//    the tag of the outbound socket, IPv4 sessions by the loopback tuple) plus
//    2·L' × the IPv4 accepts RADIUS counted since near mode started that the
//    meter has not seen a record of yet (near_stats). The heartbeat carries
//    near[account] = limit − cum − unlogged; until the next one RADIUS
//    reserves 2·L' per new Accept against it.
// 4. effective = cum + (near ? unlogged : 0) ≥ limit →
//    full=true: ctl local_block + kill(account) (repeated every tick while
//    blocked: sessions without a record yet are found once they have one);
//    full=false (a multi-node split): local_block only — new connections are
//    refused, live ones run on; the orchestrator re-splits.
// 5. effective < limit again (a raised budget, sockets closed) → unblock.
// Expiry: an account whose expiresAt passed is killed once (RADIUS already
// refuses new connections). The heartbeat goes out every tick, near or not:
// it is RADIUS's deadman signal (plan §3.4).

const MIN_H = 256 * 1024 * 1024;
const H_SECONDS = 30;
const RATE_WINDOW_MS = 15000;
const SPLICE_CHUNK = 65536;
const LOCAL_BLOCK_EVENTS_MS = 10 * 60 * 1000;

function lPrime(logdumpBytes) {
  return (Number(logdumpBytes) || 262144) + SPLICE_CHUNK;
}

// Upper bound of one socket's unlogged bytes.
function socketBound(s, lp) {
  return Math.min(Number(s.sent) || 0, lp) + Math.min(Number(s.received) || 0, lp);
}

// The local limit (rule 2). acct: { limit, cumAtReceipt }.
function localLimit(acct, meterEpoch) {
  const lim = acct && acct.limit;
  if (!lim || typeof lim !== "object") return null;
  if (lim.epoch !== undefined && lim.epoch !== null && String(lim.epoch) === String(meterEpoch) && Number.isFinite(Number(lim.bytes))) {
    return Number(lim.bytes);
  }
  if (Number.isFinite(Number(lim.allowance))) return (Number(acct.cumAtReceipt) || 0) + Number(lim.allowance);
  if (Number.isFinite(Number(lim.bytes)) && (lim.epoch === undefined || lim.epoch === null)) return Number(lim.bytes);
  return null;
}

// deps: { ctl: {call}, meter, killer, now, log, logdumpBytes() }
function createEnforcer(deps) {
  const now = deps.now || Date.now;
  const log = deps.log || console;
  const accounts = new Map(); // id -> { id, state, expiresAt, limit, localBlocked, cumAtReceipt, epochAtReceipt, limitKey }
  const lists = new Map(); // listId -> { login, accountId, status, pwRev }
  const loginAccount = new Map(); // base login -> accountId
  const accountLogins = new Map(); // accountId -> Set of base logins
  const rates = new Map(); // accountId -> [[t, cum]...]
  const blockedAt = new Map(); // accountId -> ms
  const expiredKilled = new Set();
  const localBlockEvents = [];
  const view = new Map(); // accountId -> last computed { cum, limit, near, unlogged, headroom, effective }
  let lastHeartbeatOk = null;
  let lastError = null;
  let ticks = 0;

  function lp() {
    return lPrime(deps.logdumpBytes ? deps.logdumpBytes() : 262144);
  }

  function cumOf(accountId, counters) {
    let cum = 0;
    for (const login of accountLogins.get(accountId) || []) {
      const c = counters[login];
      if (c) cum += (Number(c.up) || 0) + (Number(c.down) || 0);
    }
    return cum;
  }

  // From RADIUS `accounts` (authoritative, incl. localBlocked). Call
  // setLists first: cum at receipt is summed over the account's logins.
  function setAccounts(list) {
    const counters = deps.meter.counters();
    const seen = new Set();
    for (const a of list || []) {
      if (!a || !Number.isInteger(Number(a.id))) continue;
      const id = Number(a.id);
      seen.add(id);
      const old = accounts.get(id);
      const limitKey = JSON.stringify(a.limit || null);
      const entry = {
        id,
        state: a.state,
        expiresAt: a.expiresAt === null || a.expiresAt === undefined ? null : Number(a.expiresAt),
        limit: a.limit || null,
        localBlocked: Boolean(a.localBlocked),
        limitKey,
        cumAtReceipt: old ? old.cumAtReceipt : null,
        epochAtReceipt: old ? old.epochAtReceipt : null,
      };
      if (!old || old.limitKey !== limitKey || old.epochAtReceipt !== deps.meter.epoch) {
        entry.cumAtReceipt = cumOf(id, counters);
        entry.epochAtReceipt = deps.meter.epoch;
      }
      if (entry.localBlocked && !blockedAt.has(id)) blockedAt.set(id, now());
      if (!entry.localBlocked) blockedAt.delete(id);
      if (old && old.expiresAt !== entry.expiresAt) expiredKilled.delete(id);
      accounts.set(id, entry);
    }
    for (const id of [...accounts.keys()]) {
      if (!seen.has(id)) {
        accounts.delete(id);
        rates.delete(id);
        blockedAt.delete(id);
        view.delete(id);
      }
    }
  }

  function setLists(list) {
    lists.clear();
    loginAccount.clear();
    accountLogins.clear();
    for (const l of list || []) {
      if (!l || !Number.isInteger(Number(l.id))) continue;
      const login = String(l.login || "").toLowerCase();
      const accountId = Number(l.accountId);
      lists.set(Number(l.id), { login, accountId, status: l.status, pwRev: l.pwRev });
      loginAccount.set(login, accountId);
      if (!accountLogins.has(accountId)) accountLogins.set(accountId, new Set());
      accountLogins.get(accountId).add(login);
    }
  }

  function listAccount(listId) {
    const l = lists.get(Number(listId));
    return l ? l.accountId : null;
  }

  function loginsOf(accountId) {
    return new Set(accountLogins.get(Number(accountId)) || []);
  }

  function rateOf(accountId, cum, t) {
    let ring = rates.get(accountId);
    if (!ring) {
      ring = [];
      rates.set(accountId, ring);
    }
    ring.push([t, cum]);
    while (ring.length > 2 && t - ring[0][0] > RATE_WINDOW_MS) ring.shift();
    const [t0, c0] = ring[0];
    const dt = (t - t0) / 1000;
    return dt > 0 ? Math.max(0, (cum - c0) / dt) : 0;
  }

  async function setLocalBlock(id, blocked, info) {
    try {
      await deps.ctl.call("local_block", { accountId: id, blocked });
    } catch (e) {
      lastError = `local_block ${id}: ${e.code || e.message}`;
      log.error(`[pergb-enforcer] ${lastError}`);
      return false;
    }
    const a = accounts.get(id);
    if (a) a.localBlocked = blocked;
    if (blocked) blockedAt.set(id, now());
    else blockedAt.delete(id);
    localBlockEvents.push({ accountId: id, blocked, at: new Date(now()).toISOString(), cum: info.cum, limit: info.limit });
    if (localBlockEvents.length > 1000) localBlockEvents.splice(0, localBlockEvents.length - 1000);
    log.log(`[pergb-enforcer] account ${id} ${blocked ? "blocked" : "unblocked"} locally (cum ${info.cum}, limit ${info.limit})`);
    return true;
  }

  // The unlogged upper bound per account from one socket view (+ near_stats).
  function groupByAccount(sockView) {
    const by = new Map();
    if (!sockView) return by;
    for (const s of [...sockView.v6, ...sockView.v4]) {
      if (s.accountId === null || s.accountId === undefined) continue;
      if (!by.has(s.accountId)) by.set(s.accountId, []);
      by.get(s.accountId).push(s);
    }
    return by;
  }

  function unloggedFor(accountId, byAccount, nearStats, lpBytes) {
    let bound = 0;
    let sockets = 0;
    for (const s of byAccount.get(accountId) || []) {
      bound += socketBound(s, lpBytes);
      sockets += 1;
    }
    let unrecorded = 0;
    const ns = nearStats && nearStats[String(accountId)];
    if (ns && Number(ns.ipv4Accepts) > 0) {
      const sinceMs = Number(ns.since) ? Number(ns.since) * 1000 : 0;
      const logins = loginsOf(accountId);
      let seen = 0;
      for (const s of deps.meter.sessions({ logins })) if (s.first >= sinceMs) seen += 1;
      unrecorded = Math.max(0, Number(ns.ipv4Accepts) - seen);
      bound += 2 * lpBytes * unrecorded;
    }
    return { bound, sockets, unrecorded };
  }

  // One enforcement pass. -> { near: [...], blocked: [...], unblocked: [...], killed: [...] }
  async function tick() {
    ticks += 1;
    const t = now();
    const counters = deps.meter.counters();
    const epoch = deps.meter.epoch;
    const lpBytes = lp();
    const out = { near: [], blocked: [], unblocked: [], killed: [], heartbeat: null };
    const pass = [];
    for (const a of accounts.values()) {
      const cum = cumOf(a.id, counters);
      const rate = rateOf(a.id, cum, t);
      const limit = localLimit(a, epoch);
      const H = Math.max(MIN_H, H_SECONDS * rate);
      const near = limit !== null && limit - cum < H;
      pass.push({ a, cum, rate, limit, near });
    }
    const blockedByState = (a) => a.state === "blocked" || a.state === "released";
    const needSockets = pass.some((p) => p.near || blockedByState(p.a) || (p.a.localBlocked && p.a.limit && p.a.limit.full));
    let sockView = null;
    let nearStats = null;
    if (needSockets) {
      try {
        sockView = await deps.killer.snapshot();
      } catch (e) {
        lastError = `sockets: ${e.message || e}`;
      }
      try {
        nearStats = ((await deps.ctl.call("near_stats", {})) || {}).accounts || {};
      } catch (e) {
        nearStats = null;
      }
    }
    const byAccount = groupByAccount(sockView);
    const nearMap = {};
    for (const p of pass) {
      const { a, cum, limit } = p;
      let unlogged = 0;
      let detail = null;
      if (p.near) {
        detail = unloggedFor(a.id, byAccount, nearStats, lpBytes);
        unlogged = detail.bound;
        nearMap[String(a.id)] = Math.max(0, Math.floor(limit - cum - unlogged));
        out.near.push(a.id);
      }
      const effective = cum + (p.near ? unlogged : 0);
      view.set(a.id, { cum, limit, rate: Math.round(p.rate), near: p.near, unlogged, effective, sockets: detail ? detail.sockets : null, unrecorded4: detail ? detail.unrecorded : null });
      // blocked / released by the orchestrator: RADIUS refuses it and the
      // transition killed its sessions; a session that had no record yet is
      // found (by its tuple) once it has one — the kill repeats every tick
      if (blockedByState(a)) {
        if (sockView) {
          try {
            const r = await deps.killer.kill({ accountId: a.id }, sockView);
            if (r.killed6 || r.killed4) out.killed.push({ accountId: a.id, why: a.state, ...r });
          } catch (e) {
            lastError = `kill ${a.id}: ${e.message || e}`;
          }
        }
        continue;
      }
      if (limit === null) continue;
      const full = Boolean(a.limit && a.limit.full);
      if (effective >= limit) {
        if (!a.localBlocked) {
          if (await setLocalBlock(a.id, true, { cum, limit })) out.blocked.push(a.id);
        }
        if (full && a.localBlocked) {
          try {
            const r = await deps.killer.kill({ accountId: a.id }, sockView);
            if (r.killed6 || r.killed4 || r.matched6 || r.matched4) out.killed.push({ accountId: a.id, ...r });
          } catch (e) {
            lastError = `kill ${a.id}: ${e.message || e}`;
          }
        }
      } else if (a.localBlocked) {
        if (await setLocalBlock(a.id, false, { cum, limit })) out.unblocked.push(a.id);
      }
    }
    // expiry: kill once
    for (const a of accounts.values()) {
      if (a.expiresAt !== null && a.expiresAt * 1000 <= t && a.state === "active" && !expiredKilled.has(a.id)) {
        expiredKilled.add(a.id);
        try {
          const r = await deps.killer.kill({ accountId: a.id }, sockView);
          out.killed.push({ accountId: a.id, why: "expired", ...r });
        } catch (e) {
          lastError = `expiry kill ${a.id}: ${e.message || e}`;
        }
      }
    }
    try {
      await deps.ctl.call("heartbeat", { at: t / 1000, near: nearMap });
      lastHeartbeatOk = t;
      out.heartbeat = nearMap;
    } catch (e) {
      lastError = `heartbeat: ${e.code || e.message}`;
    }
    return out;
  }

  function localBlocks() {
    const t = now();
    const out = [];
    for (const [id, at] of blockedAt) {
      const v = view.get(id) || {};
      out.push({ accountId: id, blocked: true, at: new Date(at).toISOString(), cum: v.cum === undefined ? null : v.cum, limit: v.limit === undefined ? null : v.limit });
    }
    for (const e of localBlockEvents) {
      if (!e.blocked && t - Date.parse(e.at) <= LOCAL_BLOCK_EVENTS_MS && !blockedAt.has(e.accountId)) out.push(e);
    }
    return out;
  }

  return {
    setAccounts,
    setLists,
    listAccount,
    loginAccount: (login) => (loginAccount.has(login) ? loginAccount.get(login) : null),
    loginsOf,
    listLogins(listId) {
      const l = lists.get(Number(listId));
      return new Set(l ? [l.login] : []);
    },
    tick,
    localBlocks,
    accountView: (id) => view.get(Number(id)) || null,
    status() {
      return {
        accounts: accounts.size,
        lists: lists.size,
        near: [...view.entries()].filter(([, v]) => v.near).map(([id]) => id),
        localBlocked: [...blockedAt.keys()],
        lastHeartbeatAt: lastHeartbeatOk ? new Date(lastHeartbeatOk).toISOString() : null,
        lastError,
        ticks,
      };
    },
    _accounts: accounts,
  };
}

module.exports = {
  MIN_H,
  H_SECONDS,
  SPLICE_CHUNK,
  lPrime,
  socketBound,
  localLimit,
  createEnforcer,
};
