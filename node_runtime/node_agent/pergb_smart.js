"use strict";

// Pay-per-GB v2, amendment A12 — smart rotation, the agent's half: learn
// which /64s a site refuses, from the 3proxy log records the meter already
// parses, and tell RADIUS to skip them for that site when it draws a random
// pool /64 for a per_request pick.
//
// Signal per record (our source address %e -> its /64; the site = eTLD+1 of
// the host %n, else the destination /24 or /48):
//   failure = result code 13 (upstream connect refused / timed out), or a
//             connection that ended with 0 bytes from the remote although the
//             client sent something (a reset right after the ClientHello /
//             request — the typical IP-level block). The log has no duration,
//             so "within 3 s" is not checked; a session that already had an
//             interim record is never such a failure;
//   success = ≥ 1 KiB received;
//   codes 11/12/15 are OUR side (socket / bind): never counted against a
//   /64, only alerted (bindErrors).
// Verdict per (/64, site), sliding 5 min: ≥ 3 failures AND ≥ 50 % of the
// attempts → avoid this /64 for this site for 30 min; another verdict within
// 24 h doubles it (30 min → 1 h → 2 h …, cap 12 h). One success after an
// avoid period clears the history.
// Delivery: ctl `avoid {entries:[{net, site, until}], removed:[{net, site}],
// full}` with deltas every tick, the whole set after a RADIUS epoch change
// (and while RADIUS does not know the op yet: retried every 5 min).

const psl = require("./pergb_psl.js");

const WINDOW_MS = 5 * 60 * 1000;
const MIN_FAILURES = 3;
const FAIL_SHARE = 0.5;
const BASE_AVOID_MS = 30 * 60 * 1000;
const MAX_AVOID_MS = 12 * 3600 * 1000;
const REPEAT_MS = 24 * 3600 * 1000;
const SUCCESS_BYTES = 1024;
const OWN_SIDE_CODES = new Set([11, 12, 15]);
const PAIR_CAP = 200000;
const RETRY_UNSUPPORTED_MS = 5 * 60 * 1000;

// record -> "fail" | "ok" | "own" | null (neutral)
function classifyRecord(rec, hadInterim = false) {
  if (OWN_SIDE_CODES.has(rec.code)) return "own";
  if (rec.code === 13) return "fail";
  if (rec.inBytes >= SUCCESS_BYTES) return "ok";
  if (!rec.interim && rec.inBytes === 0 && rec.outBytes > 0 && !hadInterim) return "fail";
  return null;
}

// deps: { now, ctl, log, tagger() -> pergb_tag tagger | null, excluded() -> Set of subnet ids, psl }
function createSmart(deps = {}) {
  const now = deps.now || Date.now;
  const log = deps.log || console;
  const pslData = deps.psl || null;
  const pairs = new Map(); // "net|site" -> { net, site, events: [[t, ok]], avoidUntil, level, lastAvoidAt, lastSeen }
  const active = new Map(); // "net|site" -> until (ms)
  const added = new Map(); // pending deltas
  const removed = new Map();
  const interimSeen = new Map(); // tupleKey -> t
  const siteFailures = new Map(); // site -> [t...] (last hour)
  let needFull = true;
  let supported = null; // null = unknown, false = unknown_op seen
  let lastUnsupportedAt = 0;
  const counters = { records: 0, failures: 0, successes: 0, bindErrors: 0, verdicts: 0, pushes: 0, pushErrors: 0, evicted: 0 };
  let lastPushError = null;

  function noteSiteFailure(site, t) {
    let arr = siteFailures.get(site);
    if (!arr) {
      arr = [];
      siteFailures.set(site, arr);
    }
    arr.push(t);
    while (arr.length && t - arr[0] > 3600 * 1000) arr.shift();
    if (arr.length > 10000) arr.splice(0, arr.length - 10000);
  }

  function evictIfNeeded() {
    if (pairs.size <= PAIR_CAP) return;
    // drop the least recently seen pairs that are not avoided
    const list = [...pairs.entries()].filter(([k]) => !active.has(k)).sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    let n = pairs.size - Math.floor(PAIR_CAP * 0.9);
    for (const [k] of list) {
      if (n-- <= 0) break;
      pairs.delete(k);
      counters.evicted += 1;
    }
  }

  function verdict(p, t) {
    while (p.events.length && t - p.events[0][0] > WINDOW_MS) p.events.shift();
    if (active.has(`${p.net}|${p.site}`)) return;
    let fails = 0;
    for (const [, ok] of p.events) if (!ok) fails += 1;
    if (fails >= MIN_FAILURES && fails / p.events.length >= FAIL_SHARE) {
      p.level = p.lastAvoidAt !== null && t - p.lastAvoidAt <= REPEAT_MS ? p.level + 1 : 0;
      const dur = Math.min(BASE_AVOID_MS * 2 ** p.level, MAX_AVOID_MS);
      p.avoidUntil = t + dur;
      p.lastAvoidAt = t;
      p.events = [];
      const key = `${p.net}|${p.site}`;
      active.set(key, p.avoidUntil);
      added.set(key, { net: p.net, site: p.site, until: Math.floor(p.avoidUntil / 1000) });
      removed.delete(key);
      counters.verdicts += 1;
    }
  }

  // Records from one meter tick.
  function observe(records) {
    const tagger = deps.tagger ? deps.tagger() : null;
    if (!tagger) return;
    const excluded = deps.excluded ? deps.excluded() : null;
    const t = now();
    for (const rec of records) {
      counters.records += 1;
      const tk = `${rec.localIp}:${rec.port}<${rec.clientIp}:${rec.clientPort}`;
      const had = interimSeen.has(tk);
      if (rec.interim) {
        interimSeen.set(tk, t);
        if (interimSeen.size > 100000) {
          let n = 10000;
          for (const k of interimSeen.keys()) {
            interimSeen.delete(k);
            if (--n <= 0) break;
          }
        }
      } else if (had) interimSeen.delete(tk);
      const kind = classifyRecord(rec, had);
      if (kind === "own") {
        counters.bindErrors += 1;
        continue;
      }
      if (kind === null) continue;
      const d = tagger.decodeAddress(rec.bound);
      if (!d || !d.valid || (excluded && excluded.has(d.subnetId))) continue;
      const site = psl.siteKey(rec.host, rec.dstIp, pslData || undefined);
      if (!site) continue;
      const key = `${d.subnetId}|${site}`;
      let p = pairs.get(key);
      if (!p) {
        p = { net: d.subnetId, site, events: [], avoidUntil: null, level: 0, lastAvoidAt: null, lastSeen: t };
        pairs.set(key, p);
      }
      p.lastSeen = t;
      if (kind === "ok") {
        counters.successes += 1;
        if (p.avoidUntil !== null && p.avoidUntil <= t) {
          // a success after the avoid period: the history is cleared
          p.level = 0;
          p.lastAvoidAt = null;
          p.avoidUntil = null;
          p.events = [];
        }
        p.events.push([t, true]);
      } else {
        counters.failures += 1;
        noteSiteFailure(site, t);
        p.events.push([t, false]);
      }
      if (p.events.length > 200) p.events.splice(0, p.events.length - 200);
      verdict(p, t);
    }
    evictIfNeeded();
  }

  // Expire avoid periods (each tick).
  function maintain() {
    const t = now();
    for (const [key, until] of active) {
      if (until <= t) {
        active.delete(key);
        added.delete(key);
        const p = pairs.get(key);
        removed.set(key, { net: p ? p.net : Number(key.split("|")[0]), site: p ? p.site : key.slice(key.indexOf("|") + 1) });
      }
    }
  }

  function fullSet() {
    return [...active.entries()].map(([key, until]) => {
      const p = pairs.get(key);
      return { net: p.net, site: p.site, until: Math.floor(until / 1000) };
    });
  }

  // Push the deltas (or the full set) to RADIUS.
  async function push() {
    maintain();
    const t = now();
    if (supported === false && t - lastUnsupportedAt < RETRY_UNSUPPORTED_MS) return { skipped: "unsupported" };
    const full = needFull || supported === false;
    if (!full && !added.size && !removed.size) return { skipped: "nothing" };
    const body = full
      ? { full: true, entries: fullSet(), removed: [] }
      : { full: false, entries: [...added.values()], removed: [...removed.values()] };
    try {
      await deps.ctl.call("avoid", body);
      supported = true;
      needFull = false;
      added.clear();
      removed.clear();
      counters.pushes += 1;
      lastPushError = null;
      return { pushed: body.entries.length, removed: body.removed.length, full };
    } catch (e) {
      counters.pushErrors += 1;
      lastPushError = e.code || e.message;
      if (e.code === "unknown_op") {
        if (supported !== false) log.error("[pergb-smart] RADIUS has no ctl op `avoid` yet; retried every 5 min");
        supported = false;
        lastUnsupportedAt = t;
      }
      return { error: lastPushError };
    }
  }

  function onRadiusEpoch() {
    needFull = true;
  }

  function status(radiusSmart = null) {
    maintain();
    const t = now();
    const sites = new Map();
    for (const key of active.keys()) {
      const site = key.slice(key.indexOf("|") + 1);
      sites.set(site, (sites.get(site) || 0) + 1);
    }
    const top = [];
    for (const [site, arr] of siteFailures) {
      const f1h = arr.filter((x) => t - x <= 3600 * 1000).length;
      if (f1h || sites.has(site)) top.push({ site, nets: sites.get(site) || 0, failures1h: f1h });
    }
    top.sort((a, b) => b.nets - a.nets || b.failures1h - a.failures1h || a.site.localeCompare(b.site));
    const r = radiusSmart && typeof radiusSmart === "object" ? radiusSmart : {};
    return {
      avoidedPairs: active.size,
      sites: sites.size,
      picksAvoided1h: r.picksAvoided1h === undefined ? null : r.picksAvoided1h,
      exhausted1h: r.exhausted1h === undefined ? null : r.exhausted1h,
      top: top.slice(0, 5),
      trackedPairs: pairs.size,
      radiusSupport: supported,
      lastPushError,
      ...counters,
    };
  }

  return { observe, maintain, push, onRadiusEpoch, status, _pairs: pairs, _active: active };
}

module.exports = {
  WINDOW_MS,
  MIN_FAILURES,
  BASE_AVOID_MS,
  MAX_AVOID_MS,
  classifyRecord,
  createSmart,
};
