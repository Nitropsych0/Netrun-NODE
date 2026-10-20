"use strict";

// Audit P-N4 — ONE short-lived snapshot of `ps` and `ss -ltnH`, shared by
// /health, hygiene.js and supervisor.js. On a full node (~4 000 processes,
// ~55 k listeners) every scan costs a few hundred ms of CPU on the cores 3proxy
// serves from, and /health alone is called 5-10 times a minute (egress watchdog,
// /v1/nodes/health, the HQ watch timer, the bot's infra check).
//
//   ps({fresh})            -> { ok, error, stdout }   `ps -eo pid=,etimes=,args=`
//   ss(ports, {fresh})     -> { ok, error, stdout }   `ss -ltnH sport = :P or ...`
//                             (256 ports per `ss`, the stdout of the chunks joined)
//   invalidate()           drops every entry (a mutation just happened)
//   stats()                { ttlMs, hits, misses, coalesced, lastRefreshAt, entries }
//
// Rules:
//   - an entry younger than ttlMs is served without running anything;
//   - callers that arrive while the same scan is running share that one run;
//   - only ok results are cached, a failure is never served twice;
//   - {fresh: true} always runs and writes its result through, so a mutating
//     phase (respawn, dedupe kill) never decides on a cached view while health
//     benefits from its read; invalidate() also discards scans started before it;
//   - ps and ss are keyed by command (ss: the sorted, de-duplicated port list);
//   - ttlMs 0 = the old behaviour: no cache, no sharing, every call runs.
// Callers get the raw stdout and parse it themselves, so each keeps its parser.
//
// `run(cmd, args, {timeoutMs})` -> { code, stdout, stderr } (hygiene's run).

const DEFAULT_TTL_MS = 10000;
const LISTEN_PROBE_CHUNK = 256;
const SCAN_TIMEOUT_MS = 8000;

// NODE_AGENT_SNAPSHOT_TTL_MS: unset/empty = 10 s, 0 = off, a positive integer = ms.
function ttlFromEnv(env = process.env) {
  const raw = env.NODE_AGENT_SNAPSHOT_TTL_MS;
  if (raw === undefined || String(raw).trim() === "") return DEFAULT_TTL_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : DEFAULT_TTL_MS;
}

function errorOf(res) {
  return String((res && res.stderr) || "").trim().slice(0, 200) || `exit ${res && res.code !== undefined ? res.code : "?"}`;
}

// `ps -eo pid=,args=` (no etimes column: BSD/macOS ps) -> the etimes layout hygiene parses
// (`pid etimes args`, etimes fixed at 0: those hosts only run tests).
function withEtimes(stdout) {
  return String(stdout || "")
    .split("\n")
    .map((l) => {
      const m = /^(\s*\d+)\s+(.*)$/.exec(l);
      return m ? `${m[1]} 0 ${m[2]}` : l;
    })
    .join("\n");
}

// `etimes` (procps on Linux): true = always `pid=,etimes=,args=`; false = never; "auto" (default) =
// that, and once for good `pid=,args=` when ps does not know the keyword (BSD/macOS dev hosts).
function createProcSnapshot({ run, now = Date.now, ttlMs = DEFAULT_TTL_MS, etimes = "auto" } = {}) {
  if (typeof run !== "function") throw new Error("createProcSnapshot: run is required");
  const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : 0;
  const entries = new Map(); // key -> { startedAt, value }
  const inflight = new Map(); // key -> promise
  let epoch = 0;
  const st = { hits: 0, misses: 0, coalesced: 0, lastRefreshAt: null };
  let hasEtimes = etimes !== false;

  async function cached(key, produce, fresh) {
    if (ttl <= 0) {
      st.misses += 1;
      return produce();
    }
    if (!fresh) {
      const e = entries.get(key);
      if (e && now() - e.startedAt < ttl) {
        st.hits += 1;
        return e.value;
      }
      const f = inflight.get(key);
      if (f) {
        st.coalesced += 1;
        return f;
      }
    }
    st.misses += 1;
    const startedAt = now();
    const myEpoch = epoch;
    const p = (async () => {
      try {
        const value = await produce();
        if (value.ok && myEpoch === epoch) {
          const cur = entries.get(key);
          if (!cur || cur.startedAt <= startedAt) {
            entries.set(key, { startedAt, value });
            st.lastRefreshAt = new Date(now()).toISOString();
          }
        }
        return value;
      } finally {
        if (inflight.get(key) === p) inflight.delete(key);
      }
    })();
    inflight.set(key, p);
    return p;
  }

  function ps({ fresh = false } = {}) {
    return cached(
      "ps",
      async () => {
        let res = await run("ps", ["-eo", hasEtimes ? "pid=,etimes=,args=" : "pid=,args="], { timeoutMs: SCAN_TIMEOUT_MS });
        if (res.code !== 0 && hasEtimes && etimes === "auto" && /etimes/i.test(String(res.stderr || ""))) {
          hasEtimes = false;
          res = await run("ps", ["-eo", "pid=,args="], { timeoutMs: SCAN_TIMEOUT_MS });
        }
        if (res.code !== 0) return { ok: false, error: errorOf(res), stdout: "" };
        return { ok: true, error: null, stdout: hasEtimes ? String(res.stdout || "") : withEtimes(res.stdout) };
      },
      fresh
    );
  }

  function ss(ports, { fresh = false } = {}) {
    const list = [...new Set((ports || []).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535))];
    if (!list.length) return Promise.resolve({ ok: true, error: null, stdout: "" });
    const key = `ss:${[...list].sort((a, b) => a - b).join(",")}`;
    return cached(
      key,
      async () => {
        const parts = [];
        for (let i = 0; i < list.length; i += LISTEN_PROBE_CHUNK) {
          const filter = list.slice(i, i + LISTEN_PROBE_CHUNK).map((p) => `sport = :${p}`).join(" or ");
          const res = await run("ss", ["-ltnH", filter], { timeoutMs: SCAN_TIMEOUT_MS });
          if (res.code !== 0) return { ok: false, error: errorOf(res), stdout: "" };
          parts.push(String(res.stdout || ""));
        }
        return { ok: true, error: null, stdout: parts.join("\n") };
      },
      fresh
    );
  }

  function invalidate() {
    epoch += 1;
    entries.clear();
    inflight.clear();
  }

  function stats() {
    return { ttlMs: ttl, hits: st.hits, misses: st.misses, coalesced: st.coalesced, lastRefreshAt: st.lastRefreshAt, entries: entries.size };
  }

  return { ps, ss, invalidate, stats };
}

module.exports = { createProcSnapshot, ttlFromEnv, withEtimes, DEFAULT_TTL_MS, LISTEN_PROBE_CHUNK };
