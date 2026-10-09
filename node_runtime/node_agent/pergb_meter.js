"use strict";

// Pay-per-GB v2 — the node meter (plan §3.6, interface I4 log records).
//
// 3proxy-pergb writes one hourly file per process range,
//   /var/log/netrun-pergb/p<sp>.log.YYYY.MM.DD-HH   (node TZ = UTC)
// with `logformat "- +_G%Y%m%d%H%M%S.%. %N %p %E %U %C %c %i %e %R %r %I %O %n"`
// and `logdump 262144 262144`: every record is a DELTA (an interim record
// every 256 KiB per direction, a final one at close). 14 space-separated
// fields: time service port code user clientIp clientPort localIp bound
// dstIp dstPort bytesFromServer(%I) bytesFromClient(%O) host. The `- +_`
// prefix turns spaces into `_`, so a customer-chosen user name cannot forge
// a record.
//
// Counting: key = the base login (the first two dash tokens of the
// lowercased user, `netrun-<id>`); only base logins RADIUS knows are counted
// (up = %O, down = %I, conns = final records); records of unknown logins go
// to one unknownBytes counter (plus a capped sample of names), the probe
// login and zero-byte records (failed auths) are skipped — unauthenticated
// clients cannot grow the state.
//
// Exactly once: ONE state file, meter.json = {epoch, seq, files:{name:{ino,
// off}}, logins:{login:{up, down, conns, seq}}, ...}, written tmp + fsync +
// rename after every tick that read anything. The cursor and the counters
// move together, so a crash anywhere re-reads exactly what was not
// persisted. A tick reads from the stored offset up to the last "\n" (the
// partial tail waits for the next tick). An inode change (or a file that
// shrank) is read again from 0. A file is finished when a newer file of its
// range exists, it is read to its end and it has not grown for 120 s: it is
// gzipped into archive/ (streamed, off the tick), the original unlinked,
// and only then its cursor dropped — a file without a cursor is never an
// already-counted one.
//
// Epoch: random when the state is created; inside one epoch the counters
// never go down. A lost or corrupt meter.json while logs exist starts every
// existing file at its end (the bytes skipped are reported as unbilled,
// event pergb_meter_reset) — they are never read again, so nothing is
// charged twice. Only a node without logs (a rebuild) starts from 0.
//
// IPv4 sessions (the egress IPv4 holds no tag): the loopback tuple
// (localIp:port <- clientIp:clientPort) -> base login, for 30 min, for IPv4
// kills and the near-limit count.

const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");
const readline = require("readline");
const { pipeline } = require("stream/promises");

const STATE_VERSION = 1;
const FILE_RE = /^p(\d{1,5})\.log\.(\d{4})\.(\d{2})\.(\d{2})-(\d{2})$/;
const ARCHIVE_RE = /^p(\d{1,5})\.log\.(\d{4})\.(\d{2})\.(\d{2})-(\d{2})\.gz$/;
const TIME_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d{3})$/;
const DIGITS_RE = /^\d{1,20}$/;
const PROBE_LOGIN = "netrun-svcprobe";
const BASE_RE = /^netrun-[a-z0-9]{1,32}$/;
const MAX_LINE = 4096;
const UNKNOWN_SAMPLE_CAP = 1000;
const TUPLE_TTL_MS = 30 * 60 * 1000;
const TUPLE_CAP = 200000;
const DEFAULT_LOGDUMP = 262144;

// ── record parsing ───────────────────────────────────────────────────────

// "20261009142233.123" (UTC, the G of the logformat) -> ms since epoch, or null.
function parseLogTime(text) {
  const m = TIME_RE.exec(text);
  if (!m) return null;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], +m[7]);
  return Number.isFinite(t) ? t : null;
}

// The base login of a user: the first two dash tokens, lowercased, or null.
function baseLogin(user) {
  const u = String(user || "").toLowerCase();
  if (!u.startsWith("netrun-")) return null;
  const dash = u.indexOf("-", 7);
  const base = dash < 0 ? u : u.slice(0, dash);
  return BASE_RE.test(base) ? base : null;
}

function isIpText(s) {
  return /^[0-9a-fA-F:.]{2,45}$/.test(s) && (s.includes(".") || s.includes(":"));
}

// One log line -> record object, or null (not a valid 14-field record).
function parseRecord(line, logdump = DEFAULT_LOGDUMP) {
  if (!line || line.length > MAX_LINE) return null;
  const f = line.split(" ");
  if (f.length !== 14) return null;
  const t = parseLogTime(f[0]);
  if (t === null) return null;
  if (!/^[A-Za-z0-9_]{1,32}$/.test(f[1])) return null;
  for (const i of [2, 3, 6, 10, 11, 12]) if (!DIGITS_RE.test(f[i])) return null;
  const port = Number(f[2]);
  const clientPort = Number(f[6]);
  const dstPort = Number(f[10]);
  if (port < 1 || port > 65535 || clientPort > 65535 || dstPort > 65535) return null;
  if (!f[4] || f[4].length > 255) return null;
  for (const i of [5, 7, 8, 9]) if (!isIpText(f[i])) return null;
  const inBytes = Number(f[11]);
  const outBytes = Number(f[12]);
  if (!Number.isSafeInteger(inBytes) || !Number.isSafeInteger(outBytes)) return null;
  return {
    t,
    service: f[1],
    port,
    code: Number(f[3]),
    user: f[4],
    login: baseLogin(f[4]),
    clientIp: f[5],
    clientPort,
    localIp: f[7],
    bound: f[8],
    dstIp: f[9],
    dstPort,
    inBytes,
    outBytes,
    host: f[13],
    interim: inBytes >= logdump || outBytes >= logdump,
    ipv4: f[9].includes(".") && !f[9].includes(":"),
  };
}

// The loopback tuple of a record's accepted socket.
function tupleKey(localIp, port, clientIp, clientPort) {
  return `${localIp}:${port}<${clientIp}:${clientPort}`;
}

// "p31000.log.2026.10.09-14" -> { sp, hourMs } or null.
function parseLogName(name) {
  const m = FILE_RE.exec(name) || ARCHIVE_RE.exec(name);
  if (!m) return null;
  return { sp: Number(m[1]), hourMs: Date.UTC(+m[2], +m[3] - 1, +m[4], +m[5]) };
}

// ── state ────────────────────────────────────────────────────────────────

function randomEpoch() {
  // an integer in [2^32, 2^53): exact in JSON / JavaScript, like RADIUS's
  const hi = crypto.randomBytes(4).readUInt32BE(0) & 0x1fffff;
  const lo = crypto.randomBytes(4).readUInt32BE(0);
  const v = hi * 2 ** 32 + lo;
  return v < 2 ** 32 ? v + 2 ** 32 : v;
}

function emptyState(nowMs) {
  return {
    version: STATE_VERSION,
    epoch: randomEpoch(),
    seq: 0,
    createdAt: new Date(nowMs).toISOString(),
    files: {},
    logins: {},
    unknown: { bytes: 0, records: 0, sample: [] },
    dropped: 0,
    skipped: { bytes: 0, files: 0, at: null },
  };
}

function validState(s) {
  return (
    s &&
    typeof s === "object" &&
    s.version === STATE_VERSION &&
    Number.isSafeInteger(s.epoch) &&
    Number.isSafeInteger(s.seq) &&
    s.files &&
    typeof s.files === "object" &&
    s.logins &&
    typeof s.logins === "object"
  );
}

// ── the meter ────────────────────────────────────────────────────────────

// opts: { logDir, statePath, archiveDir, now, fsx (fs subset; tests inject
// crashes), logdumpBytes, finishedAfterMs, retainDays, fsFillPct,
// maxReadPerTick, onRecords(records), onEvent(event), log }
function createMeter(opts = {}) {
  const logDir = opts.logDir || "/var/log/netrun-pergb";
  const statePath = opts.statePath || "/var/lib/netrun-pergb/meter.json";
  const archiveDir = opts.archiveDir || path.join(logDir, "archive");
  const now = opts.now || Date.now;
  const fsx = opts.fsx || fs;
  const log = opts.log || console;
  const finishedAfterMs = opts.finishedAfterMs === undefined ? 120000 : opts.finishedAfterMs;
  const retainDays = opts.retainDays === undefined ? 14 : opts.retainDays;
  const fsFillPct = opts.fsFillPct === undefined ? 80 : opts.fsFillPct;
  const maxReadPerTick = opts.maxReadPerTick || 16 * 1024 * 1024;
  const onRecords = typeof opts.onRecords === "function" ? opts.onRecords : null;
  const onEvent = typeof opts.onEvent === "function" ? opts.onEvent : null;
  let logdump = opts.logdumpBytes || DEFAULT_LOGDUMP;

  let state = null;
  let known = null; // Map base login -> { listId, accountId } | null = not loaded yet
  const tuples = new Map(); // tupleKey -> { login, first, last, final }
  const events = [];
  let lagSince = null;
  let lastTickAt = null;
  let lastTickOkAt = null;
  let lastError = null;
  let persistFailures = 0;
  const archiving = new Set();
  const archivedNames = new Set();
  let lastRetentionAt = 0;

  function event(type, detail = {}) {
    const e = { type, at: new Date(now()).toISOString(), ...detail };
    events.push(e);
    if (events.length > 200) events.splice(0, events.length - 200);
    if (onEvent) {
      try {
        onEvent(e);
      } catch {}
    }
    log.log(`[pergb-meter] ${type} ${JSON.stringify(detail)}`);
  }

  function listLogFiles() {
    let names;
    try {
      names = fsx.readdirSync(logDir);
    } catch (e) {
      if (e && e.code === "ENOENT") return [];
      throw e;
    }
    const out = [];
    for (const name of names) {
      const p = FILE_RE.exec(name) ? parseLogName(name) : null;
      if (p) out.push({ name, ...p });
    }
    out.sort((a, b) => a.sp - b.sp || a.hourMs - b.hourMs);
    return out;
  }

  // Position just after the last "\n" of a file (fresh-state start).
  function endOfLastLine(file, size) {
    if (size === 0) return 0;
    const fd = fsx.openSync(file, "r");
    try {
      const chunk = 65536;
      let pos = size;
      while (pos > 0) {
        const len = Math.min(chunk, pos);
        const buf = Buffer.alloc(len);
        fsx.readSync(fd, buf, 0, len, pos - len);
        const nl = buf.lastIndexOf(10);
        if (nl >= 0) return pos - len + nl + 1;
        pos -= len;
      }
      return 0;
    } finally {
      fsx.closeSync(fd);
    }
  }

  function writeState(s) {
    const dir = path.dirname(statePath);
    fsx.mkdirSync(dir, { recursive: true });
    const tmp = `${statePath}.tmp`;
    const text = JSON.stringify(s);
    const fd = fsx.openSync(tmp, "w", 0o600);
    try {
      fsx.writeSync(fd, text);
      fsx.fsyncSync(fd);
    } finally {
      fsx.closeSync(fd);
    }
    fsx.renameSync(tmp, statePath);
    try {
      const dfd = fsx.openSync(dir, "r");
      try {
        fsx.fsyncSync(dfd);
      } finally {
        fsx.closeSync(dfd);
      }
    } catch {}
  }

  // Load meter.json, or start a fresh state (at the current end of every
  // existing log file when there are logs).
  function load() {
    let raw = null;
    try {
      raw = fsx.readFileSync(statePath, "utf-8");
    } catch (e) {
      if (!e || e.code !== "ENOENT") log.error(`[pergb-meter] cannot read ${statePath}: ${(e && e.message) || e}`);
    }
    if (raw !== null) {
      try {
        const parsed = JSON.parse(raw);
        if (validState(parsed)) {
          parsed.unknown = parsed.unknown || { bytes: 0, records: 0, sample: [] };
          parsed.skipped = parsed.skipped || { bytes: 0, files: 0, at: null };
          parsed.dropped = Number(parsed.dropped) || 0;
          state = parsed;
          return { fresh: false };
        }
      } catch {}
      const aside = `${statePath}.broken-${now()}`;
      try {
        fsx.renameSync(statePath, aside);
      } catch {}
      log.error(`[pergb-meter] ${statePath} is corrupt; moved to ${aside}`);
    }
    const s = emptyState(now());
    let skippedBytes = 0;
    let skippedFiles = 0;
    for (const f of listLogFiles()) {
      const file = path.join(logDir, f.name);
      let st;
      try {
        st = fsx.statSync(file);
      } catch {
        continue;
      }
      const off = endOfLastLine(file, st.size);
      s.files[f.name] = { ino: st.ino, off, size: st.size, growAt: now() };
      if (off > 0) {
        skippedBytes += off;
        skippedFiles += 1;
      }
    }
    if (skippedFiles > 0) {
      s.skipped = { bytes: skippedBytes, files: skippedFiles, at: new Date(now()).toISOString() };
    }
    writeState(s);
    state = s;
    if (skippedFiles > 0) event("pergb_meter_reset", { epoch: s.epoch, skippedBytes, files: skippedFiles });
    return { fresh: true, skippedBytes, skippedFiles };
  }

  function ensureLoaded() {
    if (!state) load();
    return state;
  }

  // logins: iterable of { login, id (listId), accountId } (RADIUS `logins`).
  // A login removed from RADIUS stays known for an hour: its last records
  // (written before the delete, read after it) are still billed.
  const gone = new Map(); // login -> { info, until }
  function setLogins(lists) {
    const next = new Map();
    for (const l of lists || []) {
      const login = baseLogin(l && l.login);
      if (!login) continue;
      next.set(login, { listId: Number(l.id), accountId: Number(l.accountId) });
    }
    const t = now();
    if (known) {
      for (const [login, info] of known) if (!next.has(login)) gone.set(login, { info, until: t + 3600 * 1000 });
    }
    for (const login of next.keys()) gone.delete(login);
    for (const [login, g] of gone) if (g.until <= t) gone.delete(login);
    known = next;
  }

  function loginInfo(login) {
    if (!known) return null;
    const k = known.get(login);
    if (k) return k;
    const g = gone.get(login);
    return g && g.until > now() ? g.info : null;
  }

  function noteTuple(rec) {
    if (!rec.ipv4 || !rec.login || !loginInfo(rec.login)) return;
    const key = tupleKey(rec.localIp, rec.port, rec.clientIp, rec.clientPort);
    const cur = tuples.get(key);
    if (cur && cur.login === rec.login && !cur.final) {
      cur.last = rec.t;
      cur.final = !rec.interim;
      return;
    }
    if (tuples.size >= TUPLE_CAP) {
      // drop the oldest tenth (Map iteration is insertion order)
      let n = Math.ceil(TUPLE_CAP / 10);
      for (const k of tuples.keys()) {
        tuples.delete(k);
        if (--n <= 0) break;
      }
    }
    tuples.set(key, { login: rec.login, first: now(), firstRecordAt: rec.t, last: rec.t, final: !rec.interim, localIp: rec.localIp, port: rec.port, clientIp: rec.clientIp, clientPort: rec.clientPort });
  }

  function pruneTuples() {
    const cutoff = now() - TUPLE_TTL_MS;
    for (const [k, v] of tuples) if (Math.max(v.first, v.last) < cutoff) tuples.delete(k);
  }

  // One tick: read every log file from its cursor, count, persist once.
  // -> { ok, read, records, counted, skipped? }
  function tick() {
    lastTickAt = now();
    ensureLoaded();
    if (!known) {
      lagSince = lagSince || now();
      return { ok: false, skipped: "no_logins" };
    }
    const t0 = now();
    let budget = maxReadPerTick;
    let behind = false;
    const files = listLogFiles();
    const present = new Set(files.map((f) => f.name));
    const newFiles = { ...state.files };
    const deltas = new Map(); // login -> { up, down, conns }
    const unknown = { bytes: 0, records: 0, names: [] };
    let dropped = 0;
    let readBytes = 0;
    const recs = [];
    let changed = false;

    // cursors of files that are gone (archived, or removed by hand)
    for (const name of Object.keys(newFiles)) {
      if (!present.has(name)) {
        if (!archivedNames.has(name)) log.log(`[pergb-meter] ${name} is gone; dropping its cursor`);
        archivedNames.delete(name);
        delete newFiles[name];
        changed = true;
      }
    }

    for (const f of files) {
      const file = path.join(logDir, f.name);
      let st;
      try {
        st = fsx.statSync(file);
      } catch {
        continue;
      }
      let cur = newFiles[f.name];
      if (!cur) {
        cur = { ino: st.ino, off: 0, size: 0, growAt: now() };
        changed = true;
      } else if (cur.ino !== st.ino || st.size < cur.off) {
        event("pergb_meter_file_replaced", { file: f.name, oldIno: cur.ino, ino: st.ino, off: cur.off, size: st.size });
        cur = { ino: st.ino, off: 0, size: 0, growAt: now() };
        changed = true;
      } else {
        cur = { ...cur };
      }
      if (st.size !== cur.size) {
        cur.size = st.size;
        cur.growAt = now();
        changed = true;
      }
      if (st.size > cur.off) {
        if (budget <= 0) {
          behind = true;
          newFiles[f.name] = cur;
          continue;
        }
        const want = st.size - cur.off;
        const len = Math.min(want, budget);
        if (len < want) behind = true;
        const buf = Buffer.alloc(len);
        const fd = fsx.openSync(file, "r");
        let got;
        try {
          got = fsx.readSync(fd, buf, 0, len, cur.off);
        } finally {
          fsx.closeSync(fd);
        }
        const data = got === len ? buf : buf.subarray(0, got);
        const nl = data.lastIndexOf(10);
        if (nl >= 0) {
          const text = data.subarray(0, nl).toString("utf-8");
          for (const line of text.split("\n")) {
            const rec = parseRecord(line, logdump);
            if (!rec) {
              if (line.length) dropped += 1;
              continue;
            }
            recs.push(rec);
          }
          cur.off += nl + 1;
          budget -= nl + 1;
          readBytes += nl + 1;
          changed = true;
        } else if (data.length >= MAX_LINE * 4) {
          // a run of bytes without a newline longer than any record: garbage
          cur.off += data.length;
          budget -= data.length;
          dropped += 1;
          changed = true;
        }
      }
      newFiles[f.name] = cur;
    }

    // count
    for (const rec of recs) {
      if (rec.login === PROBE_LOGIN) continue;
      const bytes = rec.inBytes + rec.outBytes;
      if (bytes === 0) continue;
      const info = rec.login ? loginInfo(rec.login) : null;
      if (!info) {
        unknown.bytes += bytes;
        unknown.records += 1;
        if (unknown.names.length < 16) unknown.names.push(String(rec.user).slice(0, 64));
        continue;
      }
      let d = deltas.get(rec.login);
      if (!d) {
        d = { up: 0, down: 0, conns: 0 };
        deltas.set(rec.login, d);
      }
      d.up += rec.outBytes;
      d.down += rec.inBytes;
      if (!rec.interim) d.conns += 1;
    }

    if (!changed && !recs.length && !dropped) {
      lastTickOkAt = now();
      lagSince = behind ? lagSince || now() : null;
      maybeRetention();
      scheduleArchives(files);
      return { ok: true, read: 0, records: 0, counted: 0 };
    }

    // the next state: cursors and counters together
    const next = { ...state, files: newFiles, logins: state.logins, unknown: state.unknown };
    const counted = deltas.size;
    if (deltas.size || recs.length || dropped || unknown.records) next.seq = state.seq + 1;
    if (deltas.size) {
      const logins = { ...state.logins };
      for (const [login, d] of deltas) {
        const old = logins[login] || { up: 0, down: 0, conns: 0, seq: 0 };
        logins[login] = { up: old.up + d.up, down: old.down + d.down, conns: old.conns + d.conns, seq: next.seq };
      }
      next.logins = logins;
    }
    if (unknown.records) {
      const sample = state.unknown.sample.slice();
      for (const n of unknown.names) {
        if (sample.length >= UNKNOWN_SAMPLE_CAP) break;
        if (!sample.includes(n)) sample.push(n);
      }
      next.unknown = { bytes: state.unknown.bytes + unknown.bytes, records: state.unknown.records + unknown.records, sample };
    }
    next.dropped = state.dropped + dropped;
    try {
      writeState(next);
    } catch (e) {
      persistFailures += 1;
      lastError = `persist: ${(e && e.message) || e}`;
      lagSince = lagSince || t0;
      log.error(`[pergb-meter] ${lastError} (nothing counted; re-read next tick)`);
      return { ok: false, error: "persist_failed" };
    }
    state = next;
    lastError = null;
    lastTickOkAt = now();
    lagSince = behind ? lagSince || t0 : null;
    for (const rec of recs) noteTuple(rec);
    pruneTuples();
    if (onRecords && recs.length) {
      try {
        onRecords(recs);
      } catch (e) {
        log.error(`[pergb-meter] onRecords: ${(e && e.message) || e}`);
      }
    }
    maybeRetention();
    scheduleArchives(files);
    return { ok: true, read: readBytes, records: recs.length, counted, dropped };
  }

  // ── finished files → archive/ (streamed gzip, off the tick) ─────────────

  function finishedFiles(files) {
    const newest = new Map();
    for (const f of files) newest.set(f.sp, Math.max(newest.get(f.sp) || 0, f.hourMs));
    const out = [];
    for (const f of files) {
      if (f.hourMs >= newest.get(f.sp)) continue;
      const cur = state.files[f.name];
      if (!cur) continue;
      if (cur.off !== cur.size) continue;
      if (now() - (cur.growAt || 0) < finishedAfterMs) continue;
      out.push(f.name);
    }
    return out;
  }

  // A finished file whose tail has no newline (3proxy died mid-line): after
  // the quiet period the partial tail is dropped so the file can finish.
  function dropDeadTails(files) {
    const newest = new Map();
    for (const f of files) newest.set(f.sp, Math.max(newest.get(f.sp) || 0, f.hourMs));
    let changed = false;
    const nf = { ...state.files };
    for (const f of files) {
      if (f.hourMs >= newest.get(f.sp)) continue;
      const cur = nf[f.name];
      if (!cur || cur.off >= cur.size) continue;
      if (now() - (cur.growAt || 0) < finishedAfterMs) continue;
      nf[f.name] = { ...cur, off: cur.size };
      changed = true;
    }
    if (!changed) return;
    const next = { ...state, files: nf, dropped: state.dropped + 1 };
    try {
      writeState(next);
      state = next;
    } catch (e) {
      log.error(`[pergb-meter] persist (dead tail): ${(e && e.message) || e}`);
    }
  }

  function scheduleArchives(files) {
    dropDeadTails(files);
    for (const name of finishedFiles(files)) {
      if (archiving.has(name)) continue;
      archiving.add(name);
      archiveOne(name)
        .catch((e) => log.error(`[pergb-meter] archive ${name}: ${(e && e.message) || e}`))
        .finally(() => archiving.delete(name));
    }
  }

  async function archiveOne(name) {
    const src = path.join(logDir, name);
    await fsp.mkdir(archiveDir, { recursive: true });
    const dst = path.join(archiveDir, `${name}.gz`);
    const tmp = `${dst}.tmp`;
    await pipeline(fs.createReadStream(src), zlib.createGzip({ level: 6 }), fs.createWriteStream(tmp, { mode: 0o640 }));
    const fh = await fsp.open(tmp, "r");
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fsp.rename(tmp, dst);
    await fsp.unlink(src);
    archivedNames.add(name);
  }

  // Waits for the archive jobs in flight (tests).
  async function drainArchives() {
    while (archiving.size) await new Promise((r) => setTimeout(r, 5));
  }

  // ── retention of archive/ (age, then filesystem fill) ───────────────────

  function fsUsage() {
    try {
      const s = fs.statfsSync(logDir);
      const total = s.blocks * s.bsize;
      const free = s.bavail * s.bsize;
      return { total, free, usedPct: total > 0 ? ((total - free) / total) * 100 : 0, freePct: total > 0 ? (free / total) * 100 : 100 };
    } catch {
      return null;
    }
  }

  function retention({ usage = fsUsage(), force = false } = {}) {
    lastRetentionAt = now();
    let names;
    try {
      names = fs.readdirSync(archiveDir).filter((n) => ARCHIVE_RE.test(n));
    } catch {
      return { removed: 0, cut: 0 };
    }
    const items = names
      .map((n) => ({ name: n, ...parseLogName(n) }))
      .sort((a, b) => a.hourMs - b.hourMs || a.sp - b.sp);
    let removed = 0;
    let cut = 0;
    const ageLimit = now() - retainDays * 86400 * 1000;
    const keep = [];
    for (const it of items) {
      if (it.hourMs < ageLimit) {
        try {
          fs.unlinkSync(path.join(archiveDir, it.name));
          removed += 1;
        } catch {}
      } else keep.push(it);
    }
    let u = usage;
    while (u && u.usedPct > fsFillPct && keep.length) {
      const it = keep.shift();
      let size = 0;
      try {
        size = fs.statSync(path.join(archiveDir, it.name)).size;
        fs.unlinkSync(path.join(archiveDir, it.name));
      } catch {}
      cut += 1;
      u = force ? { ...u, usedPct: u.usedPct - (u.total ? (size / u.total) * 100 : 0) } : fsUsage() || { ...u, usedPct: u.usedPct - (u.total ? (size / u.total) * 100 : 0) };
    }
    if (cut) event("pergb_log_retention_cut", { removed: cut, fsFillPct });
    return { removed, cut };
  }

  function maybeRetention() {
    if (now() - lastRetentionAt < 60000) return;
    try {
      retention();
    } catch (e) {
      log.error(`[pergb-meter] retention: ${(e && e.message) || e}`);
    }
  }

  // ── readers ─────────────────────────────────────────────────────────────

  // Cumulative counters of the logins changed after `since` (all with 0).
  function usage({ since = 0 } = {}) {
    ensureLoaded();
    const s = Number(since) || 0;
    const logins = {};
    for (const [login, c] of Object.entries(state.logins)) {
      if (c.seq > s) logins[login] = { up: c.up, down: c.down, conns: c.conns };
    }
    return { epoch: state.epoch, seq: state.seq, asOf: new Date(lastTickOkAt || now()).toISOString(), logins };
  }

  // login -> { up, down, conns } (the whole current epoch).
  function counters() {
    ensureLoaded();
    return state.logins;
  }

  function lagSec() {
    const t = now();
    let lag = lagSince ? (t - lagSince) / 1000 : 0;
    if (lastTickOkAt) lag = Math.max(lag, (t - lastTickOkAt) / 1000 - 2);
    else if (state) lag = Math.max(lag, 0);
    return Math.max(0, Math.round(lag * 10) / 10);
  }

  function status() {
    ensureLoaded();
    const pending = Object.keys(state.files).length;
    return {
      epoch: state.epoch,
      seq: state.seq,
      logLagSec: lagSec(),
      meterLagSec: lagSec(),
      droppedLines: state.dropped,
      unknownBytes: state.unknown.bytes,
      unknownRecords: state.unknown.records,
      unknownSample: state.unknown.sample.slice(0, 20),
      pendingFiles: pending,
      logins: Object.keys(state.logins).length,
      loginsKnown: known ? known.size : null,
      skipped: state.skipped,
      tuples: tuples.size,
      persistFailures,
      lastError,
      lastTickAt: lastTickAt ? new Date(lastTickAt).toISOString() : null,
      events: events.slice(-10),
    };
  }

  // IPv4 sessions known by tuple: [{ key, login, first, last, final, ... }].
  function sessions({ logins = null } = {}) {
    const out = [];
    for (const [key, v] of tuples) {
      if (logins && !logins.has(v.login)) continue;
      out.push({ key, ...v });
    }
    return out;
  }

  function tupleLogin(key) {
    const v = tuples.get(key);
    return v ? v.login : null;
  }

  // ── attribution: records of one bound source in a time window ───────────

  async function* recordsBetween(fromMs, toMs) {
    const hourMs = 3600 * 1000;
    const pick = (name, dir) => {
      const p = parseLogName(name);
      if (!p) return null;
      if (p.hourMs + hourMs < fromMs || p.hourMs > toMs) return null;
      return { file: path.join(dir, name), gz: name.endsWith(".gz"), ...p };
    };
    const items = [];
    for (const [dir, re] of [
      [archiveDir, ARCHIVE_RE],
      [logDir, FILE_RE],
    ]) {
      let names = [];
      try {
        names = await fsp.readdir(dir);
      } catch {}
      for (const n of names) if (re.test(n)) {
        const it = pick(n, dir);
        if (it) items.push(it);
      }
    }
    items.sort((a, b) => a.hourMs - b.hourMs || a.sp - b.sp);
    for (const it of items) {
      let input = fs.createReadStream(it.file);
      if (it.gz) input = input.pipe(zlib.createGunzip());
      const rl = readline.createInterface({ input, crlfDelay: Infinity });
      try {
        for await (const line of rl) {
          const rec = parseRecord(line, logdump);
          if (rec && rec.t >= fromMs && rec.t <= toMs) yield rec;
        }
      } catch (e) {
        log.error(`[pergb-meter] attribution read ${it.file}: ${(e && e.message) || e}`);
      } finally {
        rl.close();
        input.destroy();
      }
    }
  }

  return {
    load,
    tick,
    setLogins,
    loginsReady: () => known !== null,
    loginInfo,
    usage,
    counters,
    status,
    sessions,
    tupleLogin,
    retention,
    drainArchives,
    recordsBetween,
    setLogdump(v) {
      if (Number.isInteger(v) && v > 0) logdump = v;
    },
    get epoch() {
      return ensureLoaded().epoch;
    },
    get seq() {
      return ensureLoaded().seq;
    },
    _state: () => state,
  };
}

module.exports = {
  FILE_RE,
  ARCHIVE_RE,
  PROBE_LOGIN,
  parseLogTime,
  parseRecord,
  parseLogName,
  baseLogin,
  tupleKey,
  createMeter,
};
