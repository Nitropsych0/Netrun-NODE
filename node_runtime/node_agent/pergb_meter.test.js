"use strict";

// Pay-per-GB v2 — the node meter (pergb_meter.js): strict records, partial
// tails, hourly rotation, inode changes, exactly-once across crashes, a lost
// meter.json, unknown logins, archiving and retention, the usage reader.
// Run with: node --test node_runtime/node_agent/pergb_meter.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");

const meterLib = require("./pergb_meter.js");

const QUIET = { log() {}, error() {} };

function tmpdir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `pergb-meter-${tag}-`));
}

function clock(start = Date.UTC(2026, 9, 9, 14, 0, 0)) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => {
    t += ms;
  };
  now.set = (v) => {
    t = v;
  };
  return now;
}

// One I4 record line (no trailing newline).
function rec({
  t = "20261009140001.123",
  service = "SOCKS",
  port = 31000,
  code = 0,
  user = "netrun-abc12",
  cip = "127.0.0.1",
  cport = 40000,
  lip = "127.0.0.4",
  bound = "2001:db8:aa:12::1",
  dst = "2606:4700::1",
  dport = 443,
  i = 1000,
  o = 100,
  host = "example.com",
} = {}) {
  return [t, service, port, code, user, cip, cport, lip, bound, dst, dport, i, o, host].join(" ");
}

const LISTS = [
  { id: 1, login: "netrun-abc12", accountId: 10 },
  { id: 2, login: "netrun-def34", accountId: 10 },
  { id: 3, login: "netrun-ghi56", accountId: 20 },
];

function newMeter(dir, now, extra = {}) {
  const m = meterLib.createMeter({
    logDir: path.join(dir, "log"),
    statePath: path.join(dir, "state", "meter.json"),
    now,
    log: QUIET,
    ...extra,
  });
  m.setLogins(LISTS);
  return m;
}

function logFile(dir, name) {
  fs.mkdirSync(path.join(dir, "log"), { recursive: true });
  return path.join(dir, "log", name);
}

test("parseRecord: exactly 14 fields, digits where digits belong, a UTC time", () => {
  const r = meterLib.parseRecord(rec({ user: "NetRun-ABC12-Session-x1-ttl-30m", i: 5, o: 7 }));
  assert.ok(r);
  assert.strictEqual(r.login, "netrun-abc12");
  assert.strictEqual(r.inBytes, 5);
  assert.strictEqual(r.outBytes, 7);
  assert.strictEqual(r.t, Date.UTC(2026, 9, 9, 14, 0, 1, 123));
  assert.strictEqual(r.interim, false);
  assert.strictEqual(meterLib.parseRecord(rec({ i: 262144 })).interim, true);
  const line = rec();
  assert.strictEqual(meterLib.parseRecord(line.split(" ").slice(0, 13).join(" ")), null, "13 fields");
  assert.strictEqual(meterLib.parseRecord(`${line} extra`), null, "15 fields");
  assert.strictEqual(meterLib.parseRecord(rec({ i: "12a" })), null, "bytes not digits");
  assert.strictEqual(meterLib.parseRecord(rec({ t: "2026-10-09" })), null, "time");
  assert.strictEqual(meterLib.parseRecord(rec({ port: 70000 })), null, "port");
  assert.strictEqual(meterLib.parseRecord(rec({ bound: "nonsense" })), null, "address");
  assert.strictEqual(meterLib.baseLogin("netrun-abc12-session-s00042"), "netrun-abc12");
  assert.strictEqual(meterLib.baseLogin("netrun-svcprobe"), "netrun-svcprobe");
  assert.strictEqual(meterLib.baseLogin("admin"), null);
  assert.strictEqual(meterLib.baseLogin("-"), null);
});

test("counting: known base logins only; probe and zero-byte records skipped; unknown aggregated", () => {
  const dir = tmpdir("count");
  const now = clock();
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(
    f,
    [
      rec({ i: 1000, o: 100 }),
      rec({ user: "netrun-abc12-session-job1-ttl-30m", i: 10, o: 1 }),
      rec({ user: "netrun-svcprobe", i: 999, o: 999 }),
      rec({ user: "netrun-def34", i: 0, o: 0, code: 1 }),
      rec({ user: "netrun-zzzzz", i: 50, o: 5 }),
      rec({ user: "-", i: 7, o: 0 }),
      "",
    ].join("\n")
  );
  const m = newMeter(dir, now);
  // no state file and a log present: the fresh state starts at the end
  const first = m.tick();
  assert.strictEqual(first.records, 0, "a fresh state never reads old logs");
  fs.appendFileSync(f, [rec({ i: 1000, o: 100 }), rec({ user: "netrun-abc12-rotate", i: 10, o: 1 }), rec({ user: "netrun-svcprobe", i: 1, o: 1 }), rec({ user: "netrun-def34", i: 0, o: 0, code: 1 }), rec({ user: "netrun-zzzzz", i: 50, o: 5 }), ""].join("\n"));
  const r = m.tick();
  assert.strictEqual(r.ok, true);
  const c = m.counters();
  assert.deepStrictEqual(c["netrun-abc12"] && { up: c["netrun-abc12"].up, down: c["netrun-abc12"].down, conns: c["netrun-abc12"].conns }, { up: 101, down: 1010, conns: 2 });
  assert.strictEqual(c["netrun-def34"], undefined, "zero-byte record skipped");
  assert.strictEqual(c["netrun-svcprobe"], undefined, "probe never billed");
  const st = m.status();
  assert.strictEqual(st.unknownBytes, 55);
  assert.deepStrictEqual(st.unknownSample, ["netrun-zzzzz"]);
  assert.ok(st.skipped.bytes > 0, "fresh-state skip reported");
});

test("no RADIUS logins yet: the meter does not advance (nothing can be lost as unknown)", () => {
  const dir = tmpdir("nologins");
  const now = clock();
  const m = meterLib.createMeter({ logDir: path.join(dir, "log"), statePath: path.join(dir, "s", "meter.json"), now, log: QUIET });
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  m.tick(); // fresh, no logs
  fs.writeFileSync(f, `${rec()}\n`);
  assert.strictEqual(m.tick().skipped, "no_logins");
  now.advance(40000);
  assert.ok(m.status().meterLagSec >= 30, "lag grows while it waits");
  m.setLogins(LISTS);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 1000);
  assert.strictEqual(m.status().meterLagSec, 0);
});

test("partial tails, interleaved bad lines, hourly rotation, an inode change", () => {
  const dir = tmpdir("tail");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick(); // fresh state, no logs: from 0
  const f1 = logFile(dir, "p31000.log.2026.10.09-14");
  const full = rec({ i: 300, o: 30 });
  fs.writeFileSync(f1, `${rec({ i: 100, o: 10 })}\ngarbage line\n${full.slice(0, 20)}`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 100);
  assert.strictEqual(m.status().droppedLines, 1);
  fs.appendFileSync(f1, `${full.slice(20)}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 400, "the partial tail is read once complete");
  // the next hour; the old file still gets a late record
  const f2 = logFile(dir, "p31000.log.2026.10.09-15");
  fs.writeFileSync(f2, `${rec({ t: "20261009150000.000", i: 5, o: 0 })}\n`);
  fs.appendFileSync(f1, `${rec({ i: 1, o: 0 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 406);
  // another range's file
  const f3 = logFile(dir, "p31500.log.2026.10.09-15");
  fs.writeFileSync(f3, `${rec({ port: 31500, user: "netrun-ghi56", i: 9, o: 1 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-ghi56"].down, 9);
  // f2 replaced by a new inode with different content: read from 0 again
  fs.unlinkSync(f2);
  fs.writeFileSync(f2, `${rec({ i: 20, o: 0 })}\n${rec({ i: 20, o: 0 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 446);
  // the state on disk matches
  const disk = JSON.parse(fs.readFileSync(path.join(dir, "state", "meter.json"), "utf-8"));
  assert.strictEqual(disk.logins["netrun-abc12"].down, 446);
  assert.strictEqual(disk.files["p31000.log.2026.10.09-15"].off, fs.statSync(f2).size);
});

test("a log replaced under the SAME inode (Linux reuses inode numbers) is read again from 0", () => {
  const dir = tmpdir("sameino");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  const f = logFile(dir, "p31000.log.2026.10.09-16");
  fs.writeFileSync(f, `${rec({ i: 7, o: 0 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 7);
  const ino = fs.statSync(f).ino;
  // writeFileSync on an existing path truncates and rewrites the SAME inode:
  // the new content is longer than the old cursor, so only the head tells
  fs.writeFileSync(f, `${rec({ t: "20261009160500.000", i: 30, o: 0 })}\n${rec({ i: 40, o: 0 })}\n`);
  assert.strictEqual(fs.statSync(f).ino, ino, "the test needs the same inode");
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 77, "both records of the new content are counted");
  // appending to the same file does not look like a replacement
  fs.appendFileSync(f, `${rec({ i: 3, o: 0 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 80);
});

test("exactly once: a crash anywhere between read and persist, 1000 times", () => {
  const dir = tmpdir("crash");
  const now = clock();
  let rnd = 12345;
  const rand = () => {
    rnd = (rnd * 1103515245 + 12345) & 0x7fffffff;
    return rnd / 0x7fffffff;
  };
  // fs that crashes at a random point of the state write
  let armed = false;
  const CRASH = new Error("simulated crash");
  const crashy = {
    ...fs,
    openSync(p, flags, mode) {
      if (armed && String(p).endsWith(".tmp") && rand() < 0.2) throw CRASH;
      return fs.openSync(p, flags, mode);
    },
    writeSync(fd, data) {
      if (armed && typeof data === "string" && rand() < 0.2) {
        fs.writeSync(fd, data.slice(0, Math.floor(data.length / 2)));
        throw CRASH;
      }
      return fs.writeSync(fd, data);
    },
    fsyncSync(fd) {
      if (armed && rand() < 0.1) throw CRASH;
      return fs.fsyncSync(fd);
    },
    renameSync(a, b) {
      if (armed && String(a).endsWith(".tmp")) {
        const r = rand();
        if (r < 0.15) throw CRASH; // before the rename
        if (r < 0.3) {
          fs.renameSync(a, b); // after the rename, before the in-memory commit
          throw CRASH;
        }
      }
      return fs.renameSync(a, b);
    },
  };
  const make = () => newMeter(dir, now, { fsx: crashy });
  let m = make();
  m.tick();
  const files = ["p31000.log.2026.10.09-14", "p31500.log.2026.10.09-14"].map((n) => logFile(dir, n));
  let wantDown = 0;
  let wantUp = 0;
  let crashes = 0;
  for (let i = 0; i < 1000; i += 1) {
    // a few records (sometimes with a partial tail) in either file
    const n = 1 + Math.floor(rand() * 4);
    let text = "";
    for (let j = 0; j < n; j += 1) {
      const down = 1 + Math.floor(rand() * 5000);
      const up = Math.floor(rand() * 500);
      wantDown += down;
      wantUp += up;
      text += `${rec({ i: down, o: up })}\n`;
    }
    const f = files[Math.floor(rand() * files.length)];
    fs.appendFileSync(f, text);
    armed = true;
    let r;
    try {
      r = m.tick();
    } catch (e) {
      if (e !== CRASH) throw e;
      r = { ok: false };
    }
    armed = false;
    if (!r.ok) {
      crashes += 1;
      m = make(); // the process died: a new agent from what is on disk
    }
  }
  // drain without crashes
  for (let k = 0; k < 3; k += 1) m.tick();
  const c = m.counters()["netrun-abc12"];
  assert.ok(crashes > 100, `crashes simulated (${crashes})`);
  assert.strictEqual(c.down, wantDown, "every byte counted exactly once");
  assert.strictEqual(c.up, wantUp);
  const fresh = newMeter(dir, now);
  assert.strictEqual(fresh.counters()["netrun-abc12"].down, wantDown, "and persisted");
});

test("meter.json deleted (or corrupt) while logs exist: nothing is charged twice; new epoch; reset reported", () => {
  const dir = tmpdir("reset");
  const now = clock();
  const events = [];
  let m = newMeter(dir, now, { onEvent: (e) => events.push(e) });
  m.tick();
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(f, `${rec({ i: 1000, o: 0 })}\n${rec({ i: 1000, o: 0 })}\n`);
  m.tick();
  const epoch1 = m.epoch;
  assert.strictEqual(m.counters()["netrun-abc12"].down, 2000);
  fs.unlinkSync(path.join(dir, "state", "meter.json"));
  fs.appendFileSync(f, rec({ i: 7, o: 0 }).slice(0, 30)); // a record being written
  m = newMeter(dir, now, { onEvent: (e) => events.push(e) });
  m.tick();
  assert.notStrictEqual(m.epoch, epoch1, "a new epoch");
  assert.strictEqual((m.counters()["netrun-abc12"] || { down: 0 }).down, 0, "old bytes are never re-read");
  assert.ok(events.some((e) => e.type === "pergb_meter_reset" && e.skippedBytes > 0));
  fs.appendFileSync(f, `${rec({ i: 7, o: 0 }).slice(30)}\n${rec({ i: 5, o: 0 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 12, "the record in flight and the new one count");
  // corrupt file: moved aside, again a fresh state at the end
  fs.writeFileSync(path.join(dir, "state", "meter.json"), "{not json");
  m = newMeter(dir, now);
  m.tick();
  assert.strictEqual((m.counters()["netrun-abc12"] || { down: 0 }).down, 0);
  assert.ok(fs.readdirSync(path.join(dir, "state")).some((n) => n.startsWith("meter.json.broken-")));
});

test("a node without logs starts from 0; counters never go down inside an epoch", () => {
  const dir = tmpdir("zero");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  let last = 0;
  for (let i = 0; i < 20; i += 1) {
    fs.appendFileSync(f, `${rec({ i: i * 3, o: i })}\n`);
    m.tick();
    const c = m.counters()["netrun-abc12"];
    const total = c ? c.up + c.down : 0;
    assert.ok(total >= last);
    last = total;
  }
  assert.strictEqual(m.status().skipped.bytes, 0);
});

test("unknown-login flood: the state does not grow", () => {
  const dir = tmpdir("flood");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(f, `${rec()}\n`);
  m.tick();
  const before = fs.statSync(path.join(dir, "state", "meter.json")).size;
  for (let round = 0; round < 10; round += 1) {
    let text = "";
    for (let i = 0; i < 2000; i += 1) text += `${rec({ user: `netrun-x${round}y${i}-session-z`, i: 10, o: 10 })}\n`;
    fs.appendFileSync(f, text);
    m.tick();
  }
  const after = fs.statSync(path.join(dir, "state", "meter.json")).size;
  assert.strictEqual(Object.keys(m.counters()).length, 1, "only the known login");
  assert.ok(after - before < 80 * 1024, `state grew by ${after - before} B (the capped sample only)`);
  assert.strictEqual(m.status().unknownRecords, 20000);
});

test("finished files: archived (gzip) after 120 s quiet once a newer hour exists, never read twice", async () => {
  const dir = tmpdir("archive");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  const f1 = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(f1, `${rec({ i: 100 })}\n`);
  m.tick();
  now.advance(200000);
  m.tick();
  await m.drainArchives();
  assert.ok(fs.existsSync(f1), "the newest file of a range is never finished");
  const f2 = logFile(dir, "p31000.log.2026.10.09-15");
  fs.writeFileSync(f2, `${rec({ i: 1 })}\n`);
  fs.appendFileSync(f1, `${rec({ i: 0, o: 0, code: 13 })}\n`); // a late record: f1 grew now
  m.tick();
  await m.drainArchives();
  assert.ok(fs.existsSync(f1), "not before 120 s without growth (f1 grew at the last read)");
  now.advance(121000);
  m.tick();
  await m.drainArchives();
  assert.ok(!fs.existsSync(f1), "finished file removed");
  const gz = path.join(dir, "log", "archive", "p31000.log.2026.10.09-14.gz");
  assert.ok(fs.existsSync(gz));
  assert.match(zlib.gunzipSync(fs.readFileSync(gz)).toString(), /netrun-abc12/);
  m.tick();
  assert.strictEqual(m._state().files["p31000.log.2026.10.09-14"], undefined, "cursor dropped after the unlink");
  assert.strictEqual(m.counters()["netrun-abc12"].down, 101, "counted once");
  // a newer meter instance never re-reads it
  const m2 = newMeter(dir, now);
  m2.tick();
  assert.strictEqual(m2.counters()["netrun-abc12"].down, 101);
  // a dead partial tail in an old file is dropped after the quiet period
  const f3 = logFile(dir, "p31500.log.2026.10.09-14");
  const f4 = logFile(dir, "p31500.log.2026.10.09-15");
  fs.writeFileSync(f3, `${rec({ i: 3 })}\nhalf a rec`);
  fs.writeFileSync(f4, `${rec({ i: 4 })}\n`);
  m2.tick();
  now.advance(130000);
  m2.tick();
  m2.tick();
  await m2.drainArchives();
  m2.tick();
  assert.ok(!fs.existsSync(f3), "the file with a dead tail finishes too");
  assert.strictEqual(m2.counters()["netrun-abc12"].down, 108);
});

test("retention: archives older than 14 days go; over 80 % fill the oldest go first (event)", () => {
  const dir = tmpdir("retain");
  const now = clock(Date.UTC(2026, 9, 30, 0, 0, 0));
  const events = [];
  const m = newMeter(dir, now, { onEvent: (e) => events.push(e) });
  const arch = path.join(dir, "log", "archive");
  fs.mkdirSync(arch, { recursive: true });
  const names = ["p31000.log.2026.10.01-00.gz", "p31000.log.2026.10.20-00.gz", "p31000.log.2026.10.21-00.gz", "p31000.log.2026.10.29-00.gz"];
  for (const n of names) fs.writeFileSync(path.join(arch, n), Buffer.alloc(1000));
  const r1 = m.retention({ usage: { total: 1e6, free: 9e5, usedPct: 10, freePct: 90 }, force: true });
  assert.strictEqual(r1.removed, 1, "older than 14 days");
  assert.ok(!fs.existsSync(path.join(arch, names[0])));
  const r2 = m.retention({ usage: { total: 10000, free: 1000, usedPct: 90, freePct: 10 }, force: true });
  assert.ok(r2.cut >= 1);
  assert.ok(!fs.existsSync(path.join(arch, names[1])), "the oldest first");
  assert.ok(fs.existsSync(path.join(arch, names[3])), "the newest kept");
  assert.ok(events.some((e) => e.type === "pergb_log_retention_cut"));
});

test("usage: since filters by meter seq; the epoch comes along", () => {
  const dir = tmpdir("usage");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(f, `${rec({ i: 10 })}\n${rec({ user: "netrun-ghi56", i: 20 })}\n`);
  m.tick();
  const u1 = m.usage({ since: 0 });
  assert.deepStrictEqual(Object.keys(u1.logins).sort(), ["netrun-abc12", "netrun-ghi56"]);
  fs.appendFileSync(f, `${rec({ i: 5 })}\n`);
  m.tick();
  const u2 = m.usage({ since: u1.seq });
  assert.deepStrictEqual(Object.keys(u2.logins), ["netrun-abc12"]);
  assert.strictEqual(u2.logins["netrun-abc12"].down, 15, "cumulative, not a delta");
  assert.strictEqual(u2.epoch, u1.epoch);
  assert.ok(u2.seq > u1.seq);
});

test("IPv4 sessions: loopback tuple -> base login; final records close them", () => {
  const dir = tmpdir("tuple");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(
    f,
    [
      rec({ dst: "93.184.216.34", bound: "203.0.113.5", cport: 41000, i: 262144, o: 10 }),
      rec({ dst: "93.184.216.34", bound: "203.0.113.5", cport: 41001, user: "netrun-ghi56", i: 300000, o: 0 }),
      rec({ dst: "2606:4700::1", cport: 41002, i: 300000 }),
      "",
    ].join("\n")
  );
  m.tick();
  const s = m.sessions();
  assert.strictEqual(s.length, 2, "IPv6 sessions are found by tag, not by tuple");
  const k = meterLib.tupleKey("127.0.0.4", 31000, "127.0.0.1", 41000);
  assert.strictEqual(m.tupleLogin(k), "netrun-abc12");
  assert.strictEqual(s.find((x) => x.key === k).final, false);
  fs.appendFileSync(f, `${rec({ dst: "93.184.216.34", bound: "203.0.113.5", cport: 41000, i: 5, o: 1 })}\n`);
  m.tick();
  assert.strictEqual(m.sessions().find((x) => x.key === k).final, true);
  assert.strictEqual(m.sessions({ logins: new Set(["netrun-ghi56"]) }).length, 1);
});

test("a login deleted from RADIUS is still billed for an hour (records read after the delete)", () => {
  const dir = tmpdir("gone");
  const now = clock();
  const m = newMeter(dir, now);
  m.tick();
  m.setLogins(LISTS.filter((l) => l.id !== 3));
  const f = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(f, `${rec({ user: "netrun-ghi56", i: 10 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-ghi56"].down, 10);
  now.advance(3601 * 1000);
  m.setLogins(LISTS.filter((l) => l.id !== 3));
  fs.appendFileSync(f, `${rec({ user: "netrun-ghi56", i: 10 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-ghi56"].down, 10, "after the grace hour: unknown");
});

test("attribution reader: records of a time window from the live logs and the archive", async () => {
  const dir = tmpdir("attr");
  const now = clock();
  const m = newMeter(dir, now);
  const arch = path.join(dir, "log", "archive");
  fs.mkdirSync(arch, { recursive: true });
  fs.writeFileSync(
    path.join(arch, "p31000.log.2026.10.09-12.gz"),
    zlib.gzipSync(`${rec({ t: "20261009120500.000", bound: "2001:db8:aa:1::9" })}\n`)
  );
  fs.writeFileSync(logFile(dir, "p31000.log.2026.10.09-14"), `${rec({ t: "20261009140500.000", bound: "2001:db8:aa:1::9" })}\n`);
  const got = [];
  for await (const r of m.recordsBetween(Date.UTC(2026, 9, 9, 12, 0), Date.UTC(2026, 9, 9, 15, 0))) got.push(r);
  assert.strictEqual(got.length, 2);
  const late = [];
  for await (const r of m.recordsBetween(Date.UTC(2026, 9, 9, 13, 0), Date.UTC(2026, 9, 9, 15, 0))) late.push(r);
  assert.strictEqual(late.length, 1);
});

test("the proxy-owned log directory cannot steer the agent: symlinked logs are skipped, a symlinked archive/ gets nothing", async () => {
  const dir = tmpdir("symlink");
  const now = clock();
  const events = [];
  const m = newMeter(dir, now, { onEvent: (e) => events.push(e) });
  m.tick();
  const secret = path.join(dir, "secret.txt");
  fs.writeFileSync(secret, `${rec({ i: 999999 })}\n`);
  fs.symlinkSync(secret, logFile(dir, "p31000.log.2026.10.09-13"));
  const f2 = logFile(dir, "p31000.log.2026.10.09-14");
  fs.writeFileSync(f2, `${rec({ i: 10 })}\n`);
  m.tick();
  assert.strictEqual(m.counters()["netrun-abc12"].down, 10, "the symlink is not read");
  assert.ok(events.some((e) => e.type === "pergb_meter_not_a_file"));
  // archive/ replaced by a symlink to somewhere else: nothing is written there
  const elsewhere = path.join(dir, "elsewhere");
  fs.mkdirSync(elsewhere);
  fs.symlinkSync(elsewhere, path.join(dir, "log", "archive"));
  fs.writeFileSync(logFile(dir, "p31500.log.2026.10.09-13"), `${rec({ i: 1 })}\n`);
  fs.writeFileSync(logFile(dir, "p31500.log.2026.10.09-14"), `${rec({ i: 1 })}\n`);
  m.tick();
  now.advance(130000);
  m.tick();
  await m.drainArchives();
  assert.deepStrictEqual(fs.readdirSync(elsewhere), [], "no archive written through the symlink");
  assert.ok(fs.existsSync(logFile(dir, "p31500.log.2026.10.09-13")), "the finished file stays until it can be archived");
});
