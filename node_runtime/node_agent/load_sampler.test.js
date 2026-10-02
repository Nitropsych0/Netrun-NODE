"use strict";

// Wave NODE-LOAD-GUARD — run with: node node_runtime/node_agent/load_sampler.test.js

const assert = require("assert");
const ls = require("./load_sampler.js");

let passed = 0;
function ok(cond, msg) {
  assert.ok(cond, msg);
  passed += 1;
}

ok(ls.parseProcStat("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n").total === 1000, "total sums 8 fields");
ok(ls.parseProcStat("cpu  100 0 50 800 50 0 0 0 0 0\n").idle === 850, "idle includes iowait");
ok(ls.parseProcStat("garbage") === null, "no cpu line → null");
ok(ls.cpuPctBetween({ idle: 0, total: 0 }, { idle: 20, total: 100 }) === 80, "80 % busy");
ok(ls.cpuPctBetween({ idle: 0, total: 100 }, { idle: 0, total: 100 }) === null, "no elapsed ticks → null");
ok(ls.parseMeminfo("MemTotal: 4000 kB\nMemFree: 100 kB\nMemAvailable: 1000 kB\n") === 75, "mem used %");
ok(ls.parseMeminfo("MemTotal: 4000 kB\n") === null, "no MemAvailable → null");
ok(ls.parseSockstatTcp("sockets: used 9\nTCP: inuse 42 orphan 0 tw 3\n") === 42, "tcp inuse");
ok(ls.parseSockstatTcp("TCP6: inuse 7\n") === 7, "tcp6 inuse");

// A fake clock + /proc: CPU busy% per interval is driven by `busy`.
function fake() {
  let t = 0;
  let idle = 0;
  let total = 0;
  const state = { busy: 0 };
  const files = {
    "/proc/stat": () => `cpu  ${total - idle} 0 0 ${idle} 0 0 0 0 0 0\n`,
    "/proc/meminfo": () => "MemTotal: 1000 kB\nMemAvailable: 500 kB\n",
    "/proc/net/sockstat": () => "TCP: inuse 10 orphan 0\n",
    "/proc/net/sockstat6": () => "TCP6: inuse 5\n",
  };
  const s = ls.createSampler({
    readFile: (p) => {
      if (!files[p]) throw new Error("ENOENT");
      return files[p]();
    },
    now: () => t,
  });
  return {
    s,
    state,
    step(busy, n = 1) {
      for (let i = 0; i < n; i += 1) {
        t += ls.SAMPLE_MS;
        total += 100;
        idle += 100 - busy;
        s.tick();
      }
    },
    init() {
      s.tick();
    },
  };
}

{
  const f = fake();
  f.init();
  const empty = f.s.snapshot();
  ok(empty.cpuAvg5m === null && empty.cpuMin5m === null && empty.windowSec === 0, "one sample → no verdict");
  ok(empty.memUsedPct === 50 && empty.tcpInuse === 15, "mem + sockets read");

  f.step(90, 60); // 5 minutes at 90 %
  const hot = f.s.snapshot();
  ok(hot.cpuMin5m === 90 && hot.cpuAvg5m === 90 && hot.cpuPct === 90, "sustained 90 %");
  ok(hot.windowSec >= 290, "window filled");

  f.step(10, 1); // one dip
  const dip = f.s.snapshot();
  ok(dip.cpuMin5m === 10 && dip.cpuPct === 10, "a single dip drops min5m below the threshold");
  ok(dip.cpuAvg5m > 80, "but the 5-min average stays high");

  f.step(20, 60);
  const cool = f.s.snapshot();
  ok(cool.cpuAvg5m === 20 && cool.cpuAvg1m === 20, "cooled down");
  ok(f.s._samples.length <= 63, "ring stays bounded");
}

{
  const s = ls.createSampler({ readFile: () => { throw new Error("no /proc"); } });
  s.tick();
  const snap = s.snapshot();
  ok(snap.cpuPct === null && snap.memUsedPct === null && snap.tcpInuse === 0, "no /proc → nulls, never throws");
}

console.log(`load_sampler.test.js: ${passed} assertions passed`);
