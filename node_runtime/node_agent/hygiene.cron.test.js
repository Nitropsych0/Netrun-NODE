"use strict";

// Incident 2026-10-07 — crontab hygiene (hygiene.js): every line that runs a
// generator proxy-startup_*.sh goes (any directory: the generator writes
// /root/proxyserver/..., which the old post-/generate `grep -Fv
// /opt/netrun/proxyserver/...` never matched), every other line stays byte for
// byte, and an unchanged crontab is never rewritten. The last test drives the
// default runner against PATH stubs (it refuses to run unless `crontab` and
// `systemctl` resolve to the stubs, so the real crontab is never touched).
// Run with: node --test node_runtime/node_agent/hygiene.cron.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const h = require("./hygiene.js");

const NOW = Date.parse("2026-10-07T12:00:00.000Z");

const GENERATOR_LINES = [
  "@reboot /usr/bin/bash /root/proxyserver/proxy-startup_18100.sh",
  "@reboot /usr/bin/bash /root/proxyserver/proxy-startup_19600.sh",
  "*/5 * * * * /usr/bin/bash /root/proxyserver/proxy-startup_19600.sh",
  "@reboot bash /opt/netrun/proxyserver/proxy-startup_21100.sh >/dev/null 2>&1",
  '@reboot "/usr/bin/bash" "/root/proxyserver/proxy-startup_22600.sh"',
];
const OTHER_LINES = [
  "# m h  dom mon dow   command",
  'MAILTO=""',
  "SHELL=/bin/bash",
  "",
  "# @reboot /usr/bin/bash /root/proxyserver/proxy-startup_17000.sh",
  "0 4 * * * /usr/local/bin/my-proxy-startup_1.sh",
  "15 3 * * * /opt/netrun/scripts/backup.sh /root/proxyserver/proxy-startup_18100.sh.bak",
  "*/5 * * * * /opt/netrun/scripts/trend_monitor.sh",
];
// Interleaved, as years of generations leave them.
const MIXED = [
  OTHER_LINES[0], OTHER_LINES[1], OTHER_LINES[2],
  GENERATOR_LINES[0], GENERATOR_LINES[1], OTHER_LINES[3], GENERATOR_LINES[2],
  OTHER_LINES[4], OTHER_LINES[5], GENERATOR_LINES[3], OTHER_LINES[6], GENERATOR_LINES[4], OTHER_LINES[7],
].join("\n") + "\n";
const CLEAN = `${OTHER_LINES.join("\n")}\n`;

function fakeCron({ crontab = MIXED, units = "enabled\nenabled\n", busy = false, env = {}, listCode = 0, listErr = "", writeCode = 0 } = {}) {
  const state = { crontab, calls: [], writes: [], tmpFiles: [], logs: [], busy };
  const run = async (cmd, args) => {
    state.calls.push([cmd, ...args].join(" "));
    if (cmd === "crontab" && args[0] === "-l") {
      if (listCode !== 0) return { code: listCode, stdout: "", stderr: listErr };
      return { code: 0, stdout: state.crontab, stderr: "" };
    }
    if (cmd === "crontab") {
      state.tmpFiles.push(args[0]);
      const text = fs.readFileSync(args[0], "utf-8");
      if (writeCode !== 0) return { code: writeCode, stdout: "", stderr: "crontab: errors in crontab file" };
      state.writes.push(text);
      state.crontab = text;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (cmd === "systemctl") return { code: units.includes("enabled") ? 0 : 1, stdout: units, stderr: "" };
    return { code: 127, stdout: "", stderr: `unexpected ${cmd}` };
  };
  const sink = (level) => (msg) => state.logs.push(`${level} ${msg}`);
  const hygiene = h.createHygiene({
    env,
    run,
    kill: () => assert.fail("cron hygiene never kills"),
    now: () => NOW,
    isGenerationBusy: async () => state.busy,
    log: { log: sink("log"), warn: sink("warn"), error: sink("error") },
  });
  return { hygiene, state };
}

test("mixed crontab: only the generator proxy-startup lines go, the rest byte for byte", async () => {
  const { hygiene, state } = fakeCron();
  const res = await hygiene.cronHygiene();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.outcome, "removed");
  assert.deepStrictEqual(res.removed, GENERATOR_LINES);
  assert.deepStrictEqual(state.writes, [CLEAN], "written once, other lines in their order");
  assert.deepStrictEqual(state.calls, [
    "crontab -l",
    "systemctl is-enabled netrun-3proxy-restore.service netrun-ipv6-restore.service",
    `crontab ${state.tmpFiles[0]}`,
  ]);
  assert.ok(!fs.existsSync(state.tmpFiles[0]), "tmp crontab file removed");
  for (const line of GENERATOR_LINES) {
    assert.ok(state.logs.includes(`log [hygiene] cron: removed ${JSON.stringify(line)}`), line);
  }
  assert.ok(state.logs.includes(
    "log [hygiene] cron: removed 5 generator proxy-startup line(s); netrun-3proxy-restore starts the batches at boot"
  ));
  const st = hygiene.status();
  assert.strictEqual(st.cronLinesRemoved, 5);
  assert.strictEqual(st.lastCronOutcome, "removed");
  assert.strictEqual(st.lastCronAt, new Date(NOW).toISOString());

  // Converged: the next sweep reads and leaves it alone.
  state.calls.length = 0;
  const again = await hygiene.cronHygiene();
  assert.strictEqual(again.outcome, "unchanged");
  assert.deepStrictEqual(state.calls, ["crontab -l"]);
  assert.strictEqual(state.writes.length, 1);
});

test("unchanged crontab is not rewritten (and no crontab at all is fine)", async () => {
  const clean = fakeCron({ crontab: CLEAN });
  const res = await clean.hygiene.cronHygiene();
  assert.strictEqual(res.outcome, "unchanged");
  assert.deepStrictEqual(res.removed, []);
  assert.deepStrictEqual(clean.state.calls, ["crontab -l"], "no systemctl, no write");
  assert.deepStrictEqual(clean.state.writes, []);
  assert.deepStrictEqual(clean.state.logs, []);

  const none = fakeCron({ listCode: 1, listErr: "no crontab for root\n" });
  const r2 = await none.hygiene.cronHygiene();
  assert.strictEqual(r2.ok, true);
  assert.strictEqual(r2.outcome, "no_crontab");
  assert.deepStrictEqual(none.state.calls, ["crontab -l"]);

  const broken = fakeCron({ listCode: 1, listErr: "crontab: cannot open /var/spool/cron" });
  const r3 = await broken.hygiene.cronHygiene();
  assert.strictEqual(r3.ok, false);
  assert.strictEqual(r3.error, "crontab_list_failed");
  assert.deepStrictEqual(broken.state.writes, []);
});

test("boot restore units not both enabled: lines kept, warned once; force removes them anyway", async () => {
  const off = fakeCron({ units: "enabled\ndisabled\n" });
  const res = await off.hygiene.cronHygiene();
  assert.strictEqual(res.outcome, "boot_restore_units_not_enabled");
  assert.strictEqual(res.skipped, true);
  assert.deepStrictEqual(off.state.writes, []);
  await off.hygiene.cronHygiene();
  const warnings = off.state.logs.filter((l) => l.startsWith("warn "));
  assert.deepStrictEqual(warnings, [
    "warn [hygiene] cron: 5 generator proxy-startup line(s) kept: netrun-3proxy-restore.service / " +
      "netrun-ipv6-restore.service not both enabled (they are then the only boot path); " +
      "NODE_AGENT_CRON_HYGIENE=force removes them anyway",
  ]);
  assert.strictEqual(off.hygiene.status().lastCronOutcome, "boot_restore_units_not_enabled");

  const noSystemctl = fakeCron({ units: "" });
  assert.strictEqual((await noSystemctl.hygiene.cronHygiene()).outcome, "boot_restore_units_not_enabled");

  const forced = fakeCron({ units: "disabled\ndisabled\n", env: { NODE_AGENT_CRON_HYGIENE: "force" } });
  const r2 = await forced.hygiene.cronHygiene();
  assert.strictEqual(r2.outcome, "removed");
  assert.deepStrictEqual(forced.state.writes, [CLEAN]);
  assert.ok(!forced.state.calls.some((c) => c.startsWith("systemctl")));
});

test("generation lock held or switch off: the crontab is not even read", async () => {
  const held = fakeCron({ busy: true });
  const res = await held.hygiene.cronHygiene();
  assert.strictEqual(res.outcome, "generation_in_progress");
  assert.deepStrictEqual(held.state.calls, []);
  assert.strictEqual(held.hygiene.status().lastCronOutcome, "generation_in_progress");

  const off = fakeCron({ env: { NODE_AGENT_CRON_HYGIENE: "0" } });
  assert.strictEqual((await off.hygiene.cronHygiene()).outcome, "disabled");
  assert.deepStrictEqual(off.state.calls, []);
});

test("post-/generate cleanup: only this start port's lines, whatever the directory", async () => {
  const { hygiene, state } = fakeCron();
  // The agent's path for the script is /opt/...; the generator wrote /root/...
  const res = await hygiene.removeCronLines(h.startupScriptMatcher("/opt/netrun/proxyserver/proxy-startup_19600.sh"));
  assert.strictEqual(res.outcome, "removed");
  assert.deepStrictEqual(res.removed, [GENERATOR_LINES[1], GENERATOR_LINES[2]]);
  const left = state.writes[0].split("\n");
  for (const line of [GENERATOR_LINES[0], GENERATOR_LINES[3], GENERATOR_LINES[4], ...OTHER_LINES]) {
    assert.ok(left.includes(line), `kept: ${line}`);
  }
  assert.strictEqual(hygiene.status().cronLinesRemoved, 2);
});

test("a failed crontab write is reported, never thrown", async () => {
  const { hygiene, state } = fakeCron({ writeCode: 1 });
  const res = await hygiene.cronHygiene();
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, "crontab_write_failed");
  assert.deepStrictEqual(res.removed, []);
  assert.strictEqual(hygiene.status().cronLinesRemoved, 0);
  assert.ok(state.logs.some((l) => l.startsWith("error [hygiene] cron: crontab_write_failed")));
  assert.ok(!fs.existsSync(state.tmpFiles[0]), "tmp file removed on failure too");
});

test("cronLineStartupScript / planCronCleanup", () => {
  assert.strictEqual(h.cronLineStartupScript(GENERATOR_LINES[0]), "proxy-startup_18100.sh");
  assert.strictEqual(h.cronLineStartupScript(GENERATOR_LINES[4]), "proxy-startup_22600.sh");
  assert.strictEqual(h.cronLineStartupScript("@reboot bash proxy-startup_1.sh"), "proxy-startup_1.sh");
  assert.strictEqual(h.cronLineStartupScript("@reboot bash /x/proxy-startup_1.sh\r"), "proxy-startup_1.sh");
  for (const line of OTHER_LINES) assert.strictEqual(h.cronLineStartupScript(line), null, line);
  assert.deepStrictEqual(h.planCronCleanup(CLEAN), { changed: false, text: CLEAN, removed: [], kept: OTHER_LINES.length });
  assert.deepStrictEqual(h.planCronCleanup(`${GENERATOR_LINES[0]}\n`), { changed: true, text: "", removed: [GENERATOR_LINES[0]], kept: 0 });
  // No trailing newline in: one out (crontab wants it).
  assert.strictEqual(h.planCronCleanup(`${OTHER_LINES[7]}\n${GENERATOR_LINES[0]}`).text, `${OTHER_LINES[7]}\n`);
});

test("default runner against PATH stubs: tmp file + `crontab <file>`, real crontab never touched", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-cronstub-"));
  const bin = path.join(tmp, "bin");
  fs.mkdirSync(bin);
  const store = path.join(tmp, "crontab.txt");
  const writes = path.join(tmp, "writes.log");
  fs.writeFileSync(store, MIXED);
  fs.writeFileSync(
    path.join(bin, "crontab"),
    `#!/bin/sh\nif [ "$1" = "-l" ]; then cat '${store}'; exit 0; fi\ncp "$1" '${store}' && echo "$1" >> '${writes}'\n`,
    { mode: 0o755 }
  );
  fs.writeFileSync(path.join(bin, "systemctl"), "#!/bin/sh\necho enabled\necho enabled\n", { mode: 0o755 });
  const savedPath = process.env.PATH;
  process.env.PATH = `${bin}:${savedPath}`;
  try {
    for (const name of ["crontab", "systemctl"]) {
      const resolved = execFileSync("/bin/sh", ["-c", `command -v ${name}`], { env: process.env }).toString().trim();
      assert.strictEqual(resolved, path.join(bin, name), `${name} must resolve to the stub before anything runs`);
    }
    const logs = [];
    const hygiene = h.createHygiene({
      env: {},
      kill: () => assert.fail("never"),
      log: { log: (m) => logs.push(m), warn: (m) => logs.push(m), error: (m) => logs.push(m) },
    });
    const res = await hygiene.cronHygiene();
    assert.strictEqual(res.outcome, "removed", JSON.stringify(res));
    assert.strictEqual(fs.readFileSync(store, "utf-8"), CLEAN);
    const written = fs.readFileSync(writes, "utf-8").trim().split("\n");
    assert.strictEqual(written.length, 1);
    assert.ok(!fs.existsSync(written[0]), "tmp crontab removed");
    const again = await hygiene.cronHygiene();
    assert.strictEqual(again.outcome, "unchanged");
    assert.strictEqual(fs.readFileSync(writes, "utf-8").trim().split("\n").length, 1, "no second write");
  } finally {
    process.env.PATH = savedPath;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
