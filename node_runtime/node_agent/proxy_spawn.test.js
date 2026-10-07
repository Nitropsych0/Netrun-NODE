"use strict";

// Audit RES-11 — the agent's side of the one spawn helper (proxy_spawn.js):
// the helper's stdout line is parsed, its exit code decides ok, the binary is
// handed over, and without the helper the old direct start (or its error) is
// kept. The "helper" here is a temp bash script; nothing real is started.
// Run with: node --test node_runtime/node_agent/proxy_spawn.test.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert");
const ps = require("./proxy_spawn.js");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "netrun-spawn-"));
test.after(() => fs.rmSync(TMP, { recursive: true, force: true }));

function helper(name, body) {
  const p = path.join(TMP, name);
  fs.writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  return p;
}

test("parseHelperLine: the last outcome line wins; fields parsed", () => {
  const r = ps.parseHelperLine("dns-fixed start_port=18100 ...\nspawned start_port=18100 pid=4242 via=scope:netrun-3proxy-18100\n");
  assert.strictEqual(r.outcome, "spawned");
  assert.strictEqual(r.pid, 4242);
  assert.strictEqual(r.via, "scope:netrun-3proxy-18100");
  assert.strictEqual(ps.parseHelperLine("already-listening start_port=1 port=1").outcome, "already-listening");
  assert.strictEqual(ps.parseHelperLine("garbage"), null);
});

test("helperPath: default, override, off", () => {
  assert.strictEqual(ps.helperPath({}), ps.DEFAULT_HELPER);
  assert.strictEqual(ps.helperPath({ NETRUN_3PROXY_SPAWN: "/x/h.sh" }), "/x/h.sh");
  assert.strictEqual(ps.helperPath({ NETRUN_3PROXY_SPAWN: "off" }), null);
});

test("spawn3proxyCfg via the helper: cfg + NETRUN_3PROXY_BIN passed, exit code decides ok", async () => {
  const seen = path.join(TMP, "seen");
  const h = helper("ok.sh", `echo "$NETRUN_3PROXY_BIN $1" > '${seen}'\necho "spawned start_port=18100 pid=77 via=scope:netrun-3proxy-18100"`);
  const r = await ps.spawn3proxyCfg("/opt/netrun/proxyserver/3proxy/3proxy_18100.cfg", { bin: "/b/3proxy", env: { NETRUN_3PROXY_SPAWN: h, PATH: process.env.PATH } });
  assert.deepStrictEqual(
    { ok: r.ok, via: r.via, outcome: r.outcome, pid: r.pid },
    { ok: true, via: "helper", outcome: "spawned", pid: 77 }
  );
  assert.strictEqual(fs.readFileSync(seen, "utf-8").trim(), "/b/3proxy /opt/netrun/proxyserver/3proxy/3proxy_18100.cfg");
  const bad = helper("bad.sh", 'echo "failed start_port=18100 reason=no_process_after_start"; exit 3');
  const f = await ps.spawn3proxyCfg("/c/3proxy_18100.cfg", { env: { NETRUN_3PROXY_SPAWN: bad, PATH: process.env.PATH } });
  assert.strictEqual(f.ok, false);
  assert.strictEqual(f.outcome, "failed");
  assert.strictEqual(f.code, 3);
  const idem = helper("idem.sh", 'echo "already-running start_port=18100 pid=12"');
  const i = await ps.spawn3proxyCfg("/c/3proxy_18100.cfg", { env: { NETRUN_3PROXY_SPAWN: idem, PATH: process.env.PATH } });
  assert.strictEqual(i.ok, true);
  assert.strictEqual(i.outcome, "already-running");
});

test("no helper: the direct start, and BINARY_MISSING when the binary is absent", async () => {
  await assert.rejects(
    ps.spawn3proxyCfg(path.join(TMP, "3proxy", "3proxy_18100.cfg"), { env: { NETRUN_3PROXY_SPAWN: path.join(TMP, "nope.sh") } }),
    (err) => err.code === "BINARY_MISSING"
  );
  // A stand-in "3proxy" that exits at once: started detached, pid reported.
  fs.mkdirSync(path.join(TMP, "3proxy", "bin"), { recursive: true });
  const bin = path.join(TMP, "3proxy", "bin", "3proxy");
  fs.writeFileSync(bin, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  const r = await ps.spawn3proxyCfg(path.join(TMP, "3proxy", "3proxy_18100.cfg"), { env: { NETRUN_3PROXY_SPAWN: "off" } });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.via, "direct");
  assert.ok(Number.isInteger(r.pid));
});
