"use strict";

// Audit RES-11 — every 3proxy the agent starts (supervisor respawn, /deprovision
// rewrite, /egress_mode restart, pay-per-GB enable of a per-port cfg) goes
// through the node's ONE spawn helper, scripts/netrun-3proxy-spawn.sh: its own
// systemd scope per batch (an agent restart or a unit restart never takes a
// batch down), idempotent (a cfg that already runs or listens is left alone),
// a per-cfg flock (the boot restore, the supervisor and an operator script can
// never start the same cfg twice) and the legacy-DNS fix-forward.
//
// Where the helper is missing (a dev checkout, an old node copied without
// scripts/) the historical direct start is kept: `3proxy <cfg>` detached.
// NETRUN_3PROXY_SPAWN: the helper path ("off" = always the direct start).

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const DEFAULT_HELPER = "/opt/netrun/scripts/netrun-3proxy-spawn.sh";
const HELPER_TIMEOUT_MS = 60_000;

function helperPath(env = process.env) {
  const raw = String(env.NETRUN_3PROXY_SPAWN ?? "").trim();
  if (raw.toLowerCase() === "off" || raw === "0") return null;
  return raw || DEFAULT_HELPER;
}

// "spawned start_port=18100 pid=4242 via=scope:..." -> { outcome, pid, ... }
function parseHelperLine(text) {
  const lines = String(text || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const OUTCOMES = ["spawned", "already-running", "already-listening", "refused", "failed"];
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const word = lines[i].split(/\s+/)[0];
    if (!OUTCOMES.includes(word)) continue;
    const out = { outcome: word, line: lines[i] };
    for (const m of lines[i].matchAll(/\b([a-z_]+)=(\S+)/g)) out[m[1]] = m[2];
    if (out.pid && /^\d+$/.test(out.pid)) out.pid = Number(out.pid);
    return out;
  }
  return null;
}

function runHelper(helper, cfgPath, { bin = null, timeoutMs = HELPER_TIMEOUT_MS, env = process.env } = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let child;
    const childEnv = { ...env };
    if (bin) childEnv.NETRUN_3PROXY_BIN = bin;
    try {
      child = spawn("bash", [helper, cfgPath], { stdio: ["ignore", "pipe", "pipe"], env: childEnv });
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

// Start the 3proxy of one cfg. Resolves to
//   { ok, via: "helper"|"direct", outcome, pid|null, code, detail }
// ok = a 3proxy now runs (or already ran / listened) for the cfg. Never throws
// for a helper failure (the caller logs it); the direct start throws like the
// old inline code did (missing binary / spawn error), so callers keep their
// error contracts.
async function spawn3proxyCfg(cfgPath, { bin = null, env = process.env, exists = fs.existsSync, run = runHelper } = {}) {
  const helper = helperPath(env);
  if (helper && exists(helper)) {
    const res = await run(helper, cfgPath, { bin, env });
    const parsed = parseHelperLine(res.stdout) || { outcome: res.code === 0 ? "spawned" : "failed" };
    return {
      ok: res.code === 0,
      via: "helper",
      outcome: parsed.outcome,
      pid: Number.isInteger(parsed.pid) ? parsed.pid : null,
      code: res.code,
      detail: parsed.line || String(res.stderr || res.stdout || "").trim().slice(-300) || null,
    };
  }
  const proxyBin = bin || path.join(path.dirname(cfgPath), "bin", "3proxy");
  if (!exists(proxyBin)) {
    const err = new Error(`3proxy_binary_missing: ${proxyBin}`);
    err.code = "BINARY_MISSING";
    throw err;
  }
  const child = spawn(proxyBin, [cfgPath], { detached: true, stdio: "ignore" });
  child.on("error", () => {}); // a late ENOENT/EACCES must not crash the agent
  const pid = child.pid;
  child.unref();
  return { ok: true, via: "direct", outcome: "spawned", pid: pid || null, code: 0, detail: null };
}

module.exports = {
  spawn3proxyCfg,
  parseHelperLine,
  helperPath,
  DEFAULT_HELPER,
};
