"use strict";

// Pay-per-GB v2 (plan §3.4 "Clock", lane L9) — /health clock.ntpSynchronized.
// Nodes enforce a per-GB account's expiresAt against their own clock, so a
// node without time sync fails the per-GB gate (orchestrator
// pergb_node_gate_sql). Source: `timedatectl show -p NTPSynchronized --value`
// ("yes" / "no"), cached CLOCK_TTL_MS; null when it cannot be read (no
// systemd-timedated, a timeout) — unknown, never "synced".

const { spawn } = require("child_process");

const CLOCK_TTL_MS = 30_000;

function execCapture(cmd, args, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let child;
    try {
      child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (err) {
      resolve({ code: -1, stdout: "", stderr: String((err && err.message) || err) });
      return;
    }
    const timer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch {}
    }, timeoutMs);
    child.stdout.on("data", (d) => { stdout += d.toString("utf-8"); });
    child.stderr.on("data", (d) => { stderr += d.toString("utf-8"); });
    const done = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    };
    child.on("error", (err) => { stderr = stderr || String((err && err.message) || err); done(-1); });
    child.on("close", (code) => done(typeof code === "number" ? code : -1));
  });
}

// "yes\n" -> true, "no" -> false, anything else -> null.
function parseNtpSynchronized(text) {
  const v = String(text || "").trim().toLowerCase();
  if (v === "yes") return true;
  if (v === "no") return false;
  return null;
}

function createClockSync({ run = execCapture, now = () => Date.now(), ttlMs = CLOCK_TTL_MS } = {}) {
  let cached = null; // { at, value }
  let inFlight = null;

  async function probe() {
    const res = await run("timedatectl", ["show", "-p", "NTPSynchronized", "--value"], { timeoutMs: 5000 });
    const synced = res && res.code === 0 ? parseNtpSynchronized(res.stdout) : null;
    return {
      ntpSynchronized: synced,
      source: "timedatectl",
      checkedAt: new Date(now()).toISOString(),
      error: synced === null ? String((res && (res.stderr || res.stdout)) || "unreadable").trim().slice(0, 200) || `exit ${res && res.code}` : null,
    };
  }

  // -> { ntpSynchronized: true | false | null, source, checkedAt, error }
  async function status() {
    if (cached && now() - cached.at < ttlMs) return cached.value;
    if (!inFlight) {
      inFlight = probe()
        .then((value) => {
          cached = { at: now(), value };
          return value;
        })
        .finally(() => {
          inFlight = null;
        });
    }
    return inFlight;
  }

  return { status };
}

let defaultInstance = null;
function defaultClock() {
  if (!defaultInstance) defaultInstance = createClockSync();
  return defaultInstance;
}

module.exports = {
  createClockSync,
  parseNtpSynchronized,
  CLOCK_TTL_MS,
  status: () => defaultClock().status(),
};
