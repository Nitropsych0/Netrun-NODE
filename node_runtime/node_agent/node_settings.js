"use strict";

// Node settings shared by the agent and the node's bash scripts: the process
// environment wins, then ${NETRUN_ENV_FILE:-/etc/netrun/netrun.env} (KEY=VALUE
// lines, the file the generator and netrun-https already read), then the
// default. One switch in netrun.env (e.g. NETRUN_ANCHOR_DEPRECATE=0) then
// reaches the agent, the generator and the boot restore alike.

const fs = require("fs");

const DEFAULT_ENV_FILE = "/etc/netrun/netrun.env";

function parseEnvFile(text) {
  const out = new Map();
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.replace(/^\s+/, "");
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    value = value.replace(/^["' \t]+|["' \t]+$/g, "");
    out.set(key, value);
  }
  return out;
}

function nodeSetting(key, def, { env = process.env, readFile = (p) => fs.readFileSync(p, "utf-8") } = {}) {
  const fromEnv = env[key];
  if (fromEnv !== undefined && fromEnv !== null && String(fromEnv).trim() !== "") return String(fromEnv).trim();
  try {
    const file = String(env.NETRUN_ENV_FILE || DEFAULT_ENV_FILE);
    const value = parseEnvFile(readFile(file)).get(key);
    if (value !== undefined && value !== "") return value;
  } catch {
    // no file: the default
  }
  return def;
}

// "0" / "off" / "false" / "no" = off; unset or empty = the default.
function settingOn(key, def = true, opts = {}) {
  const v = String(nodeSetting(key, "", opts)).trim().toLowerCase();
  if (!v) return def;
  return !["0", "off", "false", "no"].includes(v);
}

module.exports = { nodeSetting, settingOn, parseEnvFile, DEFAULT_ENV_FILE };
