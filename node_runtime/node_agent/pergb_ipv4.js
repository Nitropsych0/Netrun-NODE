"use strict";

// Pay-per-GB v2, amendments A7 / A9 — the per-GB IPv4 addresses of a node
// (Vultr Reserved IPs attached to the instance; default 8 per node). The
// first is the ENTRY address (the per-GB haproxy binds the shared ports on
// it), all of them are EGRESS addresses for IPv4-only destinations (RADIUS
// hands one out as Framed-IP-Address).
//
// /pergb/enable configures them without a reboot: `ip addr add <a>/32 dev
// <iface>` now, and a netplan drop-in (/etc/netplan/60-netrun-pergb.yaml,
// 0600) so they come back after a reboot. `netplan apply` is NEVER run (it
// would bounce the node's networking under live per-piece traffic). Only
// addresses this module added are ever removed (state in
// /etc/netrun-pergb/ipv4s.json); the node's primary IPv4 is never touched.

const fs = require("fs");
const path = require("path");
const net = require("net");

const DROPIN_NAME = "60-netrun-pergb.yaml";

function readSettings(env = process.env) {
  return {
    netplanDir: String(env.NETRUN_PERGB_NETPLAN_DIR || "/etc/netplan"),
    statePath: path.join(String(env.NETRUN_PERGB_ETC_DIR || "/etc/netrun-pergb"), "ipv4s.json"),
  };
}

// `ip -4 route get 1.1.1.1` -> { dev, src } | null
function parseRouteGet(text) {
  const dev = /\bdev (\S+)/.exec(String(text || ""));
  const src = /\bsrc (\d+\.\d+\.\d+\.\d+)/.exec(String(text || ""));
  return dev ? { dev: dev[1], src: src ? src[1] : null } : null;
}

// `ip -4 -o addr show dev X` -> Set of addresses
function parseAddrShow(text) {
  const out = new Set();
  for (const m of String(text || "").matchAll(/\binet (\d+\.\d+\.\d+\.\d+)\/\d+/g)) out.add(m[1]);
  return out;
}

// The netplan id of an interface: the ethernets key whose name or `set-name`
// is the interface (cloud-init writes `ethernets: { enp1s0: {...} }` or a
// key with `match:` + `set-name: enp1s0`). Line-based (no YAML parser).
function netplanIdFor(iface, texts) {
  for (const text of texts) {
    const lines = String(text || "").split("\n");
    let inEth = false;
    let ethIndent = -1;
    let current = null;
    let currentIndent = -1;
    for (const line of lines) {
      if (!line.trim() || line.trim().startsWith("#")) continue;
      const indent = line.length - line.trimStart().length;
      const t = line.trim();
      if (/^ethernets:\s*$/.test(t)) {
        inEth = true;
        ethIndent = indent;
        current = null;
        continue;
      }
      if (inEth && indent <= ethIndent) inEth = false;
      if (!inEth) continue;
      const key = /^([A-Za-z0-9_.:-]+):\s*$/.exec(t);
      if (key && (currentIndent < 0 || indent <= currentIndent)) {
        current = key[1];
        currentIndent = indent;
        if (current === iface) return current;
        continue;
      }
      const sn = /^set-name:\s*["']?([^"'\s]+)["']?\s*$/.exec(t);
      if (sn && current && sn[1] === iface) return current;
    }
  }
  return iface;
}

function dropinText(id, ips) {
  const lines = [
    "# NETRUN pay-per-GB v2 — the per-GB IPv4 addresses (node_agent/pergb_ipv4.js, POST /pergb/enable).",
    "# Configured live with `ip addr add`; this file brings them back after a reboot. Do not edit.",
    "network:",
    "  version: 2",
    "  ethernets:",
    `    ${id}:`,
    "      addresses:",
    ...ips.map((ip) => `        - ${ip}/32`),
  ];
  return `${lines.join("\n")}\n`;
}

function readState(p) {
  try {
    const j = JSON.parse(fs.readFileSync(p, "utf-8"));
    return Array.isArray(j.added) ? j : { added: [] };
  } catch {
    return { added: [] };
  }
}

function writeAtomic(file, text, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, text, { mode });
  fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, file);
}

// Make the node carry exactly `ips` as per-GB addresses (added by us).
// deps: { run, settings, log }. -> { ok, iface, added, removed, dropin, error? }
async function ensureAddresses(ips, deps) {
  const run = deps.run;
  const settings = deps.settings || readSettings();
  const log = deps.log || console;
  const want = [...new Set((ips || []).map(String))];
  for (const ip of want) if (!net.isIPv4(ip)) return { ok: false, error: "bad_params", detail: `not an IPv4: ${ip}` };
  const rg = await run("ip", ["-4", "route", "get", "1.1.1.1"], { timeoutMs: 10000 });
  const route = rg.code === 0 ? parseRouteGet(rg.stdout) : null;
  if (!route) return { ok: false, error: "no_default_route", detail: String(rg.stderr || "").trim().slice(0, 200) };
  if (route.src && want.includes(route.src)) {
    return { ok: false, error: "bad_params", detail: `${route.src} is the node's primary IPv4, not a per-GB address` };
  }
  const shown = await run("ip", ["-4", "-o", "addr", "show", "dev", route.dev], { timeoutMs: 10000 });
  const have = parseAddrShow(shown.stdout);
  const state = readState(settings.statePath);
  const out = { ok: true, iface: route.dev, added: [], removed: [], dropin: null };
  for (const ip of want) {
    if (have.has(ip)) continue;
    const r = await run("ip", ["addr", "add", `${ip}/32`, "dev", route.dev], { timeoutMs: 10000 });
    if (r.code !== 0 && !/exists/i.test(String(r.stderr || ""))) {
      return { ...out, ok: false, error: "ipv4_config_failed", detail: `ip addr add ${ip}: ${String(r.stderr || "").trim().slice(0, 200)}` };
    }
    out.added.push(ip);
  }
  for (const ip of state.added) {
    if (want.includes(ip) || ip === route.src) continue;
    const r = await run("ip", ["addr", "del", `${ip}/32`, "dev", route.dev], { timeoutMs: 10000 });
    if (r.code === 0) out.removed.push(ip);
  }
  // persisted for the next boot (never applied here)
  const dropin = path.join(settings.netplanDir, DROPIN_NAME);
  let texts = [];
  try {
    texts = fs
      .readdirSync(settings.netplanDir)
      .filter((f) => f.endsWith(".yaml") && f !== DROPIN_NAME)
      .sort()
      .map((f) => fs.readFileSync(path.join(settings.netplanDir, f), "utf-8"));
  } catch {}
  // an address another netplan file already carries is not repeated
  const listed = (ip) => texts.some((t) => new RegExp(`(^|[^0-9.])${ip.replace(/\./g, "\\.")}/\\d+`).test(t));
  const persist = want.filter((ip) => !listed(ip));
  if (persist.length) {
    const text = dropinText(netplanIdFor(route.dev, texts), persist);
    let cur = null;
    try {
      cur = fs.readFileSync(dropin, "utf-8");
    } catch {}
    if (cur !== text) {
      writeAtomic(dropin, text, 0o600);
      out.dropin = dropin;
    }
  } else {
    try {
      fs.unlinkSync(dropin);
      out.dropin = dropin;
    } catch {}
  }
  // ours = what we added now plus what we had added before and still want
  const ours = [...new Set([...state.added.filter((ip) => want.includes(ip)), ...out.added])];
  writeAtomic(settings.statePath, `${JSON.stringify({ added: ours, iface: route.dev, updatedAt: new Date().toISOString() }, null, 2)}\n`, 0o600);
  if (out.added.length || out.removed.length) log.log(`[pergb-ipv4] ${route.dev}: added ${out.added.join(",") || "-"}, removed ${out.removed.join(",") || "-"}`);
  return out;
}

module.exports = { DROPIN_NAME, readSettings, parseRouteGet, parseAddrShow, netplanIdFor, dropinText, ensureAddresses };
