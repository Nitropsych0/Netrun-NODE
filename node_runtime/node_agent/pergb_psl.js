"use strict";

// Pay-per-GB v2, amendment A12 — the site key of a destination: the
// registrable domain (eTLD+1) of its host name by the Public Suffix List
// (node_runtime/radius/public_suffix_list.dat, vendored; refreshed by
// scripts/update_public_suffix_list.sh), or — without a host name (plain
// SOCKS5 with client-side DNS) — the destination /24 (IPv4) or /48 (IPv6).
// RADIUS computes the same key from Called-Station-Id / Login-IP(v6)-Host,
// so both sides must agree: the vectors in
// node_runtime/radius/tests/psl_vectors.json are checked here (and are meant
// for the RADIUS matcher too).
//
// The algorithm is the PSL one (https://publicsuffix.org/list/): the
// longest matching rule wins, an exception rule (!x) beats a wildcard (*.y),
// the default rule is "*"; ICANN and private sections alike (github.io is a
// public suffix). Unicode rules and host names compare in punycode.

const fs = require("fs");
const net = require("net");
const path = require("path");
const url = require("url");

const DEFAULT_FILE = path.resolve(__dirname, "../radius/public_suffix_list.dat");

function toAscii(name) {
  const s = String(name || "").trim().toLowerCase().replace(/\.$/, "");
  if (!s) return "";
  // eslint-disable-next-line no-control-regex
  if (/^[\x00-\x7f]*$/.test(s)) return s;
  return url.domainToASCII(s) || "";
}

// PSL text -> { rules, wild, except } (Sets of punycode names).
function parsePsl(text) {
  const rules = new Set();
  const wild = new Set();
  const except = new Set();
  for (const raw of String(text || "").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("//")) continue;
    const tok = line.split(/\s+/)[0];
    if (tok.startsWith("!")) {
      const n = toAscii(tok.slice(1));
      if (n) except.add(n);
    } else if (tok.startsWith("*.")) {
      const n = toAscii(tok.slice(2));
      if (n) wild.add(n);
    } else {
      const n = toAscii(tok);
      if (n) rules.add(n);
    }
  }
  return { rules, wild, except, size: rules.size + wild.size + except.size };
}

let defaultPsl = null;
function loadDefault(file = DEFAULT_FILE) {
  if (defaultPsl && defaultPsl.file === file) return defaultPsl;
  let text = "";
  try {
    text = fs.readFileSync(file, "utf-8");
  } catch {
    text = "";
  }
  defaultPsl = { ...parsePsl(text), file };
  return defaultPsl;
}

// host -> its registrable domain (eTLD+1), or null (an IP literal, empty,
// invalid, or a public suffix itself).
function registrableDomain(host, psl = loadDefault()) {
  let h = String(host || "").trim();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (!h || h === "-" || net.isIP(h)) return null;
  const a = toAscii(h);
  if (!a || a.length > 253) return null;
  const labels = a.split(".");
  if (labels.some((l) => !l || l.length > 63)) return null;
  let suffixLen = 1; // the default rule "*"
  for (let i = 0; i < labels.length; i += 1) {
    const cand = labels.slice(i).join(".");
    if (psl.except.has(cand)) {
      suffixLen = labels.length - i - 1;
      break;
    }
    if (psl.rules.has(cand)) {
      suffixLen = labels.length - i;
      break;
    }
    if (i + 1 < labels.length && psl.wild.has(labels.slice(i + 1).join("."))) {
      suffixLen = labels.length - i;
      break;
    }
  }
  if (labels.length <= suffixLen) return null;
  return labels.slice(labels.length - suffixLen - 1).join(".");
}

// The destination /24 or /48 as a site key: "v4:1.2.3.0/24", "v6:2606:4700:10::/48".
function addressSite(ip) {
  const s = String(ip || "").trim().replace(/^\[|\]$/g, "");
  if (net.isIPv4(s)) {
    const o = s.split(".");
    if (s === "0.0.0.0") return null;
    return `v4:${o[0]}.${o[1]}.${o[2]}.0/24`;
  }
  if (net.isIPv6(s)) {
    const { ipv6ToBig, bigToIpv6 } = require("./pergb_tag.js");
    const big = ipv6ToBig(s);
    if (big === null || big === 0n) return null;
    return `v6:${bigToIpv6((big >> 80n) << 80n)}/48`;
  }
  return null;
}

// The site of a destination: eTLD+1 of the host name, else the dst /24 or /48.
function siteKey(host, dstIp, psl = loadDefault()) {
  return registrableDomain(host, psl) || addressSite(dstIp) || (net.isIP(String(host || "")) ? addressSite(host) : null);
}

module.exports = { DEFAULT_FILE, toAscii, parsePsl, loadDefault, registrableDomain, addressSite, siteKey };
