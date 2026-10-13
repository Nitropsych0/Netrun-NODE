"use strict";

// #4 OS fingerprint v2 — the agent endpoint that receives the p0f signature
// table from the orchestrator (osfp.run_due) and writes it to
// /opt/netrun/osfp/signatures.json. The rewriter daemon (netrun-osfp) watches
// that file's mtime and hot-reloads it. The egress nft hook + the daemon are
// installed out of band (deploy/node/osfp/install-osfp.sh); this only keeps the
// signature set in sync.
//
//   GET  /osfp/signatures            -> { success, signatures }
//   POST /osfp/signatures { signatures: { name: { sig, label, enabled } | sig } }
//                                    -> { success, count } ; writes the file atomically
//
// A name must be [a-z0-9]{1,32}; a sig must be a p0f-v3 SYN signature (8
// colon-separated fields). Bad input -> 400 invalid_signatures, nothing written.

const fsp = require("fs/promises");
const path = require("path");

const SIG_PATH = process.env.OSFP_SIGNATURES_PATH || "/opt/netrun/osfp/signatures.json";
const NAME_RE = /^[a-z0-9]{1,32}$/;
const P0F_RE = /^[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/;
const MAX_SIGS = 256;

function normalize(signatures) {
  if (!signatures || typeof signatures !== "object" || Array.isArray(signatures)) return null;
  const names = Object.keys(signatures);
  if (names.length > MAX_SIGS) return null;
  const out = {};
  for (const name of names) {
    if (!NAME_RE.test(name)) return null;
    const v = signatures[name];
    const sig = typeof v === "string" ? v : v && typeof v === "object" ? v.sig : null;
    if (typeof sig !== "string" || !P0F_RE.test(sig.trim())) return null;
    const label = v && typeof v === "object" && typeof v.label === "string" ? v.label : name;
    out[name] = { sig: sig.trim(), label, enabled: true };
  }
  return out;
}

async function writeAtomic(data) {
  await fsp.mkdir(path.dirname(SIG_PATH), { recursive: true });
  const tmp = `${SIG_PATH}.tmp.${process.pid}`;
  await fsp.writeFile(tmp, `${JSON.stringify(data, null, 2)}\n`, { encoding: "utf-8", mode: 0o644 });
  await fsp.rename(tmp, SIG_PATH); // rename bumps mtime -> the daemon hot-reloads
}

async function readCurrent() {
  try {
    return JSON.parse(await fsp.readFile(SIG_PATH, "utf-8"));
  } catch {
    return {};
  }
}

// deps: { sendJson, parseJsonBody, ensureAuthorized }. Returns true if handled.
async function handleHttp(req, res, url, deps) {
  const { sendJson, parseJsonBody, ensureAuthorized } = deps;
  if (url.pathname !== "/osfp/signatures") return false;

  if (req.method === "GET") {
    if (!ensureAuthorized(req, res)) return true;
    sendJson(res, 200, { success: true, signatures: await readCurrent(), path: SIG_PATH });
    return true;
  }
  if (req.method === "POST" || req.method === "PUT") {
    if (!ensureAuthorized(req, res)) return true;
    let body;
    try {
      body = await parseJsonBody(req);
    } catch {
      sendJson(res, 400, { success: false, error: "bad_json" });
      return true;
    }
    const sigs = normalize(body && body.signatures);
    if (sigs === null) {
      sendJson(res, 400, { success: false, error: "invalid_signatures" });
      return true;
    }
    try {
      await writeAtomic(sigs);
    } catch (err) {
      sendJson(res, 500, { success: false, error: "write_failed", detail: String((err && err.message) || err) });
      return true;
    }
    sendJson(res, 200, { success: true, count: Object.keys(sigs).length });
    return true;
  }
  sendJson(res, 405, { success: false, error: "method_not_allowed" });
  return true;
}

module.exports = { handleHttp, normalize, SIG_PATH };
