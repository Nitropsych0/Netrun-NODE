"use strict";

// Pay-per-GB v2 — the agent's client of the netrun-radius control socket
// (frozen interface I5; the server is node_runtime/radius/ctl.py).
//
// Transport: unix stream socket /run/netrun-radius/ctl.sock (0600, root and
// netrun-radius only). One JSON request line and one JSON response line per
// connection; errors come back as {"error": code, ...}.
//
// call(op, body) resolves with the reply object, or rejects with a
// RadiusError:
//   err.code = "radius_unavailable"  the socket is missing / refused, the
//                                    reply timed out, was cut or was not JSON
//   err.code = <the RADIUS error>    bad_request, unknown_op, seq_mismatch,
//                                    excluded_shrink, capacity, ref_conflict, net_unavailable,
//                                    unknown_account, not_ready,
//                                    db_write_failed, internal
//   err.reply = the RADIUS reply (seq_mismatch carries epoch and seq)
// httpError(err) maps one onto the agent's HTTP answer (503
// radius_unavailable, 409 seq_mismatch {epoch, seq}, ...).

const net = require("net");

const DEFAULT_SOCKET = "/run/netrun-radius/ctl.sock";
const DEFAULT_TIMEOUT_MS = 5000;
// A full snapshot of 50k lists is ~15 MB and is diffed under the ctl lock.
const OP_TIMEOUT_MS = Object.freeze({ snapshot: 120000, apply: 60000, excluded: 30000, facts: 30000, bindings: 15000 });
const MAX_REPLY_BYTES = 64 * 1024 * 1024;

class RadiusError extends Error {
  constructor(code, message, reply = null) {
    super(message || code);
    this.name = "RadiusError";
    this.code = code;
    this.reply = reply;
  }
}

function socketPathFrom(env = process.env) {
  return String(env.NETRUN_RADIUS_CTL_SOCKET || DEFAULT_SOCKET);
}

// deps: { socketPath, timeoutMs, connect (net.createConnection-compatible, tests) }
function createRadiusClient({ socketPath = socketPathFrom(), timeoutMs = DEFAULT_TIMEOUT_MS, connect = net.createConnection } = {}) {
  let calls = 0;
  let failures = 0;
  let lastError = null;
  let lastOkAt = null;

  function call(op, body = {}, opts = {}) {
    calls += 1;
    const limit = Number(opts.timeoutMs || OP_TIMEOUT_MS[op] || timeoutMs);
    const req = { ...(body && typeof body === "object" ? body : {}), op };
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      let done = false;
      let sock;
      const finish = (err, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try {
          sock.destroy();
        } catch {}
        if (err) {
          if (err.code === "radius_unavailable") {
            failures += 1;
            lastError = err.message;
          }
          reject(err);
        } else {
          lastOkAt = Date.now();
          resolve(value);
        }
      };
      const timer = setTimeout(
        () => finish(new RadiusError("radius_unavailable", `radius ctl ${op}: no reply within ${limit} ms`)),
        limit
      );
      try {
        sock = connect(socketPath);
      } catch (e) {
        finish(new RadiusError("radius_unavailable", `radius ctl ${op}: ${e.message || e}`));
        return;
      }
      sock.on("connect", () => {
        sock.write(`${JSON.stringify(req)}\n`);
      });
      sock.on("data", (d) => {
        size += d.length;
        if (size > MAX_REPLY_BYTES) {
          finish(new RadiusError("radius_unavailable", `radius ctl ${op}: reply too large`));
          return;
        }
        chunks.push(d);
        if (d.includes(10)) {
          const text = Buffer.concat(chunks).toString("utf-8");
          const line = text.slice(0, text.indexOf("\n"));
          let reply;
          try {
            reply = JSON.parse(line);
          } catch {
            finish(new RadiusError("radius_unavailable", `radius ctl ${op}: reply is not JSON`));
            return;
          }
          if (!reply || typeof reply !== "object" || Array.isArray(reply)) {
            finish(new RadiusError("radius_unavailable", `radius ctl ${op}: reply is not an object`));
          } else if (typeof reply.error === "string") {
            finish(new RadiusError(reply.error, `radius ctl ${op}: ${reply.error}${reply.detail ? ` (${reply.detail})` : ""}`, reply));
          } else {
            finish(null, reply);
          }
        }
      });
      sock.on("error", (e) => finish(new RadiusError("radius_unavailable", `radius ctl ${op}: ${e.code || e.message || e}`)));
      sock.on("end", () => finish(new RadiusError("radius_unavailable", `radius ctl ${op}: closed without a reply`)));
      sock.on("close", () => finish(new RadiusError("radius_unavailable", `radius ctl ${op}: closed without a reply`)));
    });
  }

  return {
    call,
    socketPath,
    stats() {
      return { calls, failures, lastError, lastOkAt: lastOkAt ? new Date(lastOkAt).toISOString() : null };
    },
  };
}

// RADIUS error -> { status, body } for the agent's HTTP answer.
function httpError(err) {
  const code = err && typeof err.code === "string" ? err.code : "radius_unavailable";
  const reply = (err && err.reply) || {};
  switch (code) {
    case "radius_unavailable":
    case "not_ready":
    case "db_write_failed":
      return { status: 503, body: { success: false, error: code === "radius_unavailable" ? code : "radius_unavailable", radiusError: code, detail: String((err && err.message) || "") } };
    case "seq_mismatch":
      return { status: 409, body: { success: false, error: "seq_mismatch", epoch: reply.epoch, seq: reply.seq } };
    case "excluded_shrink":
    case "capacity":
    case "ref_conflict":
    case "net_unavailable":
      return { status: 409, body: { success: false, error: code, ...stripError(reply) } };
    case "bad_request":
      return { status: 400, body: { success: false, error: "bad_request", detail: reply.detail || null } };
    case "unknown_account":
      return { status: 404, body: { success: false, error: "unknown_account", accountId: reply.accountId } };
    case "unknown_op":
      return { status: 501, body: { success: false, error: "radius_unsupported", op: reply.op || null } };
    default:
      return { status: 502, body: { success: false, error: "radius_error", radiusError: code, detail: reply.detail || null } };
  }
}

function stripError(reply) {
  const { error, ...rest } = reply || {};
  return rest;
}

module.exports = {
  DEFAULT_SOCKET,
  DEFAULT_TIMEOUT_MS,
  OP_TIMEOUT_MS,
  RadiusError,
  socketPathFrom,
  createRadiusClient,
  httpError,
};
