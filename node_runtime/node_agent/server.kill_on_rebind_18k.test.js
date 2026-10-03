"use strict";

// Wave CAPACITY-18K — kill-on-rebind with the 18k port layout (socks from
// 18100, dual http = socks - 10000 from 8100). The sweep may only ever select
// 3proxy pids: the agent (:8085), haproxy (HTTPS front on <public-ip>:<http
// port>), unbound, sshd must survive whatever range a generation covers.
// Run with: node --test node_runtime/node_agent/server.kill_on_rebind_18k.test.js

const test = require("node:test");
const assert = require("node:assert");
const path = require("path");

const { selectPidsToKill, selectGenerationRebindPids } = require(path.resolve(__dirname, "server.js"));

const row = (addr, name, pid) => `LISTEN 0 4096 ${addr} 0.0.0.0:* users:(("${name}",pid=${pid},fd=5))`;

test("18100 x 1500: http range 8100-9599 is matched, stale 3proxy there is selected", () => {
  const ss = [
    row("127.0.0.1:8100", "3proxy", 501), // stale http listener (HTTPS front, loopback)
    row("45.32.10.20:19599", "3proxy", 502), // stale socks listener, top of range
    row("45.32.10.20:19600", "3proxy", 503), // next batch — outside
    row("127.0.0.1:8099", "3proxy", 504), // below the http range — outside
  ].join("\n");
  assert.deepStrictEqual(selectGenerationRebindPids(ss, 18100, 1500), [501, 502]);
});

test("haproxy fronting the same http ports is never selected", () => {
  const ss = [
    row("45.32.10.20:8100", "haproxy", 700),
    row("45.32.10.20:8101", "haproxy", 700),
    row("127.0.0.1:8100", "3proxy", 501),
  ].join("\n");
  assert.deepStrictEqual(selectGenerationRebindPids(ss, 18100, 1500), [501]);
});

test("node services inside a covered range are never selected", () => {
  // A generation at socks 18085 would cover http 8085 = the agent port; the
  // generator now refuses such a batch, and the sweep must not kill the agent.
  const ss = [
    `LISTEN 0 511 *:8085 *:* users:(("node",pid=1200,fd=20))`,
    row("127.0.0.1:8953", "unbound", 901),
    row("0.0.0.0:18090", "sshd", 812),
  ].join("\n");
  assert.deepStrictEqual(selectGenerationRebindPids(ss, 18080, 20), []);
  assert.deepStrictEqual(selectPidsToKill(ss, 1, 65535), []);
});

test("a socket shared by several processes: only the 3proxy holder is selected", () => {
  const ss = `LISTEN 0 13 45.32.10.20:18100 0.0.0.0:* users:(("haproxy",pid=700,fd=9),("3proxy",pid=501,fd=5))`;
  assert.deepStrictEqual(selectPidsToKill(ss, 18100, 18100), [501]);
});

test("processName null restores the any-process selection (explicit opt-in only)", () => {
  const ss = [row("45.32.10.20:8100", "haproxy", 700), row("127.0.0.1:8100", "3proxy", 501)].join("\n");
  assert.deepStrictEqual(selectPidsToKill(ss, 8100, 8100, { processName: null }), [501, 700]);
  assert.deepStrictEqual(selectPidsToKill(ss, 8100, 8100), [501]);
});
