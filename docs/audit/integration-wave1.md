# Integration — wave 1 node fixes (Netrun-NODE)

Branch `claude/integ-audit-fixes-6928d3`, cut from `main` @ `9474bc4`. Two lane branches merged with
`git merge --no-ff`, nothing pushed, no PR. Per-lane detail stays in `docs/audit/fixes-node-agent-hardening.md`
and `docs/audit/fixes-node-pergb-runtime.md`; this file is the combined view.

## Merge order and conflicts

| # | Branch | Merge commit | Result |
|---|---|---|---|
| 1 | `claude/fix-node-agent-hardening-4fb23a` (TLS `:8086` for all agent routes, fixed generator path, `HQ_WATCH_TG_*`, HTTPS-only registration, L-U2 stale lists) | `96b13ae` | clean, no conflicts |
| 2 | `claude/fix-node-pergb-runtime-80463f` (per-GB status fields, TasksMax from RAM, shared ps/ss snapshot, counter-dump timeout, log-fs warnings, `tcp_tw_reuse`) | `f6dce6b` | 3 textual conflicts, all "both sides added at the same spot" |

Conflicts in merge 2 (`NODE_SETUP_RUNBOOK.md` merged automatically):

* `node_runtime/node_agent/server.js` — the `module.exports` tail. Hardening added
  `resolveGeneratorScript, GENERATOR_ROOT, GENERATOR_SCRIPT, parkFailedAttempt, dropStaleBatchLists,
  dropIpv6List, handleAgentRequest, allowPlainHttp, plainListenHost`; pergb added `procSnapshot`. Resolution:
  keep both lists. Nothing else in `server.js` collided: `handleHealth` (pergb: reads the shared snapshot, adds
  `scanCache` / `nodeTuning.tcpTwReuse*`) and `handleAgentRequest` (hardening: the former listener callback,
  now also the TLS `agentHandler`) are different functions, so git merged them without help, and the combined
  behaviour holds — `/health` served on both listeners goes through the same `handleHealth`, snapshot cache
  included.
* `deploy/node/env.example` — two appended lane blocks (`# --- lane: node-agent-hardening ---`,
  `# --- lane: node-pergb-runtime ---`). Resolution: keep both, blank line between.
* `README.md` — two appended sections ("Agent API over TLS (:8086)" and "Per-GB runtime limits and signals").
  Resolution: keep both, blank line between.

No code was changed beyond conflict resolution.

## Contract checks on the merged tree

Ad-hoc probe (not committed): the real `handleAgentRequest` behind a real HTTPS `createTlsServer` (self-signed
`127.0.0.1` cert) and a plain `http.createServer` on the same handler.

* Same agent routes on both listeners with the same auth: `/health` 200 without a key (`{ok:true}`) and 200 with
  the full payload; `/describe`, `/load` 401 without / 200 with the key; unknown path 404 on both. `:8085` is
  plain HTTP whenever `NODE_AGENT_ALLOW_PLAIN_HTTP` is not `false` (default `true`); `false` binds it to
  `127.0.0.1` (`plainListenHost()`, unit-tested in `server.agent_tls.test.js`). `status().routes === "full"`.
* `/pergb/*` stays on `:8086` only, as before; `:8085` answers `404 pergb_tls_only` except the node-local
  `reserve_nets` / `release_nets` (pre-existing design, both lanes leave it).
* `GET /pergb/status` (200 on `:8086`, key required, 401 without) carries exactly
  `radius.{p99Ms, requests, sendErrors, drainFull, udpDrops, udpRxQueue, loopMaxMs}` (all `null` before enable),
  top-level `logFsUsedPct`, `logFsWarn`, `warnings[]`, `tasksMax`, `maxConns`, `sliceMemMax`
  (also asserted by `pergb_state.test.js`).

## Gate (macOS, node 25, Python 3.14)

| Check | Hardening alone | Pergb alone | Combined baseline | **Merged** |
|---|---|---|---|---|
| `node --test --test-reporter=spec` over all 62 `*.test.js` | 463 | 467 | 446 + 17 + 21 = **484** | **484 pass, 0 fail, 0 skipped** |
| `python3 -m pytest node_runtime/radius/tests -q` | not run (untouched) | 219 (unittest; pytest not installed there) | 219 | **218 passed, 1 skipped** (pytest in a scratch venv; `unittest discover` gives the same 219 ran, OK, skipped=1) |
| `bash -n` on every `.sh` changed vs `main` | ok | ok | — | **ok** |
| `scripts/test_*.sh` + `node_runtime/soft/generator/test_*.sh` (27) | rc=0 except 3 | rc=0 except 3 | 3 known | **24 rc=0; 3 non-zero, identical to `main`**: `test_netrun_radius_units.sh` (rc 2, "pass --throwaway-host"), `test_pergb_agent_linux.sh` (rc 2, same), `test_pergb_radius_e2e.sh` (rc 1, Linux-only) |

Nothing regressed against the combined baseline.

## Things to verify on a real node (merged, in order)

Run after the rollout steps below, on one canary node first.

1. **Slice limits (P-U1, before anything else changes capacity):** `systemctl show netrun-pergb.slice -p TasksMax -p MemoryMax`
   and `cat /etc/systemd/system/netrun-pergb.slice.d/50-netrun-enable.conf` vs `nodes.pergb_max_conns`. Record
   whether 10500 or 22500 is live. A node really running `maxConns 20000` on 1536M MemoryMax is clamped to 13228
   (TasksMax 15728) on the next enable unless MemoryMax ≥ ~2.2G. The figure goes to orchestrator-lifecycle-and-catalog
   before any capacity constant changes.
2. **Agent over TLS (S-ORCH-1):** `systemctl restart netrun-node-agent`; `curl -sk https://127.0.0.1:8086/health` →
   `{"ok":true}`; with the key `pergb.tls.listening=true, routes="full"`. From the orchestrator IP
   `curl --cacert <fleet root> https://<ip>:8086/describe -H "X-API-KEY: …"` → 200 with a verified IP cert;
   from any other IP `:8086` is dropped. Nodes guarded before 8086 existed: `netrun-harden secure` /
   `agent-firewall` (until then the listener logs `agent_firewall_without_8086` and stays closed). Nodes without a
   lego/`node.pem` certificate keep `:8086` closed (`no_ip_cert`) — run `netrun-https setup`.
   `netrun-harden.sh status` shows `A3 agent TLS :8086: listening`.
3. **Plain HTTP off (later):** `NODE_AGENT_ALLOW_PLAIN_HTTP=false`, `ss -ltn | grep 8085` shows `127.0.0.1` only,
   watchdog and `netrun-harden agent-key` still pass.
4. **Generator path (S-NODE-2):** `bash scripts/smoke_generate.sh` → `ready`;
   `journalctl -u netrun-node-agent | grep generator_script_not_allowed` empty after the next orchestrator refill.
   Non-standard `NETRUN_HOME` needs `NODE_AGENT_GENERATOR_ROOT` in the unit drop-in.
5. **Stale lists (L-U2):** regenerate on a start port whose old batch was released with a larger count → every row has
   real credentials; `journalctl … | grep "stale per-start-port"` shows the drop. Cron `proxy-startup_*.sh` generated
   before the deploy is unchanged.
6. **hq-watch (S-NODE-3):** after `node_followup_v2.sh`: `systemctl is-active netrun-hq-watch.timer` = active;
   `systemctl start netrun-hq-watch.service` is silent without the env file; once the orchestrator pushes it:
   `stat -c %a /etc/netrun/hq-watch.env` = 600, state under `/var/lib/netrun-hq-watch/`.
7. **Registration (S-U2):** a real provision-prepare delivers `REGISTER_URL_SET="https://netrun.world/node-register"`.
8. **RADIUS signals (P-N2):** `/proc/net/udp` parsing against a real socket-activated `netrun-radius`:
   `radius.udpDrops` / `udpRxQueue` non-null in `GET /pergb/status`; alert on growth of `udpDrops` / `drainFull`.
9. **Snapshot cache (P-N4):** `ps -eo pid=,etimes=,args=` through the snapshot on a loaded node: `/health` latency and
   agent CPU before/after, `/health.scanCache.hits` ≫ `misses`.
10. **Counter dump (P-N3):** a real 55k-counter dump; `slow nft counter dump` log line / `getCounterDumpStats()`; the
    scaled timeout (max 60 s) fits inside the orchestrator's `TRAFFIC_POLL_REQUEST_TIMEOUT_SEC`.
11. **tcp_tw_reuse (P-N5):** `apply_capacity_tuning.sh --only fingerprint` (dry-run first), then
    `sysctl net.ipv4.tcp_tw_reuse` = 2 (never 0 on per-GB); `/health` `nodeTuning.tcpTwReuseOk`; watch `ss -s` TIME-WAIT.
12. **Log image (P-N6):** `GET /pergb/status` → `logFsUsedPct`; `logFsWarn` / `warnings:["log_fs_warn"]` at ≥ 70 % used,
    admission unchanged below 95 %.

## Rollout steps (merged, in order)

1. Orchestrator side first (other lanes): `NODE_REGISTER_FORWARD=true` on the site and an https
   `ORCHESTRATOR_REGISTER_URL`; the orchestrator must read the new `/pergb/status` names (`tasksMax`, `maxConns`,
   `sliceMemMax`, `logFsUsedPct`, `logFsWarn`, `warnings`, `radius.*`) and tolerate `null`; orchestrator
   `TRAFFIC_POLL_REQUEST_TIMEOUT_SEC` > 60 s + parse time.
2. Do check 1 above on **every** production node before any code lands (read-only).
3. Deploy the merged tree to one canary node, run `apply_capacity_tuning.sh --only fingerprint` (dry-run, then apply),
   `netrun-harden secure` / `agent-firewall` where the guard predates 8086, `netrun-https setup` where there is no IP
   certificate, `node_followup_v2.sh` (installs hq-watch on every node), `systemctl restart netrun-node-agent`
   (a restart is also needed for the new unit/env). Go through checks 2–12.
4. Roll to the rest of the fleet in batches; per batch re-run checks 2, 9, 11.
5. Move orchestrator `nodes.url` rows to `https://<ip>:8086` (probe `/describe supports.agent_tls` /
   `agent_tls_port` first). Only when `nodes.url` has zero `http://` rows and L-O1 is deployed, set
   `NODE_AGENT_ALLOW_PLAIN_HTTP=false` per node (check 3).
6. Owner: create the dedicated alerts-only Telegram bot, push `/etc/netrun/hq-watch.env` (mode **0600**, keys
   `HQ_WATCH_TG_TOKEN/CHAT/TOPIC`, `NODE_LABEL`) via the orchestrator, and only then revoke the old admin-bot token
   still sitting in existing nodes' `hq-watch.env` (neither lane touches existing files on nodes).

## New knobs (both lanes)

| Name | Default | Lane |
|---|---|---|
| `NODE_AGENT_ALLOW_PLAIN_HTTP` | `true` (`false` = `:8085` on `127.0.0.1`) | hardening |
| `NETRUN_AGENT_TLS_REQUIRE_PERGB` | `0` | hardening |
| `NODE_AGENT_GENERATOR_ROOT` / `_SCRIPT` | `/opt/netrun/node_runtime` / `<root>/soft/generator/proxyyy_automated.sh` | hardening |
| `HQ_WATCH_TG_TOKEN` / `_CHAT` / `_TOPIC` (legacy `TG_*` still read, with a warning) | — | hardening |
| `quick-install.sh --allow-insecure-http` | off | hardening |
| `NODE_AGENT_SNAPSHOT_TTL_MS` | `10000` (0 = off) | pergb |
| `NODE_AGENT_NFT_DUMP_TIMEOUT_MAX_MS` / `NODE_AGENT_NFT_DUMP_WARN_MS` | `60000` / `5000` | pergb |
| `/describe supports.agent_tls`, `agent_tls_port`; `/health pergb.tls.routes`, `scanCache`, `nodeTuning.tcpTwReuse*` | additive | both |

## Not done / follow-ups (carried over)

* L-N1 (fail closed on a failed proxy-list write, detect a running batch) — not in either lane; sequence it after
  L-U2 (same `/generate` region).
* RADIUS scale-up (auth cache / front / `SO_REUSEPORT`) once `udpDrops` / `drainFull` fire; surface
  `getCounterDumpStats()` in `/health`.
* Not testable here (no Linux): nftables, systemd, 3proxy, real Let's Encrypt, `/proc/net/udp` on a live socket —
  covered by fakes and the verify list above.
