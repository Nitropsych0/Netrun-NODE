# Lane `node-pergb-runtime` — fixes (Netrun-NODE)

Branch `claude/fix-node-pergb-runtime-80463f`, cut from `main` @ 9474bc4. Six small commits, nothing pushed.
Gate at the end: `node --test node_runtime/node_agent/*.test.js` 467/467 (baseline 446), `python3 -m unittest discover -s node_runtime/radius/tests` 219 OK/1 skipped (baseline 214 — pytest is not installed here; the suite is unittest-based and `python3 -m pytest node_runtime/radius/tests -q` runs the same tests), `bash -n` on every touched script, `scripts/test_*.sh` identical to baseline (all pass except `test_netrun_radius_units.sh`, `test_pergb_agent_linux.sh`, `test_pergb_radius_e2e.sh`, which need Linux/systemd and fail the same way on main).

## Per finding

### 1. P-U1/node — TasksMax drift (commit 64ba3c1)
- **Changed:** `pergb_runtime.js` — one sizing rule: `maxConnsForRam(MemoryMax, count) = floor(MemoryMax/100 KB) − 2·count − 500`, `tasksMax = 2·count + maxConns + 500` (≤ MemoryMax/100 KB). `normalizeParams` **clamps** a bigger `maxConns` (no rejection, so an old orchestrator keeps working) and returns `warnings: ["max_conns_clamped"]` + `maxConnsRequested`; a slice too small for its ports (ceiling < 100) is `bad_params`. `enable.json` stores the effective `maxConns`, the request stays in `params`. New exports `maxConnsForRam`, `effectiveLimits`, `limitsOfEnable`. `install_pergb.sh render_slices` applies the same ceiling (warning + clamp) and refuses a MEM_MAX too small for 1000 ports. `netrun-pergb.slice` comment: 10500 is only the default, live value = enable drop-in, ceiling = MemoryMax/100 KB (the `TasksMax=10500` line stays). README block appended.
- **Tests:** `pergb_runtime.test.js` ("P-U1: TasksMax is sized from RAM…", "P-U1: apply clamps maxConns…" — 22500 case: 20000 on 1536M → 13228 / TasksMax 15728, on 3G → 22500), `pergb_state.test.js` (enable response + status fields, `null` before enable), `scripts/test_install_pergb.sh` (1536M/20000 → clamp warning + `TasksMax=15728`; 3G → 22500; the shell number is cross-checked against `pergb_runtime.js` via node). Fail-before verified (new tests red against the old tree).
- **Orchestrator contract:** `tasksMax`, `maxConns`, `sliceMemMax` (integers; `null` while per-GB is off) top level of `GET /pergb/status` and of the enable response; `warnings` contains `"max_conns_clamped"` while the requested `maxConns` is above the effective one. `applied.maxConnsRequested` / `applied.warnings` in the enable response.
- **Ops (not code):** on EVERY production node run `systemctl show netrun-pergb.slice -p TasksMax -p MemoryMax` and `cat /etc/systemd/system/netrun-pergb.slice.d/50-netrun-enable.conf`; compare with `nodes.pergb_max_conns` in the orchestrator DB. Record whether 10500 or 22500 is live (the Chicago load test notes say 22500 with 1536M MemoryMax — that exceeds the new ceiling 15728, so on a node that really runs maxConns 20000 the next enable will clamp it to 13228 unless MemoryMax is raised to ≥ ~2.2G). **This figure must go to orchestrator-lifecycle-and-catalog before it changes any capacity constant.**

### 2. P-N2/node — RADIUS single thread (commit 3399daf)
- **Changed:** `engine.py` (`drainFull` counter, `loop_max` gauges with a 2-window decay, `udp_drops`/`udp_rx_queue` slots, `op_status["load"]`), `netrun_radius.py` (each drain pass timed; passes that consume `DRAIN_MAX` counted; `read_udp_stats()` parses `/proc/net/udp` for the socket's drops + rx_queue every 5 s from the sweeper, `(None, None)` on any error; also correct for socket-activated sockets via `getsockname`), `pergb_state.js` (`radius.requests/sendErrors/drainFull/udpDrops/udpRxQueue/loopMaxMs`, `null` when ctl is down or RADIUS is older; `p99Ms` was already there), `radius/README.md` ("Saturation signals"), unit-file comment, README.
- **Tests:** `radius/tests/test_engine.py` (load keys, decay), `test_server.py` (`UdpStats`: parser, missing /proc, IPv6, wildcard; process-level load block after traffic), `pergb_state.test.js` (exact names, `null` before enable).
- **Deviations (per the plan):** no 3proxy auth cache, no Go/C front, no SO_REUSEPORT — multiple processes need a shared state/sqlite writer; documented as follow-ups gated on `udpDrops`/`drainFull` firing. The audit text about watchdog restarts under load is wrong (the sweeper pings while the loop iterates; overload = kernel drops) — corrected in README and unit comment.
- **Orchestrator contract:** `radius: {p99Ms, requests, sendErrors, drainFull, udpDrops, udpRxQueue, loopMaxMs}`. `udpDrops`/`udpRxQueue` are `null` where `/proc/net/udp` is unavailable — alert on growth of `udpDrops` between polls (and `drainFull`), ignore `null`.

### 3. P-N6 — per-GB log image usage (commit 615b66e)
- **Changed:** `pergb_guards.js` (`LOGFS_WARN_USED_PCT = 70`, `settings.logFsWarnUsedPct` override; `logFsUsedPct`, `logFsWarn`, `warnings: ["log_fs_warn"]` in `status()`; admission logic and `closedBy` untouched; one `pergb_log_fs_high` log line + agent event per transition with `meterLagSec`), `pergb_meter.js` (`status().logFs = {total, free, usedPct, freePct}`), `pergb_state.js` (top-level `logFsUsedPct`, `logFsWarn`, merged `warnings`; also inside `guards`), comment at `install_pergb.sh` LOG_SIZE, README.
- **Tests:** `pergb_guards.test.js` (75 % → warn, admission open, `closedBy []`; 95 % → `log_fs` closes; one event per transition; unreadable fs → null/false), `pergb_meter.test.js` (`status().logFs`, null when unreadable), `pergb_state.test.js`.
- Warn threshold is `>= 70 %` used.

### 4. P-N4 — shared ps/ss snapshot (commit d257663)
- **Changed:** new `proc_snapshot.js` (+ `proc_snapshot.test.js`): TTL cache (`NODE_AGENT_SNAPSHOT_TTL_MS`, default 10000, 0 = old behaviour/argv), in-flight coalescing, ok-only caching, `{fresh:true}` write-through, `invalidate()`, `stats()`; `ps` unified on `pid=,etimes=,args=` (auto-fallback to `pid=,args=` for BSD ps). `hygiene.js` / `supervisor.js` take an optional `snapshot` and read `{fresh:true}` (they decide kills/respawns); `process_lock.js` gains `onSettled` so every locked process-table change invalidates; `server.js` (hub, lane block + function-local edits): one `procSnapshot`, `/health` reads it via `collectRunningInstances({shared})` / `listListeningExactPortsShared` (bypassed while a generation runs; `releaseGenerationLock` invalidates), additive `/health.scanCache`.
- **Tests:** `proc_snapshot.test.js` (TTL, coalescing, fresh, failure not cached, port-set keys + 256-port chunking, TTL 0, invalidate, etimes fallback), `server.health_cache.test.js` (N `/health` → one `ps` + one `ss`; again after the TTL; a locked change invalidates), `hygiene.dedupe.test.js` + `supervisor.test.js` (a cached stale view is never used for a kill/respawn; their reads feed `/health`). The existing health/hygiene/supervisor suites pass unchanged (argv identical with TTL 0 or fresh).
- **Deviation:** only `/health` actually reads the cache; hygiene/supervisor feed it. A "read-only 600 s hygiene path" does not exist (every hygiene `ps` decides a kill).
- Ops: after deploy compare `/health` latency and agent CPU on a loaded node; `scanCache.hits` should dominate `misses`.

### 5. P-N3 — nft counter dump cost (commit 387513c)
- **Changed:** `accounting.js` — dump timeout = `max(20 s, ceil(count/12000 · 1.1 s · 6))` capped at `NODE_AGENT_NFT_DUMP_TIMEOUT_MAX_MS` (60 s) from the previous dump's item count; slow dump (> `NODE_AGENT_NFT_DUMP_WARN_MS`, 5 s) → `console.warn`, failed dump → `console.error` with duration/timeout/count (each rate-limited to once per 5 min); `getCounterDumpStats()`. Exported `NFT_DUMP_TIMEOUT_MS` stays 20000.
- **Test:** `accounting.dump_cost.test.js` (scaling math incl. 55k and 200k, warn once, failure logs + still `NftablesError`).
- **Deviation (per the plan, against the goal line):** the bulk dump + per-cycle cache are kept — the code comment documents that a targeted per-counter read measured slower, so "dump only requested ports" was NOT implemented. There is no node event bus in `accounting.js`, so "emit a node event" is a rate-limited log line + `getCounterDumpStats()` (not wired into `/health`).
- **Cross-repo note:** orchestrator `TRAFFIC_POLL_REQUEST_TIMEOUT_SEC` must exceed 60 s + parse time for the scaling to help.

### 6. P-N5 — ephemeral ports / tcp_tw_reuse (commit e2909ba)
- **Changed:** `99-zz-netrun-tcp.conf` pins `net.ipv4.tcp_tw_reuse = 2` with the rationale; `apply_capacity_tuning.sh` adds it to `TCP_KEYS` (legacy line purged from `/etc/sysctl.conf`, re-applied by `--only fingerprint`); `install_node_v2.sh` comment on the 1024–8000 range; `server.js nodeTuningStatus` gains `tcpTwReuse` / `tcpTwReuseOk` (false only for 0; reader injectable); README.
- **Tests:** `scripts/test_capacity_18k_node.sh` (file pin, not duplicated in the installer's 99-netrun.conf, never 0/1), `scripts/test_apply_capacity_tuning.sh` (legacy `= 0` purged, plan text, pinned in the file), `server.n2.test.js` (`nodeTuningStatus` 0/1/2/null).
- Ops: `sysctl net.ipv4.tcp_tw_reuse` must print 2 on live per-GB nodes; run `apply_capacity_tuning.sh --only fingerprint` (dry-run first); watch `ss -s` TIME-WAIT.

## Final `/pergb` status field list (additive; every existing key kept)
Top level: `tasksMax`, `maxConns`, `sliceMemMax` (ints/null), `logFsUsedPct`, `logFsWarn`, `warnings: []` (`max_conns_clamped`, `log_fs_warn`) — all new; `radius.{p99Ms, requests, sendErrors, drainFull, udpDrops, udpRxQueue, loopMaxMs}` (p99Ms existed; the rest new, `null` = unknown); `guards.{logFsUsedPct, logFsWarn, warnings}` additive; the enable response is `status()` + `applied.{warnings, maxConnsRequested, …}`. `/health` additive: `scanCache`, `nodeTuning.{tcpTwReuse, tcpTwReuseOk}`.

## Decisions taken by default (all config keys)
| Key | Default |
|---|---|
| `NODE_AGENT_SNAPSHOT_TTL_MS` | 10000 (0 = off) |
| `NODE_AGENT_NFT_DUMP_TIMEOUT_MAX_MS` | 60000 (floor `NODE_AGENT_NFT_DUMP_TIMEOUT_MS` 20000) |
| `NODE_AGENT_NFT_DUMP_WARN_MS` | 5000 |
| log image warn threshold | 70 % used (`settings.logFsWarnUsedPct`) |
| RAM ceiling | 100 KB per connection of `MemoryMax`, 500 task margin |
| RADIUS loop-max window | 2 × 30 s; `/proc/net/udp` sampled every 5 s |

## Still to verify on a real node (no Linux box here)
1. `systemctl show netrun-pergb.slice -p TasksMax -p MemoryMax` and the enable drop-in vs `nodes.pergb_max_conns` (see P-U1).
2. `/proc/net/udp` parsing against a real socket-activated `netrun-radius` (`udpDrops`/`udpRxQueue` non-null; unit-tested only against a fabricated file).
3. `ps -eo pid=,etimes=,args=` through the snapshot on a 4 000-process node: `/health` latency, `scanCache.hits/misses`.
4. A real 55k-counter dump: `getCounterDumpStats()` / the `slow nft counter dump` line, and that the scaled timeout is within the orchestrator's poll timeout.
5. `apply_capacity_tuning.sh --only fingerprint` on a live node and `sysctl net.ipv4.tcp_tw_reuse` = 2.

## Follow-ups (not done)
RADIUS scale-up (auth cache / front / SO_REUSEPORT) once `udpDrops`/`drainFull` fire; surface `getCounterDumpStats()` in `/health`; the orchestrator lanes consume the field names above (orchestrator-db-and-schedulers `observe_status`, orchestrator-lifecycle-and-catalog `pergb_nodes.py` RAM ceiling).
