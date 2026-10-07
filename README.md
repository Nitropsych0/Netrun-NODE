# NETRUN Node Runtime

Self-contained NETRUN proxy node runtime. This repo is only for the node-agent and proxy generator layer. It does not include orchestrator, Telegram bot, database, SKU, payment, inventory, or business logic.

## Fresh Node Install

```bash
git clone https://github.com/Tmwyw/node_runtime_new.git /opt/netrun
cd /opt/netrun
bash install_node_v2.sh
```

> `install_node_v2.sh` is the maintained installer (raised kernel pid/thread
> limits, DAD/MLD off, bounded 3proxy restore through the spawn helper, the
> pinned TCP signature `deploy/node/99-zz-netrun-tcp.conf`, unbound resolver,
> trend + IPv6-egress restore units). `install_node.sh` is now a thin shim that
> execs v2, so either filename works on a fresh node.

## Archive Install

```bash
scp netrun-node.tar.gz root@server:/opt/
ssh root@server
cd /opt
tar -xzf netrun-node.tar.gz
cd netrun-node
bash install_node_v2.sh
```

The installer copies the archive contents into `/opt/netrun` and installs the systemd service from there. It does not require `.git` and does not run git commands.

## Dirty Node Reinstall

```bash
bash scripts/clean_node.sh --remove-legacy-root
bash install_node_v2.sh
```

`install_node_v2.sh --clean --remove-legacy-root` is also supported when you explicitly want cleanup before install.

## Health Check

```bash
curl http://127.0.0.1:8085/health | jq .
bash scripts/smoke_health.sh
```

Expected health state:

```json
{
  "success": true,
  "status": "ready"
}
```

Wave FLEET-HEALTH additive fields (every older field is unchanged):

| Field | Meaning |
|---|---|
| `cfgs` | `[{startPort, count, listening, pid}]` per active `3proxy_<start>.cfg` (`*.cfg.disabled` excluded). `listening` = the cfg's FIRST socks port is bound (after a `/deprovision` rewrite the file's start port may no longer be served); `null` when the port probe failed. `pid` = its 3proxy or `null`. At most 500 items (`cfgsTotal`, `cfgsTruncated`). |
| `cfgsDown` | how many cfgs are not listening (`null` = unknown) |
| `cfgsWithoutProcess` | `[{startPort, cfgPath}]` — cfgs with no 3proxy process (from the cfg files on disk; `/reconcile` is no longer needed for this) |
| `ipv6Addresses` | `{ok, expected, present, missing, missingSample, source, checkedAt, ttlSec}` — distinct `-e` addresses of the active cfgs vs those the kernel holds (`/proc/net/if_inet6`, any interface); recomputed at most every `NODE_AGENT_IPV6_COVERAGE_TTL_SEC` (60) |
| `cfgsError` | why the cfg directory could not be read, else `null` |

`duplicatesReaped`, `lastReapAt` and `hygiene` (duplicate 3proxy reaper + crontab
hygiene) are described under "Boot duplicates" below.

Audit N2 additive fields (every older field is unchanged):

| Field | Meaning |
|---|---|
| `supervisor` | the 3proxy supervisor: `{enabled, intervalSec, lastRunAt, lastOutcome, cfgsRespawned, respawnFailures, lastRespawns[], pendingDown[], unsupervised[], seenServing[], failedCfgs[], addressesReadded, addressesMissing, anchorsDeprecated, anchorsPendingDeprecate, anchorsExpected, iface, readdAnchors, deprecateAnchors}` (also `/run/netrun/supervisor.json`) |
| `firewall` | the desired-state firewall: `{enabled, reapplySec, desired: {receivedAt, computedAt, windows, livePorts, pergbBlocked, ghostPorts} \| null, lastApply}` |
| `cfgsLegacyDns` | `{count, items: [{startPort, nservers}]}` — cfgs whose `nserver` lines name a third-party resolver (the 2026-05 geo seed); the spawn helper rewrites them at the batch's next start |
| `cfgsEgressFamily` | in `ipv6_only` egress mode: `{expectedFlag: "-6", mismatched, items: [{startPort, flags}]}` — cfgs that can leave over IPv4 (`-64`/`-46`/`-4`/no flag); `{expectedFlag: null, mismatched: null}` otherwise. Replaces the generator's dual-stack self-check, which the agent always skipped |
| `nodeTuning` | `{ipLocalPortRange, ephemeralOverlapsProxyPorts, proxyListenFloor, tcpTimestamps, ipDefaultTtl, tcpRmem, pipeUserPagesSoft}` — `ephemeralOverlapsProxyPorts: true` is the 2026-10-07 5–7 % failure bug coming back |

`proxyReady` / `proxyReadiness` probe each instance on the same first socks port.
The agent binds `NODE_AGENT_HOST` (default `0.0.0.0`; the unit template has always
set it, nothing read it, so it used to answer on `[::]` = every customer exit IPv6).
`NODE_AGENT_HOST=::` restores the old bind.

## 3proxy supervision, desired-state firewall, node source address (audit N2)

### One spawn helper (RES-11)

`scripts/netrun-3proxy-spawn.sh <cfg>` is the only way a batch is started: the boot
restore (`scripts/restore_3proxy.sh`, unit `deploy/node/netrun-3proxy-restore.service`
— the installer and the follow-up no longer write their own heredoc copies), the
agent (supervisor, `/deprovision` rewrite, `/egress_mode`, pay-per-GB enable),
`netrun-https` (HTTP listeners moved behind haproxy), `netrun-harden auth-fix` and the
generator's start-up script. It is idempotent (a 3proxy already running the cfg in any
directory, or a listening first socks port: exit 0, nothing started), takes a per-cfg
`flock` (`/run/netrun/3proxy-spawn-<sp>.lock`), refuses `*.cfg.disabled`, and starts
3proxy in its own scope: `systemd-run --scope --unit netrun-3proxy-<sp> -p KillMode=process
-p TasksMax=infinity --collect` (setsid only when no 3proxy appeared) — restarting the
restore unit, the agent or the https-sync oneshot never takes a batch down any more.
Right before a start it rewrites legacy third-party `nserver` lines (the 2026-05 geo
seed) to `127.0.0.1` / `::1` while unbound is active (`NETRUN_SPAWN_FIX_DNS=0`: off),
keeping the cfg's mode, owner and mtime (the supervisor and the firewall read the mtime:
the rewrite is not a new batch). The generator's `--dns-servers` is accepted and ignored
(its `nserver` lines never survived that first start).
`scripts/test_3proxy_spawn.sh`.

### Supervisor (RES-11)

Every `NODE_AGENT_SUPERVISOR_INTERVAL_SEC` (60; first run after
`NODE_AGENT_SUPERVISOR_FIRST_DELAY_SEC`, 120) the agent:

- respawns a batch cfg (never `*.cfg.disabled`) that runs ZERO times and whose first socks
  port does not listen — only one that DIED (seen serving since boot; the set survives an
  agent restart in `/run/netrun/supervisor.json`) or whose cfg predates the boot; a cfg
  written after the boot that never served (a failed generation's leftover) is listed as
  `unsupervised` and left to the next reboot / a regeneration — on two consecutive ticks, not within
  `NODE_AGENT_SUPERVISOR_SETTLE_SEC` (120) of a cfg write, never while a `/generate`
  holds the generation lock (checked per tick and again right before the spawn) or the
  boot restore unit is running; at most `NODE_AGENT_SUPERVISOR_MAX_RESPAWNS_PER_HOUR`
  (5) per cfg, then the cfg is `failed` (logged once, `/health supervisor.failedCfgs`)
  until it listens again or its file changes; the hourly history and the failed marks
  survive an agent restart (same status file) — an OOM / watchdog restart does not hand a
  crash-looping batch 5 fresh respawns. "Seen serving" belongs to the batch, not the start
  port: `/generate` (under its lock, after kill-on-rebind) and a whole-batch `/deprovision`
  forget the start port, so a regeneration there that fails leaves an `unsupervised`
  leftover instead of a respawned batch nobody recorded; rewrites that keep the batch
  (`/deprovision` rewrite, `/egress_mode`, the DNS fix) keep its supervision. An
  http-only cfg is probed on its own listen address (`-i127.0.0.1` behind the HTTPS
  front), never on haproxy's `<public-ip>:<port>`. The duplicate reaper and the supervisor
  share one process lock (`process_lock.js`) and never fight: the supervisor starts only
  a cfg that runs zero times, the reaper acts only on a cfg that runs twice and never
  kills its last copy; `/deprovision` and `/egress_mode` kill+respawn under the same lock;
- re-adds anchors (cfg `-e` addresses) missing from `/proc/net/if_inet6` whose /64 the node
  still has, in ONE `ip -6 -force -batch` (`/128 nodad preferred_lft 0`), at most
  `NODE_AGENT_ANCHOR_READD_BATCH` (2000) per tick — an add holds RTNL for O(addresses on the NIC), ~30 ms at 16k (`NETRUN_ANCHOR_READD=0`: off);
- deprecates anchors (below), `NODE_AGENT_ANCHOR_DEPRECATE_BATCH` (2000) per tick —
  every preferred global `nodad` address on the egress interface, not only the active
  cfgs' (a deprovisioned / regenerated batch's anchors stay on the NIC until a reboot, a
  `*.cfg.disabled`'s, an old restore's /64s: one of them added after the primary wins the
  kernel's source tie-break). `/health supervisor`: `preferredNodad` (should reach 0),
  `preferredNonNodad` (the primary: normally 1), `orphanAnchorsDeprecated`,
  `respawnHistory`, `failedCfgs[].atMs|mtimeMs`.

`NODE_AGENT_SUPERVISOR=0` turns it off. `netrun-ipv6-restore.sh` now exits 1 (loudly)
when it finds no IPv6 interface instead of exiting 0.

### Node-originated traffic leaves from the primary IPv6 (FP-01)

Every anchor is added with `preferred_lft 0` (generator, boot restore, supervisor; the
supervisor converts existing ones in batches with `ip address change … nodad valid_lft
forever preferred_lft 0`). A deprecated address is never the kernel's choice of SOURCE
(RFC 6724 rule 3, `ipv6_dev_get_saddr`), but stays valid: NDP answers for it, replies to
it are delivered, and 3proxy's explicit `-e<anchor>` bind works as before. So unbound's
recursion, apt, `ping6` in the generator and the agent's egress / DNS checks leave from
the node's own SLAAC address — not from a customer's exit IP — with no per-program
setting. Chosen over the alternatives: an `ip -6 route … src` on the default route is
owned by systemd-networkd / the RA (rewritten on every RA refresh or `netplan apply`)
and does not cover on-link /64 destinations; `unbound outgoing-interface` + an agent
`localAddress` cover two programs only and break when the SLAAC address changes. Only
`nodad` anchors are ever deprecated (the host's own address never carries nodad).
`NETRUN_ANCHOR_DEPRECATE=0` / `off` / `false` / `no`, any case (environment or
`/etc/netrun/netrun.env`; the agent, the generator and the boot restore read it the same
way) turns it off; undo on a node: the same `ip address change` with `preferred_lft forever`.
Check: `ip -6 route get 2001:500:2f::f` shows the primary as `src`.
**IPv6 only.** In egress mode `dualstack` (`-64`) a proxy's IPv4 destinations leave from
the node's single IPv4 — the address unbound's IPv4 recursion and the agent use too, so a
DNS-leak test through such a proxy shows resolver IPv4 == exit IPv4. `/health` reports
`egressMode` and `ipv4ExitSharedWithNode`; the fix is audit FP-02 (a dedicated egress
IPv4 or fail-closed `-6`).

### Uniform TCP signature (FP-01)

`deploy/node/99-zz-netrun-tcp.conf` → `/etc/sysctl.d/99-zz-netrun-tcp.conf` pins the
stock Ubuntu 24.04 / kernel 6.8 values (TTL 64, timestamps, SACK, window scaling, ECN 2,
`tcp_rmem 4096 131072 6291456`, `min_adv_mss 256`, MTU probing) on every node; it sorts
after `99-sysctl.conf` (= `/etc/sysctl.conf`), where the old generator wrote
`tcp_timestamps = 0` / `tcp_rmem 4096 87380 …`. The inert knobs are gone instead: the
generator's TCP profile (`apply_network_profile_sysctl`, written to `/etc/sysctl.conf`),
its edge "normalization" (ttl/hoplimit set, ct invalid drop, fragment drops) and every
`tcp option maxseg size set` rule (nft can only LOWER an MSS; 1460 was a no-op, the legacy
1340 read as OpenVPN). Existing nodes: `apply_capacity_tuning.sh --only fingerprint` —
it deletes those rules and keeps the (now empty) `inet proxy_normalization` table and its
chains: the pre-N2 generator refuses every `--runtime-only` generation without the table,
so a rollback to it must find it (restoring `/etc/nftables.conf` alone reloads nothing).

### Desired-state firewall for stale listeners (RES-13, node part)

`POST /firewall/desired` (X-API-KEY): `{livePorts:[int], pergbBlocked:[int], window:[lo,hi]
| windows:[[lo,hi],…], httpMirror?, computedAt?, dryRun?, force?}`. Blocks (one `nft -f` on
`inet proxy_accounting pergb_blocked`) every listener inside the windows that is not in
`livePorts` plus `pergbBlocked` (each socks port with its http port, socks − 10000), and
unblocks every blocked port in `livePorts` that is not in `pergbBlocked`. Ports of an
in-flight generation (the generation lock: range + http mirror) are never blocked and
their blocks are lifted; `/generate` also lifts the blocks of the batch it is about to
generate. A listener of a cfg written in the last `NODE_AGENT_FIREWALL_FRESH_SEC` (1800)
or after `computedAt − 5 min` is never a ghost. More than
`NODE_AGENT_FIREWALL_MAX_NEW_BLOCKS` (3000) new blocks, or no live port while listeners
exist: 409 unless `force`. The accepted push is persisted
(`/var/lib/netrun/desired.json`) and re-applied at agent start (after
`reapplyPergbBlocks`) and every `NODE_AGENT_FIREWALL_REAPPLY_SEC` (900) — a re-apply
re-asserts the pushed ghosts and `pergbBlocked` and removes stale drops on live ports,
but never declares new ghosts. `GET /firewall/desired` shows the state.
`NODE_AGENT_FIREWALL_DESIRED=0`: off. Response `report`: `{ghosts, pergbBlocked, added,
removed, skippedInFlight}` (`{count, sample}` each), `listenersInWindows`, `freshExempt`,
`togglesKept`, `ipLocalPortRange`.

- **The latest per-port intent wins.** `POST /accounts/{port}/disable|enable` records the
  toggle (`{blocked, atMs}` for the port and its http pair) in memory and in
  `NODE_AGENT_FIREWALL_TOGGLES_FILE` (`/var/lib/netrun/desired.toggles.json`) before the
  200 (same response as before). Every plan lays the toggles over the desired state: a
  disabled port stays blocked, an enabled one is live and never blocked — the 15-min and
  the boot re-apply of an older push never re-block a customer who topped up or free a
  depleted account, and `pergb_blocked.list` is never pruned / refilled against a toggle.
  A push drops the toggles older than its snapshot (`computedAt`, else its arrival, − 5 min)
  and keeps the newer ones over its payload; a generation lift drops its batch's toggles.
  The accounting call runs outside the apply chain (a slow push never delays the disable
  ack); a toggle landing while a plan applies is re-checked before `nft -f` and inside the
  list update. `/health firewall.accountToggles`.
- **Lift after a failed sweep.** When `/generate`'s kill-on-rebind sweep did not finish
  (its `ss -p` failed or it threw), one cheap `ss -Hltn` per range finds the batch ports an
  old occupant still serves (address-aware like the generator's pre-check: haproxy's
  `<public-ip>:<http-port>` frontend is not an occupant); their drops, list entries and
  toggles stay. If that snapshot fails too, everything is lifted as before.
- **Ephemeral-range guard** (`NODE_AGENT_FIREWALL_EPHEMERAL_GUARD`, default on): the drop
  rule also drops the SYN-ACKs of upstream connections whose ephemeral port is blocked (the
  2026-10-07 5–7 % incident). A push that would add blocks inside
  `net.ipv4.ip_local_port_range` → 409 `ephemeral_overlap` (`ipLocalPortRange`,
  `overlappingAdds`) unless `force`; a re-apply only warns (`ephemeralOverlap` in its report).
  Fix the node with `apply_capacity_tuning.sh --only sysctl` (1024–8000).

### 3proxy accept backlog, splice pipes, HTTPS reloads (speed)

- 3proxy 0.9.3 has no backlog option: every service calls `listen(sock, (maxconn >> 4) + 1)`
  (`mainfunc` 0xc408–0xc421 of the bundled binary) and `net.core.somaxconn` only caps a
  larger request — maxconn 200 meant an accept queue of 13 per proxy port. New batches get
  `maxconn 512` (backlog 33; also 512 concurrent connections per proxy before the listener
  pauses). `NETRUN_3PROXY_MAXCONN` (environment or `/etc/netrun/netrun.env`) or `--maxconn`
  overrides; existing batches keep their header until regenerated (no restarts).
- `fs.pipe-user-pages-soft` (all 3proxy run as uid 65535 and relay with splice, two pipes
  per connection): past the soft limit new pipes get 8 KiB instead of 64 KiB. Sized by RAM
  (largest power of two ≤ MemTotal/32 pages, 16384..262144; 2c/4GB → 65536 = full pipes for
  ~2048 relays, 256 MiB worst case). Existing nodes: `apply_capacity_tuning.sh --only pipes`.
- `netrun-https sync` reloads haproxy only when needed (it reloaded every 5 min, each
  reload leaving a draining worker for up to the 1 h tunnel timeout): the frontends or the
  base config changed, haproxy is stopped, or the files differ from the last reload that
  haproxy verifiably loaded — `/run/netrun/haproxy-applied.sha` (haproxy.cfg + certificate
  + frontends), written only once haproxy listens on every frontend's first bind port
  (`NETRUN_HTTPS_RELOAD_VERIFY`, default 1; up to `NETRUN_HTTPS_VERIFY_WAIT_SEC`, 10). A
  failed, killed or unverified reload is therefore retried on the next 5-min tick (the
  sync exits 1 meanwhile); a missing stamp (deploy, reboot) costs one reload;
  `NETRUN_HTTPS_RELOAD_MAX_AGE_H` (6; 0 = never) reloads anyway after that long. A new
  frontend set is checked with `haproxy -c` BEFORE it replaces `/etc/haproxy/netrun.d`
  (a rejected set never goes live). sync / renew / setup share one `flock`
  (`/run/netrun/https-sync.lock`). Its unit gets `KillMode=process` (`netrun-https units`;
  `apply_capacity_tuning.sh --only units` refreshes the `/usr/local/sbin` copy).
- Batch IPv6 generation: one `od` + one `awk` per batch (was ~17 subshells and one
  `ip -6 addr` dump of every NIC address per address).

### Existing nodes

```bash
bash scripts/apply_capacity_tuning.sh --only units,fingerprint,pipes,ipv6restore           # dry-run
bash scripts/apply_capacity_tuning.sh --apply --only units,fingerprint,pipes,ipv6restore   # no restarts
```

Before the first agent restart with the supervisor on an existing node: if
`/health cfgsDown > 0`, check those start ports against the orchestrator's
inventory for the node. A down cfg whose cfg file predates the boot is
respawned about 3 min after the restart; one the orchestrator does not know (a
ghost or a failed generation's leftover) should be renamed to `*.cfg.disabled`
first (never started), or watch `/health supervisor.pendingDown` in that window.

Tests: `bash scripts/test_3proxy_spawn.sh`, `bash scripts/test_generator_flags.sh`,
`bash scripts/test_apply_capacity_tuning.sh`, `bash scripts/test_capacity_18k_node.sh`,
`cd node_runtime/node_agent && node --test` (`supervisor`, `firewall`, `proxy_spawn`,
`cfg_checks`, `server.n2`, `server.lift_exclude`).

## Self-describe (for orchestrator enroll)

```bash
curl http://127.0.0.1:8085/describe | jq .
```

Returns a single JSON snapshot the orchestrator consumes via `POST /v1/nodes/enroll {agent_url}` — no per-node manual parameters required. Includes:

- `agent_version`, `node_runtime_commit`
- `capacity` (proxies this box holds: MemTotal-based, ~0.1 MB/proxy + per-process overhead, capped at the 27 436 single-IPv4 dual port ceiling; `capacity_model` shows the inputs), `max_parallel_jobs`, `max_batch_size`
- `generator_script` (resolved absolute path)
- `geo_code` (ISO 3166-1 alpha-2, cached 1h via ipapi.co)
- `ipv6`, `ipv6_egress` (same shape as `/health`)
- `api_key_required`, `jobs_root`, `proxy_root`
- `supports.{describe,enroll,accounting,egress_rotation,firewall_desired,supervisor}`
  (`egress_rotation` is true once the egress module below has its nft NAT table up;
  `firewall_desired`: `POST /firewall/desired` is served; `supervisor`: dead batches are
  respawned — audit N2)

Open access (mirrors `/health`); set `NODE_AGENT_API_KEY` only if you want auth on the write endpoints.

## Capacity tuning (18k proxies on a 2c/4GB node)

New nodes get it from `install_node_v2.sh`: `ip_local_port_range = 1024 8000`
(ephemeral ports below every listener), unbound `msg-cache 32m / rrset-cache 64m`,
and an `ip -batch … nodad` boot-time IPv6 restore. New batches from the generator
carry no `nscache`/`nscache6`, add their IPv6 addresses with one `ip -batch … nodad`,
check their ports against ONE `ss` snapshot (and refuse a batch whose ports are
already bound), and accept socks start ports from 18100 (dual http = socks − 10000
≥ 8100; floor `NETRUN_MIN_LISTEN_PORT`, default 8100).

Existing nodes are opt-in and never have 3proxy restarted:

```bash
bash scripts/apply_capacity_tuning.sh            # dry-run: prints the plan + a listener audit
bash scripts/apply_capacity_tuning.sh --apply    # sysctl range, unbound reload, legacy nft rules, ipv6 restore
```

Tests: `bash scripts/test_apply_capacity_tuning.sh`, `bash scripts/test_capacity_18k_node.sh`,
`bash scripts/test_fleet_health_node.sh`, `bash node_runtime/soft/generator/test_capacity_18k.sh`,
`bash node_runtime/soft/generator/test_fleet_health.sh`, `cd node_runtime/node_agent && node --test`.

### Conntrack ceiling that survives reboots

`net.netfilter.*` keys exist only once `nf_conntrack` is loaded, and `systemd-sysctl`
runs early in boot, before nftables loads the module lazily — so the
`nf_conntrack_max = 1048576` in `99-netrun.conf` was skipped at every reboot and the
kernel default won (65536 on a 1–4 GB box; the live Chicago node ran with 65536).
`install_node_v2.sh` / `node_followup_v2.sh` now write
`/etc/modules-load.d/netrun-conntrack.conf` (`nf_conntrack`, loaded before
`systemd-sysctl`, which is ordered `After=systemd-modules-load.service`) and
`/etc/udev/rules.d/90-netrun-conntrack.rules` (re-applies `net.netfilter.*` whenever the
module loads), and size the value by RAM: one entry per 8 KB, rounded down to a power
of two, 65536..1048576 (`NETRUN_CONNTRACK_MAX` overrides). An entry is ~300–350 B of
slab, so a full table stays under ~4 % of RAM — 2c/4GB → **262144** (~85 MB only when
full; ~130k concurrent proxied flows incl. TIME_WAIT, each flow = client leg + upstream
leg). The hash keeps the kernel default (65536 buckets): 4 entries per bucket when full.

Existing nodes (opt-in, NOT in the default step list; never lowers a higher runtime
value, never flushes):

```bash
bash scripts/apply_capacity_tuning.sh --only conntrack            # dry-run
bash scripts/apply_capacity_tuning.sh --apply --only conntrack    # [--conntrack-max N]
```

The `nf_conntrack_tcp_timeout_established = 7200` already in `99-netrun.conf` also
starts to apply at boot (it was skipped too); 3proxy closes idle connections after
1800 s, so no proxied connection is affected.

## /generate: explicit credentials, reclaim list (Wave FLEET-HEALTH)

Optional request fields (absent = exactly the old behaviour):

- `credentials`: one entry per proxy, in port order — `"login:password"` strings or
  `[login, password]` pairs, each part `[A-Za-z0-9]{1,32}`, logins unique, length =
  `proxyCount`; otherwise **400 `invalid_credentials`**. Under the generation lock the
  agent writes `random_users_<startPort>.list` atomically (tmp + fsync + rename, mode
  0600), which the generator reuses instead of drawing random ones. A file that already
  exists with OTHER content → **409 `credentials_conflict`** (same content = fine,
  idempotent retry); so does reusing an already-running batch whose credentials differ.
  A file this request created is removed again when the job fails before a cfg exists.
  Only the count is logged / stored in `job.json`.
- `freshAddresses: true`: deletes `ipv6_<startPort>.list` before the generator runs (no
  stale address list is reused).
- `reclaimStartPorts: [int]`: start ports of released batches the agent may kill if one
  of their 3proxy still listens inside the new socks / http range. With the field
  present (even `[]`) kill-on-rebind is strict: an overlapping 3proxy whose start port
  is not listed is never killed — the job answers 200
  `{success:false, status:"failed", error:"ports_in_use", detail:[{startPort, pid, cfg}]}`
  and nothing is touched. Malformed → 400 `invalid_reclaim_start_ports`. Without the
  field (older orchestrators) the old kill-everything-overlapping behaviour stays,
  unless `NODE_AGENT_REBIND_POLICY=refuse`.

Every batch kill-on-rebind tears down now loses ALL its per-start-port files (cfg,
`cfg.disabled`, `proxy-startup_<p>.sh`, `ipv6_<p>.list`, `random_users_<p>.list`,
`running_server_<p>.info`) and its egress rotation state — before, the pid→cfg lookup
ran after the kill (no file was ever removed), and a later batch at that start port
reused the old addresses AND the old credentials. The killed process is matched to the
agent's cfg by start port + directory identity (realpath), not by the literal path: the
generator starts 3proxy as `/root/proxyserver/3proxy/3proxy_<p>.cfg`, and
`/root/proxyserver` is a symlink to `/opt/netrun/proxyserver`. A 3proxy whose cfg sits in
an unrelated directory is still killed, but nothing is deleted
(`stale cfg path mismatch` in the log).

Job directories: `/opt/netrun/jobs` keeps the newest `NODE_AGENT_JOBS_KEEP` (200; 0 =
off) plus the running generation's, any queued/running job updated within 30 min and
the newest ready job of every start port that still has a cfg (the "reuse a running
instance" path). Pruned after each generation and a minute after start.

## Boot duplicates: crontab hygiene + 3proxy dedupe (incident 2026-10-07)

**Incident.** Chicago (2 vCPU / 4 GB, ~10 batch cfgs × 1500 dual proxies): after a
reboot every batch ran twice — once from `netrun-3proxy-restore.service`
(`/opt/netrun/proxyserver/3proxy/bin/3proxy /opt/netrun/proxyserver/3proxy/3proxy_<sp>.cfg`)
and once from one of 11 leftover generator crontab lines
`@reboot bash /root/proxyserver/proxy-startup_<sp>.sh`
(`/root/proxyserver/3proxy/bin/3proxy /root/proxyserver/3proxy/3proxy_<sp>.cfg`;
`/root/proxyserver` is a symlink to `/opt/netrun/proxyserver`). 19 3proxy processes,
MemAvailable 1.5 GB → 0.46 GB, `/health` slower than the Vultr watchdog's 5 s timeout,
and the watchdog rebooted the node twice — each reboot recreated the duplicates. Two
daemons on the same ports also split the accepts between them (SO_REUSEPORT).

**Why the lines survived.** The post-`/generate` cleanup
(`NODE_AGENT_CLEANUP_CRON_AFTER_RUN`) removed `/opt/netrun/proxyserver/proxy-startup_<sp>.sh`
by exact string, but the generator (`cd ~`) writes `/root/proxyserver/proxy-startup_<sp>.sh`:
it never matched, so the line of every generation stayed. These scripts also rewrite
`3proxy_<sp>.cfg` from `ipv6_<sp>.list` / `random_users_<sp>.list` before they start
3proxy, at every boot, and a `--rotating-interval` line (`*/N * * * *`) re-runs one every
N minutes. Nothing ever killed a duplicate; `/health` only reported `duplicateStatePresent`.

**What the agent does now** (`node_runtime/node_agent/hygiene.js`):

- **Crontab hygiene** — at agent start and every `NODE_AGENT_HYGIENE_INTERVAL_SEC`: reads
  `crontab -l`, drops every line that names a generator `proxy-startup_*.sh` in any
  directory (`@reboot` and rotation lines alike; comments and every other line are kept
  byte for byte) and writes the crontab back only when something changed. Every removed
  line is logged. Only while `netrun-3proxy-restore.service` AND
  `netrun-ipv6-restore.service` are both enabled (`systemctl is-enabled`): without them
  the `@reboot` line is the only thing that brings a batch (and its IPv6 addresses) back
  after a reboot, so the lines are kept and one warning is logged
  (`NODE_AGENT_CRON_HYGIENE=force` removes them anyway). The post-`/generate` cleanup
  runs the same code, matched by script name (`proxy-startup_<startPort>.sh`, any
  directory); the job's `result.cronCleanup` now carries `outcome` and `removed`.
- **3proxy dedupe** — 60 s after agent start (the boot restore has finished by then) and
  on the same tick: groups the running 3proxy processes (argv[0] is `3proxy`, the
  argument is an absolute `3proxy_<sp>.cfg`) by the realpath of the cfg, so
  `/root/proxyserver/...` and `/opt/netrun/proxyserver/...` are one cfg. A cfg with more
  than one process keeps exactly one — the oldest whose cfg argument is under the agent's
  `NODE_AGENT_PROXY_ROOT` (`/opt/netrun/proxyserver`, the path the agent and the boot
  restore use), otherwise the oldest — and the others get SIGTERM, then SIGKILL if still
  alive 3 s later. Never the last process of a cfg; never a cfg none of whose probe ports
  listens (its start port and its first socks port — a boot that is still binding is
  left alone); nothing at all while a `/generate` holds the generation lock (the
  `/health` `busy` verdict). Right before signalling it re-checks the lock and takes a
  fresh `ps`: a pid that exited or now runs something else is not touched, and when the
  process to keep is gone nothing is killed that round.

Steady state: one `crontab -l` and one `ps` per tick; `ss` only when a cfg runs twice.
The agent restart that deploys this sweeps the crontab at once. Where a reboot still
finds generator lines (boot units not enabled, or no agent restart yet), cron starts
them before the agent is up; the reaper then ends the duplicates a minute after start.

| Variable | Default | |
|---|---|---|
| `NODE_AGENT_DEDUPE_3PROXY` | on | `0` / `off` / `false` / `no` = never kill a duplicate |
| `NODE_AGENT_CRON_HYGIENE` | on | `0` / `off` = no sweep at start / on the tick; `force` = sweep even without both boot restore units |
| `NODE_AGENT_HYGIENE_INTERVAL_SEC` | 600 | period of both (minimum 60) |

`NODE_AGENT_CLEANUP_CRON_AFTER_RUN=0` still turns the post-`/generate` cleanup off.

`/health`, additive, next to `duplicateStatePresent`:

| Field | Meaning |
|---|---|
| `duplicatesReaped` | duplicate 3proxy processes terminated since the agent started |
| `lastReapAt` | when the last one was (`null` = never) |
| `hygiene` | `{dedupe3proxy, cronHygiene, intervalSec, duplicatesReaped, lastReapAt, lastDedupeAt, lastDedupeOutcome, cronLinesRemoved, lastCronAt, lastCronOutcome}`. `lastDedupeOutcome`: `ok`, `generation_in_progress`, `ps_failed`, `ss_failed`. `lastCronOutcome`: `unchanged`, `removed`, `no_crontab`, `generation_in_progress`, `boot_restore_units_not_enabled`, `crontab_unavailable`, `error`. `null` = not run yet |

Log lines (`journalctl -u netrun-node-agent | grep '\[hygiene\]'`):

```
[hygiene] dedupe_3proxy=on cron_hygiene=on interval=600s first_dedupe_in=60s
[hygiene] cron: removed "@reboot /usr/bin/bash /root/proxyserver/proxy-startup_18100.sh"
[hygiene] cron: removed 11 generator proxy-startup line(s); netrun-3proxy-restore starts the batches at boot
[hygiene] cron: 11 generator proxy-startup line(s) kept: netrun-3proxy-restore.service / netrun-ipv6-restore.service not both enabled (they are then the only boot path); NODE_AGENT_CRON_HYGIENE=force removes them anyway
[hygiene] dedupe: /opt/netrun/proxyserver/3proxy/3proxy_18100.cfg (start port 18100) runs 2 times; keeping pid 2202 (/opt/netrun/proxyserver/3proxy/3proxy_18100.cfg, up 40s)
[hygiene] dedupe: SIGTERM pid 2101 (/root/proxyserver/3proxy/3proxy_18100.cfg, up 50s), duplicate of pid 2202
[hygiene] dedupe: SIGKILL pid 2101: still alive 3000 ms after SIGTERM
[hygiene] dedupe: reaped 9 duplicate 3proxy process(es); 9 since agent start
[hygiene] dedupe: /opt/netrun/proxyserver/3proxy/3proxy_18100.cfg runs 2 times but none of port(s) 18100,18105 listens; left alone
[hygiene] dedupe: /opt/netrun/proxyserver/3proxy/3proxy_18100.cfg: pid 2202 to keep is gone; left alone this round
[hygiene] dedupe: ps failed (<stderr>); nothing killed
[hygiene] dedupe: ss failed (<stderr>); nothing killed
```

By hand on a node:

```bash
crontab -l | grep -c 'proxy-startup_'           # 0 once the sweep ran
ps -eo pid,etimes,args | grep '[b]in/3proxy '   # one line per cfg
curl -s http://127.0.0.1:8085/health | jq '{duplicateStatePresent, duplicatesReaped, lastReapAt, hygiene}'
```

Tests: `cd node_runtime/node_agent && node --test hygiene.dedupe.test.js hygiene.cron.test.js server.hygiene.test.js`.

## Accounting robustness (Wave FLEET-HEALTH)

- The `nft -j list counters` dump runs with a 20 s timeout
  (`NODE_AGENT_NFT_DUMP_TIMEOUT_MS`; was execCapture's 5 s SIGKILL) and is parsed ONCE
  per poll cycle into `Map(port → counters)`; every `/accounting` chunk is served from it.
  The first chunk of a cycle waits for the whole dump before a byte is sent, so the
  orchestrator's per-request read budget (`TRAFFIC_POLL_REQUEST_TIMEOUT_SEC`, default 10)
  must be ABOVE `NODE_AGENT_NFT_DUMP_TIMEOUT_MS / 1000` plus parse time — set it to 30 on
  the orchestrator. With the default 10 s a dump of 10–20 s still fails the whole cycle
  (client read timeout → `accounting_request_failed`), and the abandoned dump is not
  reused by the next cycle (the 2 s gap rule starts a fresh one). Measure the real dump
  time on a node (`time nft -j list counters table inet proxy_accounting >/dev/null`, or
  the orchestrator repo's `scripts/bench_node.sh`) before relying on either number.
- Opt-in `NETRUN_ACCOUNTING_MATCH_IPV4=1` in `/etc/netrun/netrun.env` (`KEY=VALUE`
  lines, read by the generator and by `netrun-https`; an environment variable of the same
  name wins, for one-off runs — do not set it only in the agent unit, the 5-min sync
  would converge the rule back; default 0): the two counter map rules also match the
  public IPv4 —
  `iifname != "lo" ip daddr <v4> counter name tcp dport map @cmap_in` /
  `oifname != "lo" ip saddr <v4> counter name tcp sport map @cmap_out` — so an
  upstream leg whose ephemeral port equals a proxy port is never billed to that proxy
  (the overlap that `ip_local_port_range 10000 65000` caused). New nodes get it from the
  generator's first batch; existing nodes converge with `netrun-https accounting` (also
  run by every `netrun-https sync`): only the rule is replaced by handle — counters and
  map elements (the billing values) are untouched; setting it back to 0 converges back.
  In the dualstack egress mode an IPv4 upstream leg also leaves from the public IPv4, so
  there the ephemeral range below 8100 (`apply_capacity_tuning.sh --only sysctl`) remains
  the guard.

## Pay-per-GB endpoints (Wave B-8.1)

Three endpoints expose per-port nftables traffic accounting and 3proxy
instance lifecycle for pay-per-GB billing:

```bash
# Get cumulative byte counters for ports 32001 and 32002
curl "http://127.0.0.1:8085/accounting?ports=32001,32002" | jq .

# Disable (kill 3proxy instance) for port 32001
curl -X POST http://127.0.0.1:8085/accounts/32001/disable

# Re-enable (restart 3proxy instance) for port 32001
curl -X POST http://127.0.0.1:8085/accounts/32001/enable
```

All three endpoints honor `X-API-KEY` if `NODE_AGENT_API_KEY` is set,
and are idempotent:

- disabling an already-disabled port returns 200 `already_disabled`
- enabling an already-enabled port returns 200 `already_enabled`
- operations on unknown ports return 404 `port_not_found`
- disable answers 200 only when the nft drop (`pergb_blocked`, socks + paired http port)
  is in the kernel; a failed `nft add element` (non-zero exit / timeout, after one
  table/set re-ensure + retry) or an unconfirmed drop rule returns 500
  `{success:false, error:"disable_failed", detail:"nft_block_failed"}` so the
  orchestrator retries. The port is still written to `pergb_blocked.list` (re-applied on
  boot) and a single-port cfg is still torn down. Enable stays best-effort on the nft
  side (`delete element` of a never-blocked port fails harmlessly).
- `GET /accounting` on missing ports returns 200 with the port omitted
  from the response (defensive contract — orchestrator handles partial
  maps gracefully)

Counter naming convention (in nftables `proxy_accounting` table):

- `proxy_${port}_in`  — IPv4 inbound TCP to port
- `proxy_${port}_out` — IPv6 outbound from instance
- `proxy_${port}_in6` — IPv6 inbound to instance

`bytes_in` aggregates `proxy_${port}_in + proxy_${port}_in6`; `bytes_out`
is `proxy_${port}_out` (ipv6_only deployment, no IPv4 egress).

nftables counters MUST persist across reboot (see `/etc/nftables.conf`
or `systemctl enable nftables.service` with `nft list ruleset >
/etc/nftables.conf`); orchestrator polling worker handles counter-reset
detection but a persistent counter is the smoothest operation.

```bash
bash scripts/smoke_accounting.sh
```

Smoke validates `/describe` advertises accounting, plus the negative
paths (400 missing ports / 404 unknown port / 200 partial empty map).
Happy-path with a real reserved port is exercised end-to-end by the
orchestrator integration tests.

## IPv6 egress rotation (Wave IPV6-ROTATION)

Changes the IPv6 address a proxy's **new** connections leave from, per port, without
touching 3proxy or its cfgs (`node_runtime/node_agent/egress.js`). One 3proxy process
serves a whole batch of customers and every cfg change restarts it, so instead each
port keeps binding to the `-e` address of its `socks` line (the **anchor**; the paired
HTTP port shares it) and an nftables SNAT rewrites the source:

```text
table ip6 netrun_egress {
  set dyn_anchors   { type ipv6_addr; }                  # ports in per_connection mode
  map static_egress { type ipv6_addr : ipv6_addr; }      # anchor -> current address
  chain dyn  { snat to numgen random mod K map { 0 : <pool0>, ... } }
  chain post { type nat hook postrouting priority srcnat; policy accept;
               ip6 saddr @dyn_anchors goto dyn
               snat to ip6 saddr map @static_egress }
  chain forward_guard { type filter hook forward priority filter; policy accept;
               ip6 daddr <the node's /64> drop }         # forward guard, see below
  chain exit_guard { type filter hook input priority filter - 10; policy accept;
               ... }                                     # exit guard, see below
}
```

Only the first packet of a connection is NATed (conntrack carries the rest), so open
sessions keep their address and other ports are never affected; pay-per-GB metering
is keyed by the client-facing port and does not change. Every nft change is one
`nft -f` transaction (an element delta; a full `add table` + `delete table` +
definition rebuild if the kernel no longer matches), so the table is never half
applied. A new address is the node's /64 + 64 random bits, never one already on the
NIC, another proxy entry, an anchor or an address of the state. The agent creates the
(empty) table when it starts; with nothing rotated it changes no outgoing packet (the
exit guard below filters inbound ones from the start).

**Proxy NDP, not NIC addresses.** Rotated, pool and draining addresses are never put
on the interface. Measured on a production node (Vultr, Ubuntu 24.04, kernel 6.8,
~16k anchors on `enp1s0`): every `ip address add|del` costs the kernel O(n) there —
1000 `address add … nodad` in one `ip -6 -batch` took ~35 s of kernel time, 200
`address del` 4.4 s — so a 1000-port rotate went over the orchestrator's 30 s node
timeout and creating the 1024-address per-connection pool took 35.8 s. Instead each
address is a proxy neighbour entry, added **before** nft maps to it and deleted only by
the GC after its drain, in one `ip -6 -force -batch` per operation:

```text
neigh add proxy <a> dev <if>      # 1000 in one batch: 0.37 s on that node
neigh del proxy <a> dev <if>      # 1000: 0.19 s
```

The kernel then answers the router's neighbour solicitations for `<a>` with the
node's MAC, and a reply to a NATed connection is de-NATed back to the anchor by
conntrack in PREROUTING, before routing, so `<a>` never has to be a local address
(verified end to end on that node: a real 3proxy port egressed from `<a>`). This needs
on the egress interface (the agent sets them at start, writing only what differs, and
keeps them in `/etc/sysctl.d/99-netrun-egress.conf`; the GC tick puts them back if
they change):

| sysctl | value | why |
|---|---|---|
| `net.ipv6.conf.<if>.proxy_ndp` | 1 | answer the router's (multicast) solicitations for the proxy entries |
| `net.ipv6.conf.all.proxy_ndp` | 1 | the router's **unicast** reachability probes for an address are addressed to it, take the forwarding path, and `ip6_forward()` hands them to neighbour discovery only when the `all` value is on; without it every probe goes unanswered and the router drops and re-resolves the entry. Entries are per device, so nothing else is answered |
| `net.ipv6.neigh.<if>.proxy_delay` | 0 | answer at once (the default delays the answer by up to 0.8 s) |
| `net.ipv6.conf.all.forwarding`, `net.ipv6.conf.<if>.forwarding` | 1 | the kernel answers for proxy entries only on a forwarding interface, and `ip6_forward()` drops everything unless `all` forwards. The installers already set both; a `1` is never written over a `1` (any such write drops RA-learned default routes), and an interface that takes RAs (`accept_ra=1`, not forwarding yet) is switched to `accept_ra=2` first |

**Forward guard.** With forwarding on and no local address, an unsolicited packet to a
proxied address (a drained one, a scan; anything without a conntrack entry to de-NAT
it) would be forwarded back out the on-link /64 and ping-pong with the router. The
node forwards for nobody, so `chain forward_guard` drops every forwarded packet to the node's
/64 (the prefix the module detected or `NODE_EGRESS_PREFIX`). Neighbour solicitations
to a proxied address are handled before the forward hook and are not affected.
Rotated addresses therefore answer no ping and accept no inbound connection; the
kernel may still send a rate-limited (1/s per destination) ICMPv6 redirect for such a
packet before the hook drops it.

**Exit guard** (audit FP-01, `EGRESS_EXIT_GUARD`, on by default). Every anchor is a
local address of the node, so without a filter a port scan of a customer's exit IPv6 —
which anti-fraud services run against a visitor's IP — finds the node's sshd on `:22`
and the agent on `:8085` (anything listening on `[::]`), and every closed port answers
with a RST: an obvious server, not a home line. A home router silently drops what nobody asked for;
`chain exit_guard` does the same for every address of the node's /64 except the node's
own:

```text
chain exit_guard {
    type filter hook input priority filter - 10; policy accept;
    iif "lo" accept                          # local traffic, also to a local anchor
    ip6 daddr != <the node's /64> accept     # link-local, multicast, other prefixes
    ip6 daddr <primary> accept               # the node's own address (none known: no rule)
    ct state established,related accept      # replies to connections the node opened
    icmpv6 type echo-request drop            # no ping answers on exit addresses
    meta l4proto ipv6-icmp accept            # NDP, packet too big, errors
    drop                                     # SYN to any port, unsolicited UDP
}
```

- **What still works.** Every reply to a connection the node opened: proxied TCP, SOCKS
  UDP ASSOCIATE replies, unbound's recursion (it listens on `::1`/`127.0.0.1` only), the
  agent's own probes, and the replies to rotated/pool addresses (conntrack de-NATs them
  back to the anchor in PREROUTING, before this hook). Neighbour discovery: the router's
  multicast solicitations and router advertisements are not addressed to the /64, its
  unicast reachability probes (for anchors, and for proxy entries, which
  `ip6_forward()` hands to local input) are ICMPv6. DHCPv6 needs no rule either: a
  client talks from its link-local address and servers answer there (Vultr uses SLAAC
  anyway). Customers reach the proxies on the node's IPv4, which this IPv6 table never
  sees.
- **Primary address.** The node's own address(es) inside the /64 keep inbound access, so
  admin SSH over IPv6 keeps working: global addresses of the egress interface whose
  prefix length is not 128 and that are not flagged `nodad`, minus every cfg anchor and
  every address of the egress state. Not the prefix length alone: `netrun-ipv6-restore`
  re-adds every anchor as a /64 at boot; every anchor is added with `nodad` (the
  generator's /128s, the restore's /64s) while the host's SLAAC/netplan address never
  is, and an anchor without the flag (an older restore script) is still a cfg anchor.
  Recomputed at start and on every 30 s GC tick (one `ip -6 -o addr show dev <if> scope
  global`); a change is one full table rebuild. More than 8 candidates → none (logged):
  the /64 then carries something unexpected and the guard must not open it all. With
  none, every address of the /64 is filtered — IPv4 access is unaffected.
- **Priority `filter - 10`**: before `inet proxy_accounting`'s input chain (priority 0),
  whose per-port meter matches `tcp dport` only (IPv6 included, unless
  `NETRUN_ACCOUNTING_MATCH_IPV4=1`), so a scan of `[exit address]:<a customer's port>`
  is dropped before it is metered as that customer's traffic.
- **Behaviour change**: unsolicited inbound to an exit address is gone, as behind a home
  NAT — SOCKS `BIND` and P2P traffic that expects a peer other than the one contacted
  to reach the exit address no longer work over IPv6, and a proxied TCP connection idle
  longer than `nf_conntrack_tcp_timeout_established` (7200 s in `99-netrun.conf`) whose
  remote side speaks first after the idle is dropped (a rotated port already depends on
  that entry for its de-NAT).
- Element deltas (rotations, mode changes) never touch chains; every full rebuild
  (start, drift repair, primary change) writes the guard. `EGRESS_EXIT_GUARD=off`
  leaves the chain out at the next start. Between the boot load of
  `/etc/nftables.conf` (the boot drop-in deletes the whole table) and the agent's
  start-up rebuild there is no guard for a few seconds; while the module is unavailable
  (`/egress` answers 503) there is none either.

`scripts/smoke_egress_rotation.sh` checks it against the real kernel: with a listener on
`[::]:22`, `[anchor]:22` and a closed anchor port time out (no SYN-ACK, no RST), the
anchor answers no ping and unsolicited UDP to it is dropped, while the node's own address
accepts `:22` and answers ping and the anchor's upstream connections keep working.

**Upgrade from the version that added NIC addresses.** At start the agent re-adds the
proxy entry of every current, pool and draining address of its state in one batch,
then deletes from the NIC each of them that is still there (with the prefix length it
carries; never an anchor) — only once its proxy entry is in place, so no port loses its
address in between, open connections included. Anything that cannot be moved stays on
the NIC (it still works there) and the GC deletes both copies once it has drained.
`address del` is the slow operation above (~22 ms per address next to 16k anchors), so
this one-time move takes as long as the old version's addresses need — ~25 s for a
1024-address pool plus a hundred rotated ports.

All endpoints honour `X-API-KEY`; at most 1000 ports per call; a port is the SOCKS port.

```bash
# new random address for new connections (mode becomes static; the old one drains)
curl -X POST http://127.0.0.1:8085/egress/rotate -d '{"ports":[32001,32002],"drain_sec":600}'
# a random pool address for every new connection / back to the anchor
curl -X POST http://127.0.0.1:8085/egress/mode -d '{"ports":[32001],"mode":"per_connection"}'
curl -X POST http://127.0.0.1:8085/egress/mode -d '{"ports":[32001],"mode":"static"}'
# forget the port entirely (egress = anchor)
curl -X POST http://127.0.0.1:8085/egress/reset -d '{"ports":[32001]}'
# what the node holds (no ports = every port with state)
curl "http://127.0.0.1:8085/egress?ports=32001,32002"
```

Mutations answer 200 `{ok, items:[{port, ok, anchor, mode, old_ipv6, new_ipv6, error}]}`:
`mode` is `static` (a rotated address) / `per_connection` / `null` (the anchor — `mode
static` without a rotation leaves no entry, like `reset`) after the call, `new_ipv6` is the egress
of new connections (`null` = the anchor, `"pool"` = per connection), `old_ipv6` the same
before the call, `error` one of `port_not_found`, `anchor_not_found`,
`address_add_failed`, `address_budget_exceeded` (the node is at
`EGRESS_MAX_EXTRA_ADDRS`, see below), `nft_failed` (a failed port keeps its previous
state; `ok` is true only if every item is). `reset` is idempotent: a port without state
(or without a cfg) answers ok. `GET /egress` answers
`{items:[{port, anchor, current, mode}], pool:{size, refreshed_at, idle_since}, draining, prefix, iface}`
(`idle_since`: when the last `per_connection` port left the pool, else `null`).
400 `bad_request` on a malformed body or more than 1000 ports; 503
`egress_unavailable` (with `detail`) when the module is not up (no nft / no NAT, no
default IPv6 route, a bad `NODE_EGRESS_PREFIX`, `sysctl_failed: …` when the proxy-NDP
sysctls cannot be set) or the state file cannot be written.
`/deprovision` also drops the egress state of the ports it removes.

Environment (agent unit drop-in):

| Variable | Default | Meaning |
|---|---|---|
| `EGRESS_DRAIN_SEC` | 600 | how long a retired address keeps its proxy entry (default for `drain_sec`; always used for pool members) |
| `EGRESS_POOL_SIZE` | 1024 | node-wide per-connection pool, created when the first port enters `per_connection` |
| `EGRESS_POOL_REFRESH_SEC` | 600 | pool refresh period; also how long a pool nobody uses is kept idle before it drains |
| `EGRESS_POOL_REFRESH_FRACTION` | 0.25 | share of the pool (oldest first) replaced on each refresh |
| `EGRESS_MAX_EXTRA_ADDRS` | 40000 | most current + pool + draining addresses (proxy entries) the node holds (anchors not counted) |
| `NODE_EGRESS_PREFIX` | — | the /64 for new addresses (e.g. `2001:db8:1:2::/64`); default: the /64 of the first global address on the default-route IPv6 interface |
| `EGRESS_NFT_DROPIN` | `/etc/systemd/system/nftables.service.d/netrun-egress.conf` | the boot drop-in below; `off` = do not write it |
| `EGRESS_SYSCTL_CONF` | `/etc/sysctl.d/99-netrun-egress.conf` | where the proxy-NDP sysctls above are persisted (rewritten at start only when different); `off` = do not write it |
| `EGRESS_EXIT_GUARD` | `on` | the exit guard above (`chain exit_guard`); `off` = leave it out of the table (at the next start) |

Address count: every extra address is one more proxy entry (and one more
solicited-node multicast group — the kernel joins it so the router's solicitations
reach the node) on an interface that already carries up to ~18k anchors, so it is
bounded whatever callers do:
- **one draining address per port**: rotating a port again (timer, rotation link, bot)
  ends the drain of its previous-but-one address at once, so a port holds at most its
  anchor, its current address and one draining address (sessions older than the
  previous rotation of that port are cut);
- **the pool is reused**: when the last `per_connection` port leaves, the pool is kept
  idle for `EGRESS_POOL_REFRESH_SEC` (no refresh meanwhile) and only then drains, so
  switching modes back and forth reuses one pool instead of adding `EGRESS_POOL_SIZE`
  each time;
- **`EGRESS_MAX_EXTRA_ADDRS`**: a call that would go over it first ends the drains due
  soonest (the GC deletes them); ports that still do not fit fail with
  `address_budget_exceeded` (a pool gets what fits, at least one address, or the
  `per_connection` items fail the same way).

Addresses and reboots: the state lives in `$PROXY_ROOT/egress_state.json` (atomic
tmp+fsync+rename, written before a call answers). Retired addresses drain and a 30 s
GC deletes their proxy entries in one batch; an anchor, a current or a pool address is
never deleted. The same tick re-detects the exit guard's primary address (a change →
one rebuild), checks that the table still exists (`nft list chain ip6 netrun_egress
exit_guard`; with the guard off `... post`, only while something is mapped) and
rebuilds it from the state after an `nft flush ruleset` or a `systemctl restart
nftables`, and — while the state
holds an address — re-checks the sysctls and lists the proxy entries
(`ip -6 neigh show proxy dev <if>`), re-adding any that vanished (the kernel drops a
device's proxy entries when it goes down, and a re-created interface starts with
`proxy_ndp` off). The kernel forgets proxy entries and the table on reboot, and
`netrun-ipv6-restore` only knows the cfgs' `-e` anchors: the **agent** re-adds the
proxy entries of its state's current, pool and draining addresses in one `ip -batch`
and rebuilds the table when it starts, dropping ports whose cfg block or anchor is
gone (an address that cannot be re-added is forgotten: that port leaves from its anchor
until it is rotated again).

Boot: the generator, `/deprovision`, `netrun-harden`, `netrun-https` and the install
scripts save the whole ruleset (`nft list ruleset > /etc/nftables.conf`), this table
included. So that a reboot never maps ports to addresses that are not back yet, a
drop-in on `nftables.service` deletes the table right after the boot load:

```ini
# /etc/systemd/system/nftables.service.d/netrun-egress.conf
[Service]
ExecStartPost=-/usr/sbin/nft delete table ip6 netrun_egress
```

Rotated ports then leave from their anchors (and the exit guard is off) until the
agent's start-up rebuild (a few seconds; the proxy entries come back in the same
start-up). `install_node_v2.sh` and `node_followup_v2.sh` install it, and the agent
writes it at start when it is missing or different (then a best-effort
`systemctl daemon-reload`), so a code deploy covers existing nodes.

Rollback to an agent without rotation (it never touches the table or the proxy
entries). Delete the proxy entries with the table: without its forward guard a proxied
address would be forwarded back out to the router. Only the egress module adds proxy
entries on a node.

```bash
IF="$(ip -6 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
ip -6 neigh show proxy dev "$IF" | awk -v d="$IF" 'NF { print "neigh del proxy " $1 " dev " d }' | ip -6 -force -batch -
nft delete table ip6 netrun_egress          # every port leaves from its anchor again; the exit guard goes too
rm -f /opt/netrun/proxyserver/egress_state.json /etc/sysctl.d/99-netrun-egress.conf
nft list ruleset > /etc/nftables.conf       # the saved copy goes too
# the drop-in may stay (a missing table is ignored); proxy_ndp=1 with no entries is harmless
```

An agent of the version before proxy NDP finds the state's addresses missing from the
NIC at start and re-adds them there (`address add`), so deleting the state as above is
what keeps a rollback quick. `scripts/clean_node.sh` also deletes the proxy entries, the
table, `egress_state.json`, the drop-in and the sysctl file.

Limits: every address stays inside the node's one /64 (anti-fraud systems that score a
whole /64 still see one network), and with dual-stack (`-64`) proxies IPv4-only sites
still see the node's single IPv4. Each rotated port holds its anchor on the NIC plus a
proxy entry for its current address and at most one draining one. Before offering short
timers at scale, watch `ipv6=` and `load=` in `/var/log/netrun-trend.log` on a full
staging node.

```bash
sudo bash scripts/smoke_egress_rotation.sh
```

The smoke runs the module against the real kernel (iproute2, proxy NDP, nft NAT,
conntrack) entirely inside throw-away network namespaces — the veth pair is created
inside them, the module's state and sysctl file go to a temp dir, everything is removed
on exit — so it leaves the host's addresses, neighbour table, ruleset and sysctls alone.
It checks the sysctls and the forward guard, the exit guard (a TCP connect from the
"internet" namespace to `[anchor]:22` with a listener on `[::]:22`, or to a closed port,
times out with no RST, no ping reply, unsolicited UDP dropped, the node's own address
still reachable, `EGRESS_EXIT_GUARD=off` and back), that rotated and pool addresses are
proxy entries and never NIC addresses, open connections across a rotation and across the
move off the NIC (all with the exit guard on), the GC, that unsolicited packets to a
rotated address are dropped at the forward hook, that a unicast reachability probe for
one is answered, and that the saved ruleset (exit guard included) loads back at boot.

## Smoke Generate

```bash
bash scripts/smoke_generate.sh
```

This creates 10 socks5 proxies for job `smoke-30000` using:

```text
proxyCount=10
startPort=30000
proxyType=socks5
ipv6Policy=ipv6_only
networkProfile=high_compatibility
fingerprintProfileVersion=v2_android_ipv6_only_dns_custom
generatorScript=/opt/netrun/node_runtime/soft/generator/proxyyy_automated.sh
```

## Download proxies.list

From your local machine:

```bash
scp root@server:/opt/netrun/jobs/smoke-30000/proxies.list .
```

For a different job, replace `smoke-30000` with the job id.

## Expected Paths

```text
/opt/netrun
/opt/netrun/jobs
/opt/netrun/proxyserver
/opt/netrun/proxyserver/3proxy/bin/3proxy
/opt/netrun/proxyserver/.netrun_bootstrap.json
/etc/systemd/system/netrun-node-agent.service
```

The bundled 3proxy binary must exist at `deploy/node/bin/3proxy`. The installer fails fast with `missing_bundled_3proxy_binary` if it is missing.

## Fingerprint Contract

Audit CLN-04: the only enforced part of the `/generate` product profile is
`ipv6_policy` (it must match the node's egress mode; a mismatch fails closed with
`ipv6_only_required` / `product_profile_contract_mismatch`). The labels
(`fingerprint_profile_version`, `network_profile`, `intended_client_os_profile`,
`client_os_profile_enforcement`, `profile_selection_*`, `ipv6_rollout_stage`) are
accepted and IGNORED — a mismatch is logged once per process — because none of them
reaches the wire: the TCP stack is set ONLY by `install_node_v2.sh` through
`deploy/node/99-zz-netrun-tcp.conf` (see "Uniform TCP signature"), and the generator's
`--network-profile` / `--tcp-timestamps-mode` / `--dns-country` flags are accepted
no-ops. The proxy layer does not control Android browser fingerprinting. `android_mobile` is an intended client OS profile only. Production logs and job metadata must report:

```text
intended_client_os_profile=android_mobile
actual_client_profile=not_controlled_by_proxy
effective_client_os_profile=not_controlled_by_proxy
client_os_profile_enforcement=not_controlled_by_proxy
ipv6_policy=ipv6_only
effective_ipv6_policy=ipv6_only
```
