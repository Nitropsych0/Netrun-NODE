# NETRUN Node Runtime

Self-contained NETRUN proxy node runtime. This repo is only for the node-agent and proxy generator layer. It does not include orchestrator, Telegram bot, database, SKU, payment, inventory, or business logic.

## Fresh Node Install

```bash
git clone https://github.com/Tmwyw/node_runtime_new.git /opt/netrun
cd /opt/netrun
bash install_node_v2.sh
```

> `install_node_v2.sh` is the maintained installer (raised kernel pid/thread
> limits, DAD/MLD off, bounded 3proxy restore, MSS 1460, unbound resolver,
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

`proxyReady` / `proxyReadiness` probe each instance on the same first socks port.
The agent binds `NODE_AGENT_HOST` (default `0.0.0.0`; the unit template has always
set it, nothing read it, so it used to answer on `[::]` = every customer exit IPv6).
`NODE_AGENT_HOST=::` restores the old bind.

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
- `supports.{describe,enroll,accounting,egress_rotation}` (`egress_rotation` is true once the
  egress module below has its nft NAT table up)

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
reused the old addresses AND the old credentials.

Job directories: `/opt/netrun/jobs` keeps the newest `NODE_AGENT_JOBS_KEEP` (200; 0 =
off) plus the running generation's, any queued/running job updated within 30 min and
the newest ready job of every start port that still has a cfg (the "reuse a running
instance" path). Pruned after each generation and a minute after start.

## Accounting robustness (Wave FLEET-HEALTH)

- The `nft -j list counters` dump runs with a 20 s timeout
  (`NODE_AGENT_NFT_DUMP_TIMEOUT_MS`; was execCapture's 5 s SIGKILL) and is parsed ONCE
  per poll cycle into `Map(port → counters)`; every 100-port chunk is served from it.
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
}
```

Only the first packet of a connection is NATed (conntrack carries the rest), so open
sessions keep their address and other ports are never affected; pay-per-GB metering
is keyed by the client-facing port and does not change. Every nft change is one
`nft -f` transaction (an element delta; a full `add table` + `delete table` +
definition rebuild if the kernel no longer matches), so the table is never half
applied. A new address is the node's /64 + 64 random bits, added with
`ip -6 -force -batch` (`address add <a> dev <if> nodad`) **before** nft maps to it.
The agent creates the (empty) table when it starts; with nothing rotated it changes
no packet.

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
`mode` is `static` / `per_connection` / `null` after the call, `new_ipv6` is the egress
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
default IPv6 route, a bad `NODE_EGRESS_PREFIX`) or the state file cannot be written.
`/deprovision` also drops the egress state of the ports it removes.

Environment (agent unit drop-in):

| Variable | Default | Meaning |
|---|---|---|
| `EGRESS_DRAIN_SEC` | 600 | how long a retired address stays on the NIC (default for `drain_sec`; always used for pool members) |
| `EGRESS_POOL_SIZE` | 1024 | node-wide per-connection pool, created when the first port enters `per_connection` |
| `EGRESS_POOL_REFRESH_SEC` | 600 | pool refresh period; also how long a pool nobody uses is kept idle before it drains |
| `EGRESS_POOL_REFRESH_FRACTION` | 0.25 | share of the pool (oldest first) replaced on each refresh |
| `EGRESS_MAX_EXTRA_ADDRS` | 40000 | most current + pool + draining addresses the node holds (anchors not counted) |
| `NODE_EGRESS_PREFIX` | — | the /64 for new addresses (e.g. `2001:db8:1:2::/64`); default: the /64 of the first global address on the default-route IPv6 interface |
| `EGRESS_NFT_DROPIN` | `/etc/systemd/system/nftables.service.d/netrun-egress.conf` | the boot drop-in below; `off` = do not write it |

Address count: every extra address is one more /128 (and MLD group) on a NIC that
already carries up to ~18k anchors, so it is bounded whatever callers do:
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
GC deletes them with the prefix length they actually carry (`/128`, or `/64` after the
boot restore); an anchor, a current or a pool address is never deleted. The same tick
checks that the table still exists (`nft list chain ip6 netrun_egress post`, only while
something is mapped) and rebuilds it from the state after an `nft flush ruleset` or a
`systemctl restart nftables`. The kernel forgets the added addresses and the table on
reboot, and `netrun-ipv6-restore` only knows the cfgs' `-e` anchors: the **agent**
re-adds the current and pool addresses of its state in one `ip -batch` and rebuilds the
table when it starts, dropping ports whose cfg block or anchor is gone (an address that
cannot be re-added is forgotten: that port leaves from its anchor until it is rotated
again). Draining addresses are not re-added (no session survives a reboot; after a plain
agent restart they are still on the NIC and the GC deletes them).

Boot: the generator, `/deprovision`, `netrun-harden`, `netrun-https` and the install
scripts save the whole ruleset (`nft list ruleset > /etc/nftables.conf`), this table
included. So that a reboot never maps ports to addresses that are not back yet, a
drop-in on `nftables.service` deletes the table right after the boot load:

```ini
# /etc/systemd/system/nftables.service.d/netrun-egress.conf
[Service]
ExecStartPost=-/usr/sbin/nft delete table ip6 netrun_egress
```

Rotated ports then leave from their anchors until the agent's start-up rebuild (a few
seconds). `install_node_v2.sh` and `node_followup_v2.sh` install it, and the agent
writes it at start when it is missing or different (then a best-effort
`systemctl daemon-reload`), so a code deploy covers existing nodes.

Rollback to an agent without rotation (it never touches the table or the addresses):

```bash
nft delete table ip6 netrun_egress          # every port leaves from its anchor again
rm -f /opt/netrun/proxyserver/egress_state.json
nft list ruleset > /etc/nftables.conf       # the saved copy goes too
# the drop-in may stay (a missing table is ignored); the added /128s go at the next reboot
```

`scripts/clean_node.sh` also deletes the table, `egress_state.json` and the drop-in.

Limits: every address stays inside the node's one /64 (anti-fraud systems that score a
whole /64 still see one network), and with dual-stack (`-64`) proxies IPv4-only sites
still see the node's single IPv4. Each rotated port holds two addresses on the NIC
(anchor + current) plus at most one draining. Before offering short timers at scale,
watch `ipv6=` and `load=` in `/var/log/netrun-trend.log` on a full staging node.

```bash
sudo bash scripts/smoke_egress_rotation.sh   # throw-away Linux box only: netns, real nft;
                                             # also proves the saved ruleset loads back at boot
```

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

The proxy layer does not control Android browser fingerprinting. `android_mobile` is an intended client OS profile only. Production logs and job metadata must report:

```text
intended_client_os_profile=android_mobile
actual_client_profile=not_controlled_by_proxy
effective_client_os_profile=not_controlled_by_proxy
client_os_profile_enforcement=not_controlled_by_proxy
ipv6_policy=ipv6_only
effective_ipv6_policy=ipv6_only
```
