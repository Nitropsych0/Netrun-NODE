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
`bash node_runtime/soft/generator/test_capacity_18k.sh`, `cd node_runtime/node_agent && node --test`.

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
  chain forward_guard { type filter hook forward priority filter; policy accept;
               ip6 daddr <the node's /64> drop }         # forward guard, see below
}
```

Only the first packet of a connection is NATed (conntrack carries the rest), so open
sessions keep their address and other ports are never affected; pay-per-GB metering
is keyed by the client-facing port and does not change. Every nft change is one
`nft -f` transaction (an element delta; a full `add table` + `delete table` +
definition rebuild if the kernel no longer matches), so the table is never half
applied. A new address is the node's /64 + 64 random bits, never one already on the
NIC, another proxy entry, an anchor or an address of the state. The agent creates the
(empty) table when it starts; with nothing rotated it changes no packet.

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
Unlike anchors, rotated addresses therefore answer no ping and accept no inbound
connection; the kernel may still send a rate-limited (1/s per destination) ICMPv6
redirect for such a packet before the hook drops it.

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
never deleted. The same tick checks that the table still exists (`nft list chain ip6
netrun_egress post`, only while something is mapped) and rebuilds it from the state
after an `nft flush ruleset` or a `systemctl restart nftables`, and — while the state
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

Rotated ports then leave from their anchors until the agent's start-up rebuild (a few
seconds; the proxy entries come back in the same start-up). `install_node_v2.sh` and `node_followup_v2.sh` install it, and the agent
writes it at start when it is missing or different (then a best-effort
`systemctl daemon-reload`), so a code deploy covers existing nodes.

Rollback to an agent without rotation (it never touches the table or the proxy
entries). Delete the proxy entries with the table: without its forward guard a proxied
address would be forwarded back out to the router. Only the egress module adds proxy
entries on a node.

```bash
IF="$(ip -6 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
ip -6 neigh show proxy dev "$IF" | awk -v d="$IF" 'NF { print "neigh del proxy " $1 " dev " d }' | ip -6 -force -batch -
nft delete table ip6 netrun_egress          # every port leaves from its anchor again
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
It checks the sysctls and the forward guard, that rotated and pool addresses are proxy
entries and never NIC addresses, open connections across a rotation and across the
move off the NIC, the GC, that unsolicited packets to a rotated address are dropped at
the forward hook, that a unicast reachability probe for one is answered, and that the
saved ruleset loads back at boot.

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
