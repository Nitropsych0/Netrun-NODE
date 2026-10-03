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
- `supports.{describe,enroll,accounting}`

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
