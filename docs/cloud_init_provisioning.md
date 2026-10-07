# NETRUN node cloud-init provisioning (variant B)

Self-provisioning for NETRUN proxy nodes. The operator creates a **fresh, clean
Vultr server** and pastes the generated cloud-init as **user_data**. On first
boot the node installs itself and registers with the orchestrator — **no SSH,
no manual install**. This replaces the old manual runbooks
(`C:\__NETRUN__\УСТАНОВКА….txt` + `ПОСЛЕ УСТАНОВКИ….txt`).

> **Variant B** = the operator creates the Vultr instance by hand; the
> orchestrator does **not** call the Vultr API. The cloud-init payload and the
> `/v1/nodes/register` contract are identical for any variant — only "who
> creates the VM" differs.

## Files

| File | Role |
|------|------|
| `deploy/node/cloud-init.sh` | The provisioning script. **Single source of truth.** Pasted directly as user_data (Vultr runs `#!`-scripts), or embedded into the YAML wrapper. |
| `deploy/node/cloud-init.yaml` | Optional `#cloud-config` wrapper that base64-embeds the `.sh` (for UIs that want a cloud-config document). No script duplication. |

The script does **not** reimplement install logic. It only invokes the baked v2
scripts already in this repo:

- `install_node_v2.sh --clean --remove-legacy-root` — unbound recursive
  resolver, pinned TCP signature (deploy/node/99-zz-netrun-tcp.conf; no MSS clamp), raised
  sysctl/pid/FD limits, `netrun-node-agent` + `netrun-3proxy-restore` units,
  `/health` gate on `:8085`.
- `scripts/node_followup_v2.sh` — `netrun-watchdog` (v3, two-tier:
  restart→reboot) + the bounded-parallel restore unit.

## How user_data is generated

The cloud-init script ships with **greppable placeholders** that the generator
(in variant B: the bot) substitutes **before** handing the payload to Vultr:

| Placeholder | Meaning |
|-------------|---------|
| `__ORCH_URL__` | Orchestrator base URL, e.g. `https://orch.netrun.live` (trailing slash optional — stripped). |
| `__SECRET__` | **One-time, per-job** secret. The server stores only `sha256(secret)`. |
| `__JOB_ID__` | Optional; for log correlation only. Safe to leave unsubstituted. |

Direct (`.sh`) form — substitute and paste:

```bash
sed -e "s|__ORCH_URL__|https://orch.netrun.live|" \
    -e "s|__SECRET__|$JOB_SECRET|" \
    -e "s|__JOB_ID__|$JOB_ID|" \
    deploy/node/cloud-init.sh > user_data.sh
# paste user_data.sh into Vultr "Startup Script / user_data"
```

YAML (`#cloud-config`) form — substitute, then base64-embed:

```bash
sed -e ... deploy/node/cloud-init.sh | base64 -w0 > /tmp/ci.b64
sed "s|__CLOUD_INIT_B64__|$(cat /tmp/ci.b64)|" deploy/node/cloud-init.yaml > user_data.yaml
```

## What happens on first boot

1. `apt-get install -y git curl ca-certificates jq`.
2. `git clone https://github.com/Tmwyw/node_runtime_new.git` → `/root/node_runtime_new`.
3. `bash install_node_v2.sh --clean --remove-legacy-root` (exit code captured).
4. `bash scripts/node_followup_v2.sh` (only if step 3 succeeded; exit code captured).
5. `install_result.ok = (both exit 0)`; `log_tail = tail -n 30` of the log.
6. `SELF_IP` from `ifconfig.me`, falling back to Vultr metadata
   `http://169.254.169.254/v1/interfaces/0/ipv4/address`.
7. `POST __ORCH_URL__/v1/nodes/register` (retry 3× with exponential backoff on
   network failure / 5xx).

All output (including `set -x` trace) is tee'd to **`/var/log/netrun-provision.log`**.

### Resilience

- If the installer or follow-up **fails**, the callback is still sent with
  `install_result.ok = false` + `log_tail`, so the orchestrator records a
  **partial-failure** instead of leaving the provision stuck in `installing`.
- The node is provisioned regardless of whether the callback succeeded; the
  script always `exit 0`s (cloud-init has no consumer of the exit code in
  variant B). The orchestrator can also reconcile later via the node agent's
  own `/health`.

## The `/v1/nodes/register` contract

The **single** integration point between a node and the orchestrator.

- **`POST {ORCH_URL}/v1/nodes/register`**, `Content-Type: application/json`.
- **No `X-NETRUN-API-KEY`** — the node is not yet registered and holds no API key.
- **Auth:** the server computes `sha256(body.secret)` and compares it to
  `node_provisions.shared_secret_hash` for the pending job. Match → register /
  update the node. Mismatch → `401`/`403`.

Request body:

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | Node public IPv4. |
| `secret` | string | One-time per-job secret; server compares `sha256`. |
| `install_result.ok` | bool | `true` ⇔ installer **and** follow-up exited 0. |
| `install_result.exit_code` | int | First failing step's code (installer first); 0 on success. |
| `install_result.log_tail` | string | Last ~30 lines of `/var/log/netrun-provision.log`. |
| `hostname` | string | `$(hostname)`. |
| `agent_version` | string | `git rev-parse --short HEAD` of the cloned repo. |

```json
{
  "ip": "203.0.113.45",
  "secret": "b3f1c9e2a7d04f88b1e6c5a2f9d8e7c6",
  "install_result": { "ok": true, "exit_code": 0, "log_tail": "...Install v2 complete..." },
  "hostname": "netrun-tokyo-01",
  "agent_version": "55bd5e1"
}
```

> Implemented by **Промпт ②** in the orchestrator, exactly per this contract.

## Security model of the secret

- The secret travels in **Vultr user_data / metadata** — acceptable: it is
  **one-time and per-job**, the server keeps only `sha256(secret)`, and it
  grants nothing beyond a single `register` call.
- cloud-init runs the secret-bearing register section under **`set +x`**, so the
  secret is **never xtrace'd into `/var/log/netrun-provision.log`** — and
  therefore can never leak into a later `log_tail` sent back to the orchestrator.
- The `log_tail` is captured **before** the register section is built, as a
  second guard.
- After provisioning, the operator may scrub user_data from the Vultr instance
  metadata if desired; the secret is single-use server-side regardless.

## Caveats

- **Clone target / branch.** cloud-init clones `node_runtime_new.git` **default
  branch (`main`)**. The v2 scripts are confirmed present on `new/main`
  (`55bd5e1`). If they move to a wave branch, either merge to `main` first or
  add `--branch <name>` to the `git clone`.
- **`install_node_v2.sh` can exit non-zero** — its final `verify_health` gate
  `die`s if `:8085/health` isn't `ready` within ~30s. That is the intended
  partial-failure signal and is reported via `install_result.ok=false`.
- **Watchdog reboots.** Despite the "non-rebooting" note in the installer
  header, `node_followup_v2.sh` installs **watchdog v3**: tier-1 restarts
  `netrun-node-agent` after 5 consecutive `/health` fails, tier-2 **reboots**
  after 20 (~20 min) to clear a Vultr abuse-network-block. Expected behaviour.
- **3proxy ignores `nserver`.** This 3proxy build resolves via
  `/etc/resolv.conf`, not the cfg `nserver` lines; DNS egress is held by the
  unbound resolver that `install_node_v2.sh` configures.
