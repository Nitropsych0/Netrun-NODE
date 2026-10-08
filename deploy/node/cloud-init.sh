#!/usr/bin/env bash
# deploy/node/cloud-init.sh — NETRUN node self-provisioning (variant B).
#
# Pasted verbatim as the Vultr "user_data" of a fresh Ubuntu server. On first
# boot cloud-init runs this as root: it clones node_runtime_new, runs the baked
# v2 installer + follow-up, then calls home to the orchestrator's /register
# endpoint with the install result. NO SSH, NO manual steps. Replaces the old
# C:\__NETRUN__\УСТАНОВКА….txt + ПОСЛЕ УСТАНОВКИ….txt manuals.
#
# This script does NOT reimplement install logic — it only invokes:
#   - install_node_v2.sh --clean --remove-legacy-root  (unbound / pinned TCP
#     signature / sysctl pid limits / node-agent + 3proxy-restore units / health)
#   - scripts/node_followup_v2.sh                        (watchdog v3 + restore)
#
# ── PLACEHOLDERS ──────────────────────────────────────────────────────────────
# Substituted by the generator (in variant B: the bot) BEFORE handing to Vultr.
# Markers are explicit + greppable: __ORCH_URL__  __SECRET__  __JOB_ID__
#   __ORCH_URL__  e.g. https://orch.netrun.live        (no trailing slash needed)
#   __SECRET__    one-time per-job secret; server stores only sha256(secret)
#   __JOB_ID__    optional, for log correlation (safe to leave as-is if unused)
# ──────────────────────────────────────────────────────────────────────────────

set -euxo pipefail

# All output (stdout + stderr, incl. `set -x` xtrace) → provision log AND console.
PROVISION_LOG="/var/log/netrun-provision.log"
exec > >(tee -a "$PROVISION_LOG") 2>&1

# ── substituted placeholders ──────────────────────────────────────────────────
ORCH_URL="__ORCH_URL__"
JOB_ID="__JOB_ID__"

# ── constants ─────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/Tmwyw/node_runtime_new.git"
REPO_DIR="/root/node_runtime_new"
REGISTER_PATH="/v1/nodes/register"
CALLBACK_RETRIES=3
CALLBACK_TIMEOUT=20

log() { printf '[netrun-provision] %s\n' "$*"; }

log "=== NETRUN node provision start (job=${JOB_ID}) ==="

# ── 1) base deps ──────────────────────────────────────────────────────────────
# jq is added on top of the prompt's git/curl/ca-certificates: the failure-path
# callback must JSON-encode log_tail safely even when the installer dies BEFORE
# it gets to install jq itself.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git curl ca-certificates jq

# ── 2) clone the runtime ──────────────────────────────────────────────────────
cd /root
rm -rf "$REPO_DIR"
git clone "$REPO_URL" "$REPO_DIR"
cd "$REPO_DIR"
AGENT_VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "cloned $REPO_URL @ ${AGENT_VERSION}"

# ── 3 + 4) install + follow-up ────────────────────────────────────────────────
# Capture exit codes WITHOUT letting `set -e` abort — the callback (step 7) must
# run even on failure so the orchestrator catches a partial-failure instead of
# leaving the provision stuck in "installing".
INSTALL_RC=0
FOLLOWUP_RC=0
set +e
bash install_node_v2.sh --clean --remove-legacy-root
INSTALL_RC=$?
log "install_node_v2.sh exit=${INSTALL_RC}"

if [ "$INSTALL_RC" -eq 0 ]; then
  bash scripts/node_followup_v2.sh
  FOLLOWUP_RC=$?
  log "node_followup_v2.sh exit=${FOLLOWUP_RC}"
else
  FOLLOWUP_RC=1
  log "skipping node_followup_v2.sh — installer failed (exit=${INSTALL_RC})"
fi
set -e

# ── 5) install result ─────────────────────────────────────────────────────────
if [ "$INSTALL_RC" -eq 0 ] && [ "$FOLLOWUP_RC" -eq 0 ]; then
  INSTALL_OK="true"
  EXIT_CODE=0
else
  INSTALL_OK="false"
  # Report the first failing step's code (installer takes precedence).
  if [ "$INSTALL_RC" -ne 0 ]; then EXIT_CODE="$INSTALL_RC"; else EXIT_CODE="$FOLLOWUP_RC"; fi
fi
log "install_ok=${INSTALL_OK} exit_code=${EXIT_CODE}"

# Grab the log tail BEFORE the (untraced) register section so the secret can
# never appear in log_tail.
LOG_TAIL="$(tail -n 30 "$PROVISION_LOG" 2>/dev/null || true)"

# ── 6) self IP ────────────────────────────────────────────────────────────────
SELF_IP="$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null || true)"
if [ -z "$SELF_IP" ]; then
  log "ifconfig.me failed — falling back to Vultr metadata"
  SELF_IP="$(curl -s --max-time 10 http://169.254.169.254/v1/interfaces/0/ipv4/address 2>/dev/null || true)"
fi
log "self_ip=${SELF_IP:-<unknown>}"

# ── 7) callback to orchestrator ───────────────────────────────────────────────
# `set +x` for the whole register section: the secret must NOT be xtrace'd into
# /var/log/netrun-provision.log (and thus never leaks into a later log_tail).
set +x
SECRET="__SECRET__"
REGISTER_URL="${ORCH_URL%/}${REGISTER_PATH}"
# Audit 2026-10-08 — the node-agent key install_node_v2.sh generated (the agent
# fails closed without it); the orchestrator stores it as nodes.api_key.
AGENT_API_KEY="$(sed -n 's/^Environment=NODE_AGENT_API_KEY=//p' /etc/systemd/system/netrun-node-agent.service.d/20-api-key.conf 2>/dev/null | tail -n1)"

PAYLOAD="$(jq -n \
  --arg ip "$SELF_IP" \
  --arg secret "$SECRET" \
  --argjson ok "$INSTALL_OK" \
  --argjson exit_code "$EXIT_CODE" \
  --arg log_tail "$LOG_TAIL" \
  --arg hostname "$(hostname)" \
  --arg agent_version "$AGENT_VERSION" \
  --arg agent_api_key "$AGENT_API_KEY" \
  '{
     ip: $ip,
     secret: $secret,
     install_result: { ok: $ok, exit_code: $exit_code, log_tail: $log_tail },
     hostname: $hostname,
     agent_version: $agent_version,
     agent_api_key: $agent_api_key
   }')"
unset SECRET AGENT_API_KEY

log "POST ${REGISTER_URL} (retry up to ${CALLBACK_RETRIES}× on network/5xx)"
attempt=0
delay=5
registered="no"
while :; do
  attempt=$((attempt + 1))
  http_code="$(curl -sS -o /tmp/netrun-register-resp.txt -w '%{http_code}' \
      --max-time "$CALLBACK_TIMEOUT" \
      -X POST "$REGISTER_URL" \
      -H 'Content-Type: application/json' \
      -d "$PAYLOAD" 2>/dev/null || echo 000)"

  if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
    log "register OK (HTTP ${http_code}, attempt ${attempt})"
    registered="yes"
    break
  fi

  # Retry only on network failure (000) or server-side 5xx; a 4xx (e.g. bad
  # secret) won't recover by retrying — stop and let the log show it.
  if [ "$http_code" = "000" ] || [ "$http_code" -ge 500 ]; then
    if [ "$attempt" -ge "$CALLBACK_RETRIES" ]; then
      log "register gave up after ${attempt} attempts (last HTTP ${http_code})"
      break
    fi
    log "register attempt ${attempt} failed (HTTP ${http_code}) — retrying in ${delay}s"
    sleep "$delay"
    delay=$((delay * 2))
    continue
  fi

  log "register rejected (HTTP ${http_code}) — not retryable; body: $(cat /tmp/netrun-register-resp.txt 2>/dev/null)"
  break
done
unset PAYLOAD
set -x

log "=== NETRUN node provision done (install_ok=${INSTALL_OK}, registered=${registered}) ==="

# Always exit 0: the node is provisioned regardless, and the real status is
# carried in the register callback's install_result. Cloud-init has no consumer
# of this exit code in variant B.
exit 0
