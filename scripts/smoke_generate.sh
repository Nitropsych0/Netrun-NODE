#!/usr/bin/env bash
set -euo pipefail

HOST="${NODE_AGENT_HOST:-127.0.0.1}"
PORT="${NODE_AGENT_PORT:-8085}"
URL="http://${HOST}:${PORT}/generate"
JOB_ID="smoke-30000"
JOB_DIR="/opt/netrun/jobs/${JOB_ID}"
PROXIES_LIST="${JOB_DIR}/proxies.list"
STDOUT_LOG="${JOB_DIR}/stdout.log"
STDERR_LOG="${JOB_DIR}/stderr.log"

payload="$(mktemp)"
cat > "$payload" <<'JSON'
{
  "jobId": "smoke-30000",
  "proxyCount": 10,
  "startPort": 30000,
  "proxyType": "socks5",
  "random": true,
  "ipv6Policy": "ipv6_only",
  "networkProfile": "high_compatibility",
  "fingerprintProfileVersion": "v2_android_ipv6_only_dns_custom",
  "intendedClientOsProfile": "android_mobile",
  "clientOsProfileEnforcement": "not_controlled_by_proxy",
  "actualClientProfile": "not_controlled_by_proxy",
  "generatorScript": "/opt/netrun/node_runtime/soft/generator/proxyyy_automated.sh",
  "timeoutSec": 900
}
JSON

# Audit 2026-10-08 — the agent needs its key (env, else the unit drop-in).
KEY="${NODE_AGENT_API_KEY:-$(sed -n 's/^Environment=NODE_AGENT_API_KEY=//p' /etc/systemd/system/netrun-node-agent.service.d/20-api-key.conf 2>/dev/null | tail -n1)}"
response="$(curl -fsS -X POST "$URL" -H "X-API-KEY: $KEY" -H 'Content-Type: application/json' --data-binary @"$payload")"
rm -f "$payload"

printf '%s\n' "$response" | jq -e '.success == true and .status == "ready"' >/dev/null
printf '%s\n' "$response" | jq -e '
  .params.ipv6Policy == "ipv6_only"
  and .profile.fingerprint_profile_version == "v2_android_ipv6_only_dns_custom"
  and .profile.intended_client_os_profile == "android_mobile"
  and .profile.actual_client_profile == "not_controlled_by_proxy"
  and .profile.effective_client_os_profile == "not_controlled_by_proxy"
  and .profile.effective_ipv6_policy == "ipv6_only"
' >/dev/null

[ -f "$PROXIES_LIST" ] || {
  printf 'missing proxies.list: %s\n' "$PROXIES_LIST" >&2
  exit 1
}

first_line="$(awk 'NF { print; exit }' "$PROXIES_LIST")"
if ! [[ "$first_line" =~ ^[^:]+:[0-9]{1,5}:[^:]+:[^:]+$ ]]; then
  printf 'invalid first proxy line: %s\n' "$first_line" >&2
  exit 1
fi

if [ -f "$STDERR_LOG" ] && grep -Eq 'dual_stack' "$STDERR_LOG"; then
  printf 'unexpected dual-stack marker in stderr log: %s\n' "$STDERR_LOG" >&2
  exit 1
fi

if [ -f "$STDOUT_LOG" ]; then
  grep -q 'ipv6_only' "$STDOUT_LOG" || {
    printf 'missing ipv6_only runtime marker in stdout log: %s\n' "$STDOUT_LOG" >&2
    exit 1
  }
fi

printf 'generated: %s\n' "$PROXIES_LIST"
head -n 3 "$PROXIES_LIST"
