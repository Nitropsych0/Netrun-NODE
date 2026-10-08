#!/usr/bin/env bash
set -euo pipefail

HOST="${NODE_AGENT_HOST:-127.0.0.1}"
PORT="${NODE_AGENT_PORT:-8085}"
URL="http://${HOST}:${PORT}/health"
# Audit 2026-10-08 — the agent needs its key (env, else the unit drop-in).
KEY="${NODE_AGENT_API_KEY:-$(sed -n 's/^Environment=NODE_AGENT_API_KEY=//p' /etc/systemd/system/netrun-node-agent.service.d/20-api-key.conf 2>/dev/null | tail -n1)}"

response="$(curl -fsS -H "X-API-KEY: $KEY" "$URL")"
printf '%s\n' "$response" | jq -e '.success == true and .status == "ready"' >/dev/null

printf 'health: ready\n'
printf 'ipv6_egress: '
printf '%s\n' "$response" | jq -c '.ipv6Egress // .ipv6 // {}'
