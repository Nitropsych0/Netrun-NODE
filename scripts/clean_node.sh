#!/usr/bin/env bash
set -euo pipefail

REMOVE_LEGACY_ROOT=0

log() {
  printf '[clean_node] %s\n' "$*"
}

die() {
  printf '[clean_node] ERROR: %s\n' "$*" >&2
  exit 1
}

for arg in "$@"; do
  case "$arg" in
    --remove-legacy-root)
      REMOVE_LEGACY_ROOT=1
      ;;
    -h|--help)
      printf 'Usage: bash scripts/clean_node.sh [--remove-legacy-root]\n'
      exit 0
      ;;
    *)
      die "unknown argument: $arg"
      ;;
  esac
done

if [ "${EUID}" -ne 0 ]; then
  die "must_run_as_root"
fi

log "Stopping systemd service"
systemctl stop netrun-node-agent 2>/dev/null || true
systemctl disable netrun-node-agent 2>/dev/null || true

log "Stopping node-agent and 3proxy processes"
pkill -f 'node_runtime/node_agent/server\.js' 2>/dev/null || true
pkill -f '3proxy' 2>/dev/null || true

# Wave IPV6-ROTATION — the agent's egress state (also under a kept legacy
# root), its nftables.service boot drop-in and its proxy-NDP sysctl file; the
# table goes with the other NETRUN tables below, together with the proxy
# entries of the rotated / pool addresses (without the table's forward guard
# a proxied address would be forwarded back out to the router). The running
# proxy_ndp / proxy_delay values are harmless with no entries.
log "Removing IPv6 egress rotation state, the nftables.service drop-in and the sysctl file"
rm -f /opt/netrun/proxyserver/egress_state.json /root/proxyserver/egress_state.json
rm -f /etc/systemd/system/nftables.service.d/netrun-egress.conf
rmdir /etc/systemd/system/nftables.service.d 2>/dev/null || true
rm -f /etc/sysctl.d/99-netrun-egress.conf

log "Removing /opt/netrun"
rm -rf /opt/netrun

if [ "$REMOVE_LEGACY_ROOT" -eq 1 ]; then
  log "Removing legacy /root/proxyserver"
  rm -rf /root/proxyserver
else
  log "Keeping legacy /root/proxyserver (pass --remove-legacy-root to remove)"
fi

log "Removing systemd service"
rm -f /etc/systemd/system/netrun-node-agent.service

log "Removing proxy startup cron lines"
if command -v crontab >/dev/null 2>&1; then
  tmp_cron="$(mktemp)"
  crontab -l 2>/dev/null \
    | grep -vE 'proxy-startup|proxy-server_[0-9]+\.cron|/opt/netrun/proxyserver|/root/proxyserver' \
    > "$tmp_cron" || true
  crontab "$tmp_cron" 2>/dev/null || true
  rm -f "$tmp_cron"
fi

# Only the agent's egress module adds proxy neighbour entries on a node; they go
# before its table (and the table's forward guard).
egress_if="$(ip -6 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }' || true)"
if [ -n "$egress_if" ]; then
  log "Deleting IPv6 egress proxy-NDP entries on $egress_if"
  { ip -6 neigh show proxy dev "$egress_if" 2>/dev/null || true; } \
    | awk -v dev="$egress_if" 'NF { print "neigh del proxy " $1 " dev " dev }' \
    | ip -6 -force -batch - >/dev/null 2>&1 || true
fi

log "Deleting NETRUN nftables tables"
if command -v nft >/dev/null 2>&1; then
  nft delete table inet proxy_normalization 2>/dev/null || true
  nft delete table inet proxy_accounting 2>/dev/null || true
  nft delete table ip6 netrun_egress 2>/dev/null || true
  nft list ruleset > /etc/nftables.conf 2>/dev/null || true
fi

systemctl daemon-reload 2>/dev/null || true

log "Remaining suspicious processes"
ps -ef | grep -E 'node_runtime/node_agent/server\.js|[3]proxy' || true

log "Remaining suspicious ports"
if command -v ss >/dev/null 2>&1; then
  ss -ltnp | grep -E ':8085|:30000|3proxy|node' || true
fi

log "Cleanup complete"
