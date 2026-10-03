#!/usr/bin/env bash
# NETRUN — re-add the proxies' egress IPv6 addresses after boot
# (netrun-ipv6-restore.service, installed by install_node_v2.sh as
# /opt/netrun/scripts/netrun-ipv6-restore.sh).
#
# The kernel does not persist the thousands of addresses the generator adds;
# without them 3proxy binds a missing -e<ipv6> source and egress fails.
#
# Wave CAPACITY-18K: ONE `ip -batch` for every address instead of one `ip`
# fork per address (18k forks at boot on a full node), and `nodad` so no
# address is ever left tentative (unusable as a source) even where accept_dad
# is still on for the interface. `-force` keeps going past "File exists".
# Same address set and /64 prefix as the previous per-address loop.
set -u

PROXY_ROOT="${NETRUN_PROXY_ROOT:-/opt/netrun/proxyserver}"
IFACE="${NETRUN_IPV6_IFACE:-$(ip -6 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')}"
[ -z "$IFACE" ] && exit 0

batch="$(mktemp 2>/dev/null)" || exit 0
trap 'rm -f "$batch"' EXIT

grep -rhoE -- '-e2001:[0-9a-f:]+' "$PROXY_ROOT/" 2>/dev/null | sed 's/^-e//' | sort -u \
  | awk -v dev="$IFACE" 'NF { print "address add " $1 "/64 dev " dev " nodad" }' > "$batch"
count="$(wc -l < "$batch" | tr -d ' ')"

if [ "$count" -gt 0 ]; then
  ip -6 -force -batch "$batch" >/dev/null 2>&1 || true
fi
logger -t netrun-ipv6-restore "re-added $count proxy IPv6 on $IFACE (ip -batch, nodad)" 2>/dev/null || true
exit 0
