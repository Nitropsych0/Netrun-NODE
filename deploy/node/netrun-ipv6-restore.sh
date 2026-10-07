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
#
# Audit FP-01 / RES-11: each anchor is added as /128 (as the generator and the
# agent's supervisor add it — was /64 here) with `preferred_lft 0`: a
# DEPRECATED address is never picked by the kernel's source address selection
# (RFC 6724 rule 3), so the node's own traffic (unbound recursion, apt, the
# agent's checks) leaves from the node's primary IPv6 instead of a customer's
# exit address, while 3proxy's explicit `-e<anchor>` bind keeps working.
# NETRUN_ANCHOR_DEPRECATE=0 adds them preferred, as before.
# No interface found = a loud failure (exit 1, the unit shows failed): the
# agent's supervisor re-adds missing anchors every minute, but an operator
# should see that the boot path did not.
set -u

PROXY_ROOT="${NETRUN_PROXY_ROOT:-/opt/netrun/proxyserver}"
IFACE="${NETRUN_IPV6_IFACE:-$(ip -6 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')}"
if [ -z "$IFACE" ]; then
  msg="no IPv6 default route / interface (set NETRUN_IPV6_IFACE) — proxy anchors NOT re-added; the agent's supervisor retries every minute"
  logger -p user.err -t netrun-ipv6-restore "$msg" 2>/dev/null || true
  echo "netrun-ipv6-restore: ERROR: $msg" >&2
  exit 1
fi

# The switch: the environment, else /etc/netrun/netrun.env (the file the agent
# and the generator read too), else on.
DEPRECATE="${NETRUN_ANCHOR_DEPRECATE:-}"
ENV_FILE="${NETRUN_ENV_FILE:-/etc/netrun/netrun.env}"
if [ -z "$DEPRECATE" ] && [ -r "$ENV_FILE" ]; then
  DEPRECATE="$(awk -F= '{ sub(/^[ \t]+/, "", $1) } $1 == "NETRUN_ANCHOR_DEPRECATE" { v = $2 } END { gsub(/["\047 \t\r]/, "", v); print v }' "$ENV_FILE")"
fi
LFT=""
case "$(printf '%s' "${DEPRECATE:-1}" | tr '[:upper:]' '[:lower:]')" in 0|off|false|no) ;; *) LFT=" preferred_lft 0" ;; esac

batch="$(mktemp 2>/dev/null)" || exit 1
trap 'rm -f "$batch"' EXIT

grep -rhoE -- '-e2001:[0-9a-f:]+' "$PROXY_ROOT/" 2>/dev/null | sed 's/^-e//' | sort -u \
  | awk -v dev="$IFACE" -v lft="$LFT" 'NF { print "address add " $1 "/128 dev " dev " nodad" lft }' > "$batch"
count="$(wc -l < "$batch" | tr -d ' ')"

if [ "$count" -gt 0 ]; then
  ip -6 -force -batch "$batch" >/dev/null 2>&1 || true
fi
logger -t netrun-ipv6-restore "re-added $count proxy IPv6 on $IFACE (ip -batch, /128, nodad${LFT:+, deprecated})" 2>/dev/null || true
exit 0
