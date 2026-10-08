#!/usr/bin/env bash
# netrun-proxy-guard — 3proxy (uid 65535) may not open connections to the node
# itself, to private / link-local / multicast / cloud-metadata addresses, or to
# the node's own addresses and prefixes (audit 2026-10-08: through a proxy a
# customer reached the agent on 127.0.0.1:8085, BIRD, the metadata service
# 169.254.169.254 and every service bound to the node's addresses). Codifies
# the table applied by hand on Chicago and Johannesburg that day:
#
#   table inet netrun_proxy_guard {
#     chain output {
#       type filter hook output priority filter; policy accept;
#       meta skuid 65535 jump proxy           only 3proxy's own sockets
#     }
#     chain proxy {
#       ip daddr 127.0.0.1 udp|tcp dport 53 accept, the same for ::1
#                                             the local unbound (cfg nserver)
#       ct state established,related accept  replies (haproxy -> 3proxy on lo)
#       ip daddr { <fixed IPv4 nets>, <the node's IPv4s> } reject
#       ip6 daddr { ::1, fe80::/10, fc00::/7, ff00::/8, <NIC /64s>, <routed> } reject
#     }
#   }
#
# NOT `meta skuid != 65535 accept` + rejects, as first applied by hand: a
# packet without a user socket (the kernel's own Neighbor Solicitations, MLD,
# ICMPv6 errors, time-wait ACKs) makes `meta skuid` BREAK, so it skipped that
# accept and hit the rejects (ff00::/8, fe80::/10): after the 2026-10-08 22:5x
# reboots neither node could resolve its IPv6 router (neighbour FAILED) — all
# IPv6 egress and the BGP session down. A positive `meta skuid 65535` match
# BREAKs the same way and lets such packets through.
#
# The sets hold NETWORKS only: every global IPv4 of the node (/32 each), the
# /64 of every global IPv6 (one element for the NIC /64 however many /128
# anchors it carries — the hand-made Johannesburg file listed 22k of them),
# and the prefixes routed to this host (`ip -6 route show table local dev lo`,
# e.g. the BGP /48). Overlaps are merged: nft refuses overlapping intervals.
#
#   netrun-proxy-guard apply [--dry-run]
#       Idempotent. Computes the file; --dry-run prints the diff against the
#       current one and changes nothing. Otherwise: `nft -c -f` of the new text,
#       /etc/netrun/nft-proxy-guard.nft rewritten atomically when it differs,
#       loaded with `nft -f` (ONE transaction: add + delete + define the table,
#       so the kernel never runs without it), verified; the nftables.service
#       drop-in netrun-proxy-guard.conf re-applies the file after every boot
#       load (daemon-reload only when it changed); this script is installed as
#       /usr/local/sbin/netrun-proxy-guard. Nothing else is touched: 3proxy,
#       its listeners and established connections are not affected.
#       Refused (nothing changes) when the text could touch a packet that is not
#       3proxy's (guard_safe below); a loaded table that fails the same check is
#       deleted again.
#   netrun-proxy-guard print      the file apply would write
#   netrun-proxy-guard check      guard_safe on a ruleset text from stdin
#   netrun-proxy-guard status     the loaded table, or "not loaded" (exit 1)
#
# Re-run whenever the node's prefixes change: `netrun-bgp apply` calls it, the
# agent calls it at start and when the routed prefixes it watches change
# (egress.js), the installer and node_followup_v2.sh call it.
#
# Settings (environment): NETRUN_PROXY_GUARD_FILE (/etc/netrun/nft-proxy-guard.nft),
# NETRUN_PROXY_UID (65535), NETRUN_PROXY_GUARD_UNIT_DIR (/etc/systemd/system),
# NETRUN_PROXY_GUARD_SELF (/usr/local/sbin/netrun-proxy-guard).
set -euo pipefail

GUARD_FILE="${NETRUN_PROXY_GUARD_FILE:-/etc/netrun/nft-proxy-guard.nft}"
PROXY_UID="${NETRUN_PROXY_UID:-65535}"
UNIT_DIR="${NETRUN_PROXY_GUARD_UNIT_DIR:-/etc/systemd/system}"
SELF="${NETRUN_PROXY_GUARD_SELF:-/usr/local/sbin/netrun-proxy-guard}"
TABLE="netrun_proxy_guard"
DROPIN="$UNIT_DIR/nftables.service.d/netrun-proxy-guard.conf"

log() { echo "[netrun-proxy-guard] $*"; }
die() { echo "[netrun-proxy-guard] ERROR: $*" >&2; exit 1; }

[[ "$PROXY_UID" =~ ^[0-9]+$ ]] || die "NETRUN_PROXY_UID must be a number"

# guard_sets: two lines, "v4 <elements>" and "v6 <elements>" (comma separated),
# from the node's addresses and local routes.
guard_sets() {
  local v4 v6 routes
  v4="$(ip -4 -o addr show scope global 2>/dev/null || true)"
  v6="$(ip -6 -o addr show scope global 2>/dev/null || true)"
  routes="$(ip -6 route show table local dev lo 2>/dev/null || true)"
  python3 - "$v4" "$v6" "$routes" <<'PY'
import ipaddress, re, sys

v4_text, v6_text, routes_text = sys.argv[1:4]
FIXED4 = ["127.0.0.0/8", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
          "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"]
FIXED6 = ["::1/128", "fe80::/10", "fc00::/7", "ff00::/8"]

def own(fixed, found):
    """found networks not covered by a fixed one, merged, sorted"""
    fixed = [ipaddress.ip_network(f) for f in fixed]
    rest = [n for n in found if not any(n.subnet_of(f) for f in fixed)]
    return sorted(ipaddress.collapse_addresses(rest), key=lambda n: (int(n.network_address), n.prefixlen))

def text(n):
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)

nodes4 = [ipaddress.ip_network(m.group(1) + "/32")
          for m in re.finditer(r"\binet ([0-9.]+)/\d+", v4_text)]
nodes6 = []
for m in re.finditer(r"\binet6 ([0-9a-fA-F:]+)/(\d+)", v6_text):
    nodes6.append(ipaddress.ip_network(f"{m.group(1)}/{min(int(m.group(2)), 64)}", strict=False))
for m in re.finditer(r"^local\s+([0-9a-fA-F:]+)/(\d+)", routes_text, re.M):
    if int(m.group(2)) <= 64:
        nodes6.append(ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False))
print("v4 " + ", ".join(FIXED4 + [text(n) for n in own(FIXED4, nodes4)]))
print("v6 " + ", ".join(["::1"] + FIXED6[1:] + [text(n) for n in own(FIXED6, nodes6)]))
PY
}

guard_text() {
  local sets v4 v6
  sets="$(guard_sets)" || die "cannot compute the address sets (python3?)"
  v4="$(printf '%s\n' "$sets" | sed -n 's/^v4 //p')"
  v6="$(printf '%s\n' "$sets" | sed -n 's/^v6 //p')"
  [ -n "$v4" ] && [ -n "$v6" ] || die "empty address sets"
  cat <<EOF
# NETRUN — 3proxy (uid $PROXY_UID) may not open connections to node-local, cloud-metadata,
# private or the node's own addresses (audit 2026-10-08). DNS to the local unbound stays.
# Written by netrun-proxy-guard (scripts/netrun-proxy-guard.sh): do not edit, run \`netrun-proxy-guard apply\`.
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid $PROXY_UID jump proxy
  }
  chain proxy {
    ip daddr 127.0.0.1 udp dport 53 accept
    ip daddr 127.0.0.1 tcp dport 53 accept
    ip6 daddr ::1 udp dport 53 accept
    ip6 daddr ::1 tcp dport 53 accept
    ct state established,related accept
    ip daddr { $v4 } reject
    ip6 daddr { $v6 } reject
  }
}
EOF
}

dropin_text() {
  cat <<EOF
# NETRUN — re-apply the 3proxy egress guard after the boot load (audit 2026-10-08)
[Service]
ExecStartPost=-$1 -f $GUARD_FILE
EOF
}

# guard_safe: the ruleset text on stdin (the generated file, or `nft list
# table` of the loaded one) may not touch a packet that is not 3proxy's: no
# `skuid !=` anywhere, every hooked chain has policy accept and nothing but
# `meta skuid <uid> jump|goto …` rules (at least one). A packet without a user
# socket — the kernel's NDP to fe80::/10 / ff02::/16, MLD, ICMPv6 errors —
# then never reaches a reject. Exit 1 with the reason on stdout otherwise.
guard_safe() {
  awk -v uid="$PROXY_UID" '
    /skuid[ \t]+!=/ { bad = "a \"skuid !=\" rule: packets without a user socket (kernel NDP) skip it and reach the rejects"; exit }
    /^[ \t]*chain[ \t]/ { inchain = 1; base = 0; next }
    inchain && /[ \t]hook[ \t]/ {
      base = 1
      if ($0 !~ /policy accept/) { bad = "a hooked chain without policy accept: " $0; exit }
      next
    }
    inchain && /^[ \t]*}/ { inchain = 0; base = 0; next }
    inchain && base && NF && $1 !~ /^#/ {
      if ($0 ~ "^[ \t]*meta skuid " uid " (jump|goto) ") { gated = 1; next }
      bad = "a hooked-chain rule not gated on meta skuid " uid ": " $0; exit
    }
    END {
      if (bad == "" && !gated) bad = "no meta skuid " uid " jump in a hooked chain"
      if (bad != "") { print bad; exit 1 }
    }'
}

# write_if_changed <path> <mode> <text>: 0 = written, 1 = already equal.
write_if_changed() {
  local path="$1" mode="$2" text="$3" tmp
  if [ -f "$path" ] && [ "$(cat "$path")" = "$text" ]; then return 1; fi
  mkdir -p "$(dirname "$path")" || die "cannot create $(dirname "$path")"
  tmp="$(mktemp "$(dirname "$path")/.netrun-proxy-guard.XXXXXX")" || die "cannot create a temp file next to $path"
  printf '%s\n' "$text" > "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$path" \
    || { rm -f "$tmp"; die "cannot write $path"; }
  return 0
}

install_self() {
  local src="${BASH_SOURCE[0]:-}"
  [ -n "$src" ] && [ -f "$src" ] || return 0
  cmp -s "$src" "$SELF" && return 0
  mkdir -p "$(dirname "$SELF")" && install -m 0755 "$src" "$SELF" || log "warning: cannot install $SELF"
}

cmd_apply() {
  local dry=0 a text nft_bin tmp err
  for a in "$@"; do
    case "$a" in --dry-run) dry=1 ;; *) die "unknown option $a" ;; esac
  done
  command -v nft >/dev/null 2>&1 || die "nft not found"
  text="$(guard_text)"
  if [ "$dry" = 1 ]; then
    if [ ! -f "$GUARD_FILE" ]; then
      log "would create $GUARD_FILE:"
      printf '%s\n' "$text"
    elif [ "$(cat "$GUARD_FILE")" = "$text" ]; then
      log "$GUARD_FILE: unchanged"
    else
      diff -u --label "$GUARD_FILE" --label "apply" "$GUARD_FILE" <(printf '%s\n' "$text") || true
    fi
    nft list table inet "$TABLE" >/dev/null 2>&1 || log "table inet $TABLE is not loaded now"
    return 0
  fi
  local why
  why="$(printf '%s\n' "$text" | guard_safe)" || die "refusing the generated guard: $why"
  tmp="$(mktemp)"; err="$(mktemp)"
  printf '%s\n' "$text" > "$tmp"
  if ! nft -c -f "$tmp" 2>"$err"; then
    local e; e="$(head -c 300 "$err" | tr '\n' ' ')"
    rm -f "$tmp" "$err"
    die "nft -c rejects the guard ($e); nothing changed"
  fi
  rm -f "$tmp"
  if write_if_changed "$GUARD_FILE" 0644 "$text"; then log "wrote $GUARD_FILE"; fi
  if ! nft -f "$GUARD_FILE" 2>"$err"; then
    local e; e="$(head -c 300 "$err" | tr '\n' ' ')"
    rm -f "$err"
    die "nft -f $GUARD_FILE failed: $e"
  fi
  rm -f "$err"
  local listed
  listed="$(nft list table inet "$TABLE" 2>/dev/null)" || listed=""
  [ -n "$listed" ] || die "table inet $TABLE is not loaded after nft -f"
  # The kernel's view too: a table that could match the kernel's own NDP
  # costs the node its IPv6 router — none at all is the safer state.
  if ! why="$(printf '%s\n' "$listed" | guard_safe)"; then
    nft delete table inet "$TABLE" 2>/dev/null || true
    die "the loaded table is unsafe ($why) — deleted it"
  fi
  printf '%s\n' "$listed" | grep -q "meta skuid $PROXY_UID jump proxy" || die "table inet $TABLE is not the one written"
  nft_bin="$(command -v nft)"
  case "$nft_bin" in /*) ;; *) nft_bin=/usr/sbin/nft ;; esac
  if write_if_changed "$DROPIN" 0644 "$(dropin_text "$nft_bin")"; then
    log "wrote $DROPIN"
    if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || log "warning: systemctl daemon-reload failed"; fi
  fi
  install_self
  log "loaded table inet $TABLE (IPv6 blocked for uid $PROXY_UID: $(printf '%s\n' "$text" | sed -n 's/^    ip6 daddr { \(.*\) } reject$/\1/p'))"
}

cmd_status() {
  if nft list table inet "$TABLE" 2>/dev/null; then return 0; fi
  echo "table inet $TABLE: not loaded"
  return 1
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    apply) cmd_apply "$@" ;;
    print) guard_text ;;
    check) guard_safe ;;   # stdin: a ruleset text (test / audit hook)
    status) cmd_status ;;
    *) echo "usage: netrun-proxy-guard apply [--dry-run] | print | status | check < ruleset" >&2; exit 2 ;;
  esac
}

if [ "${NETRUN_PROXY_GUARD_SOURCED:-0}" != 1 ]; then main "$@"; fi
