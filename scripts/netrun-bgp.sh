#!/usr/bin/env bash
# NETRUN node — announce our own IPv6 prefixes (a leased /48, one or more) to
# Vultr over BGP and route them to this host.
#
#   Vultr router ──BGP──► BIRD (export only: `route <P> unreachable` in its own
#                         table, no `protocol kernel`, so BIRD never touches the
#                         kernel's routes)
#   internet ──► <P>/48 ──► the host: `ip -6 route replace local <P> dev lo`
#                         (AnyIP: every address of P is local; 3proxy binds its
#                         -e anchors there thanks to net.ipv6.ip_nonlocal_bind=1;
#                         the agent's exit guard filters unsolicited inbound)
#
# Settings: the environment first, then /etc/netrun/netrun.env (KEY=VALUE, the
# same file the generator and the agent read):
#   NETRUN_BGP_PREFIXES    prefixes to announce (space/comma separated, /32../48);
#                          default NETRUN_IPV6_ROUTED_PREFIX (the generator's prefix);
#                          "none" = withdraw every prefix (a /48 moving to another node)
#   NETRUN_BGP_LOCAL_ASN   required: the account's ASN from the Vultr portal (BGP tab)
#   NETRUN_BGP_PASSWORD    required: the BGP password from the same tab
#   NETRUN_BGP_PEER_ASN    default 64515 (Vultr, cloud compute)
#   NETRUN_BGP_NEIGHBOR6   default 2001:19f0:ffff::1
#   NETRUN_BGP_MULTIHOP    default 2
#   NETRUN_BGP_SOURCE6     default: the SLAAC (EUI-64) address of the interface towards
#                          the neighbour — Vultr's "main IP", the one its router expects.
#                          Not what `ip -6 route get` picks: with customer anchors on the
#                          NIC (nodad, not deprecated) source selection may pick one of them
#   NETRUN_BGP_ROUTER_ID   default: the source address `ip -4 route get 1.1.1.1` picks
#   NETRUN_BGP_WITHDRAW_WAIT  seconds between withdrawing a prefix and removing
#                          its local route (default 10: traffic still in flight
#                          is answered, not bounced back to the gateway)
#
#   netrun-bgp apply [--dry-run] [--install]
#       Idempotent. --dry-run prints what would change (bird.conf diff, routes to
#       add / remove) and touches nothing. --install apt-installs bird2 when the
#       binary is missing (otherwise that is an error). Order, so an announced
#       prefix always has its local route (without it Vultr's traffic for the
#       prefix would bounce between the host and its default gateway):
#         0. the generated bird.conf is checked with `bird -p` — rejected:
#            nothing at all changes
#         1. local routes for every new prefix, the boot unit
#         2. bird.conf → `birdc configure` (or `systemctl start bird`), also
#            whenever the routes BIRD holds (`birdc show route protocol
#            netrun_v6`) differ from the list — a failed earlier configure is
#            retried — then verified: BIRD must hold exactly the list
#         3. only then (NETRUN_BGP_WITHDRAW_WAIT later) the local routes of
#            prefixes no longer announced go
#       A real apply also installs this script as /usr/local/sbin/netrun-bgp.
#       Boot: netrun-bgp-prefix.service (oneshot, one ExecStart per prefix) adds
#       the routes; a bird.service drop-in Requires= it and orders bird After= it,
#       so bird never announces before the routes exist.
#   netrun-bgp status        prefixes, their local routes, the BGP session
#   netrun-bgp check         exit 1 unless every prefix has its local route and
#                            the session is Established (for monitoring)
set -euo pipefail

NETRUN_ENV="${NETRUN_BGP_ENV_FILE:-/etc/netrun/netrun.env}"
BIRD_CONF="${NETRUN_BGP_BIRD_CONF:-/etc/bird/bird.conf}"
UNIT_DIR="${NETRUN_BGP_UNIT_DIR:-/etc/systemd/system}"
LIST_FILE="${NETRUN_BGP_LIST_FILE:-/etc/netrun/bgp-prefixes}"
SELF="${NETRUN_BGP_SELF:-/usr/local/sbin/netrun-bgp}"
UNIT="netrun-bgp-prefix.service"
PROTO="vultr6"

log() { echo "[netrun-bgp] $*"; }
die() { echo "[netrun-bgp] ERROR: $*" >&2; exit 1; }

# setting KEY [default]: the environment, else the last KEY= line of netrun.env.
setting() {
  local key="$1" def="${2:-}" val=""
  if [ -n "${!key:-}" ]; then
    printf '%s' "${!key}"
    return
  fi
  if [ -r "$NETRUN_ENV" ]; then
    val="$(grep -E "^${key}=" "$NETRUN_ENV" | tail -n1 | cut -d= -f2- || true)"
    # one matching pair of surrounding quotes, never a lone one (a password may
    # start or end with an apostrophe)
    if [ "${#val}" -ge 2 ]; then
      case "${val:0:1}${val: -1}" in '""'|"''") val="${val:1:${#val}-2}" ;; esac
    fi
  fi
  printf '%s' "${val:-$def}"
}

# canonical_prefixes "<list>": one canonical IPv6 prefix per line, /32../48,
# host bits cleared, sorted, duplicates and covered ones dropped; non-zero exit
# on anything invalid.
canonical_prefixes() {
  python3 - "$1" <<'PY'
import ipaddress, re, sys
raw = [p for p in re.split(r"[\s,]+", sys.argv[1]) if p]
nets = []
for p in raw:
    try:
        n = ipaddress.ip_network(p, strict=False)
    except ValueError:
        sys.exit(f"invalid prefix: {p}")
    if n.version != 6 or not 32 <= n.prefixlen <= 48:
        sys.exit(f"not an IPv6 /32../48 prefix: {p}")
    nets.append(n)
out = []
for n in sorted(set(nets), key=lambda n: (n.prefixlen, int(n.network_address))):
    if not any(n.subnet_of(o) for o in out):
        out.append(n)
print("\n".join(str(n) for n in sorted(out, key=lambda n: int(n.network_address))))
PY
}

route_src() {  # route_src -4|-6 <dst>: the src the kernel would use, or empty
  ip "$1" route get "$2" 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1
}

# primary6 <neighbor>: the global address of the interface towards <neighbor> whose
# interface ID is the EUI-64 of its MAC (SLAAC), or nothing.
primary6() {
  local dev mac
  dev="$(ip -6 route get "$1" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
  [ -n "$dev" ] || return 0
  mac="$(ip -o link show dev "$dev" 2>/dev/null | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p' | head -n1)"
  [ -n "$mac" ] || return 0
  ip -6 -o addr show dev "$dev" scope global 2>/dev/null | python3 -c '
import ipaddress, re, sys
b = bytes.fromhex(sys.argv[1].replace(":", ""))
iid = int.from_bytes(bytes([b[0] ^ 2]) + b[1:3] + b"\xff\xfe" + b[3:6], "big")
for line in sys.stdin:
    m = re.search(r"inet6 ([0-9a-f:]+)/(\d+)", line)
    if m and "nodad" not in line and int(ipaddress.IPv6Address(m.group(1))) & (2**64 - 1) == iid:
        print(m.group(1)); break
' "$mac"
}

bird_conf_text() {  # <router-id> <source6> <local-asn> <neighbor6> <peer-asn> <multihop> <password> <prefixes…>
  local rid="$1" src="$2" las="$3" nb="$4" pas="$5" hop="$6" pw="$7"
  shift 7
  cat <<EOF
# NETRUN — written by netrun-bgp (scripts/netrun-bgp.sh). Do not edit: change
# /etc/netrun/netrun.env and run \`netrun-bgp apply\`. Export only, import
# nothing, no "protocol kernel": BIRD never touches the kernel routing table.
log syslog all;
router id ${rid};

protocol device {
  scan time 60;
}

protocol static netrun_v6 {
  ipv6;
EOF
  local p
  for p in "$@"; do echo "  route ${p} unreachable;"; done
  cat <<EOF
}

protocol bgp ${PROTO} {
  description "Vultr IPv6";
  local ${src} as ${las};
  neighbor ${nb} as ${pas};
  multihop ${hop};
  password "${pw}";
  graceful restart on;
  ipv6 {
    import none;
    export where proto = "netrun_v6";
  };
}
EOF
}

unit_text() {  # <prefixes…>
  cat <<'EOF'
# Written by netrun-bgp (scripts/netrun-bgp.sh).
[Unit]
Description=NETRUN - route our BGP-announced IPv6 prefixes to this host (local, dev lo)
After=network-online.target
Wants=network-online.target
Before=netrun-3proxy-restore.service bird.service

[Service]
Type=oneshot
RemainAfterExit=yes
EOF
  local p
  [ "$#" -gt 0 ] || echo "ExecStart=/bin/true"
  for p in "$@"; do echo "ExecStart=/sbin/ip -6 route replace local ${p} dev lo"; done
  for p in "$@"; do echo "ExecStop=-/sbin/ip -6 route del local ${p} dev lo"; done
  cat <<'EOF'

[Install]
WantedBy=multi-user.target
EOF
}

bird_dropin_text() {
  cat <<EOF
# Written by netrun-bgp: never announce before the local routes exist.
[Unit]
Requires=${UNIT}
After=${UNIT}
EOF
}

# write_if_changed <path> <mode> <owner:group|-> <text>: 0 when written, 1 when
# equal; any failed step dies (callers use it in conditions, where errexit is off).
write_if_changed() {
  local path="$1" mode="$2" owner="$3" text="$4" tmp
  if [ -f "$path" ] && [ "$(cat "$path")" = "$text" ]; then return 1; fi
  mkdir -p "$(dirname "$path")" || die "cannot create $(dirname "$path")"
  tmp="$(mktemp "$(dirname "$path")/.netrun-bgp.XXXXXX")" || die "cannot create a temp file next to $path"
  printf '%s\n' "$text" > "$tmp" || { rm -f "$tmp"; die "cannot write $path"; }
  chmod "$mode" "$tmp" || { rm -f "$tmp"; die "cannot chmod $path"; }
  if [ "$owner" != "-" ] && ! chown "$owner" "$tmp" 2>/dev/null; then
    log "warning: chown $owner failed for $path"
  fi
  if [ -f "$path" ]; then cp -p "$path" "$path.netrun-prev" || { rm -f "$tmp"; die "cannot back up $path"; }; fi
  mv -f "$tmp" "$path" || { rm -f "$tmp"; die "cannot replace $path"; }
  return 0
}

# The prefixes BIRD's static protocol holds now (what it announces), one per
# line, as canonical_prefixes prints them; empty when none or BIRD is not up.
loaded_prefixes() {
  local got
  got="$(birdc show route protocol netrun_v6 2>/dev/null | awk '$1 ~ /^[0-9a-fA-F:]+\/[0-9]+$/ {print $1}' | tr '\n' ' ')"
  [ -n "${got// /}" ] || return 0
  canonical_prefixes "$got" 2>/dev/null || true
}

# netrun.env holds the BGP password: root only (bird.conf is 0640 root:bird).
protect_env() {
  [ -f "$NETRUN_ENV" ] && grep -q '^NETRUN_BGP_PASSWORD=' "$NETRUN_ENV" || return 0
  local before after
  before="$(stat -c %a "$NETRUN_ENV" 2>/dev/null || stat -f %Lp "$NETRUN_ENV")"
  chmod go-rwx "$NETRUN_ENV" || die "cannot chmod $NETRUN_ENV"
  after="$(stat -c %a "$NETRUN_ENV" 2>/dev/null || stat -f %Lp "$NETRUN_ENV")"
  [ "$before" = "$after" ] || log "$NETRUN_ENV: mode $before -> $after (it holds the BGP password)"
}

# The copy `netrun-bgp` runs as; nothing to do when run from stdin or the copy itself.
install_self() {
  local src="${BASH_SOURCE[0]:-}"
  [ -n "$src" ] && [ -f "$src" ] || return 0
  cmp -s "$src" "$SELF" && return 0
  mkdir -p "$(dirname "$SELF")"
  install -m 0755 "$src" "$SELF"
}

# dry_diff <label> <path> <text>: a unified diff of a file against what apply writes.
dry_diff() {
  local label="$1" path="$2" text="$3"
  if [ ! -f "$path" ]; then log "$label: would be created ($path)"; return 0; fi
  if diff -u --label "$path" --label "$label (apply)" \
       <(sed -E 's/(password )"[^"]*"/\1"<redacted>"/' "$path") \
       <(printf '%s\n' "$text" | sed -E 's/(password )"[^"]*"/\1"<redacted>"/'); then
    if [ "$(cat "$path")" = "$text" ]; then log "$label: unchanged"; else log "$label: only the password changes"; fi
  fi
  return 0
}

has_local_route() { ip -6 route show table local dev lo | grep -qE "^local ${1}( |$)"; }

load_settings() {
  local plist
  plist="$(setting NETRUN_BGP_PREFIXES "$(setting NETRUN_IPV6_ROUTED_PREFIX "")")"
  [ -n "$plist" ] || die "no prefix: set NETRUN_BGP_PREFIXES or NETRUN_IPV6_ROUTED_PREFIX in $NETRUN_ENV (none = withdraw all)"
  if [ "$(printf '%s' "$plist" | tr '[:upper:]' '[:lower:]')" = "none" ]; then
    PREFIXES=""
  else
    PREFIXES="$(canonical_prefixes "$plist")" || die "bad prefix list: $plist"
  fi
  LOCAL_ASN="$(setting NETRUN_BGP_LOCAL_ASN)"
  PASSWORD="$(setting NETRUN_BGP_PASSWORD)"
  PEER_ASN="$(setting NETRUN_BGP_PEER_ASN 64515)"
  NEIGHBOR6="$(setting NETRUN_BGP_NEIGHBOR6 2001:19f0:ffff::1)"
  MULTIHOP="$(setting NETRUN_BGP_MULTIHOP 2)"
  [[ "$LOCAL_ASN" =~ ^[0-9]+$ ]] || die "NETRUN_BGP_LOCAL_ASN must be a number (the Vultr portal's BGP tab)"
  [[ "$PEER_ASN" =~ ^[0-9]+$ ]] || die "NETRUN_BGP_PEER_ASN must be a number"
  [[ "$MULTIHOP" =~ ^[0-9]+$ ]] || die "NETRUN_BGP_MULTIHOP must be a number"
  [ -n "$PASSWORD" ] || die "NETRUN_BGP_PASSWORD is empty (the Vultr portal's BGP tab)"
  case "$PASSWORD" in *'"'*|*'\'*|*$'\n'*) die "NETRUN_BGP_PASSWORD may not contain \" or \\ or a newline" ;; esac
  SOURCE6="$(setting NETRUN_BGP_SOURCE6 "$(primary6 "$NEIGHBOR6")")"
  ROUTER_ID="$(setting NETRUN_BGP_ROUTER_ID "$(route_src -4 1.1.1.1)")"
  [ -n "$SOURCE6" ] || die "no SLAAC (EUI-64) address towards $NEIGHBOR6 (set NETRUN_BGP_SOURCE6: the instance's main IPv6)"
  [ -n "$ROUTER_ID" ] || die "no IPv4 router id (set NETRUN_BGP_ROUTER_ID)"
}

cmd_apply() {
  local dry=0 install=0 a
  for a in "$@"; do
    case "$a" in --dry-run) dry=1 ;; --install) install=1 ;; *) die "unknown option $a" ;; esac
  done
  load_settings
  local -a new=() old=() added=() removed=()
  [ -z "$PREFIXES" ] || mapfile -t new <<< "$PREFIXES"
  [ -f "$LIST_FILE" ] && mapfile -t old < <(grep -v '^\s*$' "$LIST_FILE")
  local p q found
  for p in "${new[@]}"; do
    found=0; for q in "${old[@]}"; do [ "$p" = "$q" ] && found=1; done
    [ "$found" = 1 ] || added+=("$p")
  done
  for q in "${old[@]}"; do
    found=0; for p in "${new[@]}"; do [ "$p" = "$q" ] && found=1; done
    [ "$found" = 1 ] || removed+=("$q")
  done

  local conf unit dropin
  conf="$(bird_conf_text "$ROUTER_ID" "$SOURCE6" "$LOCAL_ASN" "$NEIGHBOR6" "$PEER_ASN" "$MULTIHOP" "$PASSWORD" "${new[@]}")"
  unit="$(unit_text "${new[@]}")"
  dropin="$(bird_dropin_text)"

  if [ "$dry" = 1 ]; then
    log "dry run — nothing is changed"
    log "prefixes: ${new[*]:-none}"
    [ "${#added[@]}" -gt 0 ] && log "new (local route first, then announce): ${added[*]}"
    [ "${#removed[@]}" -gt 0 ] && log "dropped (withdraw first, then the route): ${removed[*]}"
    for p in "${new[@]}"; do has_local_route "$p" || log "local route missing now: $p"; done
    log "router id $ROUTER_ID, source $SOURCE6, AS $LOCAL_ASN -> $NEIGHBOR6 AS $PEER_ASN"
    if command -v birdc >/dev/null 2>&1; then log "BIRD announces now: $(loaded_prefixes | tr '\n' ' ')"; fi
    dry_diff bird.conf "$BIRD_CONF" "$conf"
    dry_diff "$UNIT" "$UNIT_DIR/$UNIT" "$unit"
    dry_diff "bird drop-in" "$UNIT_DIR/bird.service.d/netrun.conf" "$dropin"
    return 0
  fi

  if ! command -v bird >/dev/null 2>&1; then
    [ "$install" = 1 ] || die "bird is not installed (rerun with --install)"
    log "installing bird2"
    DEBIAN_FRONTEND=noninteractive apt-get install -y bird2 >/dev/null
  fi

  # 0. the generated config, checked before anything changes
  local tmpconf
  tmpconf="$(mktemp)"
  printf '%s\n' "$conf" > "$tmpconf"
  if ! bird -p -c "$tmpconf" >/dev/null 2>&1; then
    rm -f "$tmpconf"
    die "bird rejects the generated config (bird -p); nothing changed"
  fi
  rm -f "$tmpconf"
  protect_env

  # 1. local routes for every announced prefix (new ones before BIRD sees them)
  for p in "${new[@]}"; do ip -6 route replace local "$p" dev lo; done

  # boot: the routes unit and the bird ordering
  local units_changed=0
  write_if_changed "$UNIT_DIR/$UNIT" 0644 - "$unit" && units_changed=1
  write_if_changed "$UNIT_DIR/bird.service.d/netrun.conf" 0644 - "$dropin" && units_changed=1
  if [ "$units_changed" = 1 ]; then systemctl daemon-reload; fi
  systemctl enable "$UNIT" >/dev/null 2>&1 || true

  # 2. bird.conf → BIRD; reconfigured also when what it holds differs (an
  # earlier configure failed), then verified before any route goes
  local conf_changed=0 out i
  if write_if_changed "$BIRD_CONF" 0640 root:bird "$conf"; then
    conf_changed=1
    log "bird.conf updated (previous: $BIRD_CONF.netrun-prev)"
  else
    log "bird.conf unchanged"
  fi
  if ! systemctl is-active --quiet bird; then
    systemctl start bird || die "systemctl start bird failed; withdrawn prefixes keep their local routes"
  elif [ "$conf_changed" = 1 ] || [ "$(loaded_prefixes)" != "$PREFIXES" ]; then
    out="$(birdc configure 2>&1)" || die "birdc configure failed: ${out//$'\n'/ }; withdrawn prefixes keep their local routes"
  fi
  systemctl enable bird >/dev/null 2>&1 || true
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(loaded_prefixes)" = "$PREFIXES" ] && break
    sleep 1
  done
  [ "$(loaded_prefixes)" = "$PREFIXES" ] \
    || die "BIRD holds '$(loaded_prefixes | tr '\n' ' ')' instead of '${new[*]:-none}'; withdrawn prefixes keep their local routes"

  # 3. routes of prefixes no longer announced
  if [ "${#removed[@]}" -gt 0 ]; then
    local wait
    wait="$(setting NETRUN_BGP_WITHDRAW_WAIT 10)"
    [[ "$wait" =~ ^[0-9]+$ ]] || wait=10
    log "withdrawn: ${removed[*]} — local routes go in ${wait}s"
    sleep "$wait"
    for q in "${removed[@]}"; do ip -6 route del local "$q" dev lo 2>/dev/null || true; done
  fi
  write_if_changed "$LIST_FILE" 0644 - "$PREFIXES" || true
  install_self
  log "announced: ${new[*]:-none}"
}

cmd_status() {
  load_settings
  local p
  for p in $PREFIXES; do
    if has_local_route "$p"; then echo "route  $p  local dev lo: yes"; else echo "route  $p  local dev lo: MISSING"; fi
  done
  birdc show protocols "$PROTO" 2>/dev/null | tail -n +2 || echo "bird: not running"
}

cmd_check() {
  load_settings
  local p bad=0
  for p in $PREFIXES; do has_local_route "$p" || { echo "missing local route: $p"; bad=1; }; done
  if ! birdc show protocols "$PROTO" 2>/dev/null | grep -q Established; then
    echo "BGP session $PROTO is not Established"; bad=1
  fi
  [ "$bad" = 0 ] && echo "ok"
  return "$bad"
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    apply) cmd_apply "$@" ;;
    status) cmd_status ;;
    check) cmd_check ;;
    *) echo "usage: netrun-bgp apply [--dry-run] [--install] | status | check" >&2; exit 2 ;;
  esac
}

if [ "${NETRUN_BGP_SOURCED:-0}" != 1 ]; then main "$@"; fi
