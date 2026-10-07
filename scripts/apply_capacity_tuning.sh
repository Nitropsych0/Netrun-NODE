#!/usr/bin/env bash
# apply_capacity_tuning.sh — Wave CAPACITY-18K tuning for an EXISTING node.
#
# Opt-in and idempotent. New nodes get the same settings from
# install_node_v2.sh; this script brings a node that is already serving
# customers up to them WITHOUT touching a single proxy:
#   - never starts, stops, restarts or signals 3proxy;
#   - never changes a listener, a port, a cfg file or a sold proxy;
#   - never touches nft map/set rules, counters, or tables other than the
#     legacy per-port rules of inet proxy_accounting.
#
#   bash apply_capacity_tuning.sh                     # = --dry-run: print the plan, change nothing
#   bash apply_capacity_tuning.sh --apply             # do it
#   bash apply_capacity_tuning.sh --apply --only sysctl,unbound
#
# Steps (each guarded; each a no-op once done, so re-running is safe):
#   sysctl       net.ipv4.ip_local_port_range -> "1024 8000" (runtime + persisted
#                in /etc/sysctl.d/99-netrun.conf). Refused while ANY TCP listener
#                or ANY 3proxy cfg port (incl. *.cfg.disabled) lies inside the new
#                range. It only changes which source port FUTURE outbound
#                connect()/bind(:0) calls get: no listener and no established
#                connection is affected.
#   unbound      msg-cache-size 32m / rrset-cache-size 64m in
#                /etc/unbound/unbound.conf.d/netrun.conf, checked with
#                unbound-checkconf, then RELOADED (systemctl reload = SIGHUP, or
#                unbound-control reload). A reload drops unbound's cache (a short
#                burst of recursion). Never restarted unless --allow-unbound-restart.
#   nft          legacy per-port accounting RULES in inet proxy_accounting that
#                predate the O(1) map (f1ca871): `tcp dport|sport N counter name
#                "proxy_P_k"` and the older egress `ip6 saddr|daddr X counter name
#                ...`. Removed by handle in ONE atomic `nft -f` batch. Billing-safe:
#                  * a port rule whose port the map already meters with the SAME
#                    counter was double-counting -> deleted;
#                  * a port rule whose port has no map element is MIGRATED: the
#                    map element (same named counter) is added in the same
#                    transaction, so counting never stops and no value is reset;
#                  * `ip6 daddr ... proxy_P_in6` -> deleted (in6 is not billed);
#                  * `ip6 saddr ... proxy_P_out` -> deleted only when the map
#                    already meters proxy_P_out, otherwise kept and reported;
#                  * anything else -> kept and reported.
#                Refused while a generation holds the agent's genlock.
#   ipv6restore  /opt/netrun/scripts/netrun-ipv6-restore.sh -> the ip -batch +
#                nodad version from deploy/node/netrun-ipv6-restore.sh. Only used
#                at the next boot; NOT run now.
#   conntrack    OPT-IN (not in the default step list: name it in --only).
#                nf_conntrack_max sized by RAM (one entry per 8 KB, power of two,
#                65536..1048576; 2c/4GB -> 262144, ~85 MB when full) and made to
#                survive reboots: /etc/modules-load.d/netrun-conntrack.conf loads
#                nf_conntrack BEFORE systemd-sysctl (which otherwise skips the
#                net.netfilter.* keys — the live node fell back to 65536), a udev
#                rule re-applies net.netfilter.* whenever the module loads, and
#                the value is persisted in 99-netrun.conf. The runtime value is
#                only ever RAISED (sysctl -w); a higher runtime value is left as is
#                (the target applies from the next boot). Nothing is flushed, no
#                connection is touched. NOTE: the 99-netrun.conf line
#                nf_conntrack_tcp_timeout_established = 7200 also starts to apply
#                at boot (harmless: 3proxy drops idle connections after 1800 s).
#
# Read-only listener audit (always printed): TCP listeners below 8100 and any
# listener >= 8100 that is not 3proxy / haproxy (those would collide with
# proxy ports 8100-65535).
#
# Options:
#   --dry-run                 default; print what would be done
#   --apply                   do it (root)
#   --only LIST               comma list of: sysctl,unbound,nft,ipv6restore,conntrack
#                             (default: sysctl,unbound,nft,ipv6restore — conntrack is opt-in)
#   --ephemeral-range LO-HI   default 1024-8000
#   --conntrack-max N         conntrack step target (default: sized by MemTotal)
#   --allow-unbound-restart   last resort when unbound cannot be reloaded
#   --ignore-genlock          run the nft step even if a generation lock exists
#
# Exit: 0 = every selected step ok / planned / applied; 2 = a step was refused
# by a safety check (nothing changed for it); 3 = applied partially (unbound
# config written but not reloaded); 1 = a step failed.
#
# Test hook: NETRUN_TUNE_ROOT=<dir> prefixes every file path (fixtures); the
# commands (ss, nft, sysctl, systemctl, udevadm, unbound-checkconf, unbound-control) are
# taken from PATH.
set -uo pipefail

ROOT="${NETRUN_TUNE_ROOT:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P || echo "")"

SYSCTL_FILE="$ROOT/etc/sysctl.d/99-netrun.conf"
PROC_RANGE="$ROOT/proc/sys/net/ipv4/ip_local_port_range"
UNBOUND_CONF="$ROOT/etc/unbound/unbound.conf.d/netrun.conf"
CFG_DIR="$ROOT/opt/netrun/proxyserver/3proxy"
GENLOCK="$ROOT/opt/netrun/jobs/.generation.lock"
NFT_PERSIST="$ROOT/etc/nftables.conf"
RESTORE_TARGET="$ROOT/opt/netrun/scripts/netrun-ipv6-restore.sh"
RESTORE_UNIT="$ROOT/etc/systemd/system/netrun-ipv6-restore.service"
RESTORE_SRC="${NETRUN_IPV6_RESTORE_SRC:-${SCRIPT_DIR:+$SCRIPT_DIR/../deploy/node/netrun-ipv6-restore.sh}}"
LOCK_FILE="$ROOT/run/netrun-capacity-tuning.lock"
MEMINFO="$ROOT/proc/meminfo"
PROC_CT_MAX="$ROOT/proc/sys/net/netfilter/nf_conntrack_max"
PROC_CT_COUNT="$ROOT/proc/sys/net/netfilter/nf_conntrack_count"
CT_MODULES_FILE="$ROOT/etc/modules-load.d/netrun-conntrack.conf"
CT_UDEV_RULE="$ROOT/etc/udev/rules.d/90-netrun-conntrack.rules"
CT_MODULES_TEXT='# NETRUN — load conntrack before systemd-sysctl so net.netfilter.* in /etc/sysctl.d apply at boot
nf_conntrack'
CT_UDEV_TEXT='# NETRUN — re-apply net.netfilter.* sysctls whenever nf_conntrack is (re)loaded
ACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/netfilter"'


NFT_TABLE="proxy_accounting"
PROXY_PORT_FLOOR=8100
UNBOUND_MSG="32m"
UNBOUND_RRSET="64m"

MODE="dry-run"
ONLY="sysctl,unbound,nft,ipv6restore"
EPH_LO=1024
EPH_HI=8000
ALLOW_UNBOUND_RESTART=0
IGNORE_GENLOCK=0
CT_MAX_OVERRIDE=""

RC_REFUSED=0
RC_FAILED=0
RC_PARTIAL=0
TMPD=""

log() { printf '[capacity-tuning] %s\n' "$*"; }
step_status() { printf '[capacity-tuning] %-11s %-12s %s\n' "$1" "$2" "$3"; }
refused() { step_status "$1" "REFUSED" "$2"; RC_REFUSED=1; }
failed() { step_status "$1" "FAILED" "$2"; RC_FAILED=1; }
die() { log "ERROR: $*" >&2; exit 1; }

usage() { sed -n '2,79p' "$0" 2>/dev/null; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --apply) MODE="apply" ;;
    --only) [ $# -ge 2 ] || die "--only needs a list"; ONLY="$2"; shift ;;
    --only=*) ONLY="${1#--only=}" ;;
    --ephemeral-range) [ $# -ge 2 ] || die "--ephemeral-range needs LO-HI"; EPH_LO="${2%%[- ]*}"; EPH_HI="${2##*[- ]}"; shift ;;
    --allow-unbound-restart) ALLOW_UNBOUND_RESTART=1 ;;
    --ignore-genlock) IGNORE_GENLOCK=1 ;;
    --conntrack-max) [ $# -ge 2 ] || die "--conntrack-max needs a number"; CT_MAX_OVERRIDE="$2"; shift ;;
    --conntrack-max=*) CT_MAX_OVERRIDE="${1#--conntrack-max=}" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

case "$EPH_LO$EPH_HI" in *[!0-9]*|"") die "--ephemeral-range must be LO-HI (integers)" ;; esac
[ "$EPH_LO" -ge 1024 ] && [ "$EPH_HI" -gt "$EPH_LO" ] && [ "$EPH_HI" -lt "$PROXY_PORT_FLOOR" ] \
  || die "--ephemeral-range: need 1024 <= LO < HI < $PROXY_PORT_FLOOR (the range must stay below every proxy listener)"
for s in $(printf '%s' "$ONLY" | tr ',' ' '); do
  case "$s" in sysctl|unbound|nft|ipv6restore|conntrack) ;; *) die "--only: unknown step '$s'" ;; esac
done
if [ -n "$CT_MAX_OVERRIDE" ]; then
  case "$CT_MAX_OVERRIDE" in *[!0-9]*) die "--conntrack-max must be an integer" ;; esac
  [ "$CT_MAX_OVERRIDE" -ge 65536 ] && [ "$CT_MAX_OVERRIDE" -le 4194304 ] || die "--conntrack-max: need 65536 <= N <= 4194304"
fi
want() { case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

if [ "$MODE" = "apply" ] && [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  die "--apply must run as root"
fi

TMPD="$(mktemp -d 2>/dev/null)" || die "mktemp failed"
trap 'rm -rf "$TMPD"' EXIT

if [ "$MODE" = "apply" ] && command -v flock >/dev/null 2>&1; then
  mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
  exec 9>"$LOCK_FILE" || die "cannot open lock $LOCK_FILE"
  flock -n 9 || die "another apply_capacity_tuning.sh is running"
fi

# ── helpers ────────────────────────────────────────────────────────

ss_listen() { ss -Hltn${1:-} 2>/dev/null || ss -ltn${1:-} 2>/dev/null; }

# "<port> <addr> <process>" per LISTEN row (process "-" when ss shows none).
listen_rows() {
  ss_listen p | awk '
    $1 != "LISTEN" { next }
    {
      la = ""
      for (i = 2; i <= NF; i++) if ($i ~ /:[0-9]+$/) { la = $i; break }
      if (la == "") next
      port = la; sub(/.*:/, "", port)
      addr = la; sub(/:[0-9]+$/, "", addr)
      proc = "-"
      if (match($0, /users:\(\("[^"]*"/)) { proc = substr($0, RSTART + 9, RLENGTH - 10) }
      print port + 0, addr, proc
    }'
}

# Ports declared by 3proxy cfgs (live + disabled), one per line.
cfg_ports() {
  local f
  for f in "$CFG_DIR"/3proxy_*.cfg "$CFG_DIR"/3proxy_*.cfg.disabled; do
    [ -f "$f" ] || continue
    awk '/^[ \t]*(socks|proxy)[ \t]/ { for (i = 2; i <= NF; i++) if ($i ~ /^-p[0-9]+$/) print substr($i, 3) + 0 }' "$f"
  done
}

sysctl_file_value() {
  [ -f "$SYSCTL_FILE" ] || return 0
  awk -F= '/^[ \t]*net\.ipv4\.ip_local_port_range[ \t]*=/ { v = $2 } END { gsub(/[ \t]+/, " ", v); sub(/^ /, "", v); sub(/ $/, "", v); print v }' "$SYSCTL_FILE"
}

# Set KEY = VALUE in a sysctl.d file: replace in place or append; other lines kept.
persist_sysctl_kv() {
  local file="$1" key="$2" value="$3" ek tmp
  mkdir -p "$(dirname "$file")"
  [ -f "$file" ] || printf '# NETRUN — node sysctl\n' > "$file"
  ek="$(printf '%s' "$key" | sed 's/[.]/\\./g')"
  if grep -Eq "^[[:space:]]*${ek}[[:space:]]*=" "$file"; then
    tmp="$TMPD/sysctl.$$"
    sed -E "s|^[[:space:]]*${ek}[[:space:]]*=.*$|${key} = ${value}|" "$file" > "$tmp" && cat "$tmp" > "$file"
  else
    printf '%s = %s\n' "$key" "$value" >> "$file"
  fi
}

# ── audit (read-only) ─────────────────────────────────────────────

audit_listeners() {
  local rows
  rows="$(listen_rows)"
  if [ -z "$rows" ]; then
    log "audit: ss returned no listeners (not root, or ss unavailable)"
    return 0
  fi
  log "audit: TCP listeners below $PROXY_PORT_FLOOR (node services):"
  printf '%s\n' "$rows" | awk -v floor="$PROXY_PORT_FLOOR" '$1 < floor { print "[capacity-tuning]     " $1 " " $2 " " $3 }' | sort -u -k1,1n -k2
  printf '%s\n' "$rows" | awk -v floor="$PROXY_PORT_FLOOR" '
    $1 >= floor { if ($3 == "3proxy" || $3 == "haproxy") n[$3]++; else other[$1 " " $2 " " $3] = 1 }
    END {
      printf "[capacity-tuning] audit: listeners >= %d: 3proxy=%d haproxy=%d", floor, n["3proxy"] + 0, n["haproxy"] + 0
      c = 0; for (k in other) c++
      printf " other=%d\n", c
      for (k in other) print "[capacity-tuning]     WARNING non-proxy listener in the proxy port range: " k
    }'
}

# ── step: sysctl ephemeral range ──────────────────────────────────

step_sysctl() {
  local target="$EPH_LO $EPH_HI" cur="" persisted conflicts cfg_hits overrides
  if [ -r "$PROC_RANGE" ]; then
    cur="$(awk '{ print $1 " " $2 }' "$PROC_RANGE")"
  fi
  persisted="$(sysctl_file_value)"
  if [ "$cur" = "$target" ] && [ "$persisted" = "$target" ]; then
    step_status sysctl ok "ip_local_port_range already $target (runtime + $SYSCTL_FILE)"
    return 0
  fi

  local rows
  rows="$(listen_rows)"
  if [ -z "$rows" ]; then
    refused sysctl "cannot list TCP listeners (ss failed / not root) — will not move the ephemeral range blind"
    return 0
  fi
  conflicts="$(printf '%s\n' "$rows" | awk -v lo="$EPH_LO" -v hi="$EPH_HI" '$1 >= lo && $1 <= hi { print $1 "/" $2 "/" $3 }' | sort -u | head -n 20 | tr '\n' ' ')"
  cfg_hits="$(cfg_ports | awk -v lo="$EPH_LO" -v hi="$EPH_HI" '$1 >= lo && $1 <= hi' | sort -un | head -n 20 | tr '\n' ' ')"
  if [ -n "$conflicts" ] || [ -n "$cfg_hits" ]; then
    refused sysctl "listeners inside $EPH_LO-$EPH_HI would race outbound sockets for their port: ${conflicts:+listening: $conflicts}${cfg_hits:+cfg ports: $cfg_hits}"
    return 0
  fi

  # Later-sorting sysctl files would override the persisted value at boot.
  overrides="$(grep -lE '^[[:space:]]*net\.ipv4\.ip_local_port_range[[:space:]]*=' \
      "$ROOT"/etc/sysctl.d/*.conf "$ROOT"/etc/sysctl.conf 2>/dev/null | grep -vF "$SYSCTL_FILE" | tr '\n' ' ')"

  if [ "$MODE" = "dry-run" ]; then
    step_status sysctl would-apply "ip_local_port_range '${cur:-?}' -> '$target' (sysctl -w + $SYSCTL_FILE, persisted '${persisted:-none}'); no listener inside the new range; affects only future outbound sockets"
    [ -z "$overrides" ] || log "  NOTE: also set in: $overrides (a later file wins at boot — review it)"
    return 0
  fi

  if ! sysctl -w "net.ipv4.ip_local_port_range=$EPH_LO $EPH_HI" >/dev/null; then
    failed sysctl "sysctl -w net.ipv4.ip_local_port_range failed"
    return 0
  fi
  persist_sysctl_kv "$SYSCTL_FILE" "net.ipv4.ip_local_port_range" "$target"
  cur="$(awk '{ print $1 " " $2 }' "$PROC_RANGE" 2>/dev/null)"
  if [ "$cur" != "$target" ]; then
    failed sysctl "runtime value reads '$cur' after sysctl -w"
    return 0
  fi
  step_status sysctl applied "ip_local_port_range = $target (runtime + $SYSCTL_FILE)"
  [ -z "$overrides" ] || log "  NOTE: also set in: $overrides (a later file wins at boot — review it)"
}

# ── step: unbound cache ───────────────────────────────────────────

unbound_value() { awk -v k="$1" '$1 == k ":" { v = $2 } END { print v }' "$UNBOUND_CONF"; }

unbound_reload() {
  if systemctl reload unbound >/dev/null 2>&1; then echo "systemctl reload (SIGHUP)"; return 0; fi
  if command -v unbound-control >/dev/null 2>&1 && unbound-control reload >/dev/null 2>&1; then echo "unbound-control reload"; return 0; fi
  if [ "$ALLOW_UNBOUND_RESTART" = 1 ] && systemctl restart unbound >/dev/null 2>&1; then echo "systemctl restart (--allow-unbound-restart)"; return 0; fi
  return 1
}

step_unbound() {
  local msg rrset backup how
  if [ ! -f "$UNBOUND_CONF" ]; then
    step_status unbound skipped "no $UNBOUND_CONF (node has no netrun unbound config)"
    return 0
  fi
  msg="$(unbound_value msg-cache-size)"
  rrset="$(unbound_value rrset-cache-size)"
  if [ "$msg" = "$UNBOUND_MSG" ] && [ "$rrset" = "$UNBOUND_RRSET" ]; then
    step_status unbound ok "msg-cache-size $msg / rrset-cache-size $rrset already"
    return 0
  fi
  if [ -z "$msg" ] || [ -z "$rrset" ]; then
    refused unbound "msg-cache-size/rrset-cache-size not found in $UNBOUND_CONF (unexpected layout) — left untouched"
    return 0
  fi
  if ! command -v unbound-checkconf >/dev/null 2>&1; then
    refused unbound "unbound-checkconf not found — will not change a config it cannot validate"
    return 0
  fi
  if [ "$MODE" = "dry-run" ]; then
    step_status unbound would-apply "msg-cache-size $msg -> $UNBOUND_MSG, rrset-cache-size $rrset -> $UNBOUND_RRSET; unbound-checkconf; reload (SIGHUP; drops the cache once), no restart"
    return 0
  fi

  backup="$UNBOUND_CONF.bak-capacity-$(date +%Y%m%d%H%M%S)"
  cp -p "$UNBOUND_CONF" "$backup" || { failed unbound "cannot back up $UNBOUND_CONF"; return 0; }
  sed -E \
    -e "s|^([[:space:]]*msg-cache-size:)[[:space:]]*[^[:space:]#]+|\\1 $UNBOUND_MSG|" \
    -e "s|^([[:space:]]*rrset-cache-size:)[[:space:]]*[^[:space:]#]+|\\1 $UNBOUND_RRSET|" \
    "$backup" > "$TMPD/unbound.conf" && cat "$TMPD/unbound.conf" > "$UNBOUND_CONF"
  if ! unbound-checkconf >/dev/null 2>&1; then
    cat "$backup" > "$UNBOUND_CONF"
    failed unbound "unbound-checkconf rejected the new config — original restored (backup $backup)"
    return 0
  fi
  if how="$(unbound_reload)"; then
    if systemctl is-active --quiet unbound 2>/dev/null; then
      step_status unbound applied "msg-cache-size $UNBOUND_MSG / rrset-cache-size $UNBOUND_RRSET via $how (backup $backup)"
    else
      # Never leave the node without its resolver: put the old config back and start it.
      cat "$backup" > "$UNBOUND_CONF"
      systemctl start unbound >/dev/null 2>&1 || true
      failed unbound "unbound not active after $how — original config restored and unbound started"
    fi
  else
    step_status unbound partial "config written (backup $backup) but unbound could not be reloaded; takes effect at its next restart (or rerun with --allow-unbound-restart)"
    RC_PARTIAL=1
  fi
}

# ── step: legacy nft per-port rules ───────────────────────────────

# Classify the rules of the dumped chains against the dumped maps. Prints:
#   DEL <chain> <handle> <why>
#   MIG <chain> <handle> <map> <key> <counter>
#   KEEP <chain> <handle> <why>
# Two passes over the chains: pass 1 settles the tcp port rules (so a counter
# that this run migrates into the map counts as map-metered), pass 2 the ip6
# egress rules, which sit EARLIER in old chains than the port rules.
# Pure (files in, plan out) — exercised by the fixture test.
nft_plan() {
  awk -v fin="$1" -v fout="$2" -v fmin="$3" -v fmout="$4" '
    function elems(line, which,   s, m, k, v) {
      s = line
      while (match(s, /[0-9]+[ \t]*:[ \t]*"?proxy_[0-9]+_(in6|in|out)"?/)) {
        m = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
        k = m; sub(/[ \t]*:.*/, "", k)
        v = m; sub(/^[0-9]+[ \t]*:[ \t]*"?/, "", v); sub(/"$/, "", v)
        if (which == "in") { min[k] = v; incnt[v] = 1 } else { mout[k] = v; outcnt[v] = 1 }
      }
    }
    function handle_of(line,   h) {
      if (!match(line, /# handle [0-9]+/)) return ""
      h = substr(line, RSTART, RLENGTH); sub(/# handle /, "", h); return h
    }
    function unq(s) { gsub(/"/, "", s); return s }
    FNR == 1 { pass = ++visits[FILENAME] }
    FILENAME == fmin  { elems($0, "in");  next }
    FILENAME == fmout { elems($0, "out"); next }
    {
      chain = (FILENAME == fin) ? "input" : "output"
      h = handle_of($0)
      if (h == "") next
      if ($0 ~ /@|[ \t]map[ \t]|[ \t](drop|accept|reject|jump|goto|return|queue)([ \t]|$)/) next   # map/set/verdict rules: never ours
      is_tcp = ($1 == "tcp" && ($2 == "dport" || $2 == "sport") && $3 ~ /^[0-9]+$/ && $4 == "counter" && $5 == "name")
      is_ip6 = ($1 == "ip6" && ($2 == "saddr" || $2 == "daddr") && $4 == "counter" && $5 == "name")
      if (pass == 1 && is_ip6) next
      if (pass == 2 && !is_ip6) next
      if (is_tcp) {
        ctr = unq($6); port = $3
        if (ctr !~ /^proxy_[0-9]+_(in|out)$/) { print "KEEP", chain, h, "unexpected-counter:" ctr; next }
        if (chain == "input" && $2 == "dport" && ctr ~ /_in$/)        { mp = "cmap_in" }
        else if (chain == "output" && $2 == "sport" && ctr ~ /_out$/) { mp = "cmap_out" }
        else { print "KEEP", chain, h, "direction-mismatch:" $2 "/" ctr; next }
        cur = (mp == "cmap_in") ? ((port in min) ? min[port] : "") : ((port in mout) ? mout[port] : "")
        if (cur == "" && ((mp SUBSEP port) in planned)) cur = planned[mp, port]
        if (cur == ctr) { print "DEL", chain, h, "double-counted:" port "->" ctr; next }
        if (cur != "")  { print "KEEP", chain, h, "map-points-elsewhere:" port "->" cur "(rule " ctr ")"; next }
        planned[mp, port] = ctr
        if (mp == "cmap_in") incnt[ctr] = 1; else outcnt[ctr] = 1
        print "MIG", chain, h, mp, port, ctr
        next
      }
      if (is_ip6) {
        ctr = unq($6)
        if ($2 == "daddr" && ctr ~ /^proxy_[0-9]+_in6$/) { print "DEL", chain, h, "retired-in6:" ctr; next }
        if ($2 == "saddr" && ctr ~ /^proxy_[0-9]+_out$/) {
          if (ctr in outcnt) { print "DEL", chain, h, "egress-v6-double-counted:" ctr; next }
          print "KEEP", chain, h, "egress-v6-only-metering:" ctr; next
        }
        print "KEEP", chain, h, "unexpected-ip6-rule:" ctr; next
      }
      if ($0 ~ /tcp (dport|sport) [0-9]+[ \t]/ || $0 ~ /ip6 (saddr|daddr) [0-9a-fA-F:]+[ \t]/) {
        print "KEEP", chain, h, "unrecognised-per-port-rule"
      }
    }' "$3" "$4" "$1" "$2" "$1" "$2"
}

step_nft() {
  local fin="$TMPD/chain_in" fout="$TMPD/chain_out" fmin="$TMPD/map_in" fmout="$TMPD/map_out" plan="$TMPD/nft_plan" batch="$TMPD/nft_batch"
  local n_del n_mig n_keep
  if ! command -v nft >/dev/null 2>&1 || ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    step_status nft skipped "no inet $NFT_TABLE table (or nft unavailable / not root)"
    return 0
  fi
  nft -a list chain inet "$NFT_TABLE" input > "$fin" 2>/dev/null || : > "$fin"
  nft -a list chain inet "$NFT_TABLE" output > "$fout" 2>/dev/null || : > "$fout"
  if ! grep -q 'map @cmap_in' "$fin" || ! grep -q 'map @cmap_out' "$fout"; then
    step_status nft skipped "map-based accounting (@cmap_in/@cmap_out rules) not present — legacy rules left as they are (regenerate the node's batches first)"
    return 0
  fi
  nft list map inet "$NFT_TABLE" cmap_in > "$fmin" 2>/dev/null || : > "$fmin"
  nft list map inet "$NFT_TABLE" cmap_out > "$fmout" 2>/dev/null || : > "$fmout"
  nft_plan "$fin" "$fout" "$fmin" "$fmout" > "$plan"
  n_del="$(grep -c '^DEL ' "$plan")"
  n_mig="$(grep -c '^MIG ' "$plan")"
  n_keep="$(grep -c '^KEEP ' "$plan")"
  if [ "$n_del" -eq 0 ] && [ "$n_mig" -eq 0 ]; then
    step_status nft ok "no removable legacy per-port rules (kept: $n_keep)"
    [ "$n_keep" -eq 0 ] || grep '^KEEP ' "$plan" | head -n 5 | sed 's/^/[capacity-tuning]     /'
    return 0
  fi
  if [ "$MODE" = "dry-run" ]; then
    step_status nft would-apply "delete $n_del double-counting + migrate $n_mig map-less legacy per-port rule(s) in one atomic nft -f; keep $n_keep"
    grep -E '^(DEL|MIG) ' "$plan" | head -n 5 | sed 's/^/[capacity-tuning]     /'
    [ "$n_keep" -eq 0 ] || grep '^KEEP ' "$plan" | head -n 5 | sed 's/^/[capacity-tuning]     /'
    return 0
  fi
  if [ -e "$GENLOCK" ] && [ "$IGNORE_GENLOCK" != 1 ]; then
    refused nft "a generation holds $GENLOCK — rerun when it is done (or --ignore-genlock if the lock is stale)"
    return 0
  fi
  {
    awk '$1 == "MIG" { printf "add element inet %s %s { %s : \"%s\" }\n", tbl, $4, $5, $6 }' tbl="$NFT_TABLE" "$plan"
    awk '$1 == "MIG" || $1 == "DEL" { printf "delete rule inet %s %s handle %s\n", tbl, $2, $3 }' tbl="$NFT_TABLE" "$plan"
  } > "$batch"
  if ! nft -f "$batch" 2>"$TMPD/nft_err"; then
    failed nft "atomic nft -f rejected (nothing changed): $(head -c 300 "$TMPD/nft_err" | tr '\n' ' ') — rerun to re-plan"
    return 0
  fi
  if [ -f "$NFT_PERSIST" ]; then cp -p "$NFT_PERSIST" "$NFT_PERSIST.bak-capacity-$(date +%Y%m%d%H%M%S)" 2>/dev/null || true; fi
  nft list ruleset > "$NFT_PERSIST" 2>/dev/null || log "  WARNING: could not persist the ruleset to $NFT_PERSIST"
  step_status nft applied "deleted $n_del + migrated $n_mig legacy per-port rule(s); kept $n_keep; ruleset persisted to $NFT_PERSIST"
}

# ── step: boot-time IPv6 restore script ───────────────────────────

step_ipv6restore() {
  if [ ! -f "$RESTORE_UNIT" ] && [ ! -f "$RESTORE_TARGET" ]; then
    step_status ipv6restore skipped "netrun-ipv6-restore is not installed on this node"
    return 0
  fi
  if [ -z "$RESTORE_SRC" ] || [ ! -f "$RESTORE_SRC" ]; then
    step_status ipv6restore skipped "source deploy/node/netrun-ipv6-restore.sh not found next to this script"
    return 0
  fi
  if [ -f "$RESTORE_TARGET" ] && cmp -s "$RESTORE_SRC" "$RESTORE_TARGET"; then
    step_status ipv6restore ok "$RESTORE_TARGET already the ip -batch + nodad version"
    return 0
  fi
  if [ "$MODE" = "dry-run" ]; then
    step_status ipv6restore would-apply "replace $RESTORE_TARGET with the ip -batch + nodad version (used at next boot only; not run now)"
    return 0
  fi
  if [ -f "$RESTORE_TARGET" ]; then cp -p "$RESTORE_TARGET" "$RESTORE_TARGET.bak-capacity-$(date +%Y%m%d%H%M%S)"; fi
  mkdir -p "$(dirname "$RESTORE_TARGET")"
  cat "$RESTORE_SRC" > "$RESTORE_TARGET.new" && chmod 0755 "$RESTORE_TARGET.new" && mv -f "$RESTORE_TARGET.new" "$RESTORE_TARGET" \
    || { failed ipv6restore "could not install $RESTORE_TARGET"; return 0; }
  step_status ipv6restore applied "$RESTORE_TARGET = ip -batch + nodad version (next boot)"
}

# ── step: conntrack ceiling that survives reboots (opt-in) ─────────

# MemTotal kB -> one entry per 8 KB, rounded down to a power of two, clamped
# to 65536..1048576 (same formula as install_node_v2.sh / node_followup_v2.sh).
conntrack_max_for_mem_kb() {
  local kb="${1:-0}" v=65536
  case "$kb" in ''|*[!0-9]*) kb=0 ;; esac
  while [ "$v" -lt 1048576 ] && [ $((v * 2)) -le $((kb / 8)) ]; do v=$((v * 2)); done
  echo "$v"
}

sysctl_file_key() { # KEY -> persisted value in $SYSCTL_FILE (last one wins), or empty
  [ -f "$SYSCTL_FILE" ] || return 0
  awk -F= -v k="$1" '{ key = $1; gsub(/[ \t]/, "", key) } key == k { v = $2 } END { gsub(/^[ \t]+|[ \t]+$/, "", v); print v }' "$SYSCTL_FILE"
}

# Write TEXT (plus a final newline) to FILE atomically.
write_text_file() {
  local file="$1" text="$2"
  mkdir -p "$(dirname "$file")" || return 1
  printf '%s\n' "$text" > "$file.new.$$" && mv -f "$file.new.$$" "$file"
}

step_conntrack() {
  local mem_kb target persisted runtime count need=() overrides
  mem_kb="$(awk '/^MemTotal:/ { print $2 }' "$MEMINFO" 2>/dev/null)"
  if [ -n "$CT_MAX_OVERRIDE" ]; then
    target="$CT_MAX_OVERRIDE"
  elif [ -n "$mem_kb" ]; then
    target="$(conntrack_max_for_mem_kb "$mem_kb")"
  else
    refused conntrack "cannot read MemTotal from $MEMINFO — pass --conntrack-max N"
    return 0
  fi
  persisted="$(sysctl_file_key net.netfilter.nf_conntrack_max)"
  runtime="$(cat "$PROC_CT_MAX" 2>/dev/null || true)"
  count="$(cat "$PROC_CT_COUNT" 2>/dev/null || true)"

  [ "$(cat "$CT_MODULES_FILE" 2>/dev/null)" = "$CT_MODULES_TEXT" ] || need+=("modules-load")
  [ "$(cat "$CT_UDEV_RULE" 2>/dev/null)" = "$CT_UDEV_TEXT" ] || need+=("udev-rule")
  [ "$persisted" = "$target" ] || need+=("persist")
  if [ -n "$runtime" ] && [ "$runtime" -lt "$target" ] 2>/dev/null; then need+=("runtime-raise"); fi
  if [ "${#need[@]}" -eq 0 ]; then
    step_status conntrack ok "nf_conntrack_max $target persisted + loaded at boot (runtime ${runtime:-module not loaded}${count:+, in use $count})"
    return 0
  fi

  # Later-sorting sysctl files would override the persisted value at boot.
  overrides="$(grep -lE '^[[:space:]]*net\.netfilter\.nf_conntrack_max[[:space:]]*=' \
      "$ROOT"/etc/sysctl.d/*.conf "$ROOT"/etc/sysctl.conf 2>/dev/null | grep -vF "$SYSCTL_FILE" | tr '\n' ' ')"

  if [ "$MODE" = "dry-run" ]; then
    step_status conntrack would-apply "nf_conntrack_max -> $target (MemTotal ${mem_kb:-?} kB${CT_MAX_OVERRIDE:+, --conntrack-max}); persisted '${persisted:-none}', runtime '${runtime:-module not loaded}'${count:+, in use $count}; do: ${need[*]}"
    [ -z "$overrides" ] || log "  NOTE: also set in: $overrides (a later file wins at boot — review it)"
    return 0
  fi

  write_text_file "$CT_MODULES_FILE" "$CT_MODULES_TEXT" || { failed conntrack "cannot write $CT_MODULES_FILE"; return 0; }
  write_text_file "$CT_UDEV_RULE" "$CT_UDEV_TEXT" || { failed conntrack "cannot write $CT_UDEV_RULE"; return 0; }
  udevadm control --reload >/dev/null 2>&1 || true
  persist_sysctl_kv "$SYSCTL_FILE" "net.netfilter.nf_conntrack_max" "$target"
  local now_note
  if [ -z "$runtime" ]; then
    now_note="module not loaded now: applies when it loads (udev rule) and at boot"
  elif [ "$runtime" -lt "$target" ] 2>/dev/null; then
    if ! sysctl -w "net.netfilter.nf_conntrack_max=$target" >/dev/null; then
      failed conntrack "sysctl -w net.netfilter.nf_conntrack_max=$target failed (boot files written)"
      return 0
    fi
    runtime="$(cat "$PROC_CT_MAX" 2>/dev/null || true)"
    if [ "$runtime" != "$target" ]; then
      failed conntrack "runtime value reads '$runtime' after sysctl -w (boot files written)"
      return 0
    fi
    now_note="runtime raised to $target"
  else
    now_note="runtime $runtime >= target, left as is (target applies from the next boot)"
  fi
  step_status conntrack applied "nf_conntrack_max = $target in $SYSCTL_FILE + $CT_MODULES_FILE + $CT_UDEV_RULE; $now_note"
  [ -z "$overrides" ] || log "  NOTE: also set in: $overrides (a later file wins at boot — review it)"
}

# ── main ──────────────────────────────────────────────────────────

log "mode: $MODE | steps: $ONLY | ephemeral range target: $EPH_LO-$EPH_HI${ROOT:+ | root: $ROOT}"
log "never touches 3proxy processes, listeners, ports or cfg files"
audit_listeners
want sysctl && step_sysctl
want unbound && step_unbound
want nft && step_nft
want ipv6restore && step_ipv6restore
want conntrack && step_conntrack

if [ "$RC_FAILED" = 1 ]; then log "result: a step FAILED (see above)"; exit 1; fi
if [ "$RC_REFUSED" = 1 ]; then log "result: a step was REFUSED by a safety check (nothing changed for it)"; exit 2; fi
if [ "$RC_PARTIAL" = 1 ]; then log "result: applied PARTIALLY (see above)"; exit 3; fi
if [ "$MODE" = "dry-run" ]; then log "result: dry-run only — rerun with --apply to make these changes"; else log "result: done"; fi
exit 0
