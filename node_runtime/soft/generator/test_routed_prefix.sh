#!/usr/bin/env bash
# Routed prefix (NETRUN_IPV6_ROUTED_PREFIX) — generator tests. Same pattern as
# test_capacity_18k.sh: pull the real functions out of proxyyy_automated.sh and
# run them with controlled globals (no root, no 3proxy, no network).
#   bash node_runtime/soft/generator/test_routed_prefix.sh
set -uo pipefail

GEN="$(cd "$(dirname "$0")" && pwd -P)/proxyyy_automated.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
extract() { sed -n "/^function $1()/,/^}/p" "$GEN"; }

for f in netrun_setting routed_ipv6_addresses routed_list_inside generate_ipv6_addresses_if_needed \
         http_listen_ip_for_node create_startup_script; do
  body="$(extract "$f")"
  [ -n "$body" ] || fail "function $f not found in generator"
  eval "$body"
done

# /64 of an address, as python sees it (shell-independent formatting).
nets_of() { python3 -c '
import ipaddress, sys
for l in open(sys.argv[1]):
    l = l.strip()
    if l: print(int(ipaddress.IPv6Address(l)) >> 64)' "$1"; }
all_inside() { python3 -c '
import ipaddress, sys
p = ipaddress.IPv6Network(sys.argv[1])
sys.exit(0 if all(ipaddress.IPv6Address(l.strip()) in p for l in open(sys.argv[2]) if l.strip()) else 1)' "$1" "$2"; }

DIR="$TMP/proxyserver"; mkdir -p "$DIR"

# ── 1. every proxy gets its own /64 of the prefix ─────────────────
routed_ipv6_addresses 2001:db8:a9::/48 3000 "$DIR" "$DIR/ipv6_18100.list" > "$DIR/ipv6_18100.list" \
  || fail "allocation of 3000 /64s from a /48 failed"
[ "$(wc -l < "$DIR/ipv6_18100.list" | tr -d ' ')" = 3000 ] || fail "not 3000 addresses"
all_inside 2001:db8:a9::/48 "$DIR/ipv6_18100.list" || fail "an address outside the prefix"
[ "$(nets_of "$DIR/ipv6_18100.list" | sort -u | wc -l | tr -d ' ')" = 3000 ] || fail "two proxies share a /64"
ok "3000 addresses of a /48, 3000 distinct /64s, all inside"

# ── 2. a second batch never reuses another batch's /64 ────────────
routed_ipv6_addresses 2001:db8:a9::/48 3000 "$DIR" "$DIR/ipv6_19100.list" > "$DIR/ipv6_19100.list" \
  || fail "second batch failed"
dup="$(cat <(nets_of "$DIR/ipv6_18100.list") <(nets_of "$DIR/ipv6_19100.list") | sort | uniq -d | wc -l | tr -d ' ')"
[ "$dup" = 0 ] || fail "batches share $dup /64s"
# Addresses of other prefixes (the NIC's /64) and junk lines do not count as used.
printf '2001:19f0:5c01:cdf::1\nnot-an-address\n' > "$DIR/ipv6_20100.list"
ok "batches take disjoint /64s; foreign lines ignored"

# ── 3. exhaustion fails closed ────────────────────────────────────
D2="$TMP/small"; mkdir -p "$D2"
routed_ipv6_addresses 2001:db8:b::/60 16 "$D2" "$D2/ipv6_1.list" > "$D2/ipv6_1.list" || fail "/60 has 16 /64s"
if routed_ipv6_addresses 2001:db8:b::/60 1 "$D2" "$D2/ipv6_2.list" > /dev/null 2>&1; then
  fail "allocated past the end of the prefix"
fi
if routed_ipv6_addresses 2001:db8:b::/60 17 "$TMP/empty-dir" "$TMP/x.list" > /dev/null 2>&1; then
  fail "allocated 17 /64s of a /60"
fi
if routed_ipv6_addresses 2001:db8:b::/72 1 "$TMP/empty-dir" "$TMP/x.list" > /dev/null 2>&1; then
  fail "accepted a prefix longer than /64"
fi
ok "a full prefix, an oversized request and a /72 are refused"

# ── 4. routed_list_inside ─────────────────────────────────────────
routed_list_inside 2001:db8:a9::/48 "$DIR/ipv6_18100.list" || fail "own list not recognised as inside"
! routed_list_inside 2001:db8:a9::/48 "$DIR/ipv6_20100.list" || fail "a foreign list counted as inside"
: > "$TMP/empty.list"
! routed_list_inside 2001:db8:a9::/48 "$TMP/empty.list" || fail "an empty list counted as inside"
ok "routed_list_inside: own / foreign / empty"

# ── 5. generate_ipv6_addresses_if_needed picks the routed path ────
(
  log_err_and_exit() { echo "ERR: $1"; exit 3; }
  get_subnet_mask() { echo "SHOULD-NOT-BE-CALLED"; }
  routed_prefix=2001:db8:c::/48; proxy_count=50; proxy_dir="$TMP/gen"; mkdir -p "$proxy_dir"
  random_ipv6_list_file="$proxy_dir/ipv6_30000.list"
  generate_ipv6_addresses_if_needed > /dev/null
  all_inside 2001:db8:c::/48 "$random_ipv6_list_file" || exit 4
  [ "$(nets_of "$random_ipv6_list_file" | sort -u | wc -l | tr -d ' ')" = 50 ] || exit 5
  # A failure leaves no list behind.
  random_ipv6_list_file="$proxy_dir/ipv6_31000.list"; routed_prefix=2001:db8:d::/64; proxy_count=2
  out="$(generate_ipv6_addresses_if_needed 2>/dev/null)"; [ $? = 3 ] || exit 6
  [ ! -e "$random_ipv6_list_file" ] && [ ! -e "$random_ipv6_list_file.tmp" ] || exit 7
) || fail "generate_ipv6_addresses_if_needed routed path (exit $?)"
ok "generate_ipv6_addresses_if_needed: routed list, failure leaves nothing"

# ── 6. startup script: routed batch adds nothing to the NIC ───────
startup() { # list-content routed_prefix -> path of the script
  local home="$TMP/home-$RANDOM"
  (
    set +u
    mkdir -p "$home/proxyserver/3proxy/bin"
    printf '#!/bin/sh\nexit 0\n' > "$home/proxyserver/3proxy/bin/3proxy"; chmod +x "$home/proxyserver/3proxy/bin/3proxy"
    is_auth_used() { return 0; }
    bash_location="$(command -v bash)"; user_home_dir="$home"
    start_port=18100; last_port=18101; proxy_count=2; proxies_type=dual; mode_flag=-6
    backconnect_ipv4=45.32.10.20; interface_name=eth9; subnet=64
    dns_nserver_lines=$'  nserver 127.0.0.1\n  nserver ::1'; proxy_maxconn=200
    NETRUN_ENV_FILE="$TMP/none.env"; routed_prefix="$2"
    user=""; password=""; use_random_auth=true; allowed_hosts=""; denied_hosts=""
    proxyserver_config_path="$home/proxyserver/3proxy/3proxy_18100.cfg"
    random_ipv6_list_file="$home/proxyserver/ipv6_18100.list"
    random_users_list_file="$home/proxyserver/random_users_18100.list"
    startup_script_path="$home/proxyserver/proxy-startup_18100.sh"
    printf '%b' "$1" > "$random_ipv6_list_file"
    printf 'u1:p1\nu2:p2\n' > "$random_users_list_file"
    create_startup_script > /dev/null
  ) || fail "create_startup_script failed"
  echo "$home/proxyserver/proxy-startup_18100.sh"
}
run_startup() { # script -> file of recorded ip calls
  local calls="$TMP/ip_calls-$RANDOM"; : > "$calls"
  mkdir -p "$TMP/stub"
  printf '#!/usr/bin/env bash\necho "ip $*" >> "%s"\nexit 0\n' "$calls" > "$TMP/stub/ip"
  printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/sleep"
  chmod +x "$TMP/stub/ip" "$TMP/stub/sleep"
  NETRUN_3PROXY_SPAWN=/nonexistent PATH="$TMP/stub:$PATH" bash "$1" > /dev/null 2>&1 || true
  echo "$calls"
}
S="$(startup '2001:db8:a9:1::a\n2001:db8:a9:2::b\n' 2001:db8:a9::/48)"
calls="$(run_startup "$S")"
! grep -q -- '-batch' "$calls" || fail "a routed batch still adds addresses to the NIC: $(cat "$calls")"
CFG="$(dirname "$S")/3proxy/3proxy_18100.cfg"
grep -q -- '-e2001:db8:a9:1::a' "$CFG" && grep -q -- '-e2001:db8:a9:2::b' "$CFG" \
  || fail "routed addresses not bound with -e in the cfg"
S="$(startup '2001:db8:0:1::a\n2001:db8:0:1::b\n' 2001:db8:a9::/48)"
calls="$(run_startup "$S")"
grep -q -- '-batch' "$calls" || fail "a batch outside the routed prefix lost its NIC anchors"
S="$(startup '2001:db8:0:1::a\n2001:db8:0:1::b\n' "")"
calls="$(run_startup "$S")"
grep -q -- '-batch' "$calls" || fail "no routed prefix: anchors must still be added"
ok "startup script: routed batch adds no anchors; NIC batches unchanged"

echo "all $PASS routed-prefix checks passed"
