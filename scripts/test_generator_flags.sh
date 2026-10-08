#!/usr/bin/env bash
# Audit CLN-03 / CLN-04 / speed — generator tests (no root, no network): the
# real code is pulled out of node_runtime/soft/generator/proxyyy_automated.sh
# and run with controlled globals and stubbed commands.
#   1. legacy flags (--dns-country, --dns-servers, --network-profile,
#      --tcp-timestamps-mode, --self-check-samples, --skip-self-check) are
#      accepted and IGNORED (DNS stays the local unbound);
#   2. maxconn: 512 by default (listen backlog 33), NETRUN_3PROXY_MAXCONN
#      (env, else /etc/netrun/netrun.env) and --maxconn override it;
#   3. the generator never writes sysctl, never builds 3proxy, never touches
#      the MSS / edge-normalization table, never picks third-party DNS;
#   4. batch IPv6 generation: one od + one awk for the whole batch, unique,
#      same address layout for /64, /56 and /48, existing addresses skipped,
#      and ONE `ip -6 addr` snapshot per batch (was one per address);
#   5. the start-up script spawns through the spawn helper, refuses a missing
#      address list, and NETRUN_ANCHOR_DEPRECATE=0 / off / OFF (env or
#      netrun.env) drops preferred_lft 0.
#   bash scripts/test_generator_flags.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
GEN="$ROOT_DIR/node_runtime/soft/generator/proxyyy_automated.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
extract() { sed -n "/^function $1()/,/^}/p" "$GEN"; }

sed 's/&>>/>>/g' "$GEN" | bash -n || fail "generator syntax"

# A GNU-getopt stand-in (the generator needs GNU long options; macOS ships BSD).
getopt() {
  local short="" long="" out="" pos="" a name ch
  while [ $# -gt 0 ]; do
    case "$1" in -o) short="$2"; shift 2 ;; --long) long="$2"; shift 2 ;; --) shift; break ;; *) shift ;; esac
  done
  while [ $# -gt 0 ]; do
    a="$1"; shift
    case "$a" in
      --) while [ $# -gt 0 ]; do pos="$pos '$1'"; shift; done ;;
      --*=*) out="$out ${a%%=*} '${a#*=}'" ;;
      --*)
        name="${a#--}"
        if [[ ",$long," == *",$name:,"* ]]; then out="$out $a '$1'"; shift
        elif [[ ",$long," == *",$name,"* ]]; then out="$out $a"
        else echo "getopt: unrecognized option '$a'" >&2; return 1; fi ;;
      -?)
        ch="${a#-}"
        if [[ "$short" == *"$ch:"* ]]; then out="$out $a '$1'"; shift; else out="$out $a"; fi ;;
      *) pos="$pos '$a'" ;;
    esac
  done
  echo "$out --$pos"
}

# The generator's option block: getopt .. defaults .. the parse loop.
awk '/^options=\$\(getopt / { on = 1 } on { print } on && /^done$/ { exit }' "$GEN" > "$TMP/parse.sh"
grep -q 'while true; do' "$TMP/parse.sh" || fail "could not extract the option block"
eval "$(extract netrun_setting)"
eval "$(extract check_startup_parameters)"

parse() { # args... -> prints "var=value" lines of interest
  (
    usage() { echo "USAGE"; exit 4; }
    ip() { :; }
    set -- "$@"
    . "$TMP/parse.sh"
    for v in start_port proxy_count proxies_type ipv6_policy use_random_auth proxy_maxconn \
             network_profile tcp_timestamps_mode dns_country run_self_check self_check_samples; do
      printf '%s=%s\n' "$v" "${!v-<unset>}"
    done
  )
}

# ── 1. legacy flags accepted and ignored ──────────────────────────
out="$(NETRUN_ENV_FILE="$TMP/none.env" parse --start-port 18100 --proxy-count 5 --proxies-type dual --random \
  --ipv6-policy ipv6_only --network-profile high_compatibility --dns-country US --tcp-timestamps-mode off \
  --dns-servers 9.9.9.9,149.112.112.112 --self-check-samples 3 --skip-self-check true --port-ipv6-map-file /tmp/m.csv)"
echo "$out" | grep -qx 'start_port=18100' || fail "start_port not parsed: $out"
echo "$out" | grep -qx 'proxy_count=5' || fail "proxy_count after legacy flags: $out"
echo "$out" | grep -qx 'proxies_type=dual' || fail "proxies_type: $out"
echo "$out" | grep -qx 'ipv6_policy=ipv6_only' || fail "ipv6_policy: $out"
echo "$out" | grep -qx 'use_random_auth=true' || fail "--random: $out"
for v in network_profile tcp_timestamps_mode dns_country run_self_check self_check_samples; do
  echo "$out" | grep -qx "$v=<unset>" || fail "legacy flag still sets $v: $out"
done
# Garbage in a legacy flag is not an error any more (it was a usage error).
out="$(NETRUN_ENV_FILE="$TMP/none.env" parse --start-port 18100 --proxy-count 1 --network-profile bogus --tcp-timestamps-mode nope)"
echo "$out" | grep -qx 'start_port=18100' || fail "bogus legacy value rejected: $out"
(
  log_err_print_usage_and_exit() { echo "REJECT: $1"; exit 3; }
  log_err_and_exit() { echo "REJECT: $1"; exit 3; }
  cat() { if [[ "${1:-}" == /sys/class/net/* ]]; then echo up; else command cat "$@"; fi; }
  proxies_type=dual; start_port=18100; proxy_count=1; min_listen_port=8100; user=""; password=""
  use_random_auth=true; ipv6_policy=ipv6_only; subnet=64; rotating_interval=0; backconnect_ipv4=""
  allowed_hosts=""; denied_hosts=""; proxy_maxconn=512; interface_name=eth0
  network_profile=bogus; tcp_timestamps_mode=nope; dns_country=XYZ1; self_check_samples=abc
  check_startup_parameters >/dev/null 2>&1 && echo ACCEPT
) | grep -qx ACCEPT || fail "check_startup_parameters still validates legacy labels"
# --dns-servers: the cfg's resolvers stay the local unbound (the spawn helper
# would rewrite anything else at the first start anyway).
eval "$(extract configure_dns_servers)"
out="$(
  usage() { echo "USAGE"; exit 4; }
  ip() { :; }
  set -- --start-port 18100 --dns-servers 9.9.9.9,149.112.112.112 --proxy-count 2
  NETRUN_ENV_FILE="$TMP/none.env"
  . "$TMP/parse.sh"
  configure_dns_servers >/dev/null
  printf 'proxy_count=%s\nstrategy=%s\nservers=%s\nlines=%s\n' "$proxy_count" "$dns_selection_strategy" "$dns_selected_servers_csv" "$(printf '%s' "$dns_nserver_lines" | tr '\n' '|')"
)"
echo "$out" | grep -qx 'proxy_count=2' || fail "--dns-servers swallowed the next flag: $out"
echo "$out" | grep -qx 'strategy=local_unbound' || fail "--dns-servers still overrides: $out"
echo "$out" | grep -qx 'servers=127.0.0.1,::1' || fail "dns servers: $out"
echo "$out" | grep -qx 'lines=  nserver 127.0.0.1|  nserver ::1' || fail "nserver lines: $out"
! grep -q 'manual_override' "$GEN" || fail "the --dns-servers manual_override branch is still there"
grep -q -- '--skip-self-check' "$GEN" || fail "the agent's scriptSupportsFlag probe needs the --skip-self-check text"
grep -q -- '--runtime-only' "$GEN" || fail "--runtime-only text gone"
ok "legacy --dns-country/--dns-servers/--network-profile/--tcp-timestamps-mode/--self-check-samples/--skip-self-check accepted and ignored"

# ── 2. maxconn default 512, setting + flag override ───────────────
out="$(NETRUN_ENV_FILE="$TMP/none.env" parse --start-port 18100)"
echo "$out" | grep -qx 'proxy_maxconn=512' || fail "default maxconn: $out"
out="$(NETRUN_3PROXY_MAXCONN=200 NETRUN_ENV_FILE="$TMP/none.env" parse --start-port 18100)"
echo "$out" | grep -qx 'proxy_maxconn=200' || fail "env maxconn: $out"
printf 'NETRUN_3PROXY_MAXCONN=384\n' > "$TMP/netrun.env"
out="$(NETRUN_ENV_FILE="$TMP/netrun.env" parse --start-port 18100)"
echo "$out" | grep -qx 'proxy_maxconn=384' || fail "netrun.env maxconn: $out"
out="$(NETRUN_ENV_FILE="$TMP/netrun.env" parse --start-port 18100 --maxconn 300)"
echo "$out" | grep -qx 'proxy_maxconn=300' || fail "--maxconn must win: $out"
ok "maxconn: 512 default (backlog 33), NETRUN_3PROXY_MAXCONN env / netrun.env, --maxconn wins"

# ── 3. no sysctl / no 3proxy build / no normalization table / no geo DNS ──
code="$(grep -vE '^[[:space:]]*#' "$GEN")"
! printf '%s\n' "$code" | grep -qE 'sysctl -p|/etc/sysctl\.conf' || fail "generator still writes sysctl"
! printf '%s\n' "$code" | grep -qE 'github\.com/3proxy|make -f Makefile|wget ' || fail "generator still downloads/builds 3proxy"
! printf '%s\n' "$code" | grep -qE 'maxseg|proxy_normalization|hoplimit set|ttl set' || fail "generator still touches the normalization table"
! printf '%s\n' "$code" | grep -qE 'select_dns|seed\.json|ipapi\.co|ipwho\.is' || fail "generator still has the geo-DNS selector"
for f in apply_network_profile_sysctl setup_nftables_edge_normalization resolve_network_profile_settings \
         detect_country_code_by_ip source_dns_selector_or_die install_3proxy run_dualstack_self_check; do
  [ -z "$(extract "$f")" ] || fail "dead function $f still defined"
done
[ ! -e "$ROOT_DIR/dns" ] || fail "dns/ (geo-seed resolvers) still in the repo"
[ ! -e "$ROOT_DIR/scripts/migrate_dns_inplace.sh" ] || fail "migrate_dns_inplace.sh still in the repo"
[ ! -e "$ROOT_DIR/scripts/harden_only.sh" ] || fail "harden_only.sh (ip_local_port_range 10000-65000) still in the repo"
ok "generator: no sysctl writes, no 3proxy download/build, no MSS/edge rules, no geo-seed DNS; dns/ + legacy scripts gone"

# ── 4. batch IPv6 generation ──────────────────────────────────────
eval "$(extract random_ipv6_suffixes)"
eval "$(extract generate_ipv6_addresses_if_needed)"
out="$(random_ipv6_suffixes 2001:db8:0:1 64 1500)" || fail "random_ipv6_suffixes /64"
[ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = 1500 ] || fail "count"
[ "$(printf '%s\n' "$out" | sort -u | wc -l | tr -d ' ')" = 1500 ] || fail "not unique"
printf '%s\n' "$out" | grep -qvE '^2001:db8:0:1:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}$' && fail "/64 layout: $(printf '%s\n' "$out" | head -3)"
out="$(random_ipv6_suffixes 2001:db8:0:a1 56 5)"
printf '%s\n' "$out" | grep -qvE '^2001:db8:0:a1[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}$' && fail "/56 layout: $out"
out="$(random_ipv6_suffixes 2001:db8:5 48 5)"
printf '%s\n' "$out" | grep -qvE '^2001:db8:5(:[0-9a-f]{4}){5}$' && fail "/48 layout: $out"
# Deterministic bytes: the first candidate is "seen" (already on the NIC) and skipped.
od() { awk 'BEGIN { for (i = 0; i < 64; i++) printf "%d ", (i < 16 ? 1 : 2); print "" }'; }
printf '2001:db8:0:1:1111:1111:1111:1111\n' > "$TMP/seen"
out="$(random_ipv6_suffixes 2001:db8:0:1 64 1 "$TMP/seen")"
[ "$out" = "2001:db8:0:1:2222:2222:2222:2222" ] || fail "seen address not skipped: $out"
out="$(random_ipv6_suffixes 2001:db8:0:1 64 2 "$TMP/seen")"
[ -z "$out" ] || [ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = 1 ] || fail "duplicate candidate emitted twice: $out"
random_ipv6_suffixes 2001:db8:0:1 64 3 "$TMP/seen" >/dev/null && fail "ran out of unique candidates but exited 0"
unset -f od
(
  IP_CALLS="$TMP/ip_calls"; : > "$IP_CALLS"
  ip() { echo "ip $*" >> "$IP_CALLS"; printf '1: lo\n    inet6 ::1/128 scope host\n2: eth0\n    inet6 2001:db8:0:1::5/64 scope global\n    inet6 fe80::1/64 scope link\n'; }
  # The real one parses `ip -6 addr` with grep -P (GNU only): same contract —
  # one ip call, sets the global subnet_mask, which only sticks when it is
  # called in the generator's own shell (not inside $(...)).
  get_subnet_mask() { if [ -z "$subnet_mask" ]; then ip -6 addr >/dev/null; subnet_mask="2001:db8:0:1"; fi; echo "$subnet_mask"; }
  log_err_and_exit() { echo "EXIT $1"; exit 3; }
  subnet=64; subnet_mask=""; proxy_count=200; random_ipv6_list_file="$TMP/ipv6_18100.list"; routed_prefix=""
  generate_ipv6_addresses_if_needed >/dev/null
  [ "$(wc -l < "$TMP/ipv6_18100.list" | tr -d ' ')" = 200 ] || fail "list size"
  [ "$(wc -l < "$IP_CALLS" | tr -d ' ')" = 2 ] || fail "expected 2 ip calls (prefix + one snapshot) for 200 addresses: $(cat "$IP_CALLS")"
  grep -qvE '^2001:db8:0:1:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}$' "$TMP/ipv6_18100.list" && fail "generated list layout"
  generate_ipv6_addresses_if_needed | grep -q 'Using existing' || fail "an existing list must be reused"
  exit 0
) || exit 1
ok "IPv6 generation: one od + one awk per batch, unique, /64 /56 /48 layout, NIC addresses skipped, 2 ip calls per batch"

# ── 5. start-up script: spawn helper, missing list, deprecate switch ──
for f in netrun_setting http_listen_ip_for_node create_startup_script; do eval "$(extract "$f")"; done
mk_script() { # label deprecate-env-value [netrun.env file]
  (
    set +u
    H="$TMP/h$1"; mkdir -p "$H/proxyserver/3proxy/bin"
    printf '#!/bin/sh\nexit 0\n' > "$H/proxyserver/3proxy/bin/3proxy"; chmod +x "$H/proxyserver/3proxy/bin/3proxy"
    get_subnet_mask() { echo "2001:db8:0:1"; }
    is_auth_used() { return 0; }
    bash_location="$(command -v bash)"; user_home_dir="$H"
    start_port=18100; last_port=18100; proxy_count=1; proxies_type=dual; mode_flag=-6
    backconnect_ipv4=45.32.10.20; interface_name=eth9; subnet=64; instance_id=18100
    dns_nserver_lines=$'  nserver 127.0.0.1\n  nserver ::1'; proxy_maxconn=512
    user=""; password=""; use_random_auth=true; allowed_hosts=""; denied_hosts=""
    proxyserver_config_path="$H/proxyserver/3proxy/3proxy_18100.cfg"
    random_ipv6_list_file="$H/proxyserver/ipv6_18100.list"
    random_users_list_file="$H/proxyserver/random_users_18100.list"
    startup_script_path="$H/proxyserver/proxy-startup_18100.sh"
    printf '2001:db8:0:1::a\n' > "$random_ipv6_list_file"; printf 'u1:p1\n' > "$random_users_list_file"
    NETRUN_ENV_FILE="${3:-$TMP/none.env}" NETRUN_ANCHOR_DEPRECATE="$2" create_startup_script
  )
}
mk_script 1 1 || fail "create_startup_script"
S="$TMP/h1/proxyserver/proxy-startup_18100.sh"
mkdir -p "$TMP/stub"
printf '#!/bin/sh\nfor a; do [ -f "$a" ] && cp "$a" "%s/batch"; done\nexit 0\n' "$TMP" > "$TMP/stub/ip"
printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/sleep"
printf '#!/bin/sh\necho "helper BIN=$NETRUN_3PROXY_BIN $*" >> "%s/helper_calls"\n' "$TMP" > "$TMP/helper.sh"
chmod +x "$TMP/stub/ip" "$TMP/stub/sleep"
PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$S" >/dev/null 2>&1 || fail "start-up script failed"
grep -qx "helper BIN=$TMP/h1/proxyserver/3proxy/bin/3proxy $TMP/h1/proxyserver/3proxy/3proxy_18100.cfg" "$TMP/helper_calls" \
  || fail "spawn helper not called with the cfg: $(cat "$TMP/helper_calls" 2>/dev/null)"
grep -qx 'address add 2001:db8:0:1::a/128 dev eth9 nodad preferred_lft 0' "$TMP/batch" || fail "deprecated /128 anchor: $(cat "$TMP/batch")"
grep -qE '^[[:space:]]*maxconn 512$' "$TMP/h1/proxyserver/3proxy/3proxy_18100.cfg" || fail "cfg maxconn 512"
# Audit 2026-10-08 — the cfg names customer logins / passwords: root-only,
# also when an older 0644 cfg is overwritten; the generator itself runs umask 077.
cfgmode() { stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1"; }
[ "$(cfgmode "$TMP/h1/proxyserver/3proxy/3proxy_18100.cfg")" = 600 ] || fail "cfg mode $(cfgmode "$TMP/h1/proxyserver/3proxy/3proxy_18100.cfg")"
chmod 0644 "$TMP/h1/proxyserver/3proxy/3proxy_18100.cfg"
PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$S" >/dev/null 2>&1 || fail "start-up script rerun"
[ "$(cfgmode "$TMP/h1/proxyserver/3proxy/3proxy_18100.cfg")" = 600 ] || fail "an overwritten 0644 cfg stays readable"
grep -qx 'umask 077' "$GEN" && grep -qE '^[[:space:]]+umask 077$' "$GEN" || fail "umask 077 in the generator and its start-up script"
rm -f "$TMP/h1/proxyserver/ipv6_18100.list" "$TMP/helper_calls"
PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$S" >/dev/null 2>&1 && fail "start-up script ran without its address list"
[ ! -f "$TMP/helper_calls" ] || fail "spawned a batch with no address list"
! grep -q 'rnd_subnet_ip' "$S" || fail "start-up script still mints random addresses"
mk_script 0 0 || fail "create_startup_script (deprecate off)"
PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$TMP/h0/proxyserver/proxy-startup_18100.sh" >/dev/null 2>&1
grep -qx 'address add 2001:db8:0:1::a/128 dev eth9 nodad' "$TMP/batch" || fail "NETRUN_ANCHOR_DEPRECATE=0: $(cat "$TMP/batch")"
# The same switch values the agent and the boot restore accept: off / OFF in netrun.env, False in the env.
for v in off OFF; do
  printf 'NETRUN_ANCHOR_DEPRECATE=%s\n' "$v" > "$TMP/dep-$v.env"
  mk_script "env$v" "" "$TMP/dep-$v.env" || fail "create_startup_script (netrun.env $v)"
  rm -f "$TMP/batch"
  PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$TMP/henv$v/proxyserver/proxy-startup_18100.sh" >/dev/null 2>&1
  grep -qx 'address add 2001:db8:0:1::a/128 dev eth9 nodad' "$TMP/batch" || fail "NETRUN_ANCHOR_DEPRECATE=$v in netrun.env: $(cat "$TMP/batch" 2>/dev/null)"
done
mk_script false False || fail "create_startup_script (False)"
rm -f "$TMP/batch"
PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$TMP/hfalse/proxyserver/proxy-startup_18100.sh" >/dev/null 2>&1
grep -qx 'address add 2001:db8:0:1::a/128 dev eth9 nodad' "$TMP/batch" || fail "NETRUN_ANCHOR_DEPRECATE=False: $(cat "$TMP/batch" 2>/dev/null)"
ok "start-up script: spawn helper with the cfg (0600, umask 077), refuses a missing address list, NETRUN_ANCHOR_DEPRECATE=0/off/OFF/False adds preferred anchors"

echo "test_generator_flags.sh — all $PASS checks passed"
