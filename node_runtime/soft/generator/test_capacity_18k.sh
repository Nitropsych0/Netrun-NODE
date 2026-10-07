#!/usr/bin/env bash
# Wave CAPACITY-18K — generator tests. Same pattern as test_http_a_dual.sh:
# pull the real functions out of proxyyy_automated.sh and run them with
# controlled globals and stubbed commands (no root, no 3proxy, no network).
#   bash node_runtime/soft/generator/test_capacity_18k.sh
set -uo pipefail

GEN="$(cd "$(dirname "$0")" && pwd -P)/proxyyy_automated.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
extract() { sed -n "/^function $1()/,/^}/p" "$GEN"; }

for f in netrun_setting select_listen_conflicts count_listening_in_range ss_listen_snapshot \
         check_ports_not_listening http_listen_ip_for_node check_startup_parameters \
         create_startup_script; do
  body="$(extract "$f")"
  [ -n "$body" ] || fail "function $f not found in generator"
  eval "$body"
done

# ── 1. listener floor / port guards (check_startup_parameters) ────
# Run the real guard in a subshell with the exit helpers stubbed; the
# interface probe reads /sys, which a test box does not have — stub `cat`.
guard() { # proxies_type start_port proxy_count [min_listen_port]
  (
    log_err_print_usage_and_exit() { echo "REJECT: $1"; exit 3; }
    log_err_and_exit() { echo "REJECT: $1"; exit 3; }
    log_err() { :; }
    cat() { if [[ "${1:-}" == /sys/class/net/* ]]; then echo up; else command cat "$@"; fi; }
    proxies_type="$1"; start_port="$2"; proxy_count="$3"; min_listen_port="${4:-8100}"
    user=""; password=""; use_random_auth=true
    ipv6_policy="ipv6_only"; subnet=64; rotating_interval=0; backconnect_ipv4=""
    allowed_hosts=""; denied_hosts=""; proxy_maxconn=200; interface_name="eth0"
    check_startup_parameters >/dev/null 2>&1 && echo ACCEPT
  ) | tail -n 1
}
expect_accept() { [ "$(guard "$@")" = "ACCEPT" ] || fail "guard rejected: $*"; }
expect_reject() { [ "$(guard "$@")" != "ACCEPT" ] || fail "guard accepted: $*"; }

expect_accept dual 18100 1500        # http 8100-9599: the new 18k layout
expect_accept dual 64036 1500        # socks up to 65535
expect_accept dual 32000 1500        # today's orchestrator range keeps working
expect_reject dual 18099 1           # http 8099 < 8100
expect_reject dual 18085 1           # http 8085 = the agent port
expect_reject dual 15000 1500        # old floor (http 5000) no longer accepted
expect_reject dual 64037 1500        # socks 65536 out of range
expect_reject dual 20000 10001       # socks and http ranges would overlap
expect_accept socks5 8100 100
expect_reject socks5 8099 1
expect_reject socks5 5000 1          # old generic floor no longer accepted
expect_accept dual 15000 10 5000     # NETRUN_MIN_LISTEN_PORT=5000 restores the old floor
expect_reject dual 18100 1 abc       # bad floor value
ok "listener floor: dual start >= 18100 (http >= 8100), socks/http >= 8100, 65535 cap, no self-overlap"

# ── 2. one-snapshot conflict filter ───────────────────────────────
cat > "$TMP/ss.txt" <<'EOF'
State  Recv-Q Send-Q   Local Address:Port    Peer Address:Port Process
LISTEN 0      128            0.0.0.0:22           0.0.0.0:*
LISTEN 0      511                  *:8085               *:*
LISTEN 0      256          127.0.0.1:53           0.0.0.0:*
LISTEN 0      4096     127.0.0.53%lo:53           0.0.0.0:*
LISTEN 0      13         45.32.10.20:18100        0.0.0.0:*
LISTEN 0      4096       45.32.10.20:8150         0.0.0.0:*
LISTEN 0      13           127.0.0.1:8160         0.0.0.0:*
LISTEN 0      13             0.0.0.0:18170        0.0.0.0:*
LISTEN 0      13                [::]:8180            [::]:*
LISTEN 0      13           127.0.0.2:8190         0.0.0.0:*
LISTEN 0      13         45.32.10.20:19600        0.0.0.0:*
ESTAB  0      0          45.32.10.20:18101    1.1.1.1:5555
EOF
# Batch socks 18100-19599 on 45.32.10.20, http 8100-9599 on 127.0.0.1 (HTTPS front).
got="$(select_listen_conflicts 18100 19599 45.32.10.20 8100 9599 127.0.0.1 < "$TMP/ss.txt" | tr '\n' ',')"
[ "$got" = "18100 45.32.10.20,8160 127.0.0.1,18170 0.0.0.0,8180 ::," ] || fail "conflicts (https front): got '$got'"
# Without the HTTPS front http binds the public IP: haproxy-style 8150 collides, 127.0.0.1:8160 does not.
got="$(select_listen_conflicts 18100 19599 45.32.10.20 8100 9599 45.32.10.20 < "$TMP/ss.txt" | tr '\n' ',')"
[ "$got" = "18100 45.32.10.20,8150 45.32.10.20,18170 0.0.0.0,8180 ::," ] || fail "conflicts (public http): got '$got'"
got="$(select_listen_conflicts 30000 31499 45.32.10.20 20000 21499 127.0.0.1 < "$TMP/ss.txt")"
[ -z "$got" ] || fail "free range reported busy: '$got'"
got="$(select_listen_conflicts 8000 8100 45.32.10.20 < "$TMP/ss.txt" | tr '\n' ',')"
[ "$got" = "8085 *," ] || fail "agent *:8085 must collide with any IPv4 bind: got '$got'"
ok "conflict filter: exact address + wildcards collide, other specific addresses (haproxy vs 127.0.0.1) do not, ESTAB/header ignored"

[ "$(count_listening_in_range 18100 19599 < "$TMP/ss.txt")" = 2 ] || fail "count_listening_in_range"
[ "$(count_listening_in_range 1 65535 < "$TMP/ss.txt")" = 10 ] || fail "count distinct ports"
ok "post-start count: distinct listening ports in range from one snapshot"

# ── 3. check_ports_not_listening: one ss call, refuses before side effects ──
precheck() { # proxies_type start last [skip]
  (
    SS_CALLS="$TMP/ss_calls"; : > "$SS_CALLS"
    ss() { echo "ss $*" >> "$SS_CALLS"; command cat "$TMP/ss.txt"; }
    log_err_and_exit() { echo "REFUSED: $1"; exit 3; }
    proxies_type="$1"; start_port="$2"; last_port="$3"; backconnect_ipv4="45.32.10.20"
    NETRUN_SKIP_PORT_PRECHECK="${4:-0}"
    check_ports_not_listening
    echo "calls=$(wc -l < "$SS_CALLS" | tr -d ' ')"
  )
}
out="$(precheck dual 18100 19599)"
echo "$out" | grep -q 'REFUSED: Error: ports_already_listening: ' || fail "precheck did not refuse a busy batch: $out"
echo "$out" | grep -q '18100 45.32.10.20' || fail "precheck message lacks the port"
out="$(precheck dual 30000 31499)"
echo "$out" | grep -q 'Port pre-check OK' || fail "precheck refused a free batch: $out"
echo "$out" | grep -qx 'calls=1' || fail "precheck must take exactly ONE ss snapshot: $out"
out="$(precheck dual 18100 19599 1)"
echo "$out" | grep -q 'skipped' || fail "NETRUN_SKIP_PORT_PRECHECK=1 not honoured"
ok "pre-check: one ss snapshot per batch, refuses busy ports, escape hatch works"

# ── 4. generated startup script: no nscache, ip -batch + nodad ────
(
  set +u
  HOME_DIR="$TMP/home"; mkdir -p "$HOME_DIR/proxyserver/3proxy/bin"
  printf '#!/bin/sh\nexit 0\n' > "$HOME_DIR/proxyserver/3proxy/bin/3proxy"; chmod +x "$HOME_DIR/proxyserver/3proxy/bin/3proxy"
  get_subnet_mask() { echo "2001:db8:0:1"; }
  is_auth_used() { return 0; }
  bash_location="$(command -v bash)"; user_home_dir="$HOME_DIR"
  start_port=18100; last_port=18101; proxy_count=2; proxies_type=dual; mode_flag=-6
  backconnect_ipv4=45.32.10.20; interface_name=eth9; subnet=64
  dns_nserver_lines=$'  nserver 127.0.0.1\n  nserver ::1'; proxy_maxconn=200
  NETRUN_ENV_FILE="$TMP/none.env"
  user=""; password=""; use_random_auth=true; allowed_hosts=""; denied_hosts=""
  proxyserver_config_path="$HOME_DIR/proxyserver/3proxy/3proxy_18100.cfg"
  random_ipv6_list_file="$HOME_DIR/proxyserver/ipv6_18100.list"
  random_users_list_file="$HOME_DIR/proxyserver/random_users_18100.list"
  startup_script_path="$HOME_DIR/proxyserver/proxy-startup_18100.sh"
  printf '2001:db8:0:1::a\n2001:db8:0:1::b\n' > "$random_ipv6_list_file"
  printf 'u1:p1\nu2:p2\n' > "$random_users_list_file"
  create_startup_script
) || fail "create_startup_script failed"
S="$TMP/home/proxyserver/proxy-startup_18100.sh"
[ -f "$S" ] || fail "startup script not written"
! grep -q 'nscache' "$S" || fail "startup script still emits nscache"
grep -q 'ip -6 -force -batch' "$S" || fail "startup script does not use ip -batch"
! grep -q 'ip -6 addr add' "$S" || fail "per-address ip loop still present"
# Run it with a stub `ip` that records the batch it was handed.
mkdir -p "$TMP/stub"
cat > "$TMP/stub/ip" <<EOF
#!/usr/bin/env bash
echo "ip \$*" >> "$TMP/ip_calls"
for a; do [ -f "\$a" ] && cp "\$a" "$TMP/ip_batch"; done
exit 0
EOF
cat > "$TMP/stub/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$TMP/stub/ip" "$TMP/stub/sleep"
PATH="$TMP/stub:$PATH" NETRUN_3PROXY_SPAWN="$TMP/no-helper" bash "$S" >/dev/null 2>&1
[ "$(wc -l < "$TMP/ip_calls" | tr -d ' ')" = 1 ] || fail "expected ONE ip call, got: $(cat "$TMP/ip_calls")"
grep -q -- '-6 -force -batch' "$TMP/ip_calls" || fail "ip not called with -force -batch"
# Audit FP-01: explicit /128 + preferred_lft 0 (deprecated anchors).
printf 'address add 2001:db8:0:1::a/128 dev eth9 nodad preferred_lft 0\naddress add 2001:db8:0:1::b/128 dev eth9 nodad preferred_lft 0\n' > "$TMP/want_batch"
cmp -s "$TMP/want_batch" "$TMP/ip_batch" || { cat "$TMP/ip_batch"; fail "ip batch content"; }
CFG="$TMP/home/proxyserver/3proxy/3proxy_18100.cfg"
! grep -q 'nscache' "$CFG" || fail "cfg still has nscache"
grep -qE '^[[:space:]]*nserver 127\.0\.0\.1$' "$CFG" || fail "cfg lost nserver 127.0.0.1"
grep -qE '^[[:space:]]*maxconn 200$' "$CFG" || fail "cfg lost maxconn"
grep -q 'socks -6 -a -p18100 -i45.32.10.20 -e2001:db8:0:1::a' "$CFG" || fail "cfg socks line"
grep -qE 'proxy -6 -n -a -p8100 -i(45\.32\.10\.20|127\.0\.0\.1) -e2001:db8:0:1::a' "$CFG" || fail "cfg paired http line at 8100"
ok "startup script: header without nscache/nscache6, ONE ip -batch with nodad (/128, deprecated), dual http at 8100"

echo "test_capacity_18k.sh — all $PASS generator checks passed"
