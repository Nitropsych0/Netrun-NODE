#!/usr/bin/env bash
# Wave FLEET-HEALTH — generator tests (same pattern as test_capacity_18k.sh:
# pull the real functions out of proxyyy_automated.sh, run them with
# controlled globals and stubbed commands; no root, no 3proxy, no network).
#   1. SPD-05: the two counter map rules the generator renders — port-only by
#      default (unchanged), `iifname != lo ip daddr|saddr <public v4>` with
#      NETRUN_ACCOUNTING_MATCH_IPV4=1 (env or /etc/netrun/netrun.env); an
#      existing map rule is never re-added.
#   2. FO-06: a random_users_<start>.list written by the agent
#      (server.js writeCredentialsFile) is REUSED by the generator and its
#      logins/passwords land in the cfg in port order.
#   2b. L-U2: a stale credentials list (wrong length / malformed) is
#      regenerated atomically, never indexed past its end; an exact one is
#      reused verbatim.
#   bash node_runtime/soft/generator/test_fleet_health.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
GEN="$HERE/proxyyy_automated.sh"
AGENT="$HERE/../../node_agent/server.js"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
extract() { sed -n "/^function $1()/,/^}/p" "$GEN"; }

for f in is_valid_ip netrun_setting accounting_client_match setup_nftables_counters \
         create_random_string generate_random_users_if_needed create_startup_script http_listen_ip_for_node \
         list_line_count credentials_list_is_valid; do
  body="$(extract "$f")"
  [ -n "$body" ] || fail "function $f not found in generator"
  eval "$body"
done

# ── 1. SPD-05 rendered map rules ──────────────────────────────────
render() { # flag-source existing-rule? -> the `nft add rule` lines
  (
    : > "$TMP/nft_calls"
    ensure_nftables_ready() { :; }
    log_err_and_exit() { echo "EXIT $1" >> "$TMP/nft_calls"; exit 3; }
    nft() {
      case "$*" in
        "list table inet proxy_accounting") return 0 ;;
        "list chain inet proxy_accounting input") [ "$EXISTING" = 1 ] && echo "iifname != \"lo\" counter name tcp dport map @cmap_in # handle 5"; return 0 ;;
        "list chain inet proxy_accounting output") [ "$EXISTING" = 1 ] && echo "oifname != \"lo\" counter name tcp sport map @cmap_out # handle 6"; return 0 ;;
        add\ rule*) echo "nft $*" >> "$TMP/nft_calls" ;;
        *) return 0 ;;
      esac
    }
    bootstrap_side_effects_allowed=true
    backconnect_ipv4="45.32.10.20"
    random_ipv6_list_file="$TMP/no-such-ipv6.list"   # stop right after the map rules
    proxy_count=2; start_port=18100; proxies_type=dual
    EXISTING="$1"
    setup_nftables_counters > /dev/null 2>&1
  )
  cat "$TMP/nft_calls"
}
want_in='nft add rule inet proxy_accounting input counter name tcp dport map @cmap_in'
want_out='nft add rule inet proxy_accounting output counter name tcp sport map @cmap_out'
got="$(NETRUN_ENV_FILE="$TMP/none.env" render 0)"
[ "$got" = "$(printf '%s\n%s' "$want_in" "$want_out")" ] || fail "default rules changed: $got"
want_in4='nft add rule inet proxy_accounting input iifname != lo ip daddr 45.32.10.20 counter name tcp dport map @cmap_in'
want_out4='nft add rule inet proxy_accounting output oifname != lo ip saddr 45.32.10.20 counter name tcp sport map @cmap_out'
got="$(NETRUN_ACCOUNTING_MATCH_IPV4=1 render 0)"
[ "$got" = "$(printf '%s\n%s' "$want_in4" "$want_out4")" ] || fail "flag via env: $got"
printf '# node settings\nNETRUN_ACCOUNTING_MATCH_IPV4=1\n' > "$TMP/netrun.env"
got="$(NETRUN_ENV_FILE="$TMP/netrun.env" render 0)"
[ "$got" = "$(printf '%s\n%s' "$want_in4" "$want_out4")" ] || fail "flag via netrun.env: $got"
[ -z "$(NETRUN_ACCOUNTING_MATCH_IPV4=1 render 1)" ] || fail "an existing map rule must not be re-added"
(
  backconnect_ipv4=""
  [ -z "$(NETRUN_ACCOUNTING_MATCH_IPV4=1 accounting_client_match input "")" ] || exit 1
  [ -z "$(NETRUN_ACCOUNTING_MATCH_IPV4=1 accounting_client_match input 127.0.0.1)" ] || exit 1
  [ -z "$(NETRUN_ACCOUNTING_MATCH_IPV4=1 accounting_client_match input not-an-ip)" ] || exit 1
) || fail "no/loopback/bad IPv4 must fall back to the port-only rule"
ok "SPD-05: port-only rules by default; NETRUN_ACCOUNTING_MATCH_IPV4=1 (env or netrun.env) renders ip daddr/saddr <public v4>; existing rules untouched"

# ── 2. FO-06: the generator reuses the agent's credentials file ───
command -v node >/dev/null 2>&1 || fail "node not found (needed to run the agent's writeCredentialsFile)"
HOME_DIR="$TMP/home"; mkdir -p "$HOME_DIR/proxyserver/3proxy/bin"
USERS="$HOME_DIR/proxyserver/random_users_18100.list"
NODE_AGENT_PROXY_ROOT="$HOME_DIR/proxyserver" NODE_AGENT_JOBS_ROOT="$TMP/jobs" node -e '
  const srv = require(process.argv[1]);
  srv.writeCredentialsFile(srv.buildCredentialsListPath(18100), ["CloneA1:SecretB1", "CloneA2:SecretB2"])
    .then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
' "$AGENT" > /dev/null || fail "agent writeCredentialsFile failed"
[ "$(cat "$USERS")" = "$(printf 'CloneA1:SecretB1\nCloneA2:SecretB2')" ] || fail "agent file content"
before="$(cksum < "$USERS")"
(
  use_random_auth=true; proxy_count=2; random_users_list_file="$USERS"
  generate_random_users_if_needed
) | grep -q 'Using existing credentials' || fail "generator did not take the existing-credentials path"
[ "$(cksum < "$USERS")" = "$before" ] || fail "generator modified the agent's credentials file"
(
  set +u
  printf '#!/bin/sh\nexit 0\n' > "$HOME_DIR/proxyserver/3proxy/bin/3proxy"; chmod +x "$HOME_DIR/proxyserver/3proxy/bin/3proxy"
  get_subnet_mask() { echo "2001:db8:0:1"; }
  is_auth_used() { return 0; }
  bash_location="$(command -v bash)"; user_home_dir="$HOME_DIR"
  start_port=18100; last_port=18101; proxy_count=2; proxies_type=dual; mode_flag=-6
  backconnect_ipv4=45.32.10.20; interface_name=eth9; subnet=64
  dns_nserver_lines='  nserver 127.0.0.1'; proxy_maxconn=200
  user=""; password=""; use_random_auth=true; allowed_hosts=""; denied_hosts=""
  proxyserver_config_path="$HOME_DIR/proxyserver/3proxy/3proxy_18100.cfg"
  random_ipv6_list_file="$HOME_DIR/proxyserver/ipv6_18100.list"
  random_users_list_file="$USERS"
  startup_script_path="$HOME_DIR/proxyserver/proxy-startup_18100.sh"
  printf '2001:db8:0:1::a\n2001:db8:0:1::b\n' > "$random_ipv6_list_file"
  create_startup_script
) || fail "create_startup_script failed"
mkdir -p "$TMP/stub"
printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/ip"; printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/sleep"
chmod +x "$TMP/stub/ip" "$TMP/stub/sleep"
# The startup script uses `readarray` (bash >= 4, as on the nodes). A dev box
# with bash 3.2 (macOS) gets a minimal `readarray -t NAME` via BASH_ENV.
SHIM=""
if ! bash -c 'type readarray' >/dev/null 2>&1; then
  SHIM="$TMP/readarray_shim.sh"
  cat > "$SHIM" <<'SHIMEOF'
readarray() {
  local __n="$2" __l __i=0
  eval "$__n=()"
  while IFS= read -r __l || [ -n "$__l" ]; do eval "$__n[$__i]=\"\$__l\""; __i=$((__i + 1)); done
}
SHIMEOF
fi
PATH="$TMP/stub:$PATH" BASH_ENV="$SHIM" bash "$HOME_DIR/proxyserver/proxy-startup_18100.sh" >/dev/null 2>&1
CFG="$HOME_DIR/proxyserver/3proxy/3proxy_18100.cfg"
[ -f "$CFG" ] || fail "cfg not written"
got="$(awk '/^users / { u = $2 } /^socks / { for (i = 1; i <= NF; i++) if ($i ~ /^-p/) print substr($i, 3) " " u }' "$CFG" | tr '\n' ',')"
[ "$got" = "18100 CloneA1:CL:SecretB1,18101 CloneA2:CL:SecretB2," ] || { cat "$CFG"; fail "cfg credentials by port: $got"; }
grep -q '^allow CloneA1 ' "$CFG" && grep -q '^allow CloneA2 ' "$CFG" || fail "per-port allow lines"
ok "FO-06: the agent-written random_users_<start>.list is reused verbatim and lands in the cfg in port order"

# Control: without a file the generator draws its own (8+8 [A-Za-z0-9]).
(
  use_random_auth=true; proxy_count=3; random_users_list_file="$TMP/fresh.list"
  generate_random_users_if_needed
) > /dev/null
[ "$(wc -l < "$TMP/fresh.list" | tr -d ' ')" = 3 ] || fail "fresh credentials count"
grep -qvE '^[A-Za-z0-9]{8}:[A-Za-z0-9]{8}$' "$TMP/fresh.list" && fail "fresh credentials format"
ok "control: no file -> the generator draws 8+8 random credentials (unchanged)"

# ── 2b. L-U2: stale credentials list is regenerated, never indexed past its end ──
gen_creds() { # COUNT FILE -> runs generate_random_users_if_needed; stderr of log_err in $TMP/log_err
  (
    use_random_auth=true; proxy_count="$1"; random_users_list_file="$2"; script_log_file="$TMP/script.log"
    log_err() { echo "$1" >> "$TMP/log_err"; }
    log_err_and_exit() { log_err "$1"; exit 1; }
    generate_random_users_if_needed
  ) > /dev/null
}
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
valid_lines() { [ "$(wc -l < "$1" | tr -d ' ')" = "$2" ] && ! grep -qvE '^[A-Za-z0-9]{8}:[A-Za-z0-9]{8}$' "$1"; }

# (a) 1-line file, 3 ports -> 3 fresh lines, the old line gone, the log names 1 and 3
L="$TMP/stale_a.list"; echo "OldLogin1:OldPass1x" > "$L"; : > "$TMP/log_err"
gen_creds 3 "$L" || fail "2b(a): generator failed"
valid_lines "$L" 3 || fail "2b(a): expected 3 fresh 8+8 lines: $(cat "$L")"
grep -q OldLogin1 "$L" && fail "2b(a): the old line survived"
grep -q "regenerating" "$TMP/log_err" && grep -q "1 line" "$TMP/log_err" && grep -q "needs 3" "$TMP/log_err" || fail "2b(a): the log must name 1 and 3: $(cat "$TMP/log_err")"
# (e) no .tmp left, mode 600
ls "$TMP"/stale_a.list.tmp >/dev/null 2>&1 && fail "2b(e): a .tmp file was left"
[ "$(mode_of "$L")" = 600 ] || fail "2b(e): mode $(mode_of "$L") != 600"

# (b) 5 lines, 3 ports -> 3 fresh lines, none of the old logins
L="$TMP/stale_b.list"; printf 'OldA0001:xxxxxxx1\nOldB0002:xxxxxxx2\nOldC0003:xxxxxxx3\nOldD0004:xxxxxxx4\nOldE0005:xxxxxxx5\n' > "$L"
gen_creds 3 "$L" || fail "2b(b): generator failed"
valid_lines "$L" 3 || fail "2b(b): $(cat "$L")"
grep -q 'Old[A-E]000' "$L" && fail "2b(b): an old login survived"

# (c) a malformed line with the right count -> regenerated (empty line / no colon / dash)
for bad in 'x1234567:y1234567\n\nz1234567:w1234567' 'x1234567:y1234567\nnocolon\nz1234567:w1234567' 'x1234567:y1234567\na-b:c\nz1234567:w1234567' 'x1234567:y1234567\n:onlypass\nz1234567:w1234567'; do
  L="$TMP/stale_c.list"; printf "$bad\n" > "$L"; : > "$TMP/log_err"
  gen_creds 3 "$L" || fail "2b(c): generator failed"
  valid_lines "$L" 3 || fail "2b(c): not regenerated ($bad): $(cat "$L")"
  grep -q "regenerating" "$TMP/log_err" || fail "2b(c): no regenerate note ($bad)"
done
# a blank-only trailing newline is not a line: exactly 3 valid lines are reused verbatim
L="$TMP/stale_d.list"; printf 'Keep0001:Pass0001\nKeep0002:Pass0002\nKeep0003:Pass0003\n' > "$L"; before="$(cksum < "$L")"; : > "$TMP/log_err"
gen_creds 3 "$L" || fail "2b(d): generator failed"
[ "$(cksum < "$L")" = "$before" ] && [ ! -s "$TMP/log_err" ] || fail "2b(d): an exact list must be reused verbatim and silently"
# the validity helpers themselves
( credentials_list_is_valid "$L" 3 && ! credentials_list_is_valid "$L" 2 && ! credentials_list_is_valid "$L" 4 && ! credentials_list_is_valid "$TMP/none.list" 3 \
  && [ "$(list_line_count "$TMP/none.list")" = 0 ] && [ "$(list_line_count "$L")" = 3 ] ) || fail "2b: credentials_list_is_valid / list_line_count"
ok "L-U2: a stale credentials list (short / long / malformed) is regenerated atomically (0600, no .tmp), an exact one is reused verbatim"

echo "test_fleet_health.sh — all $PASS generator checks passed"
