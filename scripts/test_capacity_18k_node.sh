#!/usr/bin/env bash
# Wave CAPACITY-18K — node-side script tests (install_node_v2.sh settings,
# node_followup_v2.sh sysctl merge, netrun-https.sh with 4-digit HTTP ports,
# deploy/node/netrun-ipv6-restore.sh). Functions are pulled out of the real
# scripts and run against temp files with stubbed commands — no root needed.
#   bash scripts/test_capacity_18k_node.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
INSTALL="$ROOT_DIR/install_node_v2.sh"
FOLLOWUP="$ROOT_DIR/scripts/node_followup_v2.sh"
HTTPS="$ROOT_DIR/scripts/netrun-https.sh"
RESTORE="$ROOT_DIR/deploy/node/netrun-ipv6-restore.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

for f in "$INSTALL" "$FOLLOWUP" "$HTTPS" "$RESTORE" "$ROOT_DIR/scripts/apply_capacity_tuning.sh"; do
  bash -n "$f" 2>/dev/null || sed 's/&>>/>>/g' "$f" | bash -n || fail "syntax: $f"
done
ok "bash -n: installer, follow-up, netrun-https, ipv6 restore, apply_capacity_tuning"

# ── 1. installer: the 99-netrun.conf it writes (new nodes) ────────
awk '/cat > "\$SYSCTL_FILE" <<.EOF./ { on = 1; next } on && /^EOF$/ { exit } on' "$INSTALL" > "$TMP/installer-99.conf"
grep -qx 'net.ipv4.ip_local_port_range = 1024 8000' "$TMP/installer-99.conf" || fail "installer: ip_local_port_range is not 1024 8000"
! grep -q '10000 65000' "$TMP/installer-99.conf" || fail "installer: old range still present"
grep -qE '^[[:space:]]+msg-cache-size: 32m$' "$INSTALL" || fail "installer: unbound msg-cache-size not 32m"
grep -qE '^[[:space:]]+rrset-cache-size: 64m$' "$INSTALL" || fail "installer: unbound rrset-cache-size not 64m"
grep -q 'install -m 0755 "$NETRUN_HOME/deploy/node/netrun-ipv6-restore.sh" /opt/netrun/scripts/netrun-ipv6-restore.sh' "$INSTALL" \
  || fail "installer: ipv6 restore not installed from deploy/node/netrun-ipv6-restore.sh"
grep -q '^warn() ' "$INSTALL" || fail "installer: warn() (used by configure_unbound) undefined"
ok "installer: ip_local_port_range 1024 8000, unbound 32m/64m, ip -batch restore script, warn() defined"

# ── 2. follow-up merges instead of overwriting 99-netrun.conf ─────
eval "$(sed -n '/^merge_sysctl_conf() {/,/^}/p' "$FOLLOWUP")"
type merge_sysctl_conf >/dev/null 2>&1 || fail "merge_sysctl_conf not found in follow-up"
# The follow-up's own invocation, retargeted at a temp file.
awk '/^merge_sysctl_conf \/etc\/sysctl.d\/99-netrun.conf/ { on = 1 } on { print; if ($0 !~ /\\$/) exit }' "$FOLLOWUP" \
  | sed "s#/etc/sysctl.d/99-netrun.conf#\"\$TARGET\"#" > "$TMP/followup-call.sh"
grep -q 'kernel.pid_max=4194304' "$TMP/followup-call.sh" || fail "could not extract the follow-up merge call"
! grep -q 'ip_local_port_range' "$TMP/followup-call.sh" || fail "follow-up must not manage ip_local_port_range"
! grep -q "cat > /etc/sysctl.d/99-netrun.conf" "$FOLLOWUP" || fail "follow-up still overwrites 99-netrun.conf"

# (a) a fresh node: installer file + follow-up = byte-identical (same values, nothing lost)
TARGET="$TMP/new-node-99.conf"; cp "$TMP/installer-99.conf" "$TARGET"
. "$TMP/followup-call.sh"
cmp -s "$TMP/installer-99.conf" "$TARGET" || { diff "$TMP/installer-99.conf" "$TARGET"; fail "follow-up changed the installer's 99-netrun.conf"; }
for kv in 'net.ipv4.ip_local_port_range = 1024 8000' 'net.ipv6.conf.all.accept_ra = 2'; do
  grep -qx "$kv" "$TARGET" || fail "follow-up lost: $kv"
done
# Audit FP-01 — the TCP signature lives in its own file (sorts after /etc/sysctl.conf).
for kv in 'net.ipv4.tcp_timestamps = 1' 'net.ipv4.tcp_mtu_probing = 1' 'net.ipv4.ip_default_ttl = 64' \
          'net.ipv4.tcp_sack = 1' 'net.ipv4.tcp_window_scaling = 1' 'net.ipv4.tcp_rmem = 4096 131072 6291456'; do
  grep -qx "$kv" "$ROOT_DIR/deploy/node/99-zz-netrun-tcp.conf" || fail "TCP signature file lacks: $kv"
done
! grep -qE 'tcp_timestamps|maxseg|proxy_normalization' "$TMP/installer-99.conf" || fail "installer 99-netrun.conf still carries TCP signature keys"
! grep -vE '^[[:space:]]*#' "$INSTALL" | grep -qE 'maxseg size set|add table inet proxy_normalization' || fail "installer still adds the MSS rule / normalization table"
grep -q 'install -m 0644 "$src" "$SYSCTL_TCP_FILE"' "$INSTALL" || fail "installer does not install the TCP signature file"
grep -q '/etc/sysctl.d/99-zz-netrun-tcp.conf' "$FOLLOWUP" || fail "follow-up does not install the TCP signature file"
# (b) an existing node written by the OLD follow-up keeps its range (no silent change)
TARGET="$TMP/old-node-99.conf"
printf 'kernel.pid_max = 65536\nnet.ipv4.ip_local_port_range = 10000 65000\n' > "$TARGET"
. "$TMP/followup-call.sh"
grep -qx 'net.ipv4.ip_local_port_range = 10000 65000' "$TARGET" || fail "follow-up changed an existing node's range"
grep -qx 'kernel.pid_max = 4194304' "$TARGET" || fail "follow-up did not raise pid_max"
[ "$(grep -c '^kernel.pid_max' "$TARGET")" = 1 ] || fail "duplicate key after merge"
grep -qx 'net.ipv6.conf.default.forwarding = 1' "$TARGET" || fail "missing key not appended"
# (c) no file yet: created with the follow-up keys only
TARGET="$TMP/none-99.conf"
. "$TMP/followup-call.sh"
grep -qx 'fs.file-max = 2097152' "$TARGET" || fail "merge into a missing file"
ok "follow-up: merges its keys into 99-netrun.conf, keeps accept_ra/tcp_*/ip_local_port_range (fresh node: byte-identical)"

# ── 3. netrun-https.sh handles HTTP ports 8100-21999 ──────────────
for f in http_port_ranges localize_http_listeners write_frontends frontend_sets_equal; do
  pat="/^$f() {/,/^}/p"
  body="$(sed -n "$pat" "$HTTPS")"
  [ -n "$body" ] || fail "netrun-https: $f not found"
  eval "$body"
done
haproxy_check() { return 0; }   # no haproxy here (section 5 tests the check itself)
haproxy_check_crt() { haproxy_check "$@"; }   # FO-08: the hostname fallback (test_https_hostnames.sh)
PROXY_DIR="$TMP/3proxy"; FRONTEND_DIR="$TMP/netrun.d"; mkdir -p "$PROXY_DIR"
{
  echo "daemon"
  for p in 18100 18101 18102; do
    echo "socks -6 -a -p$p -i45.32.10.20 -e2001:db8::$p"
    echo "proxy -6 -n -a -p$((p - 10000)) -i45.32.10.20 -e2001:db8::$p"
  done
} > "$PROXY_DIR/3proxy_18100.cfg"
{
  for p in 31998 31999 32000 32001; do
    echo "socks -6 -a -p$p -i45.32.10.20 -e2001:db8::$p"
    echo "proxy -6 -n -a -p$((p - 10000)) -i45.32.10.20 -e2001:db8::$p"
  done
} > "$PROXY_DIR/3proxy_31998.cfg"
[ "$(http_port_ranges "$PROXY_DIR/3proxy_18100.cfg")" = "8100-8102" ] || fail "https: 4-digit range: $(http_port_ranges "$PROXY_DIR/3proxy_18100.cfg")"
[ "$(http_port_ranges "$PROXY_DIR/3proxy_31998.cfg")" = "21998-22001" ] || fail "https: range across 21999/22000"
[ "$(localize_http_listeners "$PROXY_DIR/3proxy_18100.cfg" 45.32.10.20)" = 1 ] || fail "https: localize did not change the cfg"
grep -qx 'proxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::18100' "$PROXY_DIR/3proxy_18100.cfg" || fail "https: 4-digit http listener not moved to 127.0.0.1"
grep -qx 'socks -6 -a -p18100 -i45.32.10.20 -e2001:db8::18100' "$PROXY_DIR/3proxy_18100.cfg" || fail "https: socks listener must stay public"
[ "$(localize_http_listeners "$PROXY_DIR/3proxy_18100.cfg" 45.32.10.20)" = 0 ] || fail "https: localize not idempotent"
write_frontends 45.32.10.20
grep -qx '    bind 45.32.10.20:8100-8102' "$FRONTEND_DIR/3proxy_18100.cfg" || fail "https: frontend bind for 8100-8102"
grep -qx '    bind 45.32.10.20:21998-22001' "$FRONTEND_DIR/3proxy_31998.cfg" || fail "https: frontend bind across 22000"
ok "netrun-https: 4-digit HTTP ports 8100+ are localized to 127.0.0.1 and fronted by haproxy (public p -> 127.0.0.1:p)"

# ── 4. boot-time IPv6 restore: one ip -batch, nodad, same address set ──
PR="$TMP/proxyserver"; mkdir -p "$PR/3proxy" "$TMP/stub"
printf 'socks -6 -a -p18100 -i1.2.3.4 -e2001:db8::2\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::2\nsocks -6 -a -p18101 -i1.2.3.4 -e2001:db8::1\n' > "$PR/3proxy/3proxy_18100.cfg"
printf 'socks -6 -a -p40000 -i1.2.3.4 -e2001:db8::1\n' > "$PR/3proxy/3proxy_40000.cfg.disabled"
cat > "$TMP/stub/ip" <<EOF
#!/usr/bin/env bash
echo "ip \$*" >> "$TMP/ip_calls"
for a; do [ -f "\$a" ] && cp "\$a" "$TMP/ip_batch"; done
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/logger"
chmod +x "$TMP/stub/ip" "$TMP/stub/logger"
export NETRUN_ENV_FILE="$TMP/no-netrun.env"   # hermetic: no host /etc/netrun/netrun.env
PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$PR" NETRUN_IPV6_IFACE=enp1s0 bash "$RESTORE" || fail "restore script exit"
[ "$(wc -l < "$TMP/ip_calls" | tr -d ' ')" = 1 ] || fail "restore: expected ONE ip call: $(cat "$TMP/ip_calls")"
grep -q -- '-6 -force -batch' "$TMP/ip_calls" || fail "restore: not ip -6 -force -batch"
# Audit FP-01: /128 (as the generator) + preferred_lft 0 (deprecated: never the
# kernel's source for the node's own traffic).
printf 'address add 2001:db8::1/128 dev enp1s0 nodad preferred_lft 0\naddress add 2001:db8::2/128 dev enp1s0 nodad preferred_lft 0\n' > "$TMP/want"
cmp -s "$TMP/want" "$TMP/ip_batch" || { cat "$TMP/ip_batch"; fail "restore: batch content"; }
rm -f "$TMP/ip_calls"
PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$TMP/empty" NETRUN_IPV6_IFACE=enp1s0 bash "$RESTORE" || fail "restore: empty root"
[ ! -f "$TMP/ip_calls" ] || fail "restore: ip called with nothing to add"
PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$PR" NETRUN_IPV6_IFACE=enp1s0 NETRUN_ANCHOR_DEPRECATE=0 bash "$RESTORE" || fail "restore: deprecate off"
grep -qx 'address add 2001:db8::1/128 dev enp1s0 nodad' "$TMP/ip_batch" || { cat "$TMP/ip_batch"; fail "restore: NETRUN_ANCHOR_DEPRECATE=0"; }
printf 'NETRUN_ANCHOR_DEPRECATE=off\n' > "$TMP/netrun.env"
PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$PR" NETRUN_IPV6_IFACE=enp1s0 NETRUN_ENV_FILE="$TMP/netrun.env" bash "$RESTORE" || fail "restore: netrun.env"
grep -qx 'address add 2001:db8::1/128 dev enp1s0 nodad' "$TMP/ip_batch" || { cat "$TMP/ip_batch"; fail "restore: NETRUN_ANCHOR_DEPRECATE=off from netrun.env"; }
PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$PR" NETRUN_IPV6_IFACE=enp1s0 NETRUN_ANCHOR_DEPRECATE=OFF bash "$RESTORE" || fail "restore: OFF"
grep -qx 'address add 2001:db8::1/128 dev enp1s0 nodad' "$TMP/ip_batch" || { cat "$TMP/ip_batch"; fail "restore: NETRUN_ANCHOR_DEPRECATE=OFF (any case, as the agent)"; }
# No interface: a loud failure (exit 1), not a silent exit 0.
printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/ip"
if PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$PR" NETRUN_IPV6_IFACE="" bash "$RESTORE" 2>"$TMP/restore_err"; then fail "restore: no interface must exit non-zero"; fi
grep -q 'ERROR: no IPv6 default route' "$TMP/restore_err" || fail "restore: no-interface message"
ok "ipv6 restore: unique -e addresses, /128 deprecated (switchable), ONE ip -6 -force -batch with nodad, loud failure without an interface"

# ── 5. netrun-https sync: reload only when haproxy has not loaded the files ──
# (a change, a stopped haproxy, or no verified reload of exactly these files:
# the stamp), the new frontend set validated BEFORE it goes live, a failed /
# unverified reload retried on the next sync, and never otherwise.
(
  for f in netrun_setting setting_off http_port_ranges localize_http_listeners write_frontends frontend_sets_equal \
           sha256_stream haproxy_config_hash stamp_read stamp_write stamp_expired frontend_first_ports \
           frontend_ports_missing verify_frontends_listening cmd_sync \
           https_hostnames host_cert_ok write_crt_list crt_list_pems base_config_text write_base_config \
           base_config_current update_base_config pem_expired crt_list_host_lines crt_list_hash crt_list_check \
           crt_list_drop_rejected crt_list_validate haproxy_check_crt stamp_applied json_str served_invalidate \
           served_stamp served_write file_sha256; do
    pat="/^$f() {/,/^}/p"   # (bash 3.2 brace-expands the pattern inline)
    eval "$(sed -n "$pat" "$HTTPS")"
    type "$f" >/dev/null 2>&1 || { echo "netrun-https: $f not found"; exit 1; }
  done
  RELOADS="$TMP/reloads"; : > "$RELOADS"
  export NETRUN_ENV_FILE="$TMP/no-netrun.env"
  log() { :; }; die() { echo "DIE $*" >> "$RELOADS"; exit 3; }
  public_ipv4() { echo 45.32.10.20; }
  fix_accounting() { :; }
  sleep() { :; }
  restart_cfg() { echo "restart $1" >> "$RELOADS"; }
  # reload: logged; RELOAD_FAIL=1 -> the script dies there (set -e in the real run).
  reload_haproxy() { echo reload >> "$RELOADS"; [ "${RELOAD_FAIL:-0}" = 0 ] || exit 5; }
  # haproxy -c of a candidate set: CHECK_FAIL=1 rejects it.
  haproxy_check() { [ "${CHECK_FAIL:-0}" = 0 ]; }
  systemctl() { [ "$1 $2" = "is-active --quiet" ] && [ "${HAPROXY_UP:-1}" = 1 ]; }
  # ss -Hltn '<filter>': haproxy listens on every asked port unless HAPROXY_LISTENS=0.
  ss() { [ "${HAPROXY_LISTENS:-1}" = 1 ] || return 0; for p in $(printf '%s\n' "$2" | grep -oE ':[0-9]+' | tr -d :); do echo "LISTEN 0 4096 45.32.10.20:$p 0.0.0.0:*"; done; }
  PROXY_DIR="$TMP/sync/3proxy"; FRONTEND_DIR="$TMP/sync/netrun.d"; mkdir -p "$PROXY_DIR"
  PEM="$TMP/sync/node.pem"; echo pem > "$PEM"; HAPROXY_CFG="$TMP/sync/haproxy.cfg"; echo '# Managed by netrun-https' > "$HAPROXY_CFG"
  # Audit FO-08 — the crt-list (IP certificate only: no hostname list here).
  TLS_DIR="$TMP/sync"; CRT_LIST="$TMP/sync/crt-list"; HOSTS_DIR="$TMP/sync/hosts"; HOSTNAMES_FILE="$TMP/sync/no-hostnames"
  SERVED="$TMP/sync/served.json"; CRT_LIST_OK="$TMP/sync/crt-list.ok"
  APPLIED_STAMP="$TMP/sync/run/haproxy-applied.sha"
  batch() { printf 'socks -6 -a -p%s -i45.32.10.20 -e2001:db8::1\nproxy -6 -n -a -p%s -i127.0.0.1 -e2001:db8::1\n' "$1" "$(($1 - 10000))" > "$PROXY_DIR/3proxy_$1.cfg"; }
  reloads() { grep -c '^reload$' "$RELOADS"; }
  want() { [ "$(reloads)" = "$1" ] || { cat "$RELOADS"; echo "expected $1 reload(s) — $2"; exit 1; }; }
  batch 18100
  ( cmd_sync ); want 1 "first sync must reload"
  [ "$(cat "$APPLIED_STAMP")" = "$(haproxy_config_hash)" ] || { echo "stamp not written after a verified reload"; exit 1; }
  # Audit FO-08 (review) — served.json goes with the stamp (no hostnames here).
  [ "$(served_stamp)" = "$(cat "$APPLIED_STAMP")" ] && grep -q '"crtListBound": true' "$SERVED" || { cat "$SERVED"; echo "served.json"; exit 1; }
  ( cmd_sync ); ( cmd_sync ); want 1 "unchanged syncs with a valid stamp reloaded haproxy"
  batch 18200; ( cmd_sync ); want 2 "a new batch did not reload"
  rm -f "$PROXY_DIR/3proxy_18200.cfg"; ( cmd_sync ); want 3 "a removed batch did not reload"
  [ ! -e "$FRONTEND_DIR/3proxy_18200.cfg" ] || { echo "stale frontend kept"; exit 1; }
  ( HAPROXY_UP=0 cmd_sync ); want 4 "a stopped haproxy was not started"
  # (a) the reload fails once: the files are in place, the next sync retries, later ones do not.
  batch 18300
  if ( RELOAD_FAIL=1 cmd_sync ); then echo "a failed reload must fail the sync"; exit 1; fi
  want 5 "failed reload attempt"
  [ -e "$FRONTEND_DIR/3proxy_18300.cfg" ] || { echo "validated set not installed"; exit 1; }
  ( cmd_sync ); want 6 "a failed reload was not retried"
  ( cmd_sync ); want 6 "retried twice"
  # (b) the reload "succeeds" but haproxy does not listen on the new frontend: not stamped, retried.
  batch 18400
  if ( HAPROXY_LISTENS=0 cmd_sync ); then echo "an unverified reload must fail the sync"; exit 1; fi
  want 7 "unverified reload attempt"
  [ ! -e "$SERVED" ] || { echo "served.json kept after an unverified reload"; exit 1; }
  ( HAPROXY_LISTENS=0 cmd_sync ) || true; want 8 "an unverified reload was not retried"
  ( cmd_sync ); want 9 "verified retry"
  [ "$(served_stamp)" = "$(cat "$APPLIED_STAMP")" ] || { echo "served.json not rewritten after the verified retry"; exit 1; }
  rm -f "$SERVED"; ( cmd_sync ); want 9 "a lost served.json costs no reload"
  [ "$(served_stamp)" = "$(cat "$APPLIED_STAMP")" ] || { echo "served.json not restored on a quiet sync"; exit 1; }
  ( cmd_sync ); want 9 "verified once, then quiet"
  ( HAPROXY_LISTENS=0 NETRUN_HTTPS_RELOAD_VERIFY=0 cmd_sync ); want 9 "verify off: nothing to do anyway"
  # (c) haproxy rejects the new set: the live directory is left untouched, nothing reloaded.
  batch 18500
  before="$(ls "$FRONTEND_DIR" | tr '\n' ' ')"
  if ( CHECK_FAIL=1 cmd_sync ); then echo "a rejected set must fail the sync"; exit 1; fi
  [ "$(ls "$FRONTEND_DIR" | tr '\n' ' ')" = "$before" ] || { echo "a rejected set reached the live dir"; exit 1; }
  grep -q 'DIE haproxy rejects the new frontend set' "$RELOADS" || { echo "no die on a rejected set"; exit 1; }
  want 9 "reloaded a rejected set"
  ( cmd_sync ); want 10 "the fixed set was not installed + reloaded"
  [ -e "$FRONTEND_DIR/3proxy_18500.cfg" ] || { echo "fixed set not installed"; exit 1; }
  # (d) the max-age safety net (6 h by default; 0 = off); a missing stamp (reboot) = one reload.
  touch -t 202001010000 "$APPLIED_STAMP"
  ( NETRUN_HTTPS_RELOAD_MAX_AGE_H=0 cmd_sync ); want 10 "max age 0 must never reload"
  ( cmd_sync ); want 11 "an expired stamp did not reload"
  ( cmd_sync ); want 11 "a fresh stamp reloaded"
  rm -f "$APPLIED_STAMP"; ( cmd_sync ); want 12 "no stamp (reboot) must reload once"
  ( cmd_sync ); want 12 "after the stamp is back: quiet"
  # Audit FO-08 — the first sync migrated the managed base config to the crt-list.
  grep -qx "    bind abns@netrun_tls accept-proxy ssl crt-list $CRT_LIST alpn http/1.1" "$HAPROXY_CFG" || { echo "base config not migrated"; exit 1; }
  [ "$(cat "$CRT_LIST")" = "$PEM" ] || { echo "crt-list"; exit 1; }
  # frontend_first_ports / frontend_ports_missing
  [ "$(frontend_first_ports | sort -n | tr '\n' ' ')" = "8100 8300 8400 8500 " ] || { frontend_first_ports; echo "first ports"; exit 1; }
  [ -z "$(frontend_ports_missing 45.32.10.20 8100 8300)" ] || { echo "listening ports reported missing"; exit 1; }
  [ "$(HAPROXY_LISTENS=0 frontend_ports_missing 45.32.10.20 8100 8300 | tr '\n' ' ')" = "8100 8300 " ] || { echo "missing ports not reported"; exit 1; }
  exit 0
) || fail "netrun-https: reload-on-change + reload stamp"
grep -q 'with_sync_lock cmd_sync' "$HTTPS" || fail "netrun-https: sync not serialized with flock"
# renew: the ACME exchange (lego, minutes when the CA is slow) runs OUTSIDE the
# sync lock (under the ACME lock, FO-08); only the PEM swap + reload + stamp
# take the sync lock. (scripts/test_https_hostnames.sh: the hostname step.)
(
  eval "$(sed -n '/^cmd_renew() {/,/^}/p' "$HTTPS")"
  eval "$(sed -n '/^renew_obtain() {/,/^}/p' "$HTTPS")"
  CALLS="$TMP/renew_calls"; : > "$CALLS"
  log() { :; }; public_ipv4() { echo 45.32.10.20; }
  https_hostnames() { :; }; applied_write() { :; }
  lego_obtain() { echo "lego locked=${LOCKED:-0}" >> "$CALLS"; }
  certs_obtain() { :; }
  with_acme_lock() { "$@"; }
  with_sync_lock() { LOCKED=1 "$@"; }
  cmd_renew_apply() { echo "apply locked=${LOCKED:-0}" >> "$CALLS"; }
  cmd_renew
  [ "$(tr '\n' ' ' < "$CALLS")" = "lego locked=0 apply locked=1 " ] || { cat "$CALLS"; exit 1; }
) || fail "netrun-https renew: lego must run outside the sync lock"
grep -qE '^  renew\) cmd_renew ;;' "$HTTPS" || fail "netrun-https: renew must not take the lock around lego"
grep -q 'NETRUN_HTTPS_LOCK_WAIT_SEC=60 /usr/local/sbin/netrun-https sync' "$ROOT_DIR/node_runtime/soft/generator/proxyyy_automated.sh" \
  || fail "generator: in-line netrun-https sync without a short lock wait"
grep -q '^KillMode=process$' "$HTTPS" || fail "netrun-https: sync unit without KillMode=process"
grep -q 'bash "$SPAWN_HELPER" "$cfg"' "$HTTPS" || fail "netrun-https: restart_cfg not via the spawn helper"
grep -q 'bash "$SPAWN_HELPER" "$cfg"' "$ROOT_DIR/scripts/netrun-harden.sh" || fail "netrun-harden: restart_cfg not via the spawn helper"
ok "netrun-https sync: reload only on a change / stopped haproxy / unapplied stamp; new set validated before it goes live; failed + unverified reloads retried; flock; KillMode=process; restarts via the spawn helper"

echo "test_capacity_18k_node.sh — all $PASS checks passed"
