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
# No interface: a loud failure (exit 1), not a silent exit 0.
printf '#!/bin/sh\nexit 0\n' > "$TMP/stub/ip"
if PATH="$TMP/stub:$PATH" NETRUN_PROXY_ROOT="$PR" NETRUN_IPV6_IFACE="" bash "$RESTORE" 2>"$TMP/restore_err"; then fail "restore: no interface must exit non-zero"; fi
grep -q 'ERROR: no IPv6 default route' "$TMP/restore_err" || fail "restore: no-interface message"
ok "ipv6 restore: unique -e addresses, /128 deprecated (switchable), ONE ip -6 -force -batch with nodad, loud failure without an interface"

# ── 5. netrun-https sync: haproxy reloaded ONLY when its config changed ──
(
  for f in http_port_ranges localize_http_listeners write_frontends frontend_sets_equal cmd_sync; do
    pat="/^$f() {/,/^}/p"   # (bash 3.2 brace-expands the pattern inline)
    eval "$(sed -n "$pat" "$HTTPS")"
  done
  RELOADS="$TMP/reloads"; : > "$RELOADS"
  log() { :; }; die() { echo "DIE $*"; exit 3; }
  public_ipv4() { echo 45.32.10.20; }
  fix_accounting() { :; }
  restart_cfg() { echo "restart $1" >> "$RELOADS"; }
  reload_haproxy() { echo reload >> "$RELOADS"; }
  systemctl() { [ "$1 $2" = "is-active --quiet" ] && [ "${HAPROXY_UP:-1}" = 1 ]; }
  PROXY_DIR="$TMP/sync/3proxy"; FRONTEND_DIR="$TMP/sync/netrun.d"; mkdir -p "$PROXY_DIR"
  PEM="$TMP/sync/node.pem"; echo pem > "$PEM"; HAPROXY_CFG="$TMP/sync/haproxy.cfg"; echo '# Managed by netrun-https' > "$HAPROXY_CFG"
  printf 'socks -6 -a -p18100 -i45.32.10.20 -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\n' > "$PROXY_DIR/3proxy_18100.cfg"
  cmd_sync; [ "$(grep -c reload "$RELOADS")" = 1 ] || { cat "$RELOADS"; echo "first sync must reload"; exit 1; }
  cmd_sync; cmd_sync; [ "$(grep -c reload "$RELOADS")" = 1 ] || { cat "$RELOADS"; echo "unchanged syncs reloaded haproxy"; exit 1; }
  printf 'socks -6 -a -p18200 -i45.32.10.20 -e2001:db8::2\nproxy -6 -n -a -p8200 -i127.0.0.1 -e2001:db8::2\n' > "$PROXY_DIR/3proxy_18200.cfg"
  cmd_sync; [ "$(grep -c reload "$RELOADS")" = 2 ] || { echo "a new batch did not reload"; exit 1; }
  rm -f "$PROXY_DIR/3proxy_18200.cfg"
  cmd_sync; [ "$(grep -c reload "$RELOADS")" = 3 ] || { echo "a removed batch did not reload"; exit 1; }
  [ ! -e "$FRONTEND_DIR/3proxy_18200.cfg" ] || { echo "stale frontend kept"; exit 1; }
  HAPROXY_UP=0 cmd_sync; [ "$(grep -c reload "$RELOADS")" = 4 ] || { echo "a stopped haproxy was not started"; exit 1; }
  exit 0
) || fail "netrun-https: reload-on-change"
grep -q '^KillMode=process$' "$HTTPS" || fail "netrun-https: sync unit without KillMode=process"
grep -q 'bash "$SPAWN_HELPER" "$cfg"' "$HTTPS" || fail "netrun-https: restart_cfg not via the spawn helper"
grep -q 'bash "$SPAWN_HELPER" "$cfg"' "$ROOT_DIR/scripts/netrun-harden.sh" || fail "netrun-harden: restart_cfg not via the spawn helper"
ok "netrun-https sync: haproxy reloaded only on a frontend/base change (or when stopped); KillMode=process; restarts via the spawn helper"

echo "test_capacity_18k_node.sh — all $PASS checks passed"
