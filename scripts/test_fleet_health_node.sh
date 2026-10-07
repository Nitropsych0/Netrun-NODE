#!/usr/bin/env bash
# Wave FLEET-HEALTH — node-side script tests:
#   - conntrack: RAM-sized nf_conntrack_max that survives reboots
#     (install_node_v2.sh, node_followup_v2.sh and apply_capacity_tuning.sh
#     agree on the formula and on the modules-load / udev files);
#   - SPD-05: netrun-https.sh fix_accounting converges the two counter map
#     rules (port-only + lo excluded by default; + `ip daddr|saddr <public
#     IPv4>` with NETRUN_ACCOUNTING_MATCH_IPV4=1), by handle, both ways.
# Functions are pulled out of the real scripts and run against temp files with
# stubbed commands — no root needed.
#   bash scripts/test_fleet_health_node.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
INSTALL="$ROOT_DIR/install_node_v2.sh"
FOLLOWUP="$ROOT_DIR/scripts/node_followup_v2.sh"
TUNING="$ROOT_DIR/scripts/apply_capacity_tuning.sh"
HTTPS="$ROOT_DIR/scripts/netrun-https.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
extract() { sed -n "/^$2() {/,/^}/p" "$1"; }

for f in "$INSTALL" "$FOLLOWUP" "$TUNING" "$HTTPS"; do
  bash -n "$f" 2>/dev/null || sed 's/&>>/>>/g' "$f" | bash -n || fail "syntax: $f"
done
ok "bash -n: installer, follow-up, apply_capacity_tuning, netrun-https"

# ── 1. one formula in three scripts ───────────────────────────────
for src in "$INSTALL" "$FOLLOWUP" "$TUNING"; do
  body="$(extract "$src" conntrack_max_for_mem_kb)"
  [ -n "$body" ] || fail "conntrack_max_for_mem_kb missing in $src"
  (
    eval "$body"
    check() { [ "$(conntrack_max_for_mem_kb "$1")" = "$2" ] || fail "$(basename "$src"): $1 kB -> $(conntrack_max_for_mem_kb "$1"), want $2"; }
    check 1011712 65536     # 1 GB box
    check 1990000 131072    # 2 GB
    check 3911456 262144    # 2c/4GB Vultr (MemTotal ~3.8 GiB)
    check 4026531 262144    # a "full" 4 GiB
    check 7990000 524288    # 8 GB
    check 16000000 1048576  # 16 GB
    check 65000000 1048576  # cap
    check "" 65536
    check "garbage" 65536
  ) || exit 1
done
ok "conntrack_max_for_mem_kb identical in installer / follow-up / tuning: 2c/4GB -> 262144, 65536..1048576"

# ── 2. installer: files + persisted key, heredoc no longer pins 1048576 ─
awk '/cat > "\$SYSCTL_FILE" <<.EOF./ { on = 1; next } on && /^EOF$/ { exit } on' "$INSTALL" > "$TMP/installer-99.conf"
! grep -qE '^[[:space:]]*net\.netfilter\.nf_conntrack_max[[:space:]]*=' "$TMP/installer-99.conf" || fail "installer heredoc still pins nf_conntrack_max"
grep -qx 'net.netfilter.nf_conntrack_tcp_timeout_established = 7200' "$TMP/installer-99.conf" || fail "installer lost timeout_established"
grep -q '^  configure_conntrack_persistence$' "$INSTALL" || fail "configure_sysctl does not call configure_conntrack_persistence"
(
  mkdir -p "$TMP/stub"
  printf '#!/bin/sh\necho "udevadm $*" >> "%s/calls"\n' "$TMP" > "$TMP/stub/udevadm"; chmod +x "$TMP/stub/udevadm"
  PATH="$TMP/stub:$PATH"
  log() { :; }
  eval "$(extract "$INSTALL" conntrack_max_for_mem_kb)"
  eval "$(extract "$INSTALL" set_sysctl_kv)"
  eval "$(extract "$INSTALL" configure_conntrack_persistence)"
  SYSCTL_FILE="$TMP/i/99-netrun.conf"
  CONNTRACK_MODULES_FILE="$TMP/i/modules-load.d/netrun-conntrack.conf"
  CONNTRACK_UDEV_RULE="$TMP/i/udev/90-netrun-conntrack.rules"
  mkdir -p "$TMP/i"; printf 'kernel.pid_max = 4194304\nnet.netfilter.nf_conntrack_max = 1048576\n' > "$SYSCTL_FILE"
  NETRUN_CONNTRACK_MAX=262144 configure_conntrack_persistence
  grep -qx 'net.netfilter.nf_conntrack_max = 262144' "$SYSCTL_FILE" || fail "installer: value not persisted"
  [ "$(grep -c nf_conntrack_max "$SYSCTL_FILE")" = 1 ] || fail "installer: duplicate key"
  grep -qx 'kernel.pid_max = 4194304' "$SYSCTL_FILE" || fail "installer: other key lost"
  grep -qx 'udevadm control --reload' "$TMP/calls" || fail "installer: udev not reloaded"
  cp "$CONNTRACK_MODULES_FILE" "$TMP/installer.modules"; cp "$CONNTRACK_UDEV_RULE" "$TMP/installer.udev"
) || exit 1
grep -qx 'nf_conntrack' "$TMP/installer.modules" || fail "installer: modules-load file"
grep -qx 'ACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/netfilter"' "$TMP/installer.udev" \
  || fail "installer: udev rule"
ok "installer: modules-load + udev rule written, RAM value persisted in 99-netrun.conf (replaces 1048576)"

# ── 3. tuning step + follow-up write byte-identical boot files ────
mod_text="$(sed -n "s/^CT_MODULES_TEXT='//p" "$TUNING")"
[ -n "$mod_text" ] || fail "tuning: CT_MODULES_TEXT not found"
[ "$(head -n 1 "$TMP/installer.modules")" = "$mod_text" ] || fail "modules-load comment differs (installer vs tuning)"
grep -qF "$(tail -n 1 "$TMP/installer.udev")" "$TUNING" || fail "udev rule differs (installer vs tuning)"
grep -qF "$(head -n 1 "$TMP/installer.udev")" "$TUNING" || fail "udev comment differs (installer vs tuning)"
grep -qF "$(head -n 1 "$TMP/installer.modules")" "$FOLLOWUP" || fail "modules-load comment differs (installer vs follow-up)"
grep -qF "$(tail -n 1 "$TMP/installer.udev")" "$FOLLOWUP" || fail "udev rule differs (installer vs follow-up)"
grep -q '/etc/modules-load.d/netrun-conntrack.conf' "$FOLLOWUP" && grep -q '/etc/udev/rules.d/90-netrun-conntrack.rules' "$FOLLOWUP" \
  || fail "follow-up writes other paths"
grep -q 'merge_sysctl_conf /etc/sysctl.d/99-netrun.conf "net.netfilter.nf_conntrack_max=$CONNTRACK_MAX"' "$FOLLOWUP" \
  || fail "follow-up does not persist the RAM value"
! grep -q 'nf_conntrack_max=1048576' "$FOLLOWUP" || fail "follow-up still forces 1048576"
ok "installer, follow-up and tuning step write the same modules-load / udev files and paths"

# ── 4. netrun-https: accounting rule convergence ──────────────────
eval "$(extract "$HTTPS" netrun_setting)"
eval "$(extract "$HTTPS" accounting_rules_to_fix)"
# fix_accounting persists to /etc/nftables.conf; point that write at the temp dir.
eval "$(extract "$HTTPS" fix_accounting | sed "s#/etc/nftables.conf#$TMP/nftables.conf#")"
log() { echo "LOG $*" >> "$TMP/https_calls"; }
public_ipv4() { echo 45.32.10.20; }
chain_in() { # form: plain | lo | v4
  echo "table inet proxy_accounting { # handle 3"
  echo "	chain input { # handle 1"
  echo "		tcp dport @pergb_blocked drop # handle 50"
  case "$1" in
    plain) echo "		counter name tcp dport map @cmap_in # handle 51" ;;
    lo) echo "		iifname != \"lo\" counter name tcp dport map @cmap_in # handle 51" ;;
    v4) echo "		iifname != \"lo\" ip daddr 45.32.10.20 counter name tcp dport map @cmap_in # handle 51" ;;
    v4other) echo "		iifname != \"lo\" ip daddr 45.32.10.21 counter name tcp dport map @cmap_in # handle 51" ;;
  esac
  echo "	}"
}
chain_out() {
  echo "	chain output { # handle 2"
  case "$1" in
    plain) echo "		counter name tcp sport map @cmap_out # handle 61" ;;
    lo) echo "		oifname != \"lo\" counter name tcp sport map @cmap_out # handle 61" ;;
    v4) echo "		oifname != \"lo\" ip saddr 45.32.10.20 counter name tcp sport map @cmap_out # handle 61" ;;
    v4other) echo "		oifname != \"lo\" ip saddr 45.32.10.21 counter name tcp sport map @cmap_out # handle 61" ;;
  esac
  echo "	}"
}
nft() {
  case "$*" in
    "list table inet proxy_accounting") return 0 ;;
    "-a list chain inet proxy_accounting input") chain_in "$STATE" ;;
    "-a list chain inet proxy_accounting output") chain_out "$STATE" ;;
    "list ruleset") echo "# ruleset" ;;
    *) echo "nft $*" >> "$TMP/https_calls" ;;
  esac
}
run_fix() { # state flag -> the nft replace commands issued
  : > "$TMP/https_calls"
  STATE="$1"
  ( NETRUN_ENV_FILE="$TMP/none.env" NETRUN_ACCOUNTING_MATCH_IPV4="$2"; export NETRUN_ACCOUNTING_MATCH_IPV4
    fix_accounting > /dev/null ) || fail "fix_accounting failed (state $1, flag $2)"
  grep '^nft replace' "$TMP/https_calls" || true
}

want_in_lo='nft replace rule inet proxy_accounting input handle 51 iifname != lo counter name tcp dport map @cmap_in'
want_out_lo='nft replace rule inet proxy_accounting output handle 61 oifname != lo counter name tcp sport map @cmap_out'
want_in_v4='nft replace rule inet proxy_accounting input handle 51 iifname != lo ip daddr 45.32.10.20 counter name tcp dport map @cmap_in'
want_out_v4='nft replace rule inet proxy_accounting output handle 61 oifname != lo ip saddr 45.32.10.20 counter name tcp sport map @cmap_out'

[ "$(run_fix plain 0)" = "$(printf '%s\n%s' "$want_in_lo" "$want_out_lo")" ] || fail "default: plain rules must get the lo exclusion (as before)"
[ -z "$(run_fix lo 0)" ] || fail "default: lo-only rules must be left alone (as before)"
[ "$(run_fix v4 0)" = "$(printf '%s\n%s' "$want_in_lo" "$want_out_lo")" ] || fail "default: restricted rules roll back to lo-only"
[ "$(run_fix plain 1)" = "$(printf '%s\n%s' "$want_in_v4" "$want_out_v4")" ] || fail "flag: plain -> restricted"
[ "$(run_fix lo 1)" = "$(printf '%s\n%s' "$want_in_v4" "$want_out_v4")" ] || fail "flag: lo-only -> restricted"
[ -z "$(run_fix v4 1)" ] || fail "flag: restricted rules are idempotent"
[ "$(run_fix v4other 1)" = "$(printf '%s\n%s' "$want_in_v4" "$want_out_v4")" ] || fail "flag: a changed public IPv4 is re-pinned"
grep -q '# ruleset' "$TMP/nftables.conf" || fail "ruleset not persisted (the 5-min counter snapshot)"
! grep -q 'counter inet\|element' "$TMP/https_calls" || fail "counters / map elements must never be touched"
printf 'NETRUN_ACCOUNTING_MATCH_IPV4="1"\n' > "$TMP/netrun.env"
[ "$(NETRUN_ACCOUNTING_MATCH_IPV4='' NETRUN_ENV_FILE="$TMP/netrun.env" netrun_setting NETRUN_ACCOUNTING_MATCH_IPV4 0)" = 1 ] || fail "setting from the env file"
[ "$(NETRUN_ACCOUNTING_MATCH_IPV4=0 NETRUN_ENV_FILE="$TMP/netrun.env" netrun_setting NETRUN_ACCOUNTING_MATCH_IPV4 0)" = 0 ] || fail "environment wins over the file"
[ "$(NETRUN_ENV_FILE="$TMP/none.env" netrun_setting NETRUN_ACCOUNTING_MATCH_IPV4 0)" = 0 ] || fail "default when unset"
grep -q '^  accounting) fix_accounting ;;$' "$HTTPS" || fail "netrun-https has no 'accounting' subcommand"
ok "netrun-https fix_accounting: default = today's rules; NETRUN_ACCOUNTING_MATCH_IPV4=1 pins ip daddr/saddr <public v4>; idempotent, both ways, by handle"

echo "test_fleet_health_node.sh — all $PASS checks passed"
