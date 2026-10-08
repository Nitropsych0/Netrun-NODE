#!/usr/bin/env bash
# netrun-proxy-guard: the generated table (compact network sets: the NIC /64
# for any number of /128 anchors, the routed /48, the node IPv4, fixed nets),
# the NDP safety check (guard_safe: the 2026-10-08 hand version with
# `meta skuid != 65535 accept` rejected the kernel's own NDP and cost both
# nodes their IPv6 router), apply = check + write + one-transaction load +
# verify + boot drop-in, idempotence, --dry-run, refusal paths. ip / nft /
# systemctl are stubs on PATH; python3 is real. No root.
#   bash scripts/test_netrun_proxy_guard.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
GUARD="$ROOT_DIR/scripts/netrun-proxy-guard.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3"; exit 0; }
bash -n "$GUARD" || fail "bash -n netrun-proxy-guard.sh"

STUB="$TMP/bin"; mkdir -p "$STUB"
export STUB_LOG="$TMP/calls.log" NODE_KIND=jnb LOADED="$TMP/loaded.nft" NFT_CHECK_RC_FILE="$TMP/check_rc" KERNEL_OVERRIDE="$TMP/kernel_override.nft"
: > "$STUB_LOG"
cat > "$STUB/ip" <<'EOF'
#!/usr/bin/env bash
echo "ip $*" >> "$STUB_LOG"
case "$NODE_KIND:$*" in
  *:"-4 -o addr show scope global")
    echo "2: enp1s0    inet 139.84.246.71/23 metric 100 brd 139.84.247.255 scope global enp1s0\       valid_lft forever preferred_lft forever"
    echo "3: enp6s0    inet 10.24.96.3/20 brd 10.24.111.255 scope global enp6s0\       valid_lft forever preferred_lft forever" ;;
  jnb:"-6 -o addr show scope global")
    echo "2: enp1s0    inet6 2a05:f480:3000:2976:5400:6ff:fed3:bc58/64 scope global mngtmpaddr noprefixroute \       valid_lft forever preferred_lft forever"
    # 22000 /128 anchors of the same /64, as many as Johannesburg carries: ~2.6 MB of
    # `ip -o` text, far over the 128 KiB a single argv string may have on Linux
    # (the 2026-10-09 deploy failed with "Argument list too long" on it)
    python3 -c 'import random
for i in range(22000): print("2: enp1s0    inet6 2a05:f480:3000:2976:%x:%x:%x:%x/128 scope global nodad \\       valid_lft forever preferred_lft 0sec" % tuple(random.randrange(1, 65536) for _ in range(4)))' ;;
  chi:"-6 -o addr show scope global")
    echo "2: enp1s0    inet6 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf/64 scope global mngtmpaddr noprefixroute \       valid_lft forever preferred_lft forever" ;;
  jnb:"-6 route show table local dev lo") echo "local ::1 proto kernel metric 0 pref medium" ;;
  chi:"-6 route show table local dev lo")
    echo "local ::1 proto kernel metric 0 pref medium"
    echo "local 2602:f2dc:a9::/48 metric 1024 pref medium"
    echo "local 2602:f2dc:a9:5::/64 metric 1024 pref medium"
    echo "local 2001:19f0:5c01:cdf::5 proto kernel metric 0 pref medium" ;;
  *) echo "ip stub: unexpected: $*" >&2; exit 2 ;;
esac
EOF
# The kernel: `-f` loads the file's table definition, `list table` prints it
# (or $KERNEL_OVERRIDE: a kernel that holds something else), `delete` drops it.
cat > "$STUB/nft" <<'EOF'
#!/usr/bin/env bash
echo "nft $*" >> "$STUB_LOG"
case "$*" in
  "-c -f "*) exit "$(cat "$NFT_CHECK_RC_FILE" 2>/dev/null || echo 0)" ;;
  "-f "*) awk '/^table inet netrun_proxy_guard \{/ { on = 1 } on' "$2" > "$LOADED" ;;
  "list table inet netrun_proxy_guard")
    if [ -s "$KERNEL_OVERRIDE" ]; then cat "$KERNEL_OVERRIDE"; exit 0; fi
    [ -s "$LOADED" ] && cat "$LOADED" ;;
  "delete table inet netrun_proxy_guard") rm -f "$LOADED" ;;
  *) exit 1 ;;
esac
EOF
cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
EOF
chmod +x "$STUB"/*
export PATH="$STUB:$PATH"
export NETRUN_PROXY_GUARD_FILE="$TMP/etc/netrun/nft-proxy-guard.nft" NETRUN_PROXY_GUARD_UNIT_DIR="$TMP/systemd" \
       NETRUN_PROXY_GUARD_SELF="$TMP/sbin/netrun-proxy-guard"
DROPIN="$TMP/systemd/nftables.service.d/netrun-proxy-guard.conf"
run() { bash "$GUARD" "$@"; }
mode_of() { stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1"; }

# ── 1. the sets: networks only ────────────────────────────────────
out="$(NODE_KIND=jnb run print)" || fail "print (jnb)"
v6="$(printf '%s\n' "$out" | grep 'ip6 daddr {')"
[ "$v6" = "    ip6 daddr { ::1, fe80::/10, fc00::/7, ff00::/8, 2a05:f480:3000:2976::/64 } reject" ] \
  || fail "jnb: 3000 /128 anchors + the SLAAC address must be ONE /64: $v6"
v4="$(printf '%s\n' "$out" | grep '    ip daddr {')"
[ "$v4" = "    ip daddr { 127.0.0.0/8, 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 139.84.246.71 } reject" ] \
  || fail "jnb v4 (the VPC 10.x address is covered by 10/8, not listed twice): $v4"
[ "$(printf '%s\n' "$out" | wc -c)" -lt 2000 ] || fail "the file is not compact"
out="$(NODE_KIND=chi run print)" || fail "print (chi)"
v6="$(printf '%s\n' "$out" | grep 'ip6 daddr {')"
[ "$v6" = "    ip6 daddr { ::1, fe80::/10, fc00::/7, ff00::/8, 2001:19f0:5c01:cdf::/64, 2602:f2dc:a9::/48 } reject" ] \
  || fail "chi: the routed /48 (a /64 inside it and a /128 host route merged away): $v6"
ok "sets: networks only — one NIC /64 for 22000 anchors, routed /48 merged, private IPv4 covered"

# ── 2. the NDP safety check ───────────────────────────────────────
printf '%s\n' "$out" | run check >/dev/null || fail "the generated guard fails its own check"
printf '%s\n' "$out" | grep -q 'skuid !=' && fail "the generated guard has a skuid != rule"
awk '/^table inet netrun_proxy_guard \{/ { on = 1 } on' <(printf '%s\n' "$out") | sed 's/^  /\t/' | run check >/dev/null \
  || fail "the kernel's listing of the generated guard must pass"
# the hand-made version of 2026-10-08 22:19 (killed NDP after the reboots)
cat > "$TMP/hand.nft" <<'EOF'
table inet netrun_proxy_guard {
	chain output {
		type filter hook output priority filter; policy accept;
		meta skuid != 65535 accept
		ip daddr 127.0.0.1 udp dport 53 accept
		ct state established,related accept
		ip6 daddr { ::1, 2001:19f0:5c01:cdf::/64, 2602:f2dc:a9::/48, fc00::/7, fe80::/10, ff00::/8 } reject with icmpv6 port-unreachable
	}
}
EOF
why="$(run check < "$TMP/hand.nft")" && fail "the hand-made skuid != guard passed the check"
echo "$why" | grep -q 'skuid !=' || fail "reason names skuid !=: $why"
printf '%s\n' "$out" | sed 's/meta skuid 65535 jump proxy/meta skuid 65535 jump proxy\n    ip6 daddr ff00::\/8 reject/' | run check >/dev/null \
  && fail "an ungated reject in the hooked chain passed"
printf '%s\n' "$out" | sed 's/policy accept;/policy drop;/' | run check >/dev/null && fail "policy drop passed"
printf '%s\n' "$out" | sed '/meta skuid 65535 jump proxy/d' | run check >/dev/null && fail "a guard without the jump passed"
ok "check: generated guard (file and kernel listing) safe; skuid != / ungated reject / policy drop / no jump refused"

# ── 3. dry run touches nothing ────────────────────────────────────
out="$(NODE_KIND=chi run apply --dry-run)" || fail "dry run: $out"
[ ! -e "$NETRUN_PROXY_GUARD_FILE" ] && [ ! -e "$DROPIN" ] && [ ! -e "$LOADED" ] || fail "dry run changed something"
echo "$out" | grep -q "would create" || fail "dry run report: $out"
ok "apply --dry-run: prints, writes and loads nothing"

# ── 4. apply ──────────────────────────────────────────────────────
: > "$STUB_LOG"
out="$(NODE_KIND=chi run apply)" || fail "apply: $out"
[ "$(mode_of "$NETRUN_PROXY_GUARD_FILE")" = 644 ] || fail "guard file mode"
[ "$(cat "$NETRUN_PROXY_GUARD_FILE")" = "$(NODE_KIND=chi run print)" ] || fail "guard file = print"
grep -q "meta skuid 65535 jump proxy" "$LOADED" || fail "table loaded"
check_line=$(grep -n "^nft -c -f" "$STUB_LOG" | head -1 | cut -d: -f1)
load_line=$(grep -n "^nft -f $NETRUN_PROXY_GUARD_FILE" "$STUB_LOG" | head -1 | cut -d: -f1)
[ -n "$check_line" ] && [ -n "$load_line" ] && [ "$check_line" -lt "$load_line" ] || fail "nft -c before nft -f"
grep -qx "ExecStartPost=-.*nft -f $NETRUN_PROXY_GUARD_FILE" "$DROPIN" || fail "boot drop-in: $(cat "$DROPIN")"
grep -q "systemctl daemon-reload" "$STUB_LOG" || fail "daemon-reload after a new drop-in"
cmp -s "$GUARD" "$NETRUN_PROXY_GUARD_SELF" || fail "installed as netrun-proxy-guard"
sed -n '4,6p' "$NETRUN_PROXY_GUARD_FILE" | tr '\n' '|' | grep -q '^table inet netrun_proxy_guard|delete table inet netrun_proxy_guard|table inet netrun_proxy_guard {|$' \
  || fail "one transaction: add + delete + define"
ok "apply: checked, written 0644, loaded in one transaction, verified, boot drop-in, installed copy"

: > "$STUB_LOG"
out="$(NODE_KIND=chi run apply)" || fail "second apply"
echo "$out" | grep -q "wrote" && fail "second apply rewrote a file: $out"
grep -q daemon-reload "$STUB_LOG" && fail "second apply reloaded systemd"
grep -q "^nft -f" "$STUB_LOG" || fail "second apply still (re)loads the table"
ok "apply again: no file rewritten, no daemon-reload; the table is re-asserted"

# ── 5. refusals ───────────────────────────────────────────────────
before="$(cat "$NETRUN_PROXY_GUARD_FILE")"
echo 1 > "$NFT_CHECK_RC_FILE"
NODE_KIND=jnb run apply >/dev/null 2>&1 && fail "apply passed with nft -c rejecting"
[ "$(cat "$NETRUN_PROXY_GUARD_FILE")" = "$before" ] || fail "a rejected guard was written"
rm -f "$NFT_CHECK_RC_FILE"
# the kernel holds an unsafe table after the load (someone else's edit): deleted
cp "$TMP/hand.nft" "$KERNEL_OVERRIDE"
out="$(NODE_KIND=chi run apply 2>&1)" && fail "apply passed with an unsafe kernel table"
echo "$out" | grep -q "unsafe" || fail "unsafe reason: $out"
grep -q "^nft delete table inet netrun_proxy_guard" "$STUB_LOG" || fail "the unsafe table is deleted"
rm -f "$KERNEL_OVERRIDE"
NODE_KIND=chi run apply >/dev/null || fail "recovery apply"
ok "nft -c rejects -> nothing written; an unsafe loaded table is deleted (no guard beats a guard that kills NDP)"

echo "PASS ($PASS)"
