#!/usr/bin/env bash
# netrun-proxy-guard: the generated table (compact network sets: the NIC /64
# for any number of /128 anchors, the routed /48, the node IPv4, fixed nets),
# the NDP safety check (guard_safe: the 2026-10-08 hand version with
# `meta skuid != 65535 accept` rejected the kernel's own NDP and cost both
# nodes their IPv6 router), apply = check + write + one-transaction load +
# verify + boot drop-in, idempotence, --dry-run, refusal paths. ip / nft /
# systemctl / getent are stubs on PATH; python3 is real. No root.
# Pay-per-GB v2 (sections 6-7): the per-GB uid 65533 and its chain `pergb`
# (RADIUS on 127.0.0.1:1812 allowed only there), the default uid list, the
# option-B IPv4, guard_safe with several uids; and, as root on Linux with nft
# and ip netns (CI: .github/workflows/pergb-linux.yml), the generated guard in
# a network namespace with real sockets per uid.
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
# The passwd lookup of the per-GB uid: $GETENT_65533 is the user name that
# owns uid 65533 (empty = nobody: per-GB not installed).
cat > "$STUB/getent" <<'EOF'
#!/usr/bin/env bash
if [ "$1 $2" = "passwd 65533" ] && [ -n "${GETENT_65533:-}" ]; then echo "$GETENT_65533:x:65533:65533::/nonexistent:/usr/sbin/nologin"; exit 0; fi
exit 2
EOF
chmod +x "$STUB"/*
export GETENT_65533="" NETRUN_PERGB_ENABLE_FILE="$TMP/no-enable.json"
export PATH="$STUB:$PATH"
export NETRUN_PROXY_GUARD_FILE="$TMP/etc/netrun/nft-proxy-guard.nft" NETRUN_PROXY_GUARD_UNIT_DIR="$TMP/systemd" \
       NETRUN_PROXY_GUARD_SELF="$TMP/sbin/netrun-proxy-guard"
DROPIN="$TMP/systemd/nftables.service.d/netrun-proxy-guard.conf"
run() { bash "$GUARD" "$@"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

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

# ── 6. pay-per-GB v2: the per-GB uid 65533 and its chain ──────────
out="$(NODE_KIND=chi NETRUN_PROXY_UIDS="65535 65533" run print)" || fail "print (two uids)"
hooked="$(printf '%s\n' "$out" | awk '/chain output/ { on = 1; next } on && /^  }/ { exit } on')"
[ "$(printf '%s\n' "$hooked" | grep -c 'meta skuid')" = 2 ] || fail "two gated jumps: $hooked"
printf '%s\n' "$hooked" | grep -qx '    meta skuid 65535 jump proxy' || fail "65535 -> proxy"
printf '%s\n' "$hooked" | grep -qx '    meta skuid 65533 jump pergb' || fail "65533 -> pergb"
chain_of() { printf '%s\n' "$out" | awk -v c="$1" '$1 == "chain" && $2 == c { on = 1; next } on && /^  }/ { exit } on'; }
proxy_chain="$(chain_of proxy)"; pergb_chain="$(chain_of pergb)"
[ -n "$proxy_chain" ] && [ -n "$pergb_chain" ] || fail "both chains"
# pergb = proxy + exactly the RADIUS accept, placed before every reject
[ "$(printf '%s\n' "$pergb_chain" | grep -vx '    ip daddr 127.0.0.1 udp dport 1812 accept')" = "$proxy_chain" ] \
  || fail "chain pergb is chain proxy plus the 1812 accept: $(diff <(echo "$proxy_chain") <(echo "$pergb_chain"))"
r_line="$(printf '%s\n' "$pergb_chain" | grep -n 'udp dport 1812 accept' | cut -d: -f1)"
j_line="$(printf '%s\n' "$pergb_chain" | grep -n 'reject' | head -1 | cut -d: -f1)"
[ "$r_line" -lt "$j_line" ] || fail "the 1812 accept comes before the 127/8 reject"
printf '%s\n' "$proxy_chain" | grep -q 1812 && fail "per-piece (65535) may not reach RADIUS"
# no accept for anything but DNS / RADIUS / replies: 127.0.0.3/4 (the per-GB
# listeners) and the agent stay rejected for both uids
for c in "$proxy_chain" "$pergb_chain"; do
  printf '%s\n' "$c" | grep accept | grep -Ev 'dport (53|1812) accept$|^    ct state established,related accept$' && fail "an unexpected accept"
  printf '%s\n' "$c" | grep -q 'ip daddr { 127.0.0.0/8, ' || fail "127/8 rejected in every chain"
  printf '%s\n' "$c" | grep -Eq '127\.0\.0\.[34]' && fail "no rule names the per-GB listeners"
done
printf '%s\n' "$out" | NETRUN_PROXY_UIDS="65535 65533" run check >/dev/null || fail "two-uid guard fails its own check"
ok "two uids: 65535 -> proxy, 65533 -> pergb (= proxy + udp 1812 before the rejects); 127.0.0.3/4 rejected for both"

# default uid list: the per-GB uid only once its user exists
out="$(NODE_KIND=chi GETENT_65533=netrun-pergb run print)" || fail "print (per-GB installed)"
printf '%s\n' "$out" | grep -q 'meta skuid 65533 jump pergb' || fail "installed per-GB user -> pergb chain by default"
printf '%s\n' "$out" | grep -q 'meta skuid 65535 jump proxy' || fail "per-piece kept"
out="$(NODE_KIND=chi GETENT_65533=someone-else run print)" || fail "print (uid owned by another user)"
printf '%s\n' "$out" | grep -q '65533' && fail "uid 65533 of another user must not be gated as per-GB"
out="$(NODE_KIND=chi run print)" || fail "print (no per-GB)"
printf '%s\n' "$out" | grep -q 'chain pergb' && fail "no per-GB user -> no pergb chain"
out="$(NODE_KIND=chi NETRUN_PROXY_UIDS=65533 run print)" || fail "print (per-GB only)"
printf '%s\n' "$out" | grep -q 'chain proxy' && fail "per-GB only: no proxy chain"
printf '%s\n' "$out" | NETRUN_PROXY_UIDS=65533 run check >/dev/null || fail "per-GB-only guard check"
NETRUN_PROXY_UIDS="65535 abc" run print >/dev/null 2>&1 && fail "a bad uid list is refused"
ok "default uids: + 65533 only when netrun-pergb owns it; NETRUN_PROXY_UIDS overrides; bad lists refused"

# option B: the dedicated per-GB IPv4 is one of the node's own addresses
printf '{"version":1,"egressIpv4":"45.76.10.20","dedicatedIpv4":"45.76.10.20"}\n' > "$TMP/enable.json"
out="$(NODE_KIND=chi NETRUN_PERGB_ENABLE_FILE="$TMP/enable.json" NETRUN_PROXY_UIDS="65535 65533" run print)" || fail "print (option B)"
[ "$(printf '%s\n' "$out" | grep -c '    ip daddr {.*, 45.76.10.20, 139.84.246.71 } reject')" = 2 ] || fail "dedicated IPv4 in both v4 sets: $out"
# A7: every per-GB IPv4 of params.ipv4s (entry + egress) is the node's own too
printf '{"version":1,"egressIpv4":"45.76.10.20","dedicatedIpv4":"45.76.10.20","params":{"ipv4s":["45.76.10.20","45.76.10.21"]}}\n' > "$TMP/enable.json"
out="$(NODE_KIND=chi NETRUN_PERGB_ENABLE_FILE="$TMP/enable.json" NETRUN_PROXY_UIDS="65535 65533" run print)" || fail "print (A7)"
[ "$(printf '%s\n' "$out" | grep -c '    ip daddr {.*, 45.76.10.20/31, .* } reject')" = 2 ] || fail "every per-GB IPv4 (.20 + .21 = /31) in both v4 sets: $out"
printf 'garbage' > "$TMP/enable.json"
NODE_KIND=chi NETRUN_PERGB_ENABLE_FILE="$TMP/enable.json" run print >/dev/null || fail "a broken enable.json is ignored"
ok "option B / A7: enable.json dedicatedIpv4 and params.ipv4s join the own-IPv4 set (a broken file is ignored)"

# guard_safe with several uids: positive matches of the gated uids only
good="$(NODE_KIND=chi NETRUN_PROXY_UIDS="65535 65533" run print)"
for bad_rule in 'meta skuid 1000 jump pergb' 'meta skuid != 65533 accept' 'meta skuid 65533 accept' 'ip6 daddr ff00::/8 reject' 'meta skgid 65533 jump pergb'; do
  printf '%s\n' "$good" | awk -v r="    $bad_rule" '{ print } /^    meta skuid 65533 jump pergb$/ { print r }' \
    | NETRUN_PROXY_UIDS="65535 65533" run check >/dev/null && fail "guard_safe passed: $bad_rule"
done
printf '%s\n' "$good" | NETRUN_PROXY_UIDS=65535 run check >/dev/null && fail "a jump for a uid that is not gated passed"
# an nft that prints the passwd name of a uid: still the gated uid
named="$(printf '%s\n' "$good" | sed 's/meta skuid 65533 jump pergb/meta skuid "netrun-pergb" jump pergb/')"
printf '%s\n' "$named" | GETENT_65533=netrun-pergb NETRUN_PROXY_UIDS="65535 65533" run check >/dev/null \
  || fail "the named form of uid 65533 must pass"
printf '%s\n' "$named" | sed 's/"netrun-pergb"/"mallory"/' | GETENT_65533=netrun-pergb NETRUN_PROXY_UIDS="65535 65533" run check >/dev/null \
  && fail "another user's name passed"
ok "guard_safe (two uids): ungated uid, skuid !=, verdict instead of jump, ungated reject, skgid all refused; uid names accepted"

# apply verifies every uid's jump in the kernel
rm -f "$NETRUN_PROXY_GUARD_FILE" "$LOADED"
out="$(NODE_KIND=chi NETRUN_PROXY_UIDS="65535 65533" run apply)" || fail "apply (two uids): $out"
grep -q "meta skuid 65533 jump pergb" "$LOADED" || fail "pergb jump loaded"
grep -v 'jump pergb' "$LOADED" > "$KERNEL_OVERRIDE"
out="$(NODE_KIND=chi NETRUN_PROXY_UIDS="65535 65533" run apply 2>&1)" && fail "apply passed with the pergb jump missing in the kernel"
echo "$out" | grep -q "no meta skuid 65533 jump pergb" || fail "reason: $out"
rm -f "$KERNEL_OVERRIDE"
ok "apply (two uids): both jumps verified in the loaded table"

# ── 7. kernel: the guard in a network namespace, real sockets per uid ──
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] && [ -x /usr/sbin/nft ] \
   && command -v setpriv >/dev/null 2>&1 && /usr/sbin/ip netns list >/dev/null 2>&1; then
  NS="netrun-guard-test-$$"
  /usr/sbin/ip netns add "$NS" || fail "ip netns add"
  trap '/usr/sbin/ip netns del "$NS" 2>/dev/null; rm -rf "$TMP"' EXIT
  /usr/sbin/ip netns exec "$NS" /usr/sbin/ip link set lo up
  NODE_KIND=chi NETRUN_PROXY_UIDS="65535 65533" run print > "$TMP/kernel.nft"
  /usr/sbin/ip netns exec "$NS" /usr/sbin/nft -f "$TMP/kernel.nft" || fail "the generated guard does not load in the kernel"
  # the kernel's own listing passes guard_safe and shows both jumps (numeric
  # uids, or the names when uid 65533 has a passwd entry — CI creates one)
  real_name="$(/usr/bin/getent passwd 65533 2>/dev/null | cut -d: -f1 || true)"
  listing="$(/usr/sbin/ip netns exec "$NS" /usr/sbin/nft list table inet netrun_proxy_guard)"
  printf '%s\n' "$listing" | GETENT_65533="$real_name" NETRUN_PROXY_UIDS="65535 65533" run check >/dev/null \
    || fail "the kernel listing fails guard_safe: $listing"
  printf '%s\n' "$listing" | grep -Eq "meta skuid (65533|\"?${real_name:-x}\"?) jump pergb" || fail "kernel listing: no pergb jump"
  cat > "$TMP/srv.py" <<'SRV'
import socket, sys, threading, time
def tcp(addr, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((addr, port)); s.listen(64)
    while True:
        c, _ = s.accept(); c.sendall(b"ok"); c.close()
def udp(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((addr, port))
    while True:
        d, a = s.recvfrom(2048); s.sendto(b"ok", a)
for f, a, p in [(tcp, "127.0.0.3", 31000), (tcp, "127.0.0.4", 31000), (tcp, "127.0.0.1", 8085), (udp, "127.0.0.1", 1812), (udp, "127.0.0.1", 53)]:
    threading.Thread(target=f, args=(a, p), daemon=True).start()
time.sleep(0.3)
open(sys.argv[1], "w").write("up")
time.sleep(120)
SRV
  cat > "$TMP/cli.py" <<'CLI'
import socket, sys
kind, addr, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    if kind == "tcp":
        s = socket.create_connection((addr, port), timeout=2); ok = s.recv(2) == b"ok"
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect((addr, port)); s.send(b"x"); ok = s.recv(2) == b"ok"
except OSError:
    ok = False
print("open" if ok else "blocked")
CLI
  /usr/sbin/ip netns exec "$NS" python3 "$TMP/srv.py" "$TMP/srv.up" & SRV=$!
  for _ in $(seq 1 50); do [ -s "$TMP/srv.up" ] && break; sleep 0.1; done
  probe() { /usr/sbin/ip netns exec "$NS" setpriv --reuid="$1" --regid="$1" --clear-groups python3 "$TMP/cli.py" "$2" "$3" "$4"; }
  while read -r uid kind addr port want; do
    got="$(probe "$uid" "$kind" "$addr" "$port")"
    [ "$got" = "$want" ] || { kill "$SRV" 2>/dev/null; fail "kernel: uid $uid $kind $addr:$port is $got, want $want"; }
  done <<'MATRIX'
65533 udp 127.0.0.1 1812 open
65533 udp 127.0.0.1 53 open
65533 tcp 127.0.0.3 31000 blocked
65533 tcp 127.0.0.4 31000 blocked
65533 tcp 127.0.0.1 8085 blocked
65535 udp 127.0.0.1 1812 blocked
65535 udp 127.0.0.1 53 open
65535 tcp 127.0.0.3 31000 blocked
65535 tcp 127.0.0.4 31000 blocked
65535 tcp 127.0.0.1 8085 blocked
1000 tcp 127.0.0.3 31000 open
1000 tcp 127.0.0.4 31000 open
1000 udp 127.0.0.1 1812 open
MATRIX
  kill "$SRV" 2>/dev/null || true
  ok "kernel (netns): 65533 reaches only RADIUS + DNS on loopback, 65535 only DNS; 127.0.0.3/4 blocked for both, open for others (haproxy)"
else
  echo "skip: kernel section (needs Linux, root, /usr/sbin/nft, setpriv, ip netns)"
fi

echo "PASS ($PASS)"
