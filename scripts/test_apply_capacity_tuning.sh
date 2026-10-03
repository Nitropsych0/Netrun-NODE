#!/usr/bin/env bash
# Wave CAPACITY-18K — fixture tests for scripts/apply_capacity_tuning.sh.
# No root, no real ss/nft/sysctl/systemctl: every file path is redirected under
# a fixture root (NETRUN_TUNE_ROOT) and the commands are PATH stubs that read
# fixtures and log every call. Run with:
#   bash scripts/test_apply_capacity_tuning.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
SCRIPT="$HERE/apply_capacity_tuning.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

FIX="$TMP/fix"
BIN="$TMP/bin"
CALLS="$TMP/calls.log"
mkdir -p "$FIX" "$BIN"

# ── fixtures ──────────────────────────────────────────────────────
cat > "$FIX/ss.txt" <<'EOF'
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=812,fd=4))
LISTEN 0      256        127.0.0.1:53         0.0.0.0:*    users:(("unbound",pid=901,fd=6))
LISTEN 0      256            [::1]:53            [::]:*    users:(("unbound",pid=901,fd=7))
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=15))
LISTEN 0      511                *:8085             *:*    users:(("node",pid=1200,fd=20))
LISTEN 0      13      45.32.10.20:32000       0.0.0.0:*    users:(("3proxy",pid=3001,fd=5))
LISTEN 0      13      45.32.10.20:32001       0.0.0.0:*    users:(("3proxy",pid=3001,fd=6))
LISTEN 0      13        127.0.0.1:22000       0.0.0.0:*    users:(("3proxy",pid=3001,fd=7))
LISTEN 0      13        127.0.0.1:22001       0.0.0.0:*    users:(("3proxy",pid=3001,fd=8))
LISTEN 0      4096    45.32.10.20:22000       0.0.0.0:*    users:(("haproxy",pid=700,fd=9))
LISTEN 0      4096    45.32.10.20:22001       0.0.0.0:*    users:(("haproxy",pid=700,fd=10))
EOF

cat > "$FIX/chain_in.txt" <<'EOF'
table inet proxy_accounting { # handle 3
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport @pergb_blocked drop # handle 50
		iifname != "lo" counter name tcp dport map @cmap_in # handle 51
		ip6 daddr 2001:db8::1 counter name "proxy_32000_in6" comment "proxy_32000_in6" # handle 10
		tcp dport 32000 counter name "proxy_32000_in" comment "proxy_32000_in" # handle 11
		tcp dport 22000 counter name "proxy_32000_in" comment "proxy_32000_in_http" # handle 12
		tcp dport 32001 counter name "proxy_32001_in" comment "proxy_32001_in" # handle 13
		tcp dport 32001 counter name "proxy_32001_in" comment "proxy_32001_in" # handle 14
		tcp dport 32002 counter name "proxy_32002_in" comment "proxy_32002_in" # handle 15
		tcp dport 9999 counter packets 5 bytes 100 comment "x" # handle 16
		tcp dport 8085 drop # handle 17
	}
}
EOF
cat > "$FIX/chain_out.txt" <<'EOF'
table inet proxy_accounting { # handle 3
	chain output { # handle 2
		type filter hook output priority filter; policy accept;
		oifname != "lo" counter name tcp sport map @cmap_out # handle 60
		ip6 saddr 2001:db8::1 counter name "proxy_32000_out" comment "proxy_32000_out" # handle 20
		ip6 saddr 2001:db8::3 counter name "proxy_32003_out" comment "proxy_32003_out" # handle 21
		ip6 saddr 2001:db8::2 counter name "proxy_32001_out" comment "proxy_32001_out" # handle 22
		tcp sport 32000 counter name "proxy_32000_out" comment "proxy_32000_out" # handle 23
		tcp sport 32001 counter name "proxy_32001_out" comment "proxy_32001_out" # handle 24
	}
}
EOF
cat > "$FIX/map_in.txt" <<'EOF'
table inet proxy_accounting {
	map cmap_in {
		type inet_service : counter
		elements = { 22000 : "proxy_32000_in", 32000 : "proxy_32000_in",
			     32002 : "proxy_99999_in" }
	}
}
EOF
cat > "$FIX/map_out.txt" <<'EOF'
table inet proxy_accounting {
	map cmap_out {
		type inet_service : counter
		elements = { 22000 : "proxy_32000_out", 32000 : "proxy_32000_out" }
	}
}
EOF
# Post-cleanup chains (idempotency rerun): only map/set rules + kept ones.
cat > "$FIX/chain_in_clean.txt" <<'EOF'
table inet proxy_accounting { # handle 3
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport @pergb_blocked drop # handle 50
		iifname != "lo" counter name tcp dport map @cmap_in # handle 51
	}
}
EOF
cat > "$FIX/chain_out_clean.txt" <<'EOF'
table inet proxy_accounting { # handle 3
	chain output { # handle 2
		type filter hook output priority filter; policy accept;
		oifname != "lo" counter name tcp sport map @cmap_out # handle 60
	}
}
EOF

# ── PATH stubs ────────────────────────────────────────────────────
cat > "$BIN/ss" <<EOF
#!/usr/bin/env bash
echo "ss \$*" >> "$CALLS"
cat "\${SS_FIXTURE:-$FIX/ss.txt}"
EOF
cat > "$BIN/nft" <<EOF
#!/usr/bin/env bash
echo "nft \$*" >> "$CALLS"
case "\$*" in
  "list table inet proxy_accounting") exit 0 ;;
  "-a list chain inet proxy_accounting input") cat "\${NFT_CHAIN_IN:-$FIX/chain_in.txt}" ;;
  "-a list chain inet proxy_accounting output") cat "\${NFT_CHAIN_OUT:-$FIX/chain_out.txt}" ;;
  "list map inet proxy_accounting cmap_in") cat "$FIX/map_in.txt" ;;
  "list map inet proxy_accounting cmap_out") cat "$FIX/map_out.txt" ;;
  "list ruleset") echo "# ruleset after cleanup" ;;
  -f\ *) cp "\$2" "$TMP/nft_batch.applied"; [ "\${NFT_FAIL:-0}" = 1 ] && { echo "Error: Could not process rule" >&2; exit 1; }; exit 0 ;;
  *) exit 1 ;;
esac
EOF
cat > "$BIN/sysctl" <<EOF
#!/usr/bin/env bash
echo "sysctl \$*" >> "$CALLS"
if [ "\$1" = "-w" ]; then
  v="\${2#*=}"; printf '%s\t%s\n' "\${v%% *}" "\${v##* }" > "\$NETRUN_TUNE_ROOT/proc/sys/net/ipv4/ip_local_port_range"
fi
EOF
cat > "$BIN/systemctl" <<EOF
#!/usr/bin/env bash
echo "systemctl \$*" >> "$CALLS"
[ "\${SYSTEMCTL_RELOAD_FAIL:-0}" = 1 ] && [ "\$1" = reload ] && exit 1
exit 0
EOF
cat > "$BIN/unbound-control" <<EOF
#!/usr/bin/env bash
echo "unbound-control \$*" >> "$CALLS"
[ "\${UC_FAIL:-0}" = 1 ] && exit 1
exit 0
EOF
cat > "$BIN/unbound-checkconf" <<EOF
#!/usr/bin/env bash
echo "unbound-checkconf \$*" >> "$CALLS"
[ "\${CHECKCONF_FAIL:-0}" = 1 ] && exit 1
exit 0
EOF
chmod +x "$BIN"/*

# A fresh fixture node root.
new_root() {
  local r="$TMP/root.$1"
  rm -rf "$r"
  mkdir -p "$r/proc/sys/net/ipv4" "$r/etc/sysctl.d" "$r/etc/unbound/unbound.conf.d" \
    "$r/opt/netrun/proxyserver/3proxy" "$r/opt/netrun/scripts" "$r/opt/netrun/jobs" "$r/etc/systemd/system" "$r/run"
  printf '10000\t65000\n' > "$r/proc/sys/net/ipv4/ip_local_port_range"
  cat > "$r/etc/sysctl.d/99-netrun.conf" <<'EOF'
# NETRUN — raised limits for 4000+ concurrent 3proxy instances.
kernel.pid_max = 4194304
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_timestamps = 1
net.ipv6.conf.all.accept_ra = 2
EOF
  cat > "$r/etc/unbound/unbound.conf.d/netrun.conf" <<'EOF'
server:
    interface: 127.0.0.1
    interface: ::1
    num-threads: 4
    msg-cache-size: 128m
    rrset-cache-size: 256m
    prefetch: yes
EOF
  cat > "$r/opt/netrun/proxyserver/3proxy/3proxy_32000.cfg" <<'EOF'
daemon
nserver 127.0.0.1
nscache 65536
flush
users u1:CL:p1
allow u1
deny *
socks -6 -a -p32000 -i45.32.10.20 -e2001:db8::1
proxy -6 -n -a -p22000 -i127.0.0.1 -e2001:db8::1
EOF
  echo "[Service]" > "$r/etc/systemd/system/netrun-ipv6-restore.service"
  printf '#!/usr/bin/env bash\n# old per-address restore\n' > "$r/opt/netrun/scripts/netrun-ipv6-restore.sh"
  echo "# old ruleset" > "$r/etc/nftables.conf"
  echo "$r"
}

snapshot() { (cd "$1" && find . -type f -exec cksum {} + | sort); }

run_tool() { # root, args...
  local r="$1"; shift
  : > "$CALLS"
  PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$r" bash "$SCRIPT" "$@" > "$TMP/out" 2>&1
  echo $?
}

# ── 1. dry-run (default): plans every step, changes NOTHING ────────
R="$(new_root dry)"
before="$(snapshot "$R")"
rc="$(run_tool "$R")"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "dry-run exit $rc"; }
after="$(snapshot "$R")"
[ "$before" = "$after" ] || fail "dry-run modified the fixture root"
grep -q 'mode: dry-run' "$TMP/out" || fail "dry-run is not the default mode"
grep -qE 'sysctl +would-apply .*10000 65000.*-> .1024 8000' "$TMP/out" || { cat "$TMP/out"; fail "dry-run: sysctl plan missing"; }
grep -qE 'unbound +would-apply .*128m -> 32m.*256m -> 64m' "$TMP/out" || fail "dry-run: unbound plan missing"
grep -qE 'nft +would-apply .*delete 7 .*migrate 2 .*keep 3' "$TMP/out" || { cat "$TMP/out"; fail "dry-run: nft plan counts wrong"; }
grep -qE 'ipv6restore +would-apply' "$TMP/out" || fail "dry-run: ipv6restore plan missing"
! grep -qE '^(sysctl -w|systemctl|nft -f|unbound-checkconf)' "$CALLS" || { cat "$CALLS"; fail "dry-run ran a mutating command"; }
grep -q 'audit: listeners >= 8100: 3proxy=4 haproxy=2 other=0' "$TMP/out" || { cat "$TMP/out"; fail "audit: proxy-range listener summary wrong"; }
grep -q '8085 \* node' "$TMP/out" || fail "audit: agent :8085 not listed among node services"
ok "dry-run is the default, plans all four steps and leaves every file untouched"

# ── 2. --apply: every step, no 3proxy touched ─────────────────────
R="$(new_root apply)"
rc="$(run_tool "$R" --apply)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "apply exit $rc"; }
[ "$(cat "$R/proc/sys/net/ipv4/ip_local_port_range")" = "$(printf '1024\t8000')" ] || fail "apply: runtime range not set"
grep -qx 'net.ipv4.ip_local_port_range = 1024 8000' "$R/etc/sysctl.d/99-netrun.conf" || fail "apply: range not persisted"
grep -qx 'net.ipv4.tcp_timestamps = 1' "$R/etc/sysctl.d/99-netrun.conf" || fail "apply: other sysctl lines lost"
[ "$(grep -c ip_local_port_range "$R/etc/sysctl.d/99-netrun.conf")" = 1 ] || fail "apply: duplicate range lines"
grep -qE '^ +msg-cache-size: 32m$' "$R/etc/unbound/unbound.conf.d/netrun.conf" || fail "apply: msg-cache not 32m"
grep -qE '^ +rrset-cache-size: 64m$' "$R/etc/unbound/unbound.conf.d/netrun.conf" || fail "apply: rrset-cache not 64m"
grep -q 'prefetch: yes' "$R/etc/unbound/unbound.conf.d/netrun.conf" || fail "apply: unbound config damaged"
grep -qx 'systemctl reload unbound' "$CALLS" || fail "apply: unbound not reloaded"
! grep -q 'systemctl restart' "$CALLS" || fail "apply: something was restarted"
! grep -qi '3proxy' "$CALLS" || fail "apply: 3proxy was touched"
cmp -s "$HERE/../deploy/node/netrun-ipv6-restore.sh" "$R/opt/netrun/scripts/netrun-ipv6-restore.sh" || fail "apply: ipv6 restore not installed"
grep -q 'ruleset after cleanup' "$R/etc/nftables.conf" || fail "apply: nft ruleset not persisted"
# The atomic batch: elements first, then deletes by handle — exactly the legacy rules.
B="$TMP/nft_batch.applied"
[ -f "$B" ] || fail "apply: nft -f not called"
head -n 2 "$B" | grep -qx 'add element inet proxy_accounting cmap_in { 32001 : "proxy_32001_in" }' || { cat "$B"; fail "batch: cmap_in migration missing/out of order"; }
head -n 2 "$B" | grep -qx 'add element inet proxy_accounting cmap_out { 32001 : "proxy_32001_out" }' || fail "batch: cmap_out migration missing"
got="$(grep '^delete rule' "$B" | awk '{ print $5 ":" $7 }' | sort | tr '\n' ' ')"
want="input:10 input:11 input:12 input:13 input:14 output:20 output:22 output:23 output:24 "
[ "$got" = "$want" ] || fail "batch deletes: got '$got' want '$want'"
! grep -qE 'handle (50|51|60|15|16|17|21)$' "$B" || fail "batch touches a map/set/verdict/kept rule"
[ "$(wc -l < "$B" | tr -d ' ')" = 11 ] || fail "batch has unexpected lines"
grep -q '3proxy_32000.cfg' <(cd "$R/opt/netrun/proxyserver/3proxy" && ls) || fail "cfg removed"
grep -q 'nscache 65536' "$R/opt/netrun/proxyserver/3proxy/3proxy_32000.cfg" || fail "existing cfg was rewritten"
ok "--apply: range 1024-8000 runtime+persisted, unbound 32m/64m + reload, 2 migrations + 9 deletes in one batch, restore script swapped, cfgs untouched"

# ── 3. idempotent rerun ───────────────────────────────────────────
rm -f "$TMP/nft_batch.applied"
: > "$CALLS"
PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" NFT_CHAIN_IN="$FIX/chain_in_clean.txt" NFT_CHAIN_OUT="$FIX/chain_out_clean.txt" \
  bash "$SCRIPT" --apply > "$TMP/out" 2>&1
rc=$?
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "rerun exit $rc"; }
for s in sysctl unbound nft ipv6restore; do
  grep -qE "\] $s +ok " "$TMP/out" || { cat "$TMP/out"; fail "rerun: $s not ok"; }
done
[ ! -f "$TMP/nft_batch.applied" ] || fail "rerun: nft -f called again"
! grep -qE '^(sysctl -w|systemctl reload)' "$CALLS" || fail "rerun: mutated again"
ok "rerun after apply is a no-op (every step ok)"

# ── 4. a listener inside 1024-8000 refuses the sysctl step ───────
R="$(new_root refuse)"
{ cat "$FIX/ss.txt"; echo 'LISTEN 0 13 45.32.10.20:5000 0.0.0.0:* users:(("3proxy",pid=4001,fd=5))'; } > "$TMP/ss_conflict.txt"
: > "$CALLS"
PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" SS_FIXTURE="$TMP/ss_conflict.txt" bash "$SCRIPT" --apply --only sysctl > "$TMP/out" 2>&1
rc=$?
[ "$rc" = 2 ] || { cat "$TMP/out"; fail "refusal exit $rc (want 2)"; }
grep -qE 'sysctl +REFUSED .*5000' "$TMP/out" || fail "refusal: reason missing"
[ "$(cat "$R/proc/sys/net/ipv4/ip_local_port_range")" = "$(printf '10000\t65000')" ] || fail "refusal: range changed anyway"
! grep -q 'sysctl -w' "$CALLS" || fail "refusal: sysctl -w called"
ok "a TCP listener inside the new ephemeral range refuses the sysctl step (exit 2, nothing changed)"

# ── 5. a (down / disabled) cfg port inside the range refuses too ──
R="$(new_root cfgref)"
printf 'socks -6 -a -p15000 -i1.2.3.4 -e2001:db8::9\nproxy -6 -n -a -p5000 -i1.2.3.4 -e2001:db8::9\n' \
  > "$R/opt/netrun/proxyserver/3proxy/3proxy_15000.cfg.disabled"
rc="$(run_tool "$R" --apply --only sysctl)"
[ "$rc" = 2 ] || fail "cfg refusal exit $rc"
grep -qE 'sysctl +REFUSED .*cfg ports: 5000' "$TMP/out" || { cat "$TMP/out"; fail "cfg refusal reason"; }
ok "a disabled batch cfg with a port inside the range refuses the sysctl step"

# ── 6. generation lock refuses the nft step ──────────────────────
R="$(new_root genlock)"
echo '{"pid":1}' > "$R/opt/netrun/jobs/.generation.lock"
rc="$(run_tool "$R" --apply --only nft)"
[ "$rc" = 2 ] || { cat "$TMP/out"; fail "genlock exit $rc"; }
grep -qE 'nft +REFUSED .*generation' "$TMP/out" || fail "genlock reason"
! grep -q '^nft -f' "$CALLS" || fail "genlock: nft -f ran"
ok "a held generation lock refuses the nft step"

# ── 7. unbound-checkconf failure restores the original config ────
R="$(new_root badconf)"
orig="$(cat "$R/etc/unbound/unbound.conf.d/netrun.conf")"
: > "$CALLS"
PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" CHECKCONF_FAIL=1 bash "$SCRIPT" --apply --only unbound > "$TMP/out" 2>&1
rc=$?
[ "$rc" = 1 ] || { cat "$TMP/out"; fail "checkconf failure exit $rc"; }
[ "$(cat "$R/etc/unbound/unbound.conf.d/netrun.conf")" = "$orig" ] || fail "config not restored"
! grep -q 'systemctl reload' "$CALLS" || fail "reloaded a rejected config"
ok "unbound-checkconf rejection restores the original config and skips the reload"

# ── 8. an aborted nft transaction reports FAILED, persists nothing ─
R="$(new_root nftfail)"
rc="$(PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" NFT_FAIL=1 bash "$SCRIPT" --apply --only nft > "$TMP/out" 2>&1; echo $?)"
[ "$rc" = 1 ] || { cat "$TMP/out"; fail "nft failure exit $rc"; }
grep -qx '# old ruleset' "$R/etc/nftables.conf" || fail "ruleset persisted after a failed transaction"
ok "a rejected nft -f batch reports FAILED and does not persist the ruleset"

# ── 9. unbound reload falls back to unbound-control, never restarts ─
R="$(new_root reload)"
: > "$CALLS"
PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" SYSTEMCTL_RELOAD_FAIL=1 bash "$SCRIPT" --apply --only unbound > "$TMP/out" 2>&1
rc=$?
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "unbound-control fallback exit $rc"; }
grep -qx 'unbound-control reload' "$CALLS" || fail "no unbound-control reload fallback"
R="$(new_root partial)"
: > "$CALLS"
PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" SYSTEMCTL_RELOAD_FAIL=1 UC_FAIL=1 bash "$SCRIPT" --apply --only unbound > "$TMP/out" 2>&1
rc=$?
[ "$rc" = 3 ] || { cat "$TMP/out"; fail "unreloadable unbound exit $rc (want 3)"; }
! grep -q 'systemctl restart' "$CALLS" || fail "unbound restarted without --allow-unbound-restart"
grep -qE 'unbound +partial' "$TMP/out" || fail "partial status missing"
ok "unbound: systemctl reload -> unbound-control reload fallback; no restart unless allowed (exit 3 = partial)"

# ── 10. blind ss refuses the sysctl step ───────────────────────────
R="$(new_root blind)"
: > "$TMP/empty_ss.txt"
PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" SS_FIXTURE="$TMP/empty_ss.txt" bash "$SCRIPT" --apply --only sysctl > "$TMP/out" 2>&1
rc=$?
[ "$rc" = 2 ] || { cat "$TMP/out"; fail "blind ss exit $rc"; }
grep -qE 'sysctl +REFUSED .*cannot list TCP listeners' "$TMP/out" || fail "blind ss reason"
ok "no listener list (ss failed / not root) refuses the sysctl step"

# ── 11. argument validation ───────────────────────────────────────
R="$(new_root args)"
rc="$(run_tool "$R" --only bogus)"; [ "$rc" = 1 ] || fail "--only bogus accepted"
rc="$(run_tool "$R" --ephemeral-range 900-8000)"; [ "$rc" = 1 ] || fail "range below 1024 accepted"
rc="$(run_tool "$R" --ephemeral-range 1024-8100)"; [ "$rc" = 1 ] || fail "range reaching the proxy floor accepted"
rc="$(run_tool "$R" --frobnicate)"; [ "$rc" = 1 ] || fail "unknown flag accepted"
rc="$(run_tool "$R" --help)"; [ "$rc" = 0 ] && grep -q 'Opt-in and idempotent' "$TMP/out" || fail "--help"
ok "bad arguments are rejected"

echo "test_apply_capacity_tuning.sh — all $PASS checks passed"
