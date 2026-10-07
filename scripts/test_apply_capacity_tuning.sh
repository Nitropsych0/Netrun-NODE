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
  "list table inet proxy_normalization") [ -n "\${NORM_DIR:-}" ] && [ -f "\$NORM_DIR/table.txt" ] && { cat "\$NORM_DIR/table.txt"; exit 0; }; exit 1 ;;
  "-a list chain inet proxy_normalization output") [ -n "\${NORM_DIR:-}" ] && cat "\$NORM_DIR/output.txt" ;;
  "-a list chain inet proxy_normalization postrouting") [ -n "\${NORM_DIR:-}" ] && cat "\$NORM_DIR/postrouting.txt" ;;
  -f\ *) cp "\$2" "$TMP/nft_batch.applied"; [ "\${NFT_FAIL:-0}" = 1 ] && { echo "Error: Could not process rule" >&2; exit 1; }; exit 0 ;;
  *) exit 1 ;;
esac
EOF
cat > "$BIN/sysctl" <<EOF
#!/usr/bin/env bash
echo "sysctl \$*" >> "$CALLS"
if [ "\$1" = "-w" ]; then
  k="\${2%%=*}"; v="\${2#*=}"
  case "\$k" in
    net.ipv4.ip_local_port_range) printf '%s\t%s\n' "\${v%% *}" "\${v##* }" > "\$NETRUN_TUNE_ROOT/proc/sys/net/ipv4/ip_local_port_range" ;;
    net.netfilter.nf_conntrack_max) [ "\${SYSCTL_CT_FAIL:-0}" = 1 ] && exit 1; echo "\$v" > "\$NETRUN_TUNE_ROOT/proc/sys/net/netfilter/nf_conntrack_max" ;;
    fs.pipe-user-pages-soft) echo "\$v" > "\$NETRUN_TUNE_ROOT/proc/sys/fs/pipe-user-pages-soft" ;;
  esac
fi
EOF
cat > "$BIN/udevadm" <<EOF
#!/usr/bin/env bash
echo "udevadm \$*" >> "$CALLS"
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
  mkdir -p "$r/proc/sys/net/ipv4" "$r/proc/sys/net/netfilter" "$r/etc/sysctl.d" "$r/etc/unbound/unbound.conf.d" \
    "$r/opt/netrun/proxyserver/3proxy" "$r/opt/netrun/scripts" "$r/opt/netrun/jobs" "$r/etc/systemd/system" "$r/run"
  printf '10000\t65000\n' > "$r/proc/sys/net/ipv4/ip_local_port_range"
  printf 'MemTotal:        3911456 kB\nMemFree:          301234 kB\n' > "$r/proc/meminfo"
  echo 65536 > "$r/proc/sys/net/netfilter/nf_conntrack_max"
  echo 1234 > "$r/proc/sys/net/netfilter/nf_conntrack_count"
  cat > "$r/etc/sysctl.d/99-netrun.conf" <<'EOF'
# NETRUN — raised limits for 4000+ concurrent 3proxy instances.
kernel.pid_max = 4194304
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
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
! grep -q 'conntrack' "$TMP/out" || fail "conntrack is opt-in: not part of the default step list"
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

# ── 12. conntrack (opt-in): dry-run plans, changes nothing ────────
CT_MOD_WANT="$(printf '%s\n' '# NETRUN — load conntrack before systemd-sysctl so net.netfilter.* in /etc/sysctl.d apply at boot' 'nf_conntrack')"
CT_UDEV_WANT="$(printf '%s\n' '# NETRUN — re-apply net.netfilter.* sysctls whenever nf_conntrack is (re)loaded' 'ACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/netfilter"')"
R="$(new_root ctdry)"
before="$(snapshot "$R")"
rc="$(run_tool "$R" --only conntrack)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "conntrack dry-run exit $rc"; }
[ "$before" = "$(snapshot "$R")" ] || fail "conntrack dry-run modified the fixture root"
grep -qE "conntrack +would-apply +nf_conntrack_max -> 262144 \(MemTotal 3911456 kB\); persisted '1048576', runtime '65536', in use 1234; do: modules-load udev-rule persist runtime-raise" "$TMP/out" \
  || { cat "$TMP/out"; fail "conntrack dry-run plan"; }
! grep -qE '^(sysctl -w|udevadm)' "$CALLS" || fail "conntrack dry-run ran a mutating command"
ok "conntrack: opt-in step; dry-run sizes 2c/4GB to 262144 and changes nothing"

# ── 13. conntrack --apply: boot files + persisted value + runtime raise; rerun ok ─
R="$(new_root ctapply)"
rc="$(run_tool "$R" --apply --only conntrack)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "conntrack apply exit $rc"; }
[ "$(cat "$R/etc/modules-load.d/netrun-conntrack.conf")" = "$CT_MOD_WANT" ] || fail "modules-load file content"
[ "$(cat "$R/etc/udev/rules.d/90-netrun-conntrack.rules")" = "$CT_UDEV_WANT" ] || fail "udev rule content"
grep -qx 'net.netfilter.nf_conntrack_max = 262144' "$R/etc/sysctl.d/99-netrun.conf" || fail "value not persisted"
[ "$(grep -c nf_conntrack_max "$R/etc/sysctl.d/99-netrun.conf")" = 1 ] || fail "duplicate nf_conntrack_max lines"
grep -qx 'net.netfilter.nf_conntrack_tcp_timeout_established = 7200' "$R/etc/sysctl.d/99-netrun.conf" || fail "other netfilter line lost"
[ "$(cat "$R/proc/sys/net/netfilter/nf_conntrack_max")" = 262144 ] || fail "runtime not raised"
grep -qx 'sysctl -w net.netfilter.nf_conntrack_max=262144' "$CALLS" || fail "no sysctl -w"
grep -qx 'udevadm control --reload' "$CALLS" || fail "udev rules not reloaded"
! grep -qiE '3proxy|^nft|systemctl' "$CALLS" || { cat "$CALLS"; fail "conntrack step touched something else"; }
rc="$(run_tool "$R" --apply --only conntrack)"
[ "$rc" = 0 ] && grep -qE '\] conntrack +ok ' "$TMP/out" || { cat "$TMP/out"; fail "conntrack rerun not ok"; }
! grep -q 'sysctl -w' "$CALLS" || fail "conntrack rerun mutated again"
ok "conntrack --apply: modules-load + udev rule + 99-netrun.conf 262144 + runtime raised; rerun is a no-op"

# ── 14. conntrack never lowers a higher runtime value; module not loaded ─
R="$(new_root cthigh)"
echo 1048576 > "$R/proc/sys/net/netfilter/nf_conntrack_max"
rc="$(run_tool "$R" --apply --only conntrack)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "conntrack high exit $rc"; }
[ "$(cat "$R/proc/sys/net/netfilter/nf_conntrack_max")" = 1048576 ] || fail "runtime was lowered"
! grep -q 'sysctl -w' "$CALLS" || fail "sysctl -w called to lower"
grep -q 'left as is' "$TMP/out" || fail "high runtime note"
grep -qx 'net.netfilter.nf_conntrack_max = 262144' "$R/etc/sysctl.d/99-netrun.conf" || fail "target not persisted (high runtime)"
R="$(new_root ctnomod)"
rm -f "$R/proc/sys/net/netfilter/nf_conntrack_max" "$R/proc/sys/net/netfilter/nf_conntrack_count"
rc="$(run_tool "$R" --apply --only conntrack)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "conntrack no-module exit $rc"; }
grep -q 'module not loaded now' "$TMP/out" || fail "no-module note"
[ -f "$R/etc/modules-load.d/netrun-conntrack.conf" ] || fail "no-module: boot file missing"
! grep -q 'sysctl -w' "$CALLS" || fail "no-module: sysctl -w called"
ok "conntrack: a higher runtime value is never lowered; without the module only boot files are written"

# ── 15. conntrack: --conntrack-max, unreadable MemTotal, sysctl failure ─
R="$(new_root ctover)"
rc="$(run_tool "$R" --apply --only conntrack --conntrack-max 524288)"
[ "$rc" = 0 ] && [ "$(cat "$R/proc/sys/net/netfilter/nf_conntrack_max")" = 524288 ] || { cat "$TMP/out"; fail "--conntrack-max override"; }
rc="$(run_tool "$R" --only conntrack --conntrack-max 1000)"; [ "$rc" = 1 ] || fail "--conntrack-max below 65536 accepted"
rc="$(run_tool "$R" --only conntrack --conntrack-max lots)"; [ "$rc" = 1 ] || fail "--conntrack-max non-numeric accepted"
R="$(new_root ctnomem)"
rm -f "$R/proc/meminfo"
rc="$(run_tool "$R" --apply --only conntrack)"
[ "$rc" = 2 ] && grep -qE 'conntrack +REFUSED .*MemTotal' "$TMP/out" || { cat "$TMP/out"; fail "no MemTotal must refuse"; }
[ ! -f "$R/etc/modules-load.d/netrun-conntrack.conf" ] || fail "refused step wrote files"
R="$(new_root ctfail)"
rc="$(PATH="$BIN:$PATH" NETRUN_TUNE_ROOT="$R" SYSCTL_CT_FAIL=1 bash "$SCRIPT" --apply --only conntrack > "$TMP/out" 2>&1; echo $?)"
[ "$rc" = 1 ] && grep -qE 'conntrack +FAILED' "$TMP/out" || { cat "$TMP/out"; fail "sysctl -w failure must be FAILED"; }
ok "conntrack: --conntrack-max override/validation; no MemTotal refuses (exit 2); sysctl failure reports FAILED"

# ── 16. units (opt-in, RES-11): restore unit -> repo, https-sync KillMode, no restarts ─
REPO_ROOT="$(cd "$HERE/.." && pwd -P)"
R="$(new_root units)"
printf '[Service]\nExecStart=/opt/netrun/scripts/restore-3proxy.sh\n' > "$R/etc/systemd/system/netrun-3proxy-restore.service"
printf '#!/usr/bin/env bash\n# heredoc copy\n' > "$R/opt/netrun/scripts/restore-3proxy.sh"
printf '[Service]\nType=oneshot\nExecStart=/usr/local/sbin/netrun-https sync\n' > "$R/etc/systemd/system/netrun-https-sync.service"
mkdir -p "$R/usr/local/sbin"; printf '#!/usr/bin/env bash\n# copy taken at setup\n' > "$R/usr/local/sbin/netrun-https"
rc="$(run_tool "$R" --apply --only units)"
[ "$rc" = 2 ] && grep -qE 'units +REFUSED .*restore_3proxy.sh' "$TMP/out" || { cat "$TMP/out"; fail "units must refuse before the code is deployed"; }
cp "$REPO_ROOT/scripts/restore_3proxy.sh" "$REPO_ROOT/scripts/netrun-3proxy-spawn.sh" "$R/opt/netrun/scripts/"
before="$(snapshot "$R")"
rc="$(run_tool "$R" --only units)"
[ "$rc" = 0 ] && [ "$before" = "$(snapshot "$R")" ] || { cat "$TMP/out"; fail "units dry-run changed files"; }
chmod 0644 "$R/opt/netrun/scripts/restore_3proxy.sh"   # a deploy that lost the exec bit
grep -qE 'units +would-apply .*restore-unit' "$TMP/out" || { cat "$TMP/out"; fail "units plan"; }
rc="$(run_tool "$R" --only units)"
grep -qE 'units +would-apply .*restore-unit exec-bits legacy-restore-script https-sync-killmode netrun-https-copy' "$TMP/out" || { cat "$TMP/out"; fail "units plan"; }
rc="$(run_tool "$R" --apply --only units)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "units apply exit $rc"; }
cmp -s "$REPO_ROOT/deploy/node/netrun-3proxy-restore.service" "$R/etc/systemd/system/netrun-3proxy-restore.service" || fail "restore unit not the repo unit"
grep -qx 'ExecStart=/opt/netrun/scripts/restore_3proxy.sh' "$R/etc/systemd/system/netrun-3proxy-restore.service" || fail "restore unit ExecStart"
[ ! -e "$R/opt/netrun/scripts/restore-3proxy.sh" ] || fail "legacy restore-3proxy.sh kept"
grep -qx 'KillMode=process' "$R/etc/systemd/system/netrun-https-sync.service.d/10-killmode.conf" || fail "https-sync KillMode drop-in"
cmp -s "$REPO_ROOT/scripts/netrun-https.sh" "$R/usr/local/sbin/netrun-https" || fail "netrun-https copy not refreshed"
[ -x "$R/opt/netrun/scripts/restore_3proxy.sh" ] || fail "restore script not executable"
grep -qx 'systemctl daemon-reload' "$CALLS" || fail "no daemon-reload"
! grep -qE 'systemctl (start|stop|restart|reload) ' "$CALLS" || { cat "$CALLS"; fail "units step started/stopped something"; }
rc="$(run_tool "$R" --apply --only units)"
[ "$rc" = 0 ] && grep -qE '\] units +ok ' "$TMP/out" || { cat "$TMP/out"; fail "units rerun not ok"; }
ok "units: restore unit -> repo restore_3proxy.sh (+ legacy copy gone), https-sync KillMode=process, netrun-https refreshed, daemon-reload only; refuses before the code deploy"

# ── 17. fingerprint (opt-in, FP-01): TCP pins, sysctl.conf purge, normalization rules ─
R="$(new_root fp)"
printf 'net.ipv4.tcp_timestamps = 0\nnet.ipv4.tcp_rmem = 4096 87380 6291456\nnet.ipv4.icmp_echo_ignore_all = 1\nvm.swappiness = 10\n' > "$R/etc/sysctl.conf"
mkdir -p "$R/opt/netrun/node_runtime/soft/generator"
echo '# new generator' > "$R/opt/netrun/node_runtime/soft/generator/proxyyy_automated.sh"
ND="$TMP/norm"; mkdir -p "$ND"
printf 'table inet proxy_normalization {\n\tchain output {\n\t\ttcp flags syn tcp option maxseg size set 1340\n\t}\n}\n' > "$ND/table.txt"
printf 'table inet proxy_normalization { # handle 9\n\tchain output { # handle 1\n\t\ttype filter hook output priority -150; policy accept;\n\t\tmeta l4proto tcp tcp flags syn tcp option maxseg size set 1340 # handle 4\n\t\tct state invalid drop # handle 5\n\t}\n}\n' > "$ND/output.txt"
printf 'table inet proxy_normalization { # handle 9\n\tchain postrouting { # handle 2\n\t\ttype filter hook postrouting priority -150; policy accept;\n\t\tmeta l4proto tcp ip6 hoplimit set 64 # handle 7\n\t}\n}\n' > "$ND/postrouting.txt"
before="$(snapshot "$R")"
rc="$(NORM_DIR="$ND" run_tool "$R" --only fingerprint)"
[ "$rc" = 0 ] && [ "$before" = "$(snapshot "$R")" ] || { cat "$TMP/out"; fail "fingerprint dry-run changed files"; }
grep -q '1340 = reads as OpenVPN' "$TMP/out" || { cat "$TMP/out"; fail "audit: 1340 clamp not flagged"; }
grep -qE 'fingerprint +would-apply .*tcp-signature-file sysctl.conf:net.ipv4.tcp_timestamps net.ipv4.tcp_rmem nft-normalization-rules:3 nft-normalization-table' "$TMP/out" || { cat "$TMP/out"; fail "fingerprint plan"; }
: > "$R/opt/netrun/jobs/.generation.lock"
rc="$(NORM_DIR="$ND" run_tool "$R" --apply --only fingerprint)"
[ "$rc" = 2 ] && grep -qE 'fingerprint +REFUSED .*generation' "$TMP/out" || { cat "$TMP/out"; fail "fingerprint must refuse under the genlock"; }
rm -f "$R/opt/netrun/jobs/.generation.lock" "$TMP/nft_batch.applied"
rc="$(NORM_DIR="$ND" run_tool "$R" --apply --only fingerprint)"
[ "$rc" = 0 ] || { cat "$TMP/out"; fail "fingerprint apply exit $rc"; }
cmp -s "$REPO_ROOT/deploy/node/99-zz-netrun-tcp.conf" "$R/etc/sysctl.d/99-zz-netrun-tcp.conf" || fail "TCP signature file"
! grep -qE 'tcp_timestamps|tcp_rmem' "$R/etc/sysctl.conf" || fail "pinned keys left in /etc/sysctl.conf"
grep -qx 'net.ipv4.icmp_echo_ignore_all = 1' "$R/etc/sysctl.conf" && grep -qx 'vm.swappiness = 10' "$R/etc/sysctl.conf" || fail "unrelated sysctl.conf lines removed"
ls "$R/etc/" | grep -q '^sysctl.conf.bak-fingerprint-' || fail "no sysctl.conf backup"
grep -qx "sysctl -p $R/etc/sysctl.d/99-zz-netrun-tcp.conf" "$CALLS" || fail "pins not applied at runtime"
printf 'delete rule inet proxy_normalization output handle 4\ndelete rule inet proxy_normalization output handle 5\ndelete rule inet proxy_normalization postrouting handle 7\ndelete table inet proxy_normalization\n' > "$TMP/want_norm"
cmp -s "$TMP/want_norm" "$TMP/nft_batch.applied" || { cat "$TMP/nft_batch.applied"; fail "normalization batch"; }
grep -q 'ruleset after cleanup' "$R/etc/nftables.conf" || fail "ruleset not persisted"
! grep -qi '3proxy' "$CALLS" || fail "fingerprint touched 3proxy"
# An OLD generator (still checks for the table): rules go, the table stays.
echo 'nft list table inet proxy_normalization' > "$R/opt/netrun/node_runtime/soft/generator/proxyyy_automated.sh"
rm -f "$TMP/nft_batch.applied"
rc="$(NORM_DIR="$ND" run_tool "$R" --apply --only fingerprint)"
[ "$rc" = 0 ] && ! grep -q 'delete table' "$TMP/nft_batch.applied" || { cat "$TMP/out"; fail "table deleted although the generator still needs it"; }
rc="$(run_tool "$R" --apply --only fingerprint)"
[ "$rc" = 0 ] && grep -qE '\] fingerprint +ok ' "$TMP/out" || { cat "$TMP/out"; fail "fingerprint rerun not ok"; }
ok "fingerprint: 99-zz TCP pins + runtime, pinned keys out of /etc/sysctl.conf (backup; others kept), MSS 1340/ct/hoplimit rules + table removed in one nft -f; genlock refuses"

# ── 18. pipes (opt-in): RAM-sized fs.pipe-user-pages-soft, only raised ─
R="$(new_root pipes)"
mkdir -p "$R/proc/sys/fs"; echo 16384 > "$R/proc/sys/fs/pipe-user-pages-soft"
rc="$(run_tool "$R" --only pipes)"
[ "$rc" = 0 ] && grep -qE "pipes +would-apply +fs.pipe-user-pages-soft -> 65536 pages \(MemTotal 3911456 kB\)" "$TMP/out" || { cat "$TMP/out"; fail "pipes plan"; }
rc="$(run_tool "$R" --apply --only pipes)"
[ "$rc" = 0 ] && [ "$(cat "$R/proc/sys/fs/pipe-user-pages-soft")" = 65536 ] || { cat "$TMP/out"; fail "pipes not raised"; }
grep -qx 'fs.pipe-user-pages-soft = 65536' "$R/etc/sysctl.d/99-netrun.conf" || fail "pipes not persisted"
echo 262144 > "$R/proc/sys/fs/pipe-user-pages-soft"
rc="$(run_tool "$R" --apply --only pipes)"
[ "$rc" = 0 ] && [ "$(cat "$R/proc/sys/fs/pipe-user-pages-soft")" = 262144 ] || fail "pipes lowered a higher runtime value"
rc="$(run_tool "$R" --only pipes --pipe-pages 100)"; [ "$rc" = 1 ] || fail "--pipe-pages below 16384 accepted"
for src in "$HERE/../install_node_v2.sh" "$HERE/node_followup_v2.sh" "$SCRIPT"; do
  ( eval "$(sed -n '/^pipe_pages_for_mem_kb() {/,/^}/p' "$src")"
    [ "$(pipe_pages_for_mem_kb 3911456)" = 65536 ] && [ "$(pipe_pages_for_mem_kb 1011712)" = 16384 ] \
      && [ "$(pipe_pages_for_mem_kb 7990000)" = 131072 ] && [ "$(pipe_pages_for_mem_kb 64000000)" = 262144 ] \
      && [ "$(pipe_pages_for_mem_kb "")" = 16384 ] ) || fail "pipe formula differs in $src"
done
ok "pipes: 2c/4GB -> 65536 pages persisted + raised, never lowered, same formula in installer / follow-up / tuning"

# ── 19. audit: legacy third-party nserver + ephemeral overlap are reported ─
R="$(new_root dnsaudit)"
printf 'daemon\nnserver 1.0.0.19\nnserver 2a0d:2a00:1::\nflush\nsocks -6 -a -p33000 -i45.32.10.20 -e2001:db8::9\n' > "$R/opt/netrun/proxyserver/3proxy/3proxy_33000.cfg"
rc="$(run_tool "$R" --only unbound)"
grep -q 'WARNING 1 batch cfg(s) send customer DNS to third-party resolvers (legacy geo seed): 3proxy_33000.cfg' "$TMP/out" || { cat "$TMP/out"; fail "legacy DNS audit"; }
grep -q 'ip_local_port_range 10000 65000 overlaps the proxy ports' "$TMP/out" || { cat "$TMP/out"; fail "ephemeral overlap audit"; }
ok "audit: third-party nserver cfgs and an ephemeral range overlapping the proxy ports are reported (read-only)"

echo "test_apply_capacity_tuning.sh — all $PASS checks passed"
