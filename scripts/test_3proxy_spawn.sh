#!/usr/bin/env bash
# Audit RES-11 — tests for scripts/netrun-3proxy-spawn.sh (the one 3proxy
# spawn helper) and scripts/restore_3proxy.sh (the one boot restore). No root,
# no 3proxy: pgrep / ss / systemd-run / setsid / systemctl / flock / logger are
# PATH stubs driven by fixture files; pgrep applies the helper's real pattern
# to a fixture process table.
#   bash scripts/test_3proxy_spawn.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
SPAWN="$HERE/netrun-3proxy-spawn.sh"
RESTORE="$HERE/restore_3proxy.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

for f in "$SPAWN" "$RESTORE"; do bash -n "$f" || fail "syntax: $f"; done

BIN="$TMP/bin"; CALLS="$TMP/calls"; PS="$TMP/ps.txt"; SS="$TMP/ss.txt"; mkdir -p "$BIN"
CFGDIR="$TMP/proxyserver/3proxy"; mkdir -p "$CFGDIR/bin"
printf '#!/bin/sh\nexit 0\n' > "$CFGDIR/bin/3proxy"; chmod +x "$CFGDIR/bin/3proxy"
CFG="$CFGDIR/3proxy_18100.cfg"

stub() { printf '#!/usr/bin/env bash\necho "%s $*" >> "%s"\n%s\n' "$1" "$CALLS" "$2" > "$BIN/$1"; chmod +x "$BIN/$1"; }
# pgrep -f PATTERN: the pids of fixture "pid cmdline" lines whose cmdline matches.
stub pgrep 'pat="${@: -1}"; n=1; while read -r pid cmd; do printf "%s\n" "$cmd" | grep -qE -- "$pat" && { echo "$pid"; n=0; }; done < "'"$PS"'"; exit $n'
stub ss 'cat "'"$SS"'"'
# systemd-run: "starts" 3proxy (adds a process line) unless SR_FAIL / SR_NOPROC.
stub systemd-run '[ "${SR_FAIL:-0}" = 1 ] && exit 1; [ "${SR_NOPROC:-0}" = 1 ] && exit 0; for a; do last="$a"; done; echo "4242 '"$CFGDIR"'/bin/3proxy $last" >> "'"$PS"'"; exit 0'
stub setsid '[ "${SETSID_NOPROC:-0}" = 1 ] && exit 0; echo "4343 $*" >> "'"$PS"'"; exit 0'
stub systemctl 'case "$*" in "is-active --quiet unbound") [ "${UNBOUND_UP:-1}" = 1 ] ;; *) exit 1 ;; esac'
stub flock 'exit 0'
stub logger 'exit 0'
stub sleep '/bin/sleep 0.02'

run() { # args... -> exit code; stdout in $TMP/out
  : > "$CALLS"
  PATH="$BIN:$PATH" NETRUN_SPAWN_LOCK_DIR="$TMP/lock" NETRUN_SPAWN_WAIT_SEC=1 bash "$SPAWN" "$@" > "$TMP/out" 2>&1
  echo $?
}
reset() { : > "$PS"; : > "$SS"; printf 'daemon\nnserver 127.0.0.1\nnserver ::1\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\n' > "$CFG"; }

# ── 1. refusals ───────────────────────────────────────────────────
reset
cp "$CFG" "$CFG.disabled"
[ "$(run "$CFG.disabled")" = 2 ] && grep -q '^refused start_port=18100.cfg.disabled reason=disabled_cfg\|^refused .*disabled_cfg' "$TMP/out" || { cat "$TMP/out"; fail "a .cfg.disabled must be refused (exit 2)"; }
! grep -qE '^(systemd-run|setsid)' "$CALLS" || fail "disabled cfg started"
[ "$(run "$CFGDIR/3proxy_99999.cfg")" = 1 ] || fail "missing cfg must exit 1"
[ "$(run "$CFGDIR/other.cfg")" = 1 ] || fail "non-batch cfg name must exit 1"
[ "$(NETRUN_3PROXY_BIN=/nonexistent run "$CFG")" = 1 ] && grep -q 'binary_missing' "$TMP/out" || fail "missing binary must exit 1"
[ "$(run)" = 1 ] || fail "no argument must exit 1"
ok "refused: *.cfg.disabled (2); missing cfg, non-batch name, missing binary, no argument (1)"

# ── 2. idempotent: running (any dir) or listening -> nothing started ─
reset
echo "777 /root/proxyserver/3proxy/bin/3proxy /root/proxyserver/3proxy/3proxy_18100.cfg" > "$PS"
[ "$(run "$CFG")" = 0 ] && grep -q '^already-running start_port=18100 pid=777' "$TMP/out" || { cat "$TMP/out"; fail "already running (symlink path)"; }
! grep -qE '^(systemd-run|setsid)' "$CALLS" || fail "started a duplicate"
# A wrapper shell / the helper itself / another start port never count as running.
printf '%s\n' "11 bash $SPAWN $CFG" "12 bash -c setsid $CFGDIR/bin/3proxy $CFG" \
  "13 $CFGDIR/bin/3proxy $CFGDIR/3proxy_181000.cfg" "14 $CFGDIR/bin/3proxy $CFGDIR/3proxy_18100.cfg.disabled" > "$PS"
echo "LISTEN 0 13 45.32.10.20:18100 0.0.0.0:*" > "$SS"
[ "$(run "$CFG")" = 0 ] && grep -q '^already-listening start_port=18100 port=18100' "$TMP/out" || { cat "$TMP/out"; fail "listening probe"; }
grep -q '^ss -Hltn ( sport = :18100 )' "$CALLS" || fail "probe must be the first socks port: $(cat "$CALLS")"
! grep -qE '^(systemd-run|setsid)' "$CALLS" || fail "started over a listening port"
ok "idempotent: a 3proxy of this cfg (any directory) or a listening first socks port -> exit 0, nothing started; wrappers/other ports never match"

# ── 3. start: own scope; setsid only when no 3proxy appeared ──────
reset
[ "$(run "$CFG")" = 0 ] || { cat "$TMP/out"; fail "spawn exit"; }
grep -q '^spawned start_port=18100 pid=4242 via=scope:netrun-3proxy-18100$' "$TMP/out" || { cat "$TMP/out"; fail "spawn line"; }
grep -qx "systemd-run --scope --quiet --collect --unit netrun-3proxy-18100 -p KillMode=process -p TasksMax=infinity $CFGDIR/bin/3proxy $CFG" "$CALLS" \
  || { cat "$CALLS"; fail "systemd-run arguments"; }
! grep -q '^setsid' "$CALLS" || fail "setsid after a successful scope start (duplicate)"
reset
[ "$(SR_FAIL=1 run "$CFG")" = 0 ] && grep -q 'via=scope:netrun-3proxy-18100,setsid systemd_run_rc=1' "$TMP/out" || { cat "$TMP/out"; fail "setsid fallback"; }
reset
[ "$(NETRUN_SPAWN_SYSTEMD_RUN=0 run "$CFG")" = 0 ] && grep -q 'pid=4343 via=setsid$' "$TMP/out" && ! grep -q '^systemd-run' "$CALLS" || { cat "$TMP/out"; fail "NETRUN_SPAWN_SYSTEMD_RUN=0"; }
reset
[ "$(SR_NOPROC=1 SETSID_NOPROC=1 run "$CFG")" = 3 ] && grep -q '^failed start_port=18100 reason=no_process_after_start' "$TMP/out" || { cat "$TMP/out"; fail "no process must exit 3"; }
ok "start: systemd-run --scope --unit netrun-3proxy-<sp> KillMode=process TasksMax=infinity --collect; setsid only if no 3proxy appeared; exit 3 when none did"

# ── 4. legacy third-party DNS fixed forward at the (re)start ──────
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
reset
printf 'daemon\nnserver 1.0.0.19\nnserver 2a0d:2a00:1::\n  maxconn 200\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::1\n' > "$CFG"
touch -t 202001020304 "$CFG"; chmod 600 "$CFG"
m_before="$(mtime "$CFG")"
[ "$(run "$CFG")" = 0 ] || fail "spawn with legacy dns"
printf 'daemon\nnserver 127.0.0.1\nnserver ::1\n  maxconn 200\nflush\nsocks -6 -a -p18100 -i45.32.10.20 -e2001:db8::1\n' > "$TMP/want"
cmp -s "$TMP/want" "$CFG" || { cat "$CFG"; fail "legacy nserver not rewritten"; }
grep -q '^dns-fixed start_port=18100' "$TMP/out" || fail "dns fix not reported"
[ "$(mtime "$CFG")" = "$m_before" ] || fail "the DNS fix changed the cfg mtime ($m_before -> $(mtime "$CFG")): supervisor/firewall would see a new batch"
[ "$(mode "$CFG")" = 600 ] || fail "the DNS fix changed the cfg mode: $(mode "$CFG")"
chmod 644 "$CFG"
reset
printf 'daemon\nnserver 8.8.8.8\nflush\nsocks -6 -a -p18100 -i1.2.3.4 -e2001:db8::1\n' > "$CFG"
cp "$CFG" "$TMP/orig"
UNBOUND_UP=0 run "$CFG" >/dev/null
cmp -s "$TMP/orig" "$CFG" || fail "rewritten while unbound is down"
NETRUN_SPAWN_FIX_DNS=0 run "$CFG" >/dev/null; reset
printf 'daemon\nnserver 8.8.8.8\nflush\nsocks -6 -a -p18100 -i1.2.3.4 -e2001:db8::1\n' > "$CFG"; : > "$PS"
NETRUN_SPAWN_FIX_DNS=0 run "$CFG" >/dev/null
grep -qx 'nserver 8.8.8.8' "$CFG" || fail "NETRUN_SPAWN_FIX_DNS=0 rewrote"
reset; cp "$CFG" "$TMP/orig"; echo "1 $CFGDIR/bin/3proxy $CFG" > "$PS"
run "$CFG" >/dev/null
cmp -s "$TMP/orig" "$CFG" || fail "a running batch's cfg was touched"
ok "legacy geo-seed nserver -> 127.0.0.1/::1 right before a start (mtime + mode kept; only with unbound up; NETRUN_SPAWN_FIX_DNS=0 off; never for a running batch)"

# ── 5. restore_3proxy.sh: one snapshot, helper per non-listening cfg ──
reset
printf 'socks -6 -a -p18200 -i1.2.3.4 -e2001:db8::2\n' > "$CFGDIR/3proxy_18200.cfg"
printf 'socks -6 -a -p18300 -i1.2.3.4 -e2001:db8::3\n' > "$CFGDIR/3proxy_18300.cfg.disabled"
echo "LISTEN 0 13 1.2.3.4:18200 0.0.0.0:*" > "$SS"
cat > "$TMP/helper.sh" <<EOF
#!/usr/bin/env bash
echo "helper \$*" >> "$TMP/helper_calls"
case "\$1" in *18100*) echo "spawned start_port=18100 pid=1 via=scope" ;; *) echo "failed start_port=x reason=test" ;; esac
EOF
: > "$TMP/helper_calls"
PATH="$BIN:$PATH" NETRUN_PROXY_CFG_DIR="$CFGDIR" NETRUN_3PROXY_SPAWN="$TMP/helper.sh" bash "$RESTORE" > "$TMP/out" 2>&1 \
  || { cat "$TMP/out"; fail "restore exit"; }
[ "$(cat "$TMP/helper_calls")" = "helper $CFG" ] || { cat "$TMP/helper_calls"; fail "restore: helper must run for the non-listening live cfg only"; }
grep -q 'starting: 2 cfgs, 1 already listening, 1 to start, parallel=4' "$TMP/out" || { cat "$TMP/out"; fail "restore: start summary"; }
grep -q 'done: spawned=1 already=0 failed=0 skipped_listening=1' "$TMP/out" || { cat "$TMP/out"; fail "restore: done summary"; }
grep -q 'restore_3proxy.sh' "$HERE/../deploy/node/netrun-3proxy-restore.service" || fail "unit does not run restore_3proxy.sh"
grep -q 'install -m 0644 "$NETRUN_HOME/deploy/node/netrun-3proxy-restore.service"' "$HERE/../install_node_v2.sh" || fail "installer does not install the repo unit"
! grep -q "RESTORESH" "$HERE/../install_node_v2.sh" "$HERE/node_followup_v2.sh" || fail "a heredoc restore copy is still written"
ok "restore_3proxy.sh: one ss snapshot, the spawn helper for each non-listening batch cfg (never *.cfg.disabled), counts logged; installer + follow-up use the repo unit"

echo "test_3proxy_spawn.sh — all $PASS checks passed"
