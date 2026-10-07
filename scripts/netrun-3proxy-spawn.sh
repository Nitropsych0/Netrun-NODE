#!/usr/bin/env bash
# netrun-3proxy-spawn.sh — the ONE way a NETRUN node starts a 3proxy batch
# (audit RES-11). Every spawner calls it:
#   - scripts/restore_3proxy.sh            (netrun-3proxy-restore.service, boot)
#   - the node agent                       (supervisor respawn, /deprovision
#                                            rewrite, /egress_mode, pay-per-GB enable)
#   - scripts/netrun-https.sh restart_cfg  (HTTP listeners moved behind haproxy)
#   - scripts/netrun-harden.sh restart_cfg (auth-fix)
#   - generator start-up scripts           (proxy-startup_<sp>.sh, a new batch)
#
#   netrun-3proxy-spawn.sh /opt/netrun/proxyserver/3proxy/3proxy_<startPort>.cfg
#
# Before this there were four spawners with four cgroup stories: a restore-unit
# child (`systemctl restart netrun-3proxy-restore` killed every batch it had
# started), an https-sync oneshot child (killed with the oneshot unless a
# KillMode drop-in existed), an agent child, an ssh-session child.
#
# What it guarantees:
#   - idempotent: nothing is started when a 3proxy already runs this cfg
#     (any directory: /root/proxyserver is a symlink to /opt/netrun/proxyserver)
#     or when the cfg's first socks port already listens — exit 0 either way;
#   - never two at once for one cfg: flock on $LOCK_DIR/3proxy-spawn-<sp>.lock
#     (the boot restore, the agent supervisor and an operator script can race);
#   - its own systemd scope per batch: systemd-run --scope --unit
#     netrun-3proxy-<sp> -p KillMode=process -p TasksMax=infinity --collect, so
#     no unit restart, agent restart or closed ssh session takes a batch down.
#     setsid is the fallback when systemd-run is unavailable or failed BEFORE a
#     3proxy appeared (never a second start when one did);
#   - a *.cfg.disabled (pay-per-GB demoted cfg) is refused;
#   - legacy third-party DNS is fixed forward (NETRUN_SPAWN_FIX_DNS=1, default):
#     a cfg whose `nserver` lines name anything but the node's own unbound
#     (127.0.0.1 / ::1) — the 2026-05 geo-seed resolvers — gets exactly
#     `nserver 127.0.0.1` + `nserver ::1` right before 3proxy reads it, and only
#     while unbound is active. No batch is ever restarted for it: the fix lands
#     at the batch's next (re)start. The rewrite keeps the cfg's mode, owner and
#     MTIME: it is not a new batch — the agent's supervisor (respawn only a cfg
#     older than the boot or seen serving) and firewall (cfgs written after a
#     cutoff are "fresh", never ghosts) both read the mtime.
#
# stdout: one line "<outcome> start_port=<sp> ...", outcome one of
#   spawned | already-running | already-listening | refused | failed
# Exit: 0 spawned / already running or listening; 1 usage, missing cfg or
#   binary; 2 refused (disabled cfg, a 3proxy of this cfg is still being
#   started by someone else past the lock wait); 3 start attempted, no 3proxy
#   process appeared.
#
# Env: NETRUN_3PROXY_BIN (default <cfg dir>/bin/3proxy, else
#   /opt/netrun/proxyserver/3proxy/bin/3proxy), NETRUN_SPAWN_LOCK_DIR
#   (/run/netrun), NETRUN_SPAWN_WAIT_SEC (5), NETRUN_SPAWN_LOCK_WAIT_SEC (30),
#   NETRUN_SPAWN_SYSTEMD_RUN (1; 0 = setsid only), NETRUN_SPAWN_FIX_DNS (1).
set -u

TAG="netrun-3proxy-spawn"
cfg="${1:-}"

say() { printf '%s\n' "$*"; logger -t "$TAG" "$*" 2>/dev/null || true; }

if [ -z "$cfg" ] || [ "$cfg" = "-h" ] || [ "$cfg" = "--help" ]; then
  sed -n '2,46p' "$0" >&2
  exit 1
fi

base="$(basename "$cfg")"
case "$base" in
  3proxy_*.cfg.disabled)
    say "refused start_port=${base#3proxy_} reason=disabled_cfg cfg=$cfg"
    exit 2 ;;
esac
sp="${base#3proxy_}"; sp="${sp%.cfg}"
case "$base" in 3proxy_*.cfg) ;; *) sp="" ;; esac
case "$sp" in ''|*[!0-9]*)
  say "failed reason=not_a_batch_cfg cfg=$cfg"
  exit 1 ;;
esac
if [ ! -f "$cfg" ]; then
  say "failed start_port=$sp reason=cfg_missing cfg=$cfg"
  exit 1
fi

bin="${NETRUN_3PROXY_BIN:-}"
if [ -z "$bin" ]; then
  bin="$(dirname "$cfg")/bin/3proxy"
  [ -x "$bin" ] || bin="/opt/netrun/proxyserver/3proxy/bin/3proxy"
fi
if [ ! -x "$bin" ]; then
  say "failed start_port=$sp reason=binary_missing bin=$bin"
  exit 1
fi

# pid of a 3proxy running THIS cfg (argv[0] is the 3proxy binary, argv[1] a path
# ending in 3proxy_<sp>.cfg, any directory), or nothing. A wrapper shell
# (`bash -c 'setsid .../3proxy <cfg>'`, this very script) never matches.
running_pid() {
  pgrep -f "^([^ ]*/)?3proxy ([^ ]*/)?3proxy_${sp}\\.cfg\$" 2>/dev/null | head -n 1
}

# First socks port of the cfg (socks listeners belong to 3proxy alone; an http
# port may also carry haproxy's public front), empty for an http-only cfg.
probe_port() {
  awk '/^[ \t]*socks[ \t]/ { for (i = 2; i <= NF; i++) if ($i ~ /^-p[0-9]+$/) { print substr($i, 3); exit } }' "$cfg"
}

port_listening() { # PORT -> 0 listening, 1 not, 2 unknown (ss failed)
  local out
  out="$(ss -Hltn "( sport = :$1 )" 2>/dev/null)" || return 2
  [ -n "$out" ]
}

unbound_active() { systemctl is-active --quiet unbound 2>/dev/null; }

# SRC DST: DST gets SRC's mode, owner and mtime (GNU first, BSD stat fallback).
copy_file_attrs() {
  chmod --reference="$1" "$2" 2>/dev/null || chmod "$(stat -f %Lp "$1" 2>/dev/null)" "$2" 2>/dev/null || true
  chown --reference="$1" "$2" 2>/dev/null || true
  touch -r "$1" "$2"
}

# Legacy geo-seed resolvers -> the node's unbound (see the header).
fix_legacy_dns() {
  [ "${NETRUN_SPAWN_FIX_DNS:-1}" = 1 ] || return 0
  awk '
    /^[ \t]*nserver[ \t]/ {
      a = $2
      if (a != "127.0.0.1" && a != "::1" && a != "localhost" && a !~ /^127\./ && a !~ /^\[::1\]/) bad = 1
    }
    END { exit bad ? 0 : 1 }' "$cfg" || return 0
  if ! unbound_active; then
    say "kept start_port=$sp legacy third-party nserver lines (unbound is not active)"
    return 0
  fi
  local tmp="$cfg.dnsfix.$$"
  awk '
    /^[ \t]*nserver[ \t]/ {
      if (!done) { match($0, /^[ \t]*/); ind = substr($0, 1, RLENGTH); print ind "nserver 127.0.0.1"; print ind "nserver ::1"; done = 1 }
      next
    }
    { print }' "$cfg" > "$tmp" && copy_file_attrs "$cfg" "$tmp" && mv -f "$tmp" "$cfg" \
    || { rm -f "$tmp"; say "kept start_port=$sp legacy nserver lines (rewrite failed)"; return 0; }
  say "dns-fixed start_port=$sp legacy third-party nserver lines -> 127.0.0.1 / ::1 (local unbound)"
}

lock_dir="${NETRUN_SPAWN_LOCK_DIR:-/run/netrun}"
if command -v flock >/dev/null 2>&1 && mkdir -p "$lock_dir" 2>/dev/null \
   && { exec 9>"$lock_dir/3proxy-spawn-$sp.lock"; } 2>/dev/null; then
  if ! flock -w "${NETRUN_SPAWN_LOCK_WAIT_SEC:-30}" 9; then
    say "refused start_port=$sp reason=another_spawn_in_progress"
    exit 2
  fi
fi

pid="$(running_pid)"
if [ -n "$pid" ]; then
  say "already-running start_port=$sp pid=$pid"
  exit 0
fi
pp="$(probe_port)"
if [ -n "$pp" ] && port_listening "$pp"; then
  say "already-listening start_port=$sp port=$pp"
  exit 0
fi

fix_legacy_dns

ulimit -n 1048576 2>/dev/null || ulimit -n 600000 2>/dev/null || true
ulimit -u unlimited 2>/dev/null || true

wait_for_process() {
  local i n
  n=$(( ${NETRUN_SPAWN_WAIT_SEC:-5} * 10 ))
  for ((i = 0; i < n; i++)); do
    pid="$(running_pid)"
    [ -n "$pid" ] && return 0
    sleep 0.1
  done
  return 1
}

via=""
rc_sr=""
if [ "${NETRUN_SPAWN_SYSTEMD_RUN:-1}" = 1 ] && command -v systemd-run >/dev/null 2>&1; then
  # The cfg carries `daemon`: 3proxy forks into the scope and systemd-run
  # returns at once. A same-named scope that still exists means a process of
  # this cfg is (dying) in it — then a timestamped name.
  unit="netrun-3proxy-$sp"
  systemctl is-active --quiet "$unit.scope" 2>/dev/null && unit="netrun-3proxy-$sp-$(date +%s)"
  # 9>&-: the lock fd must not live on in the daemon (it would hold the lock).
  systemd-run --scope --quiet --collect --unit "$unit" \
    -p KillMode=process -p TasksMax=infinity \
    "$bin" "$cfg" </dev/null >/dev/null 2>&1 9>&-
  rc_sr=$?
  via="scope:$unit"
  if wait_for_process; then
    say "spawned start_port=$sp pid=$pid via=$via"
    exit 0
  fi
fi
if [ -z "$(running_pid)" ]; then
  # No systemd-run, or it did not leave a 3proxy behind: plain detached start.
  setsid "$bin" "$cfg" </dev/null >/dev/null 2>&1 9>&- &
  disown 2>/dev/null || true
  via="${via:+$via,}setsid"
  if wait_for_process; then
    say "spawned start_port=$sp pid=$pid via=$via${rc_sr:+ systemd_run_rc=$rc_sr}"
    exit 0
  fi
fi
pid="$(running_pid)"
if [ -n "$pid" ]; then
  say "spawned start_port=$sp pid=$pid via=$via"
  exit 0
fi
say "failed start_port=$sp reason=no_process_after_start via=$via${rc_sr:+ systemd_run_rc=$rc_sr} cfg=$cfg"
exit 3
