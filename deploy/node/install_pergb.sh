#!/usr/bin/env bash
# install_pergb.sh — the pay-per-GB v2 runtime on a node (lane L2): standalone
# and idempotent. Installs everything the per-GB data path runs from and leaves
# it DISABLED; the agent's POST /pergb/enable writes the cfgs and starts
# netrun-pergb.target. Never touches a per-piece process, cfg, port, the
# per-piece haproxy, nftables, BGP or the 3proxy egress guard.
#
#   bash deploy/node/install_pergb.sh       (root; from the repo, e.g. /opt/netrun)
#
# install_node_v2.sh runs it on new nodes. On a live node run it ALONE — never
# re-run node_followup_v2.sh for per-GB (it re-runs the haproxy setup,
# `netrun-bgp apply` and the guard).
#
# What it does (each step only when something differs; a second run changes
# nothing and prints "0 change(s)"):
#   preflight (before any change; a refusal changes nothing):
#     - deploy/node/bin/3proxy-pergb matches deploy/node/bin/3proxy-pergb.sha256
#       (missing: build it with scripts/build_3proxy_pergb.sh);
#     - uid/gid 65533 is free or already netrun-pergb's, and netrun-pergb has
#       no other uid ("uid_taken" otherwise);
#     - before the log image exists: free disk >= 2 x its size.
#   users: netrun-pergb (uid/gid 65533, the per-GB 3proxy; gated by
#     netrun-proxy-guard's `pergb` chain) and netrun-radius (system user).
#   directories: /opt/netrun/pergb/{bin,cfg,haproxy} (cfg 0750 root:netrun-pergb),
#     /etc/netrun-pergb (0750 root:netrun-radius: radius.secret is 0640
#     root:netrun-radius, enable.json 0600 root), /var/lib/netrun-pergb (0700).
#   binary: /opt/netrun/pergb/bin/3proxy-pergb (0755) + 3proxy-pergb.sha256,
#     which the units' ExecStartPre checks; refused when it cannot run here
#     (ldd: a glibc older than the build's).
#   RADIUS: node_runtime/radius -> /opt/netrun/radius (root, 0644 files; tests
#     and caches left out), when the checkout has it.
#   log filesystem: /var/lib/netrun-pergb/log.img (NETRUN_PERGB_LOG_SIZE, 16G,
#     fully allocated, ext4) mounted on /var/log/netrun-pergb by
#     var-log-netrun\x2dpergb.mount (not enabled: the per-GB units pull it in
#     with RequiresMountsFor). Its root: 0751 netrun-pergb (3proxy-pergb
#     writes p<sp>.log.*; rsyslog may traverse), archive/ 0750 root,
#     haproxy.log 0660 syslog:netrun-pergb.
#   rsyslog: /etc/rsyslog.d/30-netrun-pergb-haproxy.conf (tag
#     netrun-pergb-haproxy -> /var/log/netrun-pergb/haproxy.log; rsyslog
#     restarted when the rule changed); logrotate 14 days
#     (/etc/logrotate.d/netrun-pergb-haproxy).
#   units (installed, daemon-reload, NOT enabled or started): netrun-pergb.target,
#     netrun.slice + netrun-pergb.slice (NETRUN_PERGB_CPU_WEIGHT 50,
#     NETRUN_PERGB_MEM_MAX 1536M -> MemoryHigh 85 %, NETRUN_PERGB_MAX_CONNS
#     8000 -> TasksMax), netrun-pergb-3proxy@.service, netrun-pergb-haproxy.service,
#     netrun-pergb-certs.path/.service, the log mount, and netrun-radius.socket /
#     .service when the checkout has them.
#
# Test hooks: NETRUN_PERGB_ROOT=<dir> prefixes every path written;
# NETRUN_PERGB_SRC=<dir> is the repo to install from; NETRUN_PERGB_NO_CHOWN=1
# skips chown (and owner checks). Commands come from PATH.
set -euo pipefail

SRC="${NETRUN_PERGB_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)}"
ROOT="${NETRUN_PERGB_ROOT:-}"
NO_CHOWN="${NETRUN_PERGB_NO_CHOWN:-0}"
PERGB_USER="netrun-pergb"
RADIUS_USER="netrun-radius"
PERGB_UID="${NETRUN_PERGB_UID:-65533}"
LOG_SIZE="${NETRUN_PERGB_LOG_SIZE:-16G}"
MEM_MAX="${NETRUN_PERGB_MEM_MAX:-1536M}"
CPU_WEIGHT="${NETRUN_PERGB_CPU_WEIGHT:-50}"
MAX_CONNS="${NETRUN_PERGB_MAX_CONNS:-8000}"
PORT_COUNT=1000

OPT="$ROOT/opt/netrun/pergb"
BIN_DIR="$OPT/bin"
CFG_DIR="$OPT/cfg"
HAP_DIR="$OPT/haproxy"
ETC="$ROOT/etc/netrun-pergb"
STATE_REAL="/var/lib/netrun-pergb"
STATE="$ROOT$STATE_REAL"
IMAGE_REAL="$STATE_REAL/log.img"
IMAGE="$ROOT$IMAGE_REAL"
LOGDIR_REAL="/var/log/netrun-pergb"
LOGDIR="$ROOT$LOGDIR_REAL"
RADIUS_DST="$ROOT/opt/netrun/radius"
UNIT_DIR="$ROOT/etc/systemd/system"
RSYSLOG_CONF="$ROOT/etc/rsyslog.d/30-netrun-pergb-haproxy.conf"
LOGROTATE_CONF="$ROOT/etc/logrotate.d/netrun-pergb-haproxy"
MOUNT_UNIT='var-log-netrun\x2dpergb.mount'
DEPLOY="$SRC/deploy/node"

CHANGES=0
UNITS_CHANGED=0

log() { printf '[install_pergb] %s\n' "$*"; }
die() { printf '[install_pergb] ERROR: %s\n' "$*" >&2; exit 1; }
changed() { CHANGES=$((CHANGES + 1)); log "$*"; }

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# "<mode> <uid> <gid>" of a path (GNU or BSD stat).
meta_of() { stat -c '%a %u %g' "$1" 2>/dev/null || stat -f '%Lp %u %g' "$1"; }

# (getent exits 2 for "no such entry": never a failure here, under pipefail)
id_of_user() { { getent passwd "$1" 2>/dev/null || true; } | cut -d: -f3; }
id_of_group() { { getent group "$1" 2>/dev/null || true; } | cut -d: -f3; }

# own <path> <user> <group>: chown unless the test hook says not to.
own() {
  [ "$NO_CHOWN" = 1 ] && return 0
  chown "$2:$3" "$1"
}

# meta_ok <path> <mode> <user> <group>: the mode (and, with chown, the owner) match.
meta_ok() {
  local want_u want_g m
  m="$(meta_of "$1")" || return 1
  [ "${m%% *}" = "$(printf '%o' "0$2")" ] || return 1
  [ "$NO_CHOWN" = 1 ] && return 0
  want_u="$(id_of_user "$3")"; want_g="$(id_of_group "$4")"
  [ "$m" = "$(printf '%o' "0$2") $want_u $want_g" ]
}

# ensure_dir <path> <mode> <user> <group>
ensure_dir() {
  if [ -d "$1" ] && meta_ok "$1" "$2" "$3" "$4"; then return 0; fi
  mkdir -p "$1"
  chmod "$2" "$1"
  own "$1" "$3" "$4"
  changed "directory $1 ($2 $3:$4)"
}

# ensure_file <dest> <mode> <user> <group> < content — written atomically when
# the content, mode or owner differs. 0 = written, 1 = already so.
ensure_file() {
  local dest="$1" mode="$2" user="$3" group="$4" tmp
  tmp="$(mktemp "$(dirname "$dest")/.install_pergb.XXXXXX" 2>/dev/null)" || { mkdir -p "$(dirname "$dest")"; tmp="$(mktemp "$(dirname "$dest")/.install_pergb.XXXXXX")"; }
  cat > "$tmp"
  if [ -f "$dest" ] && cmp -s "$tmp" "$dest" && meta_ok "$dest" "$mode" "$user" "$group"; then
    rm -f "$tmp"
    return 1
  fi
  chmod "$mode" "$tmp"
  own "$tmp" "$user" "$group"
  mv -f "$tmp" "$dest"
  changed "wrote $dest"
  return 0
}

# size text (16G, 512M, bytes) -> bytes
size_bytes() {
  local v="$1" n unit
  [[ "$v" =~ ^([0-9]+)([KMGT]?)$ ]] || die "bad size: $v (use e.g. 16G)"
  n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
  case "$unit" in K) n=$((n * 1024)) ;; M) n=$((n * 1024 * 1024)) ;; G) n=$((n * 1024 * 1024 * 1024)) ;; T) n=$((n * 1024 * 1024 * 1024 * 1024)) ;; esac
  echo "$n"
}

# ── preflight: nothing changes before every check passed ──────────

preflight() {
  local bin="$DEPLOY/bin/3proxy-pergb" sums="$DEPLOY/bin/3proxy-pergb.sha256" pinned u g owner
  [ -n "$ROOT" ] || [ "$(id -u)" = 0 ] || die "run as root"
  [ -f "$bin" ] && [ -f "$sums" ] \
    || die "missing $bin or its .sha256 — build it on a Linux box with Docker: bash scripts/build_3proxy_pergb.sh"
  pinned="$(cut -d' ' -f1 "$sums")"
  [[ "$pinned" =~ ^[0-9a-f]{64}$ ]] || die "bad pinned sha256 in $sums"
  [ "$(sha256_of "$bin")" = "$pinned" ] || die "binary_hash_mismatch: $bin does not match $sums"
  for f in netrun-pergb.target netrun.slice netrun-pergb.slice netrun-pergb-3proxy@.service netrun-pergb-haproxy.service \
           netrun-pergb-certs.path netrun-pergb-certs.service netrun-pergb-log.mount.in netrun-pergb-rsyslog.conf netrun-pergb-logrotate; do
    [ -f "$DEPLOY/$f" ] || die "missing $DEPLOY/$f"
  done
  [[ "$PERGB_UID" =~ ^[0-9]+$ ]] || die "NETRUN_PERGB_UID must be a number"
  [[ "$CPU_WEIGHT" =~ ^[0-9]+$ ]] && [ "$CPU_WEIGHT" -ge 1 ] && [ "$CPU_WEIGHT" -le 10000 ] || die "NETRUN_PERGB_CPU_WEIGHT must be 1..10000"
  [[ "$MAX_CONNS" =~ ^[0-9]+$ ]] && [ "$MAX_CONNS" -ge 100 ] || die "NETRUN_PERGB_MAX_CONNS must be >= 100"
  [ "$(size_bytes "$MEM_MAX")" -ge $((256 * 1024 * 1024)) ] || die "NETRUN_PERGB_MEM_MAX must be at least 256M"
  # uid / gid 65533: free, or netrun-pergb's
  u="$(id_of_user "$PERGB_USER")"
  [ -z "$u" ] || [ "$u" = "$PERGB_UID" ] || die "uid_taken: user $PERGB_USER exists with uid $u, expected $PERGB_UID"
  owner="$({ getent passwd "$PERGB_UID" 2>/dev/null || true; } | cut -d: -f1)"
  [ -z "$owner" ] || [ "$owner" = "$PERGB_USER" ] || die "uid_taken: uid $PERGB_UID belongs to $owner"
  g="$(id_of_group "$PERGB_USER")"
  [ -z "$g" ] || [ "$g" = "$PERGB_UID" ] || die "uid_taken: group $PERGB_USER exists with gid $g, expected $PERGB_UID"
  owner="$({ getent group "$PERGB_UID" 2>/dev/null || true; } | cut -d: -f1)"
  [ -z "$owner" ] || [ "$owner" = "$PERGB_USER" ] || die "uid_taken: gid $PERGB_UID belongs to $owner"
  # the log image: free disk >= 2 x its size (only before it exists)
  if [ ! -e "$IMAGE" ]; then
    local size need avail_kb probe="$STATE"
    size="$(size_bytes "$LOG_SIZE")"
    [ "$size" -ge $((256 * 1024 * 1024)) ] || die "NETRUN_PERGB_LOG_SIZE must be at least 256M"
    while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
    avail_kb="$(df -Pk "$probe" | awk 'NR == 2 { print $4 }')"
    [[ "$avail_kb" =~ ^[0-9]+$ ]] || die "cannot read the free space of $probe"
    need=$((2 * size / 1024))
    [ "$avail_kb" -ge "$need" ] \
      || die "low_disk: $((avail_kb / 1024)) MiB free on $probe, the $LOG_SIZE log image needs 2 x = $((need / 1024)) MiB (set NETRUN_PERGB_LOG_SIZE)"
  fi
}

# ── steps ─────────────────────────────────────────────────────────

ensure_users() {
  if [ -z "$(id_of_group "$PERGB_USER")" ]; then
    groupadd --system -g "$PERGB_UID" "$PERGB_USER"
    changed "group $PERGB_USER (gid $PERGB_UID)"
  fi
  if [ -z "$(id_of_user "$PERGB_USER")" ]; then
    useradd --system -u "$PERGB_UID" -g "$PERGB_USER" -M -d /nonexistent -s /usr/sbin/nologin \
      -c "NETRUN per-GB 3proxy" "$PERGB_USER"
    changed "user $PERGB_USER (uid $PERGB_UID)"
  fi
  if [ -z "$(id_of_user "$RADIUS_USER")" ]; then
    useradd --system -U -M -d /nonexistent -s /usr/sbin/nologin -c "NETRUN per-GB RADIUS" "$RADIUS_USER"
    changed "user $RADIUS_USER"
  fi
}

ensure_dirs() {
  # /opt/netrun must be traversable: netrun-pergb executes the binary below it
  if [ ! -d "$ROOT/opt/netrun" ]; then
    ensure_dir "$ROOT/opt/netrun" 0755 root root
  elif [ $(( 0$(meta_of "$ROOT/opt/netrun" | cut -d' ' -f1) & 1 )) -eq 0 ]; then
    chmod o+x "$ROOT/opt/netrun"
    changed "chmod o+x $ROOT/opt/netrun (netrun-pergb runs /opt/netrun/pergb/bin/3proxy-pergb)"
  fi
  ensure_dir "$OPT" 0755 root root
  ensure_dir "$BIN_DIR" 0755 root root
  ensure_dir "$CFG_DIR" 0750 root "$PERGB_USER"
  ensure_dir "$HAP_DIR" 0755 root root
  ensure_dir "$ETC" 0750 root "$RADIUS_USER"
  ensure_dir "$STATE" 0700 root root
  # the mount point on the root filesystem: nobody but root writes there while
  # the log filesystem is not mounted
  if ! is_mounted; then ensure_dir "$LOGDIR" 0750 root root; fi
}

ensure_binary() {
  local pinned
  pinned="$(cut -d' ' -f1 "$DEPLOY/bin/3proxy-pergb.sha256")"
  ensure_file "$BIN_DIR/3proxy-pergb" 0755 root root < "$DEPLOY/bin/3proxy-pergb" || true
  ensure_file "$BIN_DIR/3proxy-pergb.sha256" 0644 root root < <(printf '%s  3proxy-pergb\n' "$pinned") || true
  [ "$(sha256_of "$BIN_DIR/3proxy-pergb")" = "$pinned" ] || die "the installed binary does not match the pinned sha256"
  if [ -z "$ROOT" ] && command -v ldd >/dev/null 2>&1; then
    local out
    out="$(ldd "$BIN_DIR/3proxy-pergb" 2>&1 || true)"
    if printf '%s\n' "$out" | grep -Eq 'not found|not a dynamic executable'; then
      die "3proxy-pergb cannot run on this node: $(printf '%s\n' "$out" | grep -E 'not found|not a dynamic' | head -n 3 | tr '\n' ' ')"
    fi
  fi
}

ensure_radius_code() {
  local src="$SRC/node_runtime/radius" stage
  if [ ! -d "$src" ]; then
    log "node_runtime/radius is not in this checkout — /opt/netrun/radius left as it is"
    return 0
  fi
  stage="$(mktemp -d)"
  (cd "$src" && tar --exclude='./tests' --exclude='__pycache__' --exclude='*.pyc' -cf - .) | tar -C "$stage" -xf -
  find "$stage" -type d -exec chmod 0755 {} +
  find "$stage" -type f -exec chmod 0644 {} +
  if [ -d "$RADIUS_DST" ] && diff -r -q "$stage" "$RADIUS_DST" >/dev/null 2>&1; then
    rm -rf "$stage"
    return 0
  fi
  mkdir -p "$(dirname "$RADIUS_DST")"
  rm -rf "$RADIUS_DST.new" "$RADIUS_DST.old"
  mv "$stage" "$RADIUS_DST.new"
  chmod 0755 "$RADIUS_DST.new"
  [ "$NO_CHOWN" = 1 ] || chown -R root:root "$RADIUS_DST.new"
  [ -d "$RADIUS_DST" ] && mv "$RADIUS_DST" "$RADIUS_DST.old"
  mv "$RADIUS_DST.new" "$RADIUS_DST"
  rm -rf "$RADIUS_DST.old"
  changed "RADIUS code -> $RADIUS_DST"
}

ensure_log_image() {
  local size
  [ -e "$IMAGE" ] && return 0
  size="$(size_bytes "$LOG_SIZE")"
  if ! fallocate -l "$size" "$IMAGE" 2>/dev/null; then
    dd if=/dev/zero of="$IMAGE" bs=1M count=$((size / 1024 / 1024)) status=none || { rm -f "$IMAGE"; die "cannot allocate $IMAGE"; }
  fi
  chmod 0600 "$IMAGE"
  mkfs.ext4 -q -F -m 0 -L netrun-pergb-log "$IMAGE" || { rm -f "$IMAGE"; die "mkfs.ext4 $IMAGE failed"; }
  changed "log image $IMAGE ($LOG_SIZE, ext4)"
}

is_mounted() { mountpoint -q "$LOGDIR" 2>/dev/null; }

ensure_log_mounted() {
  if ! is_mounted; then
    systemctl start "$MOUNT_UNIT" || die "cannot mount $LOGDIR_REAL ($MOUNT_UNIT)"
    is_mounted || die "$LOGDIR_REAL is not a mount point after starting $MOUNT_UNIT"
    changed "mounted $LOGDIR_REAL"
  fi
  # the filesystem's own root, archive/ and the haproxy log
  ensure_dir "$LOGDIR" 0751 "$PERGB_USER" "$PERGB_USER"
  ensure_dir "$LOGDIR/archive" 0750 root root
  local syslog_user=root
  if [ -n "$(id_of_user syslog)" ]; then syslog_user=syslog; fi
  if [ ! -e "$LOGDIR/haproxy.log" ]; then
    : > "$LOGDIR/haproxy.log"
    changed "created $LOGDIR/haproxy.log"
  fi
  if ! meta_ok "$LOGDIR/haproxy.log" 0660 "$syslog_user" "$PERGB_USER"; then
    chmod 0660 "$LOGDIR/haproxy.log"
    own "$LOGDIR/haproxy.log" "$syslog_user" "$PERGB_USER"
    changed "$LOGDIR/haproxy.log 0660 $syslog_user:$PERGB_USER"
  fi
}

ensure_logging() {
  if ensure_file "$RSYSLOG_CONF" 0644 root root < "$DEPLOY/netrun-pergb-rsyslog.conf"; then
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
      systemctl restart rsyslog || log "WARNING: rsyslog restart failed — the per-GB haproxy log goes nowhere until it restarts"
    else
      log "rsyslog is not running: the per-GB haproxy log needs it"
    fi
  fi
  ensure_file "$LOGROTATE_CONF" 0644 root root < "$DEPLOY/netrun-pergb-logrotate" || true
}

render_slices() {
  local max high tasks
  max="$(size_bytes "$MEM_MAX")"
  high=$((max * 85 / 100 / 1024 / 1024))
  tasks=$((2 * PORT_COUNT + MAX_CONNS + 500))
  ensure_file "$UNIT_DIR/netrun-pergb.slice" 0644 root root < <(
    sed -e "s/^CPUWeight=.*/CPUWeight=$CPU_WEIGHT/" -e "s/^MemoryHigh=.*/MemoryHigh=${high}M/" \
        -e "s/^MemoryMax=.*/MemoryMax=$((max / 1024 / 1024))M/" -e "s/^TasksMax=.*/TasksMax=$tasks/" \
        "$DEPLOY/netrun-pergb.slice") && UNITS_CHANGED=1
  ensure_file "$UNIT_DIR/netrun.slice" 0644 root root < <(sed -e "s/^CPUWeight=.*/CPUWeight=$CPU_WEIGHT/" "$DEPLOY/netrun.slice") \
    && UNITS_CHANGED=1
  return 0
}

ensure_units() {
  local u
  mkdir -p "$UNIT_DIR"
  for u in netrun-pergb.target netrun-pergb-3proxy@.service netrun-pergb-haproxy.service netrun-pergb-certs.path netrun-pergb-certs.service \
           netrun-radius.socket netrun-radius.service; do
    if [ ! -f "$DEPLOY/$u" ]; then
      log "$u is not in this checkout — not installed"
      continue
    fi
    ensure_file "$UNIT_DIR/$u" 0644 root root < "$DEPLOY/$u" && UNITS_CHANGED=1
  done
  render_slices
  ensure_file "$UNIT_DIR/$MOUNT_UNIT" 0644 root root < <(
    sed -e "s#@IMAGE@#$IMAGE_REAL#" -e "s#@WHERE@#$LOGDIR_REAL#" -e "s#@IMAGE_DIR@#$STATE_REAL#" "$DEPLOY/netrun-pergb-log.mount.in") \
    && UNITS_CHANGED=1
  if [ "$UNITS_CHANGED" = 1 ]; then
    systemctl daemon-reload || die "systemctl daemon-reload failed"
    log "daemon-reload (units installed, none enabled or started)"
  fi
  return 0
}

main() {
  preflight
  ensure_users
  ensure_dirs
  ensure_binary
  ensure_radius_code
  ensure_log_image
  ensure_units
  ensure_log_mounted
  ensure_logging
  log "done: $CHANGES change(s); per-GB stays disabled until POST /pergb/enable"
}

main "$@"
