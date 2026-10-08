#!/usr/bin/env bash
# netrun-nft-persist — the ONE way the live nftables ruleset reaches
# /etc/nftables.conf, and the boot load with a fallback (audit 2026-10-08).
#
#   netrun-nft-persist save [--allow-empty]
#       Under a lock every writer shares (the generator, the agent's
#       deprovision, the netrun-https sync, netrun-harden, the installer,
#       apply_capacity_tuning, clean_node): `nft list ruleset` -> a 0600 temp
#       file next to the target -> refused when empty (--allow-empty: a
#       comment line is saved instead, so the boot load does not fall back to
#       the previous rules) or when `nft -c -f` rejects it (xt-compat leftovers,
#       2026-05-22) -> fsync -> the current file becomes .prev (hard link +
#       rename, no copy) when it looks whole -> rename over the target -> fsync
#       of the directory. A crash leaves the old file or the new one, never a
#       torn one. Exit 1 (target unchanged) on any refusal.
#   netrun-nft-persist boot-load
#       nftables.service's ExecStart (drop-in written by `install`): loads the
#       target when `nft -c -f` accepts it and it is not empty, else .prev,
#       else the target as is (the unit fails like before).
#   netrun-nft-persist install
#       Copies itself to /usr/local/sbin/netrun-nft-persist, writes the
#       nftables.service drop-in netrun-boot-fallback.conf (daemon-reload only
#       when it changed; nothing is started, stopped or reloaded) and makes the
#       saved rulesets 0600. Idempotent.
#   netrun-nft-persist check
#       exit 0 when the target passes `nft -c -f` (read-only).
#
# Why: the 4-5 MB file was rewritten IN PLACE (`nft list ruleset >
# /etc/nftables.conf`) every 5 min by several writers; a hard reset during a
# write booted an empty or truncated firewall (Johannesburg 2026-10-08: 0 bytes
# for ~4 s of every sync).
#
# Settings (environment): NETRUN_NFT_CONF (default /etc/nftables.conf),
# NETRUN_NFT_LOCK (/run/lock/netrun-nft-persist.lock), NETRUN_NFT_LOCK_WAIT_SEC
# (120), NETRUN_NFT_PERSIST_CHECK (1; 0 = skip the `nft -c -f` of a dump,
# ~1.6 s on a 5 MB ruleset), NETRUN_NFT_UNIT_DIR (/etc/systemd/system),
# NETRUN_NFT_SELF (/usr/local/sbin/netrun-nft-persist).
set -uo pipefail

CONF="${NETRUN_NFT_CONF:-/etc/nftables.conf}"
LOCK="${NETRUN_NFT_LOCK:-/run/lock/netrun-nft-persist.lock}"
WAIT="${NETRUN_NFT_LOCK_WAIT_SEC:-120}"
CHECK="${NETRUN_NFT_PERSIST_CHECK:-1}"
UNIT_DIR="${NETRUN_NFT_UNIT_DIR:-/etc/systemd/system}"
SELF="${NETRUN_NFT_SELF:-/usr/local/sbin/netrun-nft-persist}"
DROPIN_NAME="netrun-boot-fallback.conf"
EMPTY_MARK="# netrun-nft-persist: empty ruleset"

log() { echo "[netrun-nft-persist] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

case "$WAIT" in ''|*[!0-9]*) WAIT=120 ;; esac

fsync_path() { sync -- "$1" 2>/dev/null || true; }

# A file that ends with the closing brace of a table (what `nft list ruleset`
# writes last) or is our empty-ruleset marker: worth keeping as .prev.
looks_whole() {
  [ -s "$1" ] || return 1
  [ "$(tail -c 2 "$1" 2>/dev/null)" = "}" ] && return 0
  [ "$(cat "$1" 2>/dev/null)" = "$EMPTY_MARK" ]
}

cmd_save() {
  local allow_empty=0 a dir
  for a in "$@"; do
    case "$a" in --allow-empty) allow_empty=1 ;; *) die "unknown option $a" ;; esac
  done
  command -v nft >/dev/null 2>&1 || die "nft not found"
  dir="$(dirname "$CONF")"
  mkdir -p "$(dirname "$LOCK")" 2>/dev/null || true
  exec 8>"$LOCK" || die "cannot open the lock $LOCK"
  if command -v flock >/dev/null 2>&1; then
    flock -w "$WAIT" 8 || die "$LOCK still held after ${WAIT}s — $CONF unchanged"
  fi
  SAVE_TMP="$(mktemp "$dir/.nftables.conf.XXXXXX")" || die "cannot create a temp file in $dir"
  SAVE_ERR="$SAVE_TMP.err"
  trap 'rm -f "${SAVE_TMP:-}" "${SAVE_ERR:-}"' EXIT
  local tmp="$SAVE_TMP" err="$SAVE_ERR"
  chmod 0600 "$tmp" 2>/dev/null || true
  nft list ruleset > "$tmp" 2>"$err" || die "nft list ruleset failed ($(head -c 200 "$err" | tr '\n' ' ')) — $CONF unchanged"
  if ! grep -q '[^[:space:]]' "$tmp"; then
    [ "$allow_empty" = 1 ] || die "the live ruleset is empty — $CONF unchanged (save --allow-empty to persist that)"
    printf '%s\n' "$EMPTY_MARK" > "$tmp" || die "cannot write $tmp"
  elif [ "$CHECK" != 0 ] && ! nft -c -f "$tmp" 2>"$err"; then
    die "nft -c rejects the dump ($(head -c 300 "$err" | tr '\n' ' ')) — $CONF unchanged"
  fi
  fsync_path "$tmp"
  if looks_whole "$CONF"; then
    ln -f "$CONF" "$CONF.prev.tmp" 2>/dev/null && mv -f "$CONF.prev.tmp" "$CONF.prev" \
      || log "warning: could not keep $CONF.prev"
  fi
  mv -f "$tmp" "$CONF" || die "cannot rename into $CONF"
  chmod 0600 "$CONF" "$CONF.prev" 2>/dev/null || true
  fsync_path "$dir"
  return 0
}

cmd_boot_load() {
  local f
  for f in "$CONF" "$CONF.prev"; do
    if [ ! -s "$f" ]; then
      log "$f is empty or missing"
      continue
    fi
    if nft -c -f "$f"; then
      [ "$f" = "$CONF" ] || log "WARNING: $CONF was rejected — loading $f"
      exec nft -f "$f"
    fi
    log "$f is rejected by nft -c"
  done
  log "WARNING: neither $CONF nor $CONF.prev passes nft -c — loading $CONF as is"
  exec nft -f "$CONF"
}

dropin_text() {
  local nft_bin="$1"
  cat <<EOF
# NETRUN (audit 2026-10-08) — written by netrun-nft-persist install.
# Boot loads $CONF only when \`nft -c -f\` accepts it, else $CONF.prev:
# a torn or empty save must never boot an empty firewall.
[Service]
ExecStart=
ExecStart=/bin/sh -c 'if [ -x $SELF ]; then exec $SELF boot-load; else exec $nft_bin -f $CONF; fi'
EOF
}

cmd_install() {
  local src="${BASH_SOURCE[0]:-}" dropin text nft_bin changed=0
  if [ -n "$src" ] && [ -f "$src" ] && ! cmp -s "$src" "$SELF"; then
    mkdir -p "$(dirname "$SELF")" || die "cannot create $(dirname "$SELF")"
    install -m 0755 "$src" "$SELF" || die "cannot install $SELF"
    log "installed $SELF"
  fi
  nft_bin="$(command -v nft || echo /usr/sbin/nft)"
  dropin="$UNIT_DIR/nftables.service.d/$DROPIN_NAME"
  text="$(dropin_text "$nft_bin")"
  if [ ! -f "$dropin" ] || [ "$(cat "$dropin")" != "$text" ]; then
    mkdir -p "$(dirname "$dropin")" || die "cannot create $(dirname "$dropin")"
    printf '%s\n' "$text" > "$dropin.tmp" && chmod 0644 "$dropin.tmp" && mv -f "$dropin.tmp" "$dropin" \
      || die "cannot write $dropin"
    changed=1
    log "wrote $dropin"
  fi
  chmod 0600 "$CONF" "$CONF".prev "$CONF".bak* 2>/dev/null || true
  if [ "$changed" = 1 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || log "warning: systemctl daemon-reload failed"
  fi
  return 0
}

cmd_check() {
  [ -s "$CONF" ] || { log "$CONF is empty or missing"; return 1; }
  nft -c -f "$CONF"
}

case "${1:-}" in
  save) shift; cmd_save "$@" ;;
  boot-load) cmd_boot_load ;;
  install) cmd_install ;;
  check) cmd_check ;;
  *) sed -n '2,32p' "$0" >&2; exit 2 ;;
esac
