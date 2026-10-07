#!/usr/bin/env bash
# restore_3proxy.sh — netrun-3proxy-restore.service: start every batch cfg after
# a boot. The ONE restore script (audit RES-11/CLN-03): install_node_v2.sh and
# node_followup_v2.sh both point the unit here instead of writing their own
# heredoc copies (restore-3proxy.sh / restore_3proxy.sh), and a code deploy of
# the repo to /opt/netrun updates it.
#
# Each cfg goes through scripts/netrun-3proxy-spawn.sh (own systemd scope per
# batch, idempotent, per-cfg lock), so restarting this unit never kills a
# batch and a batch the agent's supervisor already started is left alone.
# Bounded parallelism (the 2026-05-15 fork-bomb lesson): $PARALLEL helpers at
# a time. *.cfg.disabled (demoted pay-per-GB cfgs) are never started.
#
# Env (the unit may set them for a legacy layout): NETRUN_PROXY_CFG_DIR
# (/opt/netrun/proxyserver/3proxy), NETRUN_3PROXY_BIN (helper default),
# NETRUN_3PROXY_SPAWN (the helper next to this script), NETRUN_RESTORE_PARALLEL (4).
set -u

TAG="netrun-3proxy-restore"
PROXY_CFG_DIR="${NETRUN_PROXY_CFG_DIR:-/opt/netrun/proxyserver/3proxy}"
SPAWN="${NETRUN_3PROXY_SPAWN:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/netrun-3proxy-spawn.sh}"
PARALLEL="${NETRUN_RESTORE_PARALLEL:-4}"

log() { logger -t "$TAG" "$*" 2>/dev/null || true; printf '[%s] %s\n' "$TAG" "$*"; }

ulimit -n 1048576 2>/dev/null || true
ulimit -u unlimited 2>/dev/null || true

shopt -s nullglob
cfgs=("$PROXY_CFG_DIR"/3proxy_*.cfg)
if [ "${#cfgs[@]}" -eq 0 ]; then
  log "no batch cfgs in $PROXY_CFG_DIR"
  exit 0
fi

# One ss snapshot: cfgs whose first socks port already listens are skipped
# without forking a helper (the helper re-checks anyway).
listening="$(ss -Hltn 2>/dev/null | awk '{ p = $4; sub(/.*:/, "", p); print p }' | sort -u)"
worklist="$(mktemp)"
results="$(mktemp)"
trap 'rm -f "$worklist" "$results"' EXIT
skipped=0
for cfg in "${cfgs[@]}"; do
  [ -f "$cfg" ] || continue
  p="$(awk '/^[ \t]*socks[ \t]/ { for (i = 2; i <= NF; i++) if ($i ~ /^-p[0-9]+$/) { print substr($i, 3); exit } }' "$cfg")"
  if [ -n "$p" ] && printf '%s\n' "$listening" | grep -qx "$p"; then
    skipped=$((skipped + 1))
    continue
  fi
  printf '%s\n' "$cfg" >> "$worklist"
done
total="$(wc -l < "$worklist" | tr -d ' ')"
log "starting: ${#cfgs[@]} cfgs, $skipped already listening, $total to start, parallel=$PARALLEL"

if [ "$total" -gt 0 ]; then
  if [ -f "$SPAWN" ]; then
    < "$worklist" xargs -P "$PARALLEL" -I{} bash "$SPAWN" {} >> "$results" 2>&1 || true
  else
    # No helper (a node copied without scripts/): the historical detached start.
    log "WARNING: spawn helper $SPAWN missing — plain setsid start"
    bin="${NETRUN_3PROXY_BIN:-$PROXY_CFG_DIR/bin/3proxy}"
    while read -r cfg; do
      setsid "$bin" "$cfg" </dev/null >/dev/null 2>&1 &
      echo "spawned cfg=$cfg via=setsid-fallback" >> "$results"
      sleep 0.3
    done < "$worklist"
  fi
fi

spawned="$(grep -c '^spawned ' "$results" 2>/dev/null)"; spawned="${spawned:-0}"
already="$(grep -cE '^already-(running|listening) ' "$results" 2>/dev/null)"; already="${already:-0}"
bad="$(grep -cE '^(failed|refused) ' "$results" 2>/dev/null)"; bad="${bad:-0}"
log "done: spawned=$spawned already=$already failed=$bad skipped_listening=$skipped"
if [ "$bad" -gt 0 ]; then
  grep -E '^(failed|refused) ' "$results" | head -n 20 | while read -r line; do
    logger -p user.err -t "$TAG" "$line" 2>/dev/null || true
    printf '[%s] %s\n' "$TAG" "$line"
  done
fi
exit 0
