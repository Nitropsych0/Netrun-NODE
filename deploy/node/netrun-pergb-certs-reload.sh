#!/usr/bin/env bash
# NETRUN pay-per-GB v2 — reload the per-GB haproxy after a certificate change.
#
# Run by netrun-pergb-certs.service (started by netrun-pergb-certs.path when
# netrun-https rewrites the crt-list, the IP certificate or a hostname
# certificate) and, with --stamp, by netrun-pergb-haproxy.service right after
# it started. The stamp is a sha256 over the crt-list and every PEM it names
# (what the running haproxy loaded); a reload happens only when that changed,
# only while the per-GB haproxy runs, and only when `haproxy -c` accepts the
# config with the new files. The per-piece haproxy is never touched.
#
#   netrun-pergb-certs-reload.sh            reload when the certificates changed
#   netrun-pergb-certs-reload.sh --stamp    record the current state, no reload
#
# Settings (environment, for the tests): NETRUN_HTTPS_TLS_DIR (/etc/netrun/tls),
# NETRUN_PERGB_HAPROXY_CFG (/opt/netrun/pergb/haproxy/haproxy.cfg),
# NETRUN_PERGB_CERTS_STAMP (/run/netrun-pergb/certs-applied.sha),
# NETRUN_PERGB_CERTS_SETTLE (seconds to let a burst of writes settle, 2).
set -uo pipefail

TLS_DIR="${NETRUN_HTTPS_TLS_DIR:-/etc/netrun/tls}"
CRT_LIST="$TLS_DIR/crt-list"
CFG="${NETRUN_PERGB_HAPROXY_CFG:-/opt/netrun/pergb/haproxy/haproxy.cfg}"
STAMP="${NETRUN_PERGB_CERTS_STAMP:-/run/netrun-pergb/certs-applied.sha}"
UNIT="netrun-pergb-haproxy.service"

log() { echo "[netrun-pergb-certs] $*"; }

# sha256 over the crt-list and each PEM it names (first field of a line).
certs_hash() {
  {
    cat "$CRT_LIST" 2>/dev/null || echo "no crt-list"
    awk 'NF && $1 !~ /^#/ { print $1 }' "$CRT_LIST" 2>/dev/null | while read -r pem; do
      printf '%s ' "$pem"
      sha256sum < "$pem" 2>/dev/null || echo missing
    done
  } | sha256sum | cut -d' ' -f1
}

write_stamp() {
  mkdir -p "$(dirname "$STAMP")" && printf '%s\n' "$1" > "$STAMP.tmp" && mv -f "$STAMP.tmp" "$STAMP"
}

main() {
  local h _
  if [ "${1:-}" = "--stamp" ]; then
    write_stamp "$(certs_hash)"
    return 0
  fi
  # netrun-https writes the crt-list and the PEMs one after another, and a write that
  # lands while this runs does not start the unit again (it is still active): let the
  # burst settle first, and after a reload look again (at most 5 reloads per run).
  sleep "${NETRUN_PERGB_CERTS_SETTLE:-2}"
  for _ in 1 2 3 4 5; do
    if ! systemctl is-active --quiet "$UNIT"; then
      # not running: the next start loads the current files (and stamps them)
      rm -f "$STAMP"
      return 0
    fi
    h="$(certs_hash)"
    if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$h" ]; then
      return 0
    fi
    if ! haproxy -c -q -f "$CFG" >/dev/null 2>&1; then
      log "haproxy rejects $CFG with the current certificates — not reloading (the running haproxy keeps the old ones)"
      return 1
    fi
    if ! systemctl reload "$UNIT"; then
      log "systemctl reload $UNIT failed"
      return 1
    fi
    write_stamp "$h"
    log "certificates changed — $UNIT reloaded"
  done
  return 0
}

main "$@"
