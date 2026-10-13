#!/usr/bin/env bash
# Install the OS-fingerprint egress rewriter on a per-GB node. REVIEW-GATED:
# this touches the node's egress (an nft output hook) and grants the per-GB
# 3proxy CAP_NET_ADMIN (for SO_MARK). Run by the owner after review, not by the
# normal node deploy. Idempotent. `--off` removes everything.
set -euo pipefail
OSFP=/opt/netrun/osfp
log(){ echo "[osfp] $*"; }

if [ "${1:-}" = "--off" ]; then
  systemctl disable --now netrun-osfp.service 2>/dev/null || true
  nft delete table inet netrun_osfp 2>/dev/null || true
  rm -f /etc/systemd/system/netrun-pergb-3proxy@.service.d/10-osfp-cap.conf
  systemctl daemon-reload; systemctl restart 'netrun-pergb-3proxy@*' 2>/dev/null || true
  log "removed (3proxy restarted without CAP_NET_ADMIN; marked SYNs now pass unmodified)"; exit 0
fi

log "1) deps (scapy + netfilterqueue)"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y python3-scapy nftables >/dev/null
# netfilterqueue: apt where packaged (Ubuntu), else pip with the dev lib
if ! python3 -c 'import netfilterqueue' 2>/dev/null; then
  apt-get -qq install -y python3-netfilterqueue >/dev/null 2>&1 || {
    apt-get -qq install -y python3-pip python3-dev gcc libnetfilter-queue-dev >/dev/null
    pip install --break-system-packages -q netfilterqueue >/dev/null
  }
fi
python3 -c 'import netfilterqueue, scapy' && log "   deps ok"

log "2) code -> $OSFP"
install -d -m 0755 "$OSFP"
install -m 0644 "$(dirname "$0")/osfp_rewrite.py" "$OSFP/osfp_rewrite.py"
install -m 0755 "$(dirname "$0")/netrun-osfp-daemon.py" "$OSFP/netrun-osfp-daemon.py"
# seed signatures.json only if absent (never clobber a synced table)
[ -f "$OSFP/signatures.json" ] || install -m 0644 "$(dirname "$0")/signatures.json" "$OSFP/signatures.json"

log "3) unit"
install -m 0644 "$(dirname "$0")/netrun-osfp.service" /etc/systemd/system/netrun-osfp.service

log "4) 3proxy gets CAP_NET_ADMIN (for SO_MARK)"
install -d -m 0755 /etc/systemd/system/netrun-pergb-3proxy@.service.d
cat > /etc/systemd/system/netrun-pergb-3proxy@.service.d/10-osfp-cap.conf <<'CAP'
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CAP
systemctl daemon-reload

log "5) start the rewriter, then the nft rule (bypass: safe if the daemon dies)"
systemctl enable --now netrun-osfp.service
sleep 1
systemctl is-active --quiet netrun-osfp.service || { log "ABORT: daemon not active"; exit 1; }
nft -f "$(dirname "$0")/netrun-osfp.nft"

log "6) restart 3proxy so SO_MARK takes effect"
systemctl restart 'netrun-pergb-3proxy@*'
log "done. verify: a -os-windows login's egress SYN shows win 64240, opts mss,nop,ws8,nop,nop,sackOK, no TS."
