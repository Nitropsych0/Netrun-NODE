#!/usr/bin/env bash
# NETRUN node — HTTPS on the HTTP proxy ports.
#
# Every proxy's HTTP port answers BOTH plain HTTP-proxy and HTTPS-proxy (TLS
# to the proxy) clients, so a customer keeps the same IP:port/login/password
# and just picks «HTTP» or «HTTPS» in the antidetect.
#
#   client ──► haproxy <public-ip>:<http-port>
#                ├─ first bytes are a TLS ClientHello → TLS terminated with the
#                │  node's Let's Encrypt IP certificate → 3proxy 127.0.0.1:<port>
#                └─ anything else (plain HTTP proxy) ─────► 3proxy 127.0.0.1:<port>
#
# 3proxy's `proxy` (HTTP) listeners move from the public IPv4 to 127.0.0.1 on
# the SAME port numbers; SOCKS listeners and every egress (-e<ipv6>) are left
# alone. The certificate is a Let's Encrypt short-lived IP certificate (6 days,
# HTTP-01 on :80), renewed automatically by the netrun-https-renew timer.
#
#   netrun-https setup   # once: haproxy + lego, certificate, timers, then sync
#   netrun-https sync    # idempotent: move HTTP listeners, (re)write frontends
#   netrun-https renew   # timer: renew the certificate when due, reload haproxy
#   netrun-https status  # short report
#   netrun-https accounting  # only (re)write the two per-port counter map rules
#
# Settings (environment, else ${NETRUN_ENV_FILE:-/etc/netrun/netrun.env}):
#   NETRUN_ACCOUNTING_MATCH_IPV4=1  meter only client legs: the map rules also
#     match `ip daddr|saddr <public IPv4>` (default 0 = port-only, as before).
set -euo pipefail

PROXY_DIR="${NETRUN_PROXY_DIR:-/opt/netrun/proxyserver/3proxy}"
PROXY_BIN="$PROXY_DIR/bin/3proxy"
TLS_DIR=/etc/netrun/tls
LEGO_DIR=/etc/netrun/lego
PEM="$TLS_DIR/node.pem"
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
FRONTEND_DIR=/etc/haproxy/netrun.d
LEGO_VERSION="${LEGO_VERSION:-v5.5.2}"
SELF=/usr/local/sbin/netrun-https

log() { printf '[netrun-https] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# KEY DEFAULT -> the environment wins, then $NETRUN_ENV_FILE (KEY=VALUE lines).
netrun_setting() {
  local key="$1" def="$2" v="${!1:-}" f="${NETRUN_ENV_FILE:-/etc/netrun/netrun.env}"
  if [ -z "$v" ] && [ -r "$f" ]; then
    v="$(awk -v k="$key" '{ sub(/^[ \t]+/, "") } index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { gsub(/^["\047 \t]+|["\047 \t\r]+$/, "", v); print v }' "$f")"
  fi
  printf '%s' "${v:-$def}"
}

public_ipv4() {
  ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

# ── certificate ───────────────────────────────────────────────────

build_pem() {
  local ip="$1" crt="$LEGO_DIR/certificates/$1.crt" key="$LEGO_DIR/certificates/$1.key"
  [ -s "$crt" ] && [ -s "$key" ] || die "certificate files missing for $ip"
  install -d -m 0700 "$TLS_DIR"
  cat "$crt" "$key" > "$PEM.tmp"
  chmod 0600 "$PEM.tmp"
  mv -f "$PEM.tmp" "$PEM"
}

issue_or_renew() {
  local ip
  ip="$(public_ipv4)"
  [ -n "$ip" ] || die "cannot detect the public IPv4"
  install -d -m 0700 "$LEGO_DIR"
  # `lego run` obtains the certificate or renews it once due (half of the
  # 6-day lifetime for short-lived certificates). HTTP-01 needs :80 free.
  lego run --path "$LEGO_DIR" --accept-tos --domains "$ip" --http --profile shortlived \
    --no-random-sleep >/dev/null
  build_pem "$ip"
}

# ── 3proxy HTTP listeners → 127.0.0.1 ─────────────────────────────

pids_for_cfg() {
  pgrep -f -- "3proxy/bin/3proxy .*/$(basename "$1")\$" || true
}

restart_cfg() {
  local cfg="$1" pids survivors
  pids="$(pids_for_cfg "$cfg")"
  if [ -n "$pids" ]; then
    # SIGTERM is graceful in 3proxy (it holds the listener while connections
    # drain) — SIGKILL survivors so the ports are free for the respawn.
    kill $pids 2>/dev/null || true
    sleep 2
    survivors="$(pids_for_cfg "$cfg")"
    [ -z "$survivors" ] || kill -9 $survivors 2>/dev/null || true
  fi
  # Same launch shape as the generator (raised limits, config `daemon`).
  bash -c "ulimit -n 600000; ulimit -u 600000; exec '$PROXY_BIN' '$cfg'" </dev/null >/dev/null 2>&1 &
  sleep 1
}

# Rewrite `proxy ... -i<public-ip> ...` to listen on 127.0.0.1. Prints 1 when
# the file changed.
localize_http_listeners() {
  local cfg="$1" ip="$2" tmp
  tmp="$(mktemp)"
  sed -E "s/^(proxy .* -i)${ip//./\\.}([[:space:]])/\\1127.0.0.1\\2/" "$cfg" > "$tmp"
  if cmp -s "$cfg" "$tmp"; then
    rm -f "$tmp"
    echo 0
  else
    cat "$tmp" > "$cfg"
    rm -f "$tmp"
    echo 1
  fi
}

# Contiguous "a-b" ranges of the HTTP ports served by one config.
http_port_ranges() {
  { grep -oE '^proxy .* -p[0-9]+' "$1" || true; } | grep -oE '[0-9]+$' | sort -n | awk '
    NR == 1 { start = $1; prev = $1; next }
    $1 == prev + 1 { prev = $1; next }
    { print start "-" prev; start = $1; prev = $1 }
    END { if (NR) print start "-" prev }' || true
}

# ── haproxy ───────────────────────────────────────────────────────

write_base_config() {
  cat > "$HAPROXY_CFG" <<'EOF'
# Managed by netrun-https — per-batch frontends live in /etc/haproxy/netrun.d.
global
    log /dev/log local0 warning
    maxconn 100000
    nbthread 2
    ssl-default-bind-options ssl-min-ver TLSv1.2
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy

defaults
    mode tcp
    log global
    option dontlognull
    maxconn 100000
    timeout connect 10s
    timeout client 1h
    timeout server 1h
    timeout tunnel 1h

# TLS terminator. The per-batch frontends loop TLS clients in here over an
# abstract socket; the PROXY v2 header carries the original destination, so the
# port-less server below reaches 127.0.0.1:<the port the client dialed>.
frontend netrun_tls
    bind abns@netrun_tls accept-proxy ssl crt /etc/netrun/tls/node.pem alpn http/1.1
    no log
    default_backend netrun_local

backend netrun_tls_loop
    server tls abns@netrun_tls send-proxy-v2

backend netrun_local
    server local 127.0.0.1
EOF
}

write_frontends() {
  local ip="$1" cfg name ranges tmpdir
  tmpdir="$(mktemp -d)"
  for cfg in "$PROXY_DIR"/3proxy_*.cfg; do
    [ -e "$cfg" ] || continue
    ranges="$(http_port_ranges "$cfg")"
    [ -n "$ranges" ] || continue
    name="$(basename "$cfg" .cfg)"
    {
      echo "frontend http_${name#3proxy_}"
      while read -r r; do echo "    bind ${ip}:${r}"; done <<< "$ranges"
      cat <<'EOF'
    no log
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    tcp-request content accept if { req.len gt 0 } !{ req.payload(0,1) -m bin 16 }
    use_backend netrun_tls_loop if { req.ssl_hello_type 1 }
    default_backend netrun_local
EOF
    } > "$tmpdir/$name.cfg"
  done
  install -d -m 0755 "$FRONTEND_DIR"
  # Replace the set atomically enough: new/changed files in, stale ones out.
  rm -f "$FRONTEND_DIR"/*.cfg
  cp "$tmpdir"/*.cfg "$FRONTEND_DIR"/ 2>/dev/null || true
  rm -rf "$tmpdir"
}

reload_haproxy() {
  haproxy -c -q -f "$HAPROXY_CFG" -f "$FRONTEND_DIR" || die "haproxy config check failed"
  if systemctl is-active --quiet haproxy; then
    systemctl reload haproxy
  else
    systemctl enable --now haproxy >/dev/null
  fi
}

# ── traffic accounting ────────────────────────────────────────────

# The per-port counters (proxy_accounting cmap_in/cmap_out) must not see the
# loopback leg haproxy → 3proxy, or every HTTP proxy byte is counted twice.
#
# Wave FLEET-HEALTH (SPD-05) — and, with NETRUN_ACCOUNTING_MATCH_IPV4=1, not an
# upstream leg either: the maps are keyed by port only, so a 3proxy upstream
# socket whose ephemeral port equals a proxy port was billed to that proxy
# whenever ip_local_port_range overlapped the listeners. Clients only reach the
# public IPv4, so the rules then also match `ip daddr|saddr <public IPv4>`.
# Converges both ways (setting off -> the iifname-only rule of before); only
# the map rule is replaced (`nft replace` by handle), counters and map
# elements — the billing values — are untouched.

# Handles of the `map @<map>` rules in an `nft -a list chain` dump (stdin) that
# differ from the wanted form: <ifkey> != "lo", plus `ip <addrkey> <ip>` when ip
# is set, and no `ip <addrkey>` at all when it is empty. Pure (tested).
accounting_rules_to_fix() {
  local map="$1" ifkey="$2" addrkey="$3" ip="${4:-}"
  awk -v map="map @$map" -v ifk="$ifkey != \"lo\"" -v ak="ip $addrkey " -v ip="$ip" '
    index($0, map) == 0 { next }
    {
      ok = index($0, ifk) > 0
      if (ip != "") ok = ok && index($0, ak ip " ") > 0
      else ok = ok && index($0, ak) == 0
      if (!ok && match($0, /# handle [0-9]+/)) print substr($0, RSTART + 9, RLENGTH - 9)
    }'
}

fix_accounting() {
  local h ip=""
  nft list table inet proxy_accounting >/dev/null 2>&1 || return 0
  if [ "$(netrun_setting NETRUN_ACCOUNTING_MATCH_IPV4 0)" = 1 ]; then
    ip="$(public_ipv4 || true)"
    [ -n "$ip" ] || log "WARNING: NETRUN_ACCOUNTING_MATCH_IPV4=1 but no public IPv4 found — keeping port-only rules"
  fi
  for h in $(nft -a list chain inet proxy_accounting input | accounting_rules_to_fix cmap_in iifname daddr "$ip"); do
    if [ -n "$ip" ]; then
      nft replace rule inet proxy_accounting input handle "$h" \
        iifname != "lo" ip daddr "$ip" counter name tcp dport map @cmap_in
    else
      nft replace rule inet proxy_accounting input handle "$h" \
        iifname != "lo" counter name tcp dport map @cmap_in
    fi
  done
  for h in $(nft -a list chain inet proxy_accounting output | accounting_rules_to_fix cmap_out oifname saddr "$ip"); do
    if [ -n "$ip" ]; then
      nft replace rule inet proxy_accounting output handle "$h" \
        oifname != "lo" ip saddr "$ip" counter name tcp sport map @cmap_out
    else
      nft replace rule inet proxy_accounting output handle "$h" \
        oifname != "lo" counter name tcp sport map @cmap_out
    fi
  done
  # Always persisted (as before): the 5-min sync is also what snapshots the
  # counter VALUES into /etc/nftables.conf for a reboot.
  nft list ruleset > /etc/nftables.conf
}

# ── commands ──────────────────────────────────────────────────────

cmd_sync() {
  local ip cfg changed=0
  ip="$(public_ipv4)"
  [ -n "$ip" ] || die "cannot detect the public IPv4"
  [ -s "$PEM" ] || die "no certificate at $PEM — run: netrun-https setup"
  [ -s "$HAPROXY_CFG" ] && grep -q "netrun-https" "$HAPROXY_CFG" || write_base_config
  fix_accounting
  local moved=()
  for cfg in "$PROXY_DIR"/3proxy_*.cfg; do
    [ -e "$cfg" ] || continue
    if [ "$(localize_http_listeners "$cfg" "$ip")" = 1 ]; then
      moved+=("$cfg")
    fi
  done
  # Free the public HTTP ports (3proxy respawns on 127.0.0.1), then let haproxy
  # take them. The gap is a few seconds per config.
  for cfg in "${moved[@]}"; do
    log "moving HTTP listeners of $(basename "$cfg") to 127.0.0.1"
    restart_cfg "$cfg"
    changed=1
  done
  write_frontends "$ip"
  reload_haproxy
  [ "$changed" = 0 ] || log "synced: ${#moved[@]} config(s) moved behind haproxy"
}

cmd_renew() {
  local before after
  before="$(sha256sum "$PEM" 2>/dev/null | cut -d' ' -f1 || true)"
  issue_or_renew
  after="$(sha256sum "$PEM" | cut -d' ' -f1)"
  if [ "$before" != "$after" ] && systemctl is-active --quiet haproxy; then
    systemctl reload haproxy
    log "certificate renewed, haproxy reloaded"
  fi
}

install_lego() {
  command -v lego >/dev/null 2>&1 && return 0
  local f="lego_${LEGO_VERSION}_linux_amd64.tar.gz" tmp
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$f" "https://github.com/go-acme/lego/releases/download/$LEGO_VERSION/$f"
  curl -fsSL -o "$tmp/sums.txt" \
    "https://github.com/go-acme/lego/releases/download/$LEGO_VERSION/lego_${LEGO_VERSION#v}_checksums.txt"
  (cd "$tmp" && grep " $f\$" sums.txt | sha256sum -c - >/dev/null) || die "lego checksum mismatch"
  tar -xzf "$tmp/$f" -C "$tmp" lego
  install -m 0755 "$tmp/lego" /usr/local/bin/lego
  rm -rf "$tmp"
}

install_units() {
  cat > /etc/systemd/system/netrun-https-renew.service <<EOF
[Unit]
Description=NETRUN — renew the node HTTPS certificate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF renew
EOF
  cat > /etc/systemd/system/netrun-https-renew.timer <<'EOF'
[Unit]
Description=NETRUN — node HTTPS certificate renewal (twice a day)

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=45m
Persistent=true

[Install]
WantedBy=timers.target
EOF
  # Periodic reconcile: new batches from the generator / whole-batch
  # deprovisions get their HTTP ports fronted without a manual step.
  cat > /etc/systemd/system/netrun-https-sync.service <<EOF
[Unit]
Description=NETRUN — keep HTTP proxy ports behind the HTTPS frontend
After=haproxy.service

[Service]
Type=oneshot
ExecStart=$SELF sync
EOF
  cat > /etc/systemd/system/netrun-https-sync.timer <<'EOF'
[Unit]
Description=NETRUN — HTTPS frontend reconcile (every 5 minutes)

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
  install -d /etc/systemd/system/haproxy.service.d
  cat > /etc/systemd/system/haproxy.service.d/netrun.conf <<'EOF'
[Service]
LimitNOFILE=1048576
Environment="EXTRAOPTS=-S /run/haproxy-master.sock -f /etc/haproxy/netrun.d"
EOF
  systemctl daemon-reload
  systemctl enable --now netrun-https-renew.timer netrun-https-sync.timer >/dev/null
}

cmd_setup() {
  export DEBIAN_FRONTEND=noninteractive
  command -v haproxy >/dev/null 2>&1 || { apt-get update -q >/dev/null; apt-get install -y -q haproxy >/dev/null; }
  install_lego
  install -m 0755 "$0" "$SELF" 2>/dev/null || true
  install -d -m 0755 "$FRONTEND_DIR"
  write_base_config
  # Certificate first: the sync timer fires as soon as it is enabled.
  issue_or_renew
  cmd_sync
  install_units
  log "HTTPS ready on $(public_ipv4): same ports as HTTP"
}

cmd_status() {
  local ip
  ip="$(public_ipv4)"
  echo "public ip : $ip"
  echo "haproxy   : $(systemctl is-active haproxy 2>/dev/null)"
  [ -s "$PEM" ] && openssl x509 -in "$PEM" -noout -enddate | sed 's/^/cert      : /'
  echo "frontends : $(ls "$FRONTEND_DIR"/*.cfg 2>/dev/null | wc -l)"
  echo "3proxy http on public ip : $(cat "$PROXY_DIR"/3proxy_*.cfg 2>/dev/null | grep -cE "^proxy .* -i${ip//./\\.}[[:space:]]" || true)"
  echo "3proxy http on 127.0.0.1 : $(cat "$PROXY_DIR"/3proxy_*.cfg 2>/dev/null | grep -cE '^proxy .* -i127\.0\.0\.1[[:space:]]' || true)"
}

case "${1:-}" in
  setup) cmd_setup ;;
  sync) cmd_sync ;;
  renew) cmd_renew ;;
  status) cmd_status ;;
  accounting) fix_accounting ;;
  *) echo "usage: $0 {setup|sync|renew|status|accounting}" >&2; exit 2 ;;
esac
