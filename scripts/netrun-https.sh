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
#   netrun-https sync    # idempotent: move HTTP listeners, (re)write frontends;
#                        # haproxy is reloaded ONLY when what it loaded differs
#                        # from the files (see "reload stamp" below)
#   netrun-https renew   # timer: renew the certificate when due, reload haproxy
#   netrun-https status  # short report
#   netrun-https accounting  # only (re)write the two per-port counter map rules
#   netrun-https units   # (re)write the renew/sync units (KillMode=process); no restarts
#
# Settings (environment, else ${NETRUN_ENV_FILE:-/etc/netrun/netrun.env}):
#   NETRUN_ACCOUNTING_MATCH_IPV4=1  meter only client legs: the map rules also
#     match `ip daddr|saddr <public IPv4>` (default 0 = port-only, as before).
#   NETRUN_HTTPS_RELOAD_VERIFY (1)  after a reload, wait up to
#     NETRUN_HTTPS_VERIFY_WAIT_SEC (10) for haproxy to listen on every
#     frontend's first bind port before the reload counts as applied; 0 = trust
#     the reload's exit code.
#   NETRUN_HTTPS_RELOAD_MAX_AGE_H (6)  reload anyway when the last applied
#     reload is older than this (a safety net; 0 = never).
#
# Reload stamp (audit follow-up): the frontend set is validated with
# `haproxy -c` BEFORE it replaces /etc/haproxy/netrun.d (a set haproxy rejects
# never becomes the live one), and a reload counts only once haproxy really
# listens on the frontends; then a hash of haproxy.cfg + the certificate + the
# frontend files goes to /run/netrun/haproxy-applied.sha. Every sync reloads
# when the files differ from that stamp, so a failed / killed / unverified
# reload is retried on the next 5-min tick (it used to be lost for good: the
# files were in place, the diff said "unchanged"). A missing stamp (first sync
# after a deploy or a reboot) costs one reload. sync / renew / setup run under
# one flock (/run/netrun/https-sync.lock): the generator, the timer and
# /deprovision call it concurrently.
set -euo pipefail

PROXY_DIR="${NETRUN_PROXY_DIR:-/opt/netrun/proxyserver/3proxy}"
PROXY_BIN="$PROXY_DIR/bin/3proxy"
# Audit RES-11 — the node's one 3proxy spawn helper (own systemd scope per
# batch, idempotent); the repo copy, not a copy taken at setup time.
SPAWN_HELPER="${NETRUN_3PROXY_SPAWN:-/opt/netrun/scripts/netrun-3proxy-spawn.sh}"
TLS_DIR=/etc/netrun/tls
LEGO_DIR=/etc/netrun/lego
PEM="$TLS_DIR/node.pem"
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
FRONTEND_DIR=/etc/haproxy/netrun.d
LEGO_VERSION="${LEGO_VERSION:-v5.5.2}"
SELF=/usr/local/sbin/netrun-https
SYSTEMD_DIR="${NETRUN_SYSTEMD_DIR:-/etc/systemd/system}"
APPLIED_STAMP="${NETRUN_HTTPS_APPLIED_STAMP:-/run/netrun/haproxy-applied.sha}"
SYNC_LOCK="${NETRUN_HTTPS_SYNC_LOCK:-/run/netrun/https-sync.lock}"

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

# 0 (true) when KEY is switched off: 0 / off / false / no, any case.
setting_off() {
  case "$(netrun_setting "$1" "${2:-1}" | tr '[:upper:]' '[:lower:]')" in
    0|off|false|no) return 0 ;;
  esac
  return 1
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

# `lego run` obtains the certificate or renews it once due (half of the
# 6-day lifetime for short-lived certificates). HTTP-01 needs :80 free.
# Network I/O that can take minutes: `renew` runs it OUTSIDE the sync lock.
lego_obtain() {
  local ip
  ip="$(public_ipv4)"
  [ -n "$ip" ] || die "cannot detect the public IPv4"
  install -d -m 0700 "$LEGO_DIR"
  lego run --path "$LEGO_DIR" --accept-tos --domains "$ip" --http --profile shortlived \
    --no-random-sleep >/dev/null
}

issue_or_renew() {
  lego_obtain
  build_pem "$(public_ipv4)"
}

# ── 3proxy HTTP listeners → 127.0.0.1 ─────────────────────────────

pids_for_cfg() {
  pgrep -f -- "3proxy/bin/3proxy .*/$(basename "$1")\$" || true
}

restart_cfg() {
  local cfg="$1" pids survivors
  pids="$(pids_for_cfg "$cfg")"
  if [ -n "$pids" ]; then
    # SIGTERM is graceful in 3proxy (listeners close within ~1 s, open
    # connections drain) — SIGKILL survivors so nothing old is left at the respawn.
    kill $pids 2>/dev/null || true
    sleep 2
    survivors="$(pids_for_cfg "$cfg")"
    [ -z "$survivors" ] || kill -9 $survivors 2>/dev/null || true
    # Gone before haproxy takes the public ports (a SIGKILLed 3proxy can
    # linger an instant; its listener would make haproxy's bind fail).
    local i=0
    while [ -n "$(pids_for_cfg "$cfg")" ] && [ "$i" -lt 10 ]; do sleep 0.5; i=$((i + 1)); done
  fi
  # Audit RES-11 — the respawn goes through the spawn helper: its own systemd
  # scope, so this oneshot (the 5-min sync timer) can never take the batch down
  # with it when it exits. The plain start is only for a node without it.
  if [ -f "$SPAWN_HELPER" ]; then
    NETRUN_3PROXY_BIN="$PROXY_BIN" bash "$SPAWN_HELPER" "$cfg" >/dev/null 2>&1 \
      || log "WARNING: spawn helper failed for $(basename "$cfg") (the agent's supervisor retries)"
  else
    # 9>&-: the sync lock fd (with_sync_lock) must not live on in the daemon.
    bash -c "ulimit -n 600000; ulimit -u 600000; exec '$PROXY_BIN' '$cfg'" </dev/null >/dev/null 2>&1 9>&- &
    sleep 1
  fi
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
  # Audit RES-11 — compare before touching anything: an identical set leaves
  # the live files (and haproxy) alone. FRONTENDS_CHANGED tells cmd_sync.
  if frontend_sets_equal "$tmpdir" "$FRONTEND_DIR"; then
    FRONTENDS_CHANGED=0
    rm -rf "$tmpdir"
    return 0
  fi
  FRONTENDS_CHANGED=1
  # Validate the NEW set before it replaces the live one: a set haproxy
  # rejects never lands in $FRONTEND_DIR (the running haproxy, the next sync
  # and the next boot keep the last good set; this run fails loudly).
  if ! haproxy_check "$tmpdir"; then
    rm -rf "$tmpdir"
    die "haproxy rejects the new frontend set — $FRONTEND_DIR left as it was"
  fi
  # Replace the set atomically enough: new/changed files in, stale ones out.
  rm -f "$FRONTEND_DIR"/*.cfg
  cp "$tmpdir"/*.cfg "$FRONTEND_DIR"/ 2>/dev/null || true
  rm -rf "$tmpdir"
}

# 0 when directories A and B hold the same *.cfg files with the same content.
frontend_sets_equal() {
  local a="$1" b="$2" f
  [ "$( (cd "$a" && ls -1 -- *.cfg 2>/dev/null) | sort)" = "$( (cd "$b" && ls -1 -- *.cfg 2>/dev/null) | sort)" ] || return 1
  for f in "$a"/*.cfg; do
    [ -e "$f" ] || continue
    cmp -s "$f" "$b/$(basename "$f")" || return 1
  done
  return 0
}

# `haproxy -c` of the base config + a frontend directory.
haproxy_check() {
  haproxy -c -q -f "$HAPROXY_CFG" -f "$1"
}

reload_haproxy() {
  haproxy_check "$FRONTEND_DIR" || die "haproxy config check failed"
  if systemctl is-active --quiet haproxy; then
    systemctl reload haproxy
  else
    systemctl enable --now haproxy >/dev/null
  fi
}

# ── reload stamp: what haproxy really loaded ──────────────────────

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# sha256 over haproxy.cfg, the certificate and the sorted frontend files
# (names + contents): the files a reload makes haproxy load.
haproxy_config_hash() {
  local f
  {
    for f in "$HAPROXY_CFG" "$PEM"; do
      printf '== %s\n' "$f"
      cat "$f" 2>/dev/null || true
    done
    for f in $( (cd "$FRONTEND_DIR" 2>/dev/null && ls -1 -- *.cfg 2>/dev/null) | sort); do
      printf '== %s\n' "$f"
      cat "$FRONTEND_DIR/$f"
    done
  } | sha256_stream
}

stamp_read() { cat "$APPLIED_STAMP" 2>/dev/null || true; }

stamp_write() {
  mkdir -p "$(dirname "$APPLIED_STAMP")" 2>/dev/null || true
  printf '%s\n' "$1" > "$APPLIED_STAMP.tmp" && mv -f "$APPLIED_STAMP.tmp" "$APPLIED_STAMP"
}

# 0 when the stamp exists and is older than NETRUN_HTTPS_RELOAD_MAX_AGE_H.
stamp_expired() {
  local h
  h="$(netrun_setting NETRUN_HTTPS_RELOAD_MAX_AGE_H 6)"
  case "$h" in ''|*[!0-9]*) return 1 ;; esac
  [ "$h" -gt 0 ] && [ -f "$APPLIED_STAMP" ] || return 1
  [ -n "$(find "$APPLIED_STAMP" -mmin +$((h * 60)) 2>/dev/null)" ]
}

# The first port of each frontend file's first bind line, one per line.
frontend_first_ports() {
  local f
  for f in "$FRONTEND_DIR"/*.cfg; do
    [ -e "$f" ] || continue
    awk '$1 == "bind" { n = split($2, a, ":"); split(a[n], r, "-"); print r[1]; exit }' "$f"
  done
}

# Of the ports given, those with no listener on IP:port — ONE `ss -Hltn`
# (no -p: that would walk every 3proxy's fds). Exit 2 when ss fails.
frontend_ports_missing() {
  local ip="$1" filter="" p have
  shift
  [ "$#" -gt 0 ] || return 0
  for p in "$@"; do filter="${filter:+$filter or }sport = :$p"; done
  have="$(ss -Hltn "$filter" 2>/dev/null)" || return 2
  have="$(printf '%s\n' "$have" | awk '{ print $4 }')"
  for p in "$@"; do
    printf '%s\n' "$have" | grep -qxF "$ip:$p" || echo "$p"
  done
}

# After a reload: haproxy listens on every frontend's first bind port (it
# gets NETRUN_HTTPS_VERIFY_WAIT_SEC to bind them). `systemctl reload` only
# signals the master, and a new worker that cannot bind leaves the old one
# serving the old set — this is what says the new set is live.
verify_frontends_listening() {
  local ip="$1" ports missing="" waited=0 limit
  setting_off NETRUN_HTTPS_RELOAD_VERIFY 1 && return 0
  ports="$(frontend_first_ports)"
  [ -n "$ports" ] || return 0
  limit="$(netrun_setting NETRUN_HTTPS_VERIFY_WAIT_SEC 10)"
  case "$limit" in ''|*[!0-9]*) limit=10 ;; esac
  while :; do
    # shellcheck disable=SC2086
    if missing="$(frontend_ports_missing "$ip" $ports)"; then
      [ -n "$missing" ] || return 0
    else
      missing="(ss failed)"
    fi
    [ "$waited" -lt "$limit" ] || break
    sleep 1
    waited=$((waited + 1))
  done
  log "WARNING: after the reload haproxy does not listen on $ip port(s) $(printf '%s' "$missing" | tr '\n' ' ')— not marked applied; the next sync retries"
  return 1
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
  local ip cfg changed=0 base_changed=0
  ip="$(public_ipv4)"
  [ -n "$ip" ] || die "cannot detect the public IPv4"
  [ -s "$PEM" ] || die "no certificate at $PEM — run: netrun-https setup"
  if ! { [ -s "$HAPROXY_CFG" ] && grep -q "netrun-https" "$HAPROXY_CFG"; }; then
    write_base_config
    base_changed=1
  fi
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
  for cfg in ${moved[@]+"${moved[@]}"}; do
    log "moving HTTP listeners of $(basename "$cfg") to 127.0.0.1"
    restart_cfg "$cfg"
    changed=1
  done
  FRONTENDS_CHANGED=1
  write_frontends "$ip"
  # Audit RES-11 — reload ONLY when needed (it used to reload every 5 min:
  # each reload re-binds every frontend on a 2-vCPU box and leaves the old
  # worker draining for up to the 1 h tunnel timeout): a change, a stopped
  # haproxy, or files haproxy has not (verifiably) loaded yet — the stamp.
  local want stamp reason=""
  want="$(haproxy_config_hash)"
  stamp="$(stamp_read)"
  if [ "$FRONTENDS_CHANGED" = 1 ]; then reason="frontends changed"
  elif [ "$base_changed" = 1 ]; then reason="base config written"
  elif [ "$changed" = 1 ]; then reason="listeners moved"
  elif ! systemctl is-active --quiet haproxy; then reason="haproxy was not running"
  elif [ -z "$stamp" ]; then reason="no reload stamp yet"
  elif [ "$stamp" != "$want" ]; then reason="files not applied by the last reload"
  elif stamp_expired; then reason="last applied reload older than $(netrun_setting NETRUN_HTTPS_RELOAD_MAX_AGE_H 6) h"
  fi
  [ -n "$reason" ] || return 0
  reload_haproxy
  if verify_frontends_listening "$ip"; then
    stamp_write "$want"
    log "synced: haproxy reloaded ($reason; moved=${#moved[@]})"
  else
    log "synced: haproxy reloaded ($reason) but NOT verified"
    return 1
  fi
}

# renew: the ACME exchange without the lock (it can take minutes when the CA
# is slow, and a /generate's sync must not wait on it), then the PEM swap +
# reload + stamp under the lock.
cmd_renew() {
  lego_obtain
  with_sync_lock cmd_renew_apply
}

cmd_renew_apply() {
  local before after
  before="$(sha256sum "$PEM" 2>/dev/null | cut -d' ' -f1 || true)"
  build_pem "$(public_ipv4)"
  after="$(sha256sum "$PEM" | cut -d' ' -f1)"
  if [ "$before" != "$after" ] && systemctl is-active --quiet haproxy; then
    systemctl reload haproxy
    # The stamp covers the certificate: an unverified reload here is retried
    # by the next sync.
    if verify_frontends_listening "$(public_ipv4)"; then stamp_write "$(haproxy_config_hash)"; fi
    log "certificate renewed, haproxy reloaded"
  fi
}

# sync / renew's apply step / setup one at a time (generator, timer,
# /deprovision). NETRUN_HTTPS_LOCK_WAIT_SEC (300): in-line callers pass less.
with_sync_lock() {
  if command -v flock >/dev/null 2>&1; then
    mkdir -p "$(dirname "$SYNC_LOCK")" 2>/dev/null || true
    exec 9>"$SYNC_LOCK"
    flock -w "${NETRUN_HTTPS_LOCK_WAIT_SEC:-300}" 9 || die "another netrun-https run still holds $SYNC_LOCK"
  fi
  "$@"
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
  write_units
  systemctl daemon-reload
  systemctl enable --now netrun-https-renew.timer netrun-https-sync.timer >/dev/null
}

# The unit files only (setup, and `netrun-https units` for an existing node).
# Audit RES-11 — the sync oneshot gets KillMode=process: a 3proxy it started
# (an HTTP-listener move) must never die with it, even where the spawn helper
# is missing; until now only nodes built from the orchestrator's cloud-init
# template had that drop-in.
write_units() {
  cat > "$SYSTEMD_DIR/netrun-https-renew.service" <<EOF
[Unit]
Description=NETRUN — renew the node HTTPS certificate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF renew
EOF
  cat > "$SYSTEMD_DIR/netrun-https-renew.timer" <<'EOF'
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
  cat > "$SYSTEMD_DIR/netrun-https-sync.service" <<EOF
[Unit]
Description=NETRUN — keep HTTP proxy ports behind the HTTPS frontend
After=haproxy.service

[Service]
Type=oneshot
ExecStart=$SELF sync
KillMode=process
EOF
  cat > "$SYSTEMD_DIR/netrun-https-sync.timer" <<'EOF'
[Unit]
Description=NETRUN — HTTPS frontend reconcile (every 5 minutes)

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
  install -d "$SYSTEMD_DIR/haproxy.service.d"
  cat > "$SYSTEMD_DIR/haproxy.service.d/netrun.conf" <<'EOF'
[Service]
LimitNOFILE=1048576
Environment="EXTRAOPTS=-S /run/haproxy-master.sock -f /etc/haproxy/netrun.d"
EOF
}

# `netrun-https units`: rewrite the unit files of an existing node (and refresh
# the /usr/local/sbin copy the timers run) — daemon-reload only; nothing is
# restarted, the timers keep their schedule.
cmd_units() {
  install -m 0755 "$0" "$SELF" 2>/dev/null || true
  write_units
  systemctl daemon-reload
  log "units rewritten (netrun-https-sync.service: KillMode=process); nothing restarted"
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
  # An unverified first reload must not keep the timers (the retry) away.
  cmd_sync || log "WARNING: first sync not verified — the sync timer retries"
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
  setup) with_sync_lock cmd_setup ;;
  sync) with_sync_lock cmd_sync ;;
  renew) cmd_renew ;;
  status) cmd_status ;;
  accounting) fix_accounting ;;
  units) cmd_units ;;
  *) echo "usage: $0 {setup|sync|renew|status|accounting|units}" >&2; exit 2 ;;
esac
