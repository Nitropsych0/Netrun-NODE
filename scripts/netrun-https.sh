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
#   netrun-https renew   # timer: renew the IP certificate when due, then the
#                        # hostname certificates; reload haproxy on a change
#   netrun-https certs   # hostname certificates only (the agent starts it)
#   netrun-https status  # short report
#   netrun-https accounting  # only (re)write the two per-port counter map rules
#   netrun-https units   # (re)write the renew/sync units (KillMode=process); no restarts
#
# Audit FO-08 — hostname certificates chosen by SNI. The orchestrator gives the
# node DNS names (us1.proxy.netrun.lol -> the node's IPv4) and customers dial
# https://login:pass@<name>:port; the IP certificate does not name them. The
# agent (POST /https/hostnames) writes the names, one lowercase FQDN per line,
# to $HOSTNAMES_FILE and starts `certs` detached:
#   1. outside the sync lock, under the ACME lock (/run/netrun/https-acme.lock,
#      also taken by the IP renewal: one HTTP-01 client on :80 at a time): every
#      listed name whose A record (the node's own resolver) is exactly the
#      public IPv4 gets `lego run` (default profile, LEGO_DIR kept, so a renewal
#      is `run` again) once its certificate is missing or within
#      NETRUN_HTTPS_HOST_RENEW_DAYS (30) of expiry. A name that does not point
#      here is skipped and never sent to the CA (failed validations count
#      against Let's Encrypt limits); a name whose lego run failed waits
#      NETRUN_HTTPS_ACME_RETRY_MIN (60) before the next try; one failing name
#      never stops the others. The outcome per name: $HOSTS_DIR/<name>.error.
#   2. under the sync lock: $HOSTS_DIR/<name>.pem (0600) per listed name with a
#      valid certificate, PEMs of names no longer listed deleted, and the
#      crt-list the TLS terminator loads — the IP certificate FIRST (the
#      default: IP clients send no SNI), then one `<pem> <name>` line per valid
#      hostname PEM. haproxy is reloaded only when the crt-list or a PEM in it
#      changed (the reload stamp covers them all).
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
TLS_DIR="${NETRUN_HTTPS_TLS_DIR:-/etc/netrun/tls}"
LEGO_DIR="${NETRUN_HTTPS_LEGO_DIR:-/etc/netrun/lego}"
PEM="$TLS_DIR/node.pem"
# Audit FO-08 — hostname certificates (see the header).
HOSTS_DIR="$TLS_DIR/hosts"
CRT_LIST="$TLS_DIR/crt-list"
HOSTNAMES_FILE="${NETRUN_HTTPS_HOSTNAMES_FILE:-/etc/netrun/https-hostnames}"
ACME_LOCK="${NETRUN_HTTPS_ACME_LOCK:-/run/netrun/https-acme.lock}"
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
# Network I/O that can take minutes: `renew` runs it OUTSIDE the sync lock
# (and under the ACME lock: see with_acme_lock).
lego_obtain() {
  local ip
  ip="$(public_ipv4)"
  [ -n "$ip" ] || die "cannot detect the public IPv4"
  install -d -m 0700 "$LEGO_DIR"
  lego run --path "$LEGO_DIR" --accept-tos --domains "$ip" --http --profile shortlived \
    --no-random-sleep >/dev/null
}

issue_or_renew() {
  with_acme_lock lego_obtain
  build_pem "$(public_ipv4)"
}

# ── hostname certificates (audit FO-08) ───────────────────────────

# The listed hostnames: lowercase FQDNs (letters, digits, hyphens; labels of
# 1-63, at most 253 in all, a TLD that starts with a letter — so never an IP),
# deduplicated, in file order. Anything else in the file is ignored. Validated
# here as well as in the agent: the name becomes a file name and a lego argument.
https_hostnames() {
  [ -s "$HOSTNAMES_FILE" ] || return 0
  tr -d ' \t\r' < "$HOSTNAMES_FILE" | tr '[:upper:]' '[:lower:]' \
    | awk '
        !/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$/ { next }
        length($0) > 253 || seen[$0]++ { next }
        { n = split($0, l, "."); for (i = 1; i <= n; i++) if (length(l[i]) > 63) next; print }'
}

# The IPv4 addresses (A records) the node's own resolver gives for $1, sorted,
# one per line; nothing when it does not resolve. getent (nsswitch: /etc/hosts,
# then the system resolver), else dig. Never fails.
resolve_ipv4() {
  if command -v getent >/dev/null 2>&1; then
    { getent ahostsv4 "$1" 2>/dev/null || true; } | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1 }' | sort -u
  elif command -v dig >/dev/null 2>&1; then
    { dig +short +time=3 +tries=2 A "$1" 2>/dev/null || true; } | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | sort -u
  fi
  return 0
}

# 0 when certificate file $2 (key: $3, default the same file — a PEM holds
# both) is for hostname $1 (a DNS name in its subjectAltName), has not
# expired (or, with $4 seconds, does not expire within them) and matches the key.
host_cert_ok() {
  local h="$1" crt="$2" key="${3:-$2}" within="${4:-0}" names a b
  [ -s "$crt" ] && [ -s "$key" ] || return 1
  openssl x509 -in "$crt" -noout -checkend "$within" >/dev/null 2>&1 || return 1
  names="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed 's/^[[:space:]]*//')" || return 1
  case $'\n'"$names"$'\n' in *$'\n'"DNS:$h"$'\n'*) ;; *) return 1 ;; esac
  a="$(openssl x509 -in "$crt" -noout -pubkey 2>/dev/null)" || return 1
  b="$(openssl pkey -in "$key" -pubout 2>/dev/null)" || return 1
  [ -n "$a" ] && [ "$a" = "$b" ]
}

# Per-name outcome of the last `certs` run (none = fine): "dns: ..." (skipped,
# no CA call) or "acme: ..." (lego failed). The agent shows it.
host_note() {
  install -d -m 0700 "$HOSTS_DIR"
  printf '%s\n' "$2" > "$HOSTS_DIR/$1.error"
}

# 0 while the last lego run for $1 failed less than NETRUN_HTTPS_ACME_RETRY_MIN
# (60) minutes ago: at most one failed validation per name and hour (Let's
# Encrypt allows 5). Delete the .error file to retry at once.
host_acme_backoff() {
  local f="$HOSTS_DIR/$1.error" min
  min="$(netrun_setting NETRUN_HTTPS_ACME_RETRY_MIN 60)"
  case "$min" in ''|*[!0-9]*) min=60 ;; esac
  [ "$min" -gt 0 ] && [ -f "$f" ] || return 1
  [ "$(head -c 5 "$f")" = "acme:" ] || return 1
  [ -z "$(find "$f" -mmin +"$min" 2>/dev/null)" ]
}

lego_obtain_host() {
  install -d -m 0700 "$LEGO_DIR"
  lego run --path "$LEGO_DIR" --accept-tos --domains "$1" --http --no-random-sleep >/dev/null
}

# The ACME step of `certs` (call it under the ACME lock, outside the sync
# lock): `lego run` for every listed name that points here and needs it.
# Returns 1 when a lego run failed (or a name still backs off) — after
# trying every name; a name pointing elsewhere is not a failure.
certs_obtain() {
  local ip="$1" h addrs days crt errf rc failed=0
  [ -n "$ip" ] || { log "ERROR: cannot detect the public IPv4 — no hostname certificate"; return 1; }
  days="$(netrun_setting NETRUN_HTTPS_HOST_RENEW_DAYS 30)"
  case "$days" in ''|*[!0-9]*) days=30 ;; esac
  for h in $(https_hostnames); do
    addrs="$(resolve_ipv4 "$h" | tr '\n' ' ')"
    addrs="${addrs% }"
    if [ "$addrs" != "$ip" ]; then
      log "skip $h: its A record is ${addrs:-missing}, not $ip — not sent to the CA"
      host_note "$h" "dns: A ${addrs:-missing}, not $ip"
      continue
    fi
    crt="$LEGO_DIR/certificates/$h.crt"
    if host_cert_ok "$h" "$crt" "$LEGO_DIR/certificates/$h.key" $((days * 86400)); then
      rm -f "$HOSTS_DIR/$h.error"
      continue
    fi
    if host_acme_backoff "$h"; then
      log "skip $h: its last ACME attempt failed less than $(netrun_setting NETRUN_HTTPS_ACME_RETRY_MIN 60) min ago"
      failed=1
      continue
    fi
    errf="$(mktemp)"
    if lego_obtain_host "$h" 2>"$errf"; then
      rm -f "$HOSTS_DIR/$h.error"
      log "certificate for $h obtained / renewed"
    else
      rc=$?
      cat "$errf" >&2 || true
      host_note "$h" "acme: lego exit $rc: $(tail -n 1 "$errf" | cut -c1-300)"
      log "WARNING: lego failed for $h (exit $rc) — the other names go on"
      failed=1
    fi
    rm -f "$errf"
  done
  return "$failed"
}

# Under the sync lock: $HOSTS_DIR/<name>.pem for every listed name with a
# valid certificate (rewritten only when the content differs), and no PEM (or
# .error) of a name no longer listed.
build_host_pems() {
  local h pem keep=" " crt key
  install -d -m 0700 "$HOSTS_DIR"
  for h in $(https_hostnames); do
    keep="$keep$h "
    crt="$LEGO_DIR/certificates/$h.crt"
    key="$LEGO_DIR/certificates/$h.key"
    [ -s "$crt" ] || continue
    if ! host_cert_ok "$h" "$crt" "$key"; then
      log "WARNING: $crt is expired, not for $h or not its key's — not served"
      continue
    fi
    pem="$HOSTS_DIR/$h.pem"
    (umask 077 && cat "$crt" "$key" > "$pem.tmp")
    if cmp -s "$pem.tmp" "$pem"; then
      rm -f "$pem.tmp"
    else
      mv -f "$pem.tmp" "$pem"
      log "certificate of $h installed"
    fi
  done
  for pem in "$HOSTS_DIR"/*.pem; do
    [ -e "$pem" ] || continue
    h="$(basename "$pem" .pem)"
    case "$keep" in
      *" $h "*) ;;
      *) rm -f "$pem" "$HOSTS_DIR/$h.error"; log "certificate of $h removed (no longer listed)" ;;
    esac
  done
  for pem in "$HOSTS_DIR"/*.error; do
    [ -e "$pem" ] || continue
    h="$(basename "$pem" .error)"
    case "$keep" in *" $h "*) ;; *) rm -f "$pem" ;; esac
  done
}

# The crt-list of the TLS terminator: the IP certificate FIRST — haproxy's
# default for a client without SNI (IP clients send none) or with an SNI no
# line names — then `<pem> <name>` for every listed name whose PEM is in place
# and valid. Always leaves a crt-list (at least the IP line) behind: the base
# config names it, so it must exist before any `haproxy -c` / reload. With
# "ip-only": the IP line alone. Replaced atomically, only when it differs.
write_crt_list() {
  local h pem
  install -d -m 0700 "$TLS_DIR"
  {
    printf '%s\n' "$PEM"
    if [ "${1:-}" != ip-only ]; then
      for h in $(https_hostnames); do
        pem="$HOSTS_DIR/$h.pem"
        if host_cert_ok "$h" "$pem"; then printf '%s %s\n' "$pem" "$h"; fi
      done
    fi
  } > "$CRT_LIST.tmp"
  if cmp -s "$CRT_LIST.tmp" "$CRT_LIST"; then
    rm -f "$CRT_LIST.tmp"
  else
    mv -f "$CRT_LIST.tmp" "$CRT_LIST"
  fi
}

# The hostname PEMs named by the crt-list (the IP PEM is hashed on its own).
crt_list_pems() {
  awk -v pem="$PEM" '$1 != "" && $1 !~ /^#/ && $1 != pem { print $1 }' "$CRT_LIST" 2>/dev/null || true
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

# The base config. Audit FO-08 — the TLS terminator loads the crt-list (the IP
# certificate first = the default, then the hostname certificates by SNI).
base_config_text() {
  cat <<EOF
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
    bind abns@netrun_tls accept-proxy ssl crt-list ${CRT_LIST} alpn http/1.1
    no log
    default_backend netrun_local

backend netrun_tls_loop
    server tls abns@netrun_tls send-proxy-v2

backend netrun_local
    server local 127.0.0.1
EOF
}

write_base_config() {
  base_config_text > "$HAPROXY_CFG.tmp"
  mv -f "$HAPROXY_CFG.tmp" "$HAPROXY_CFG"
}

# 0 when haproxy.cfg is exactly what base_config_text gives.
base_config_current() {
  [ -s "$HAPROXY_CFG" ] && base_config_text | cmp -s - "$HAPROXY_CFG"
}

# cmd_sync: (re)write haproxy.cfg when it differs from base_config_text — so
# an existing node moves from `crt node.pem` to the crt-list on its next sync.
# A file of ours is replaced only once haproxy accepts the new one with the
# live frontends (a rejected one never goes live: the running haproxy, the
# next reload and the next boot keep the old); a missing or foreign file is
# written as before. 0 when it was written. Needs the crt-list (write_crt_list).
update_base_config() {
  if [ -s "$HAPROXY_CFG" ] && grep -q "netrun-https" "$HAPROXY_CFG"; then
    install -d -m 0755 "$FRONTEND_DIR"
    base_config_text > "$HAPROXY_CFG.new"
    if ! haproxy_check "$FRONTEND_DIR" "$HAPROXY_CFG.new"; then
      rm -f "$HAPROXY_CFG.new"
      log "WARNING: haproxy rejects the new base config — $HAPROXY_CFG left as it was"
      return 1
    fi
    mv -f "$HAPROXY_CFG.new" "$HAPROXY_CFG"
  else
    write_base_config
  fi
  log "base config written ($HAPROXY_CFG)"
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

# `haproxy -c` of the base config ($2, default haproxy.cfg) + a frontend
# directory. The base config names the crt-list: write_crt_list first.
haproxy_check() {
  haproxy -c -q -f "${2:-$HAPROXY_CFG}" -f "$1"
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

# sha256 over haproxy.cfg, the certificate, the crt-list and every hostname
# PEM it names (FO-08), and the sorted frontend files (names + contents): the
# files a reload makes haproxy load.
haproxy_config_hash() {
  local f
  {
    # shellcheck disable=SC2046
    for f in "$HAPROXY_CFG" "$PEM" "$CRT_LIST" $(crt_list_pems); do
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
  # Audit FO-08 — the crt-list before anything runs `haproxy -c` (the base
  # config names it); a name dropped from the list leaves it here already.
  write_crt_list
  if ! base_config_current && update_base_config; then
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

# renew: the ACME exchange without the sync lock (it can take minutes when the
# CA is slow, and a /generate's sync must not wait on it) but under the ACME
# lock, then the PEM swap + reload + stamp under the sync lock. Audit FO-08 —
# the hostname certificates ride along: same ACME step (after the IP one, also
# when that failed), same apply step (one reload for both). Exits non-zero
# when the IP renewal or a hostname's lego run failed.
cmd_renew() {
  local rc=0
  with_acme_lock renew_obtain || rc=$?
  with_sync_lock cmd_renew_apply
  return "$rc"
}

renew_obtain() {
  local rc=0
  lego_obtain || rc=$?
  [ "$rc" = 0 ] || log "WARNING: IP certificate renewal failed (exit $rc)"
  certs_obtain "$(public_ipv4)" || rc=1
  return "$rc"
}

cmd_renew_apply() {
  certs_apply ip
}

# `certs` (the agent starts it after POST /https/hostnames): the hostname
# certificates alone. A list rewritten while it ran (the agent never starts
# a second run) is picked up by another pass, at most 3 in all.
cmd_certs() {
  local ip rc pass=0 seen
  ip="$(public_ipv4 || true)"
  [ -n "$ip" ] || die "cannot detect the public IPv4"
  while :; do
    rc=0
    seen="$(cat "$HOSTNAMES_FILE" 2>/dev/null || true)"
    with_acme_lock certs_obtain "$ip" || rc=$?
    with_sync_lock certs_apply
    pass=$((pass + 1))
    [ "$pass" -lt 3 ] && [ "$(cat "$HOSTNAMES_FILE" 2>/dev/null || true)" != "$seen" ] || break
    log "the hostname list changed during the run — one more pass"
  done
  return "$rc"
}

# Under the sync lock: the IP PEM (with "ip": renew), the hostname PEMs and
# the crt-list; haproxy is reloaded only when one of them changed — and then
# only once `haproxy -c` accepts them. A hostname set haproxy rejects is
# dropped (crt-list back to the IP line alone, hostname PEMs deleted; returns
# 1) so the 5-min sync never trips over it; the next `certs` rebuilds them
# from lego's files.
certs_apply() {
  local ip before rc=0
  ip="$(public_ipv4)"
  before="$(haproxy_config_hash)"
  [ "${1:-}" != ip ] || build_pem "$ip"
  build_host_pems
  write_crt_list
  if [ "$(haproxy_config_hash)" = "$before" ]; then
    return 0
  fi
  if ! systemctl is-active --quiet haproxy; then
    log "certificates changed; haproxy is not running (the next sync starts it)"
    return 0
  fi
  if ! haproxy_check "$FRONTEND_DIR"; then
    log "ERROR: haproxy rejects the hostname certificates — serving the IP certificate alone"
    rm -f "$HOSTS_DIR"/*.pem
    write_crt_list ip-only
    haproxy_check "$FRONTEND_DIR" || die "haproxy config check failed"
    rc=1
    [ "$(haproxy_config_hash)" != "$before" ] || return "$rc"
  fi
  systemctl reload haproxy
  # The stamp covers the certificates: an unverified reload here is retried
  # by the next sync.
  if verify_frontends_listening "$ip"; then stamp_write "$(haproxy_config_hash)"; fi
  log "certificates changed, haproxy reloaded"
  return "$rc"
}

# sync / renew's apply step / certs' apply step / setup one at a time
# (generator, timers, agent, /deprovision). NETRUN_HTTPS_LOCK_WAIT_SEC (300):
# in-line callers pass less.
with_sync_lock() {
  if command -v flock >/dev/null 2>&1; then
    mkdir -p "$(dirname "$SYNC_LOCK")" 2>/dev/null || true
    exec 9>"$SYNC_LOCK"
    flock -w "${NETRUN_HTTPS_LOCK_WAIT_SEC:-300}" 9 || die "another netrun-https run still holds $SYNC_LOCK"
  fi
  "$@"
}

# Audit FO-08 — one HTTP-01 client on :80 at a time (the IP renewal, hostname
# issuance; never under the sync lock, which may be held around this one by
# setup only — so no lock-order cycle). A subshell holds fd 8: the lock goes
# with it, and nothing started later (3proxy, haproxy) can inherit it.
# NETRUN_HTTPS_ACME_LOCK_WAIT_SEC (1800).
with_acme_lock() {
  if ! command -v flock >/dev/null 2>&1; then
    "$@"
    return
  fi
  mkdir -p "$(dirname "$ACME_LOCK")" 2>/dev/null || true
  (
    flock -w "${NETRUN_HTTPS_ACME_LOCK_WAIT_SEC:-1800}" 8 || die "another ACME run still holds $ACME_LOCK"
    "$@"
  ) 8>"$ACME_LOCK"
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
  # Audit FO-08 — hostname certificates (SNI) and the crt-list haproxy loads.
  local h pem
  for h in $(https_hostnames); do
    pem="$HOSTS_DIR/$h.pem"
    if [ -s "$pem" ]; then
      echo "host cert : $h $(openssl x509 -in "$pem" -noout -enddate 2>/dev/null)$(grep -qxF "$pem $h" "$CRT_LIST" 2>/dev/null || echo ' (not in the crt-list)')"
    else
      echo "host cert : $h none$( [ -s "$HOSTS_DIR/$h.error" ] && printf ' — %s' "$(cat "$HOSTS_DIR/$h.error")")"
    fi
  done
  echo "crt-list  : $( [ -s "$CRT_LIST" ] && wc -l < "$CRT_LIST" | tr -d ' ' || echo 0) line(s)$(grep -q 'ssl crt-list' "$HAPROXY_CFG" 2>/dev/null || echo ' — haproxy.cfg not migrated yet (next sync)')"
  echo "frontends : $(ls "$FRONTEND_DIR"/*.cfg 2>/dev/null | wc -l)"
  echo "3proxy http on public ip : $(cat "$PROXY_DIR"/3proxy_*.cfg 2>/dev/null | grep -cE "^proxy .* -i${ip//./\\.}[[:space:]]" || true)"
  echo "3proxy http on 127.0.0.1 : $(cat "$PROXY_DIR"/3proxy_*.cfg 2>/dev/null | grep -cE '^proxy .* -i127\.0\.0\.1[[:space:]]' || true)"
}

case "${1:-}" in
  setup) with_sync_lock cmd_setup ;;
  sync) with_sync_lock cmd_sync ;;
  renew) cmd_renew ;;
  certs) cmd_certs ;;
  status) cmd_status ;;
  accounting) fix_accounting ;;
  units) cmd_units ;;
  *) echo "usage: $0 {setup|sync|renew|certs|status|accounting|units}" >&2; exit 2 ;;
esac
