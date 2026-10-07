#!/usr/bin/env bash
# Audit FO-08 — netrun-https hostname certificates (SNI): the hostname list,
# the DNS gate (no CA call for a name that does not point here), one failing
# name never stopping the others, the crt-list (IP certificate first), stale
# PEM removal, reload only on a change, the base-config migration to the
# crt-list, and renew calling the hostname step. lego / haproxy / systemctl /
# getent / ip are stubs on PATH; certificates are real (openssl, self-signed).
# Part 1 sources the script's functions; part 2 runs the script itself
# (set -euo pipefail for real). No root needed.
#   bash scripts/test_https_hostnames.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
HTTPS="$ROOT_DIR/scripts/netrun-https.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

command -v openssl >/dev/null 2>&1 || { echo "SKIP: no openssl"; exit 0; }
bash -n "$HTTPS" || fail "bash -n netrun-https.sh"

# ── stubs ─────────────────────────────────────────────────────────
STUB="$TMP/bin"; mkdir -p "$STUB"
export STUB_LOG="$TMP/calls.log" DNS_MAP="$TMP/dns.map"
: > "$STUB_LOG"; : > "$DNS_MAP"
# lego: logs the call; LEGO_FAIL names fail like a refused HTTP-01; an IP gets
# dummy files, a hostname a real self-signed certificate (LEGO_DAYS, 90).
cat > "$STUB/lego" <<'EOF'
#!/usr/bin/env bash
echo "lego $*" >> "$STUB_LOG"
path="" dom=""
while [ $# -gt 0 ]; do
  case "$1" in --path) path="$2"; shift ;; --domains) dom="$2"; shift ;; esac
  shift
done
case " ${LEGO_FAIL:-} " in *" $dom "*)
  echo "[ERROR] acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: $dom: invalid response" >&2; exit 1 ;;
esac
mkdir -p "$path/certificates"
if [[ "$dom" =~ ^[0-9.]+$ ]]; then
  printf 'IPCERT %s\n' "${LEGO_IP_SERIAL:-1}" > "$path/certificates/$dom.crt"
  echo IPKEY > "$path/certificates/$dom.key"
  exit 0
fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$path/certificates/$dom.key" -out "$path/certificates/$dom.crt" -days "${LEGO_DAYS:-90}" \
  -subj "/CN=$dom" -addext "subjectAltName=DNS:$dom" >/dev/null 2>&1
EOF
# getent ahostsv4 <name>: "<name> <ip>" lines of $DNS_MAP (exit 2 = not found).
cat > "$STUB/getent" <<'EOF'
#!/usr/bin/env bash
[ "$1" = ahostsv4 ] || exit 2
awk -v h="$2" '$1 == h { print $2 "       STREAM " h; print $2 "       DGRAM"; f = 1 } END { exit f ? 0 : 2 }' "$DNS_MAP"
EOF
# haproxy -c: fails when $TMP/haproxy.reject exists, or when a crt-list named
# by a -f config (or a PEM it names) is missing — as the real check does.
cat > "$STUB/haproxy" <<'EOF'
#!/usr/bin/env bash
echo "haproxy $*" >> "$STUB_LOG"
[ ! -e "$HAPROXY_REJECT" ] || exit 1
while [ $# -gt 0 ]; do
  if [ "$1" = -f ] && [ -f "$2" ]; then
    l="$(awk '{ for (i = 1; i < NF; i++) if ($i == "crt-list") print $(i + 1) }' "$2")"
    if [ -n "$l" ]; then
      [ -s "$l" ] || { echo "crt-list $l missing" >&2; exit 1; }
      for p in $(awk '{ print $1 }' "$l"); do [ -s "$p" ] || exit 1; done
    fi
  fi
  shift
done
exit 0
EOF
cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
case "$1" in is-active) [ "${HAPROXY_UP:-1}" = 1 ] ;; *) exit 0 ;; esac
EOF
printf '#!/bin/sh\necho "1.1.1.1 via 10.0.0.1 dev eth0 src 45.32.10.20 uid 0"\n' > "$STUB/ip"
chmod +x "$STUB"/*
export PATH="$STUB:$PATH" HAPROXY_REJECT="$TMP/haproxy.reject"
export NETRUN_ENV_FILE="$TMP/no-netrun.env"   # hermetic: no host /etc/netrun/netrun.env

IP=45.32.10.20
dns() { printf '%s %s\n' "$1" "$2" >> "$DNS_MAP"; }
lego_calls() { grep -c "^lego run .*--domains $1 " "$STUB_LOG" || true; }
reloads() { grep -c '^systemctl reload haproxy' "$STUB_LOG" || true; }
# Self-signed certificate for $1 (SAN DNS:$1) -> $2.crt / $2.key, $3 days.
mkcert() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$2.key" -out "$2.crt" \
    -days "${3:-90}" -subj "/CN=$1" -addext "subjectAltName=DNS:$1" >/dev/null 2>&1 || fail "openssl req"
}

# The script's functions and settings, without its dispatch.
sed '/^case "\${1:-}" in/,$d' "$HTTPS" > "$TMP/lib.sh"
grep -q '^cmd_certs() {' "$TMP/lib.sh" || fail "netrun-https: cmd_certs missing"

# Fresh paths per group.
fresh() {
  local d="$TMP/$1"
  rm -rf "$d"; mkdir -p "$d/etc" "$d/run" "$d/netrun.d"
  export NETRUN_HTTPS_TLS_DIR="$d/tls" NETRUN_HTTPS_LEGO_DIR="$d/lego" \
    NETRUN_HTTPS_HOSTNAMES_FILE="$d/etc/https-hostnames" NETRUN_HTTPS_ACME_LOCK="$d/run/acme.lock" \
    NETRUN_HTTPS_SYNC_LOCK="$d/run/sync.lock" NETRUN_HTTPS_APPLIED_STAMP="$d/run/applied.sha"
  mkdir -p "$d/tls" "$d/lego/certificates"
  printf 'IPCERT 0\nIPKEY\n' > "$d/tls/node.pem"
  : > "$STUB_LOG"; : > "$DNS_MAP"; rm -f "$HAPROXY_REJECT"
  D="$d"
}
# Source the functions with the fresh paths; haproxy.cfg / frontends in $D.
load() {
  # shellcheck disable=SC1090
  . "$TMP/lib.sh"
  set +e
  HAPROXY_CFG="$D/haproxy.cfg"; FRONTEND_DIR="$D/netrun.d"
  log() { printf '%s\n' "$*" >> "$D/log"; }
  NETRUN_HTTPS_RELOAD_VERIFY=0
}

# ── 1. the hostname list ──────────────────────────────────────────
(
  fresh list; load
  long="$(printf 'a%.0s' $(seq 1 64)).example.com"
  printf '%s\n' 'US1.Proxy.Netrun.lol' 'us1.proxy.netrun.lol' '1.2.3.4' '*.x.com' 'bad..name.com' '-bad.com' \
    'ok-2.example.com' '  spaced.example.org ' "$long" '# comment' 'bad_name.com' 'x.com.' 'xn--p1ai.xn--p1ai' > "$HOSTNAMES_FILE"
  got="$(https_hostnames | tr '\n' ' ')"
  [ "$got" = "us1.proxy.netrun.lol ok-2.example.com spaced.example.org xn--p1ai.xn--p1ai " ] || { echo "got: $got"; exit 1; }
  rm -f "$HOSTNAMES_FILE"; [ -z "$(https_hostnames)" ] || exit 1
  # resolve_ipv4: sorted unique A records; nothing (and success) when unknown.
  dns a.example.com 9.9.9.9; dns a.example.com "$IP"
  [ "$(resolve_ipv4 a.example.com | tr '\n' ' ')" = "$IP 9.9.9.9 " ] || exit 1
  resolve_ipv4 nope.example.com > "$D/out" || exit 1
  [ ! -s "$D/out" ] || exit 1
) || fail "hostname list: lowercase FQDNs only (no IP / wildcard / bad label), deduplicated; resolve_ipv4"
ok "hostname list: lowercase FQDNs, deduplicated, IPs / wildcards / bad labels dropped; resolve_ipv4 never fails"

# ── 2. ACME step: DNS gate, one failure never stops the others, backoff ──
(
  fresh obtain; load
  printf '%s\n' a.example.com b.example.com c.example.com d.example.com e.example.com > "$HOSTNAMES_FILE"
  dns a.example.com "$IP"; dns b.example.com 9.9.9.9; dns c.example.com "$IP"
  dns d.example.com "$IP"; dns d.example.com 9.9.9.9          # round robin: not only here
  export LEGO_FAIL="c.example.com"
  if certs_obtain "$IP" 2>/dev/null; then echo "a failed lego run must make certs_obtain fail"; exit 1; fi
  for h in b d e; do [ "$(lego_calls $h.example.com)" = 0 ] || { echo "CA called for $h (DNS not here)"; exit 1; }; done
  [ "$(lego_calls a.example.com)" = 1 ] && [ "$(lego_calls c.example.com)" = 1 ] || { cat "$STUB_LOG"; exit 1; }
  # c came before d / e and failed: they were still looked at (b, d, e notes).
  grep -q '^dns: A 9.9.9.9, not 45.32.10.20$' "$HOSTS_DIR/b.example.com.error" || exit 1
  grep -q "^dns: A $IP 9.9.9.9, not $IP\$" "$HOSTS_DIR/d.example.com.error" || exit 1
  grep -q '^dns: A missing' "$HOSTS_DIR/e.example.com.error" || exit 1
  grep -q '^acme: lego exit 1: .*unauthorized' "$HOSTS_DIR/c.example.com.error" || { cat "$HOSTS_DIR/c.example.com.error"; exit 1; }
  [ ! -e "$HOSTS_DIR/a.example.com.error" ] || exit 1
  grep -q -- '--domains a.example.com --http --no-random-sleep' "$STUB_LOG" || exit 1
  ! grep -q 'a.example.com.*--profile' "$STUB_LOG" || { echo "hostnames use the default profile"; exit 1; }
  # Again at once: a is fresh (no CA call), c waits out its backoff.
  : > "$STUB_LOG"
  certs_obtain "$IP" && { echo "c still fails"; exit 1; }
  [ "$(lego_calls a.example.com)" = 0 ] || { echo "a fresh certificate was renewed"; exit 1; }
  [ "$(lego_calls c.example.com)" = 0 ] || { echo "backoff ignored"; exit 1; }
  NETRUN_HTTPS_ACME_RETRY_MIN=0 certs_obtain "$IP" 2>/dev/null; [ "$(lego_calls c.example.com)" = 1 ] || exit 1
  # c fixed + backoff over: obtained, its note gone, certs_obtain succeeds.
  unset LEGO_FAIL; touch -t 202001010000 "$HOSTS_DIR/c.example.com.error"; : > "$STUB_LOG"
  printf '%s\n' a.example.com c.example.com > "$HOSTNAMES_FILE"
  certs_obtain "$IP" || { echo "all good now"; exit 1; }
  [ "$(lego_calls c.example.com)" = 1 ] && [ ! -e "$HOSTS_DIR/c.example.com.error" ] || exit 1
  # Renewal window: a certificate within NETRUN_HTTPS_HOST_RENEW_DAYS is renewed.
  mkcert a.example.com "$LEGO_DIR/certificates/a.example.com" 20; : > "$STUB_LOG"
  certs_obtain "$IP"; [ "$(lego_calls a.example.com)" = 1 ] || { echo "a 20-day certificate was not renewed"; exit 1; }
) || fail "ACME step"
ok "ACME step: a name whose A record is not exactly the node IPv4 never reaches lego; one failing name never stops the others; fresh certs skipped; failed names back off"

# ── 3. apply step: crt-list (IP first), PEMs 0600, stale removal, reload only on change ──
(
  fresh apply; load
  base_config_text > "$HAPROXY_CFG"
  printf '%s\n' a.example.com c.example.com f.example.com > "$HOSTNAMES_FILE"
  mkcert a.example.com "$LEGO_DIR/certificates/a.example.com"
  mkcert c.example.com "$LEGO_DIR/certificates/c.example.com"
  mkcert other.example.com "$LEGO_DIR/certificates/f.example.com"   # not for f: never served
  mkdir -p "$HOSTS_DIR"; mkcert zzz.example.com "$TMP/zzz"; cat "$TMP/zzz.crt" "$TMP/zzz.key" > "$HOSTS_DIR/zzz.example.com.pem"
  echo "dns: x" > "$HOSTS_DIR/zzz.example.com.error"
  certs_apply || exit 1
  printf '%s\n' "$PEM" "$HOSTS_DIR/a.example.com.pem a.example.com" "$HOSTS_DIR/c.example.com.pem c.example.com" > "$D/want"
  cmp -s "$D/want" "$CRT_LIST" || { cat "$CRT_LIST"; echo "crt-list"; exit 1; }
  [ "$(head -n 1 "$CRT_LIST")" = "$PEM" ] || exit 1
  [ ! -e "$HOSTS_DIR/f.example.com.pem" ] || { echo "a certificate for another name was served"; exit 1; }
  [ ! -e "$HOSTS_DIR/zzz.example.com.pem" ] && [ ! -e "$HOSTS_DIR/zzz.example.com.error" ] || { echo "stale PEM kept"; exit 1; }
  [ "$(ls -l "$HOSTS_DIR/a.example.com.pem" | cut -c1-10)" = "-rw-------" ] || { ls -l "$HOSTS_DIR"; exit 1; }
  cmp -s "$HOSTS_DIR/a.example.com.pem" <(cat "$LEGO_DIR/certificates/a.example.com.crt" "$LEGO_DIR/certificates/a.example.com.key") || exit 1
  [ "$(reloads)" = 1 ] || { cat "$STUB_LOG"; echo "first apply must reload once"; exit 1; }
  [ "$(cat "$APPLIED_STAMP")" = "$(haproxy_config_hash)" ] || { echo "stamp"; exit 1; }
  grep -q '^haproxy -c -q' "$STUB_LOG" || { echo "no haproxy -c before the reload"; exit 1; }
  # Unchanged: no reload, PEM untouched.
  touch -t 202001010000 "$HOSTS_DIR/a.example.com.pem"
  certs_apply; [ "$(reloads)" = 1 ] || { echo "unchanged apply reloaded"; exit 1; }
  [ -z "$(find "$HOSTS_DIR/a.example.com.pem" -newer "$CRT_LIST")" ] || { echo "PEM rewritten"; exit 1; }
  # A renewed certificate (same name): PEM rewritten, one reload.
  mkcert a.example.com "$LEGO_DIR/certificates/a.example.com"; certs_apply
  [ "$(reloads)" = 2 ] || { echo "a renewed PEM did not reload"; exit 1; }
  # The stamp covers every PEM of the crt-list: a PEM swapped behind its back differs.
  want="$(haproxy_config_hash)"; cp "$HOSTS_DIR/c.example.com.pem" "$D/c.bak"; echo "# x" >> "$HOSTS_DIR/c.example.com.pem"
  [ "$(haproxy_config_hash)" != "$want" ] || { echo "the stamp does not cover the hostname PEMs"; exit 1; }
  cp "$D/c.bak" "$HOSTS_DIR/c.example.com.pem"
  # A name dropped from the list: its PEM goes, the crt-list shrinks, one reload.
  printf '%s\n' c.example.com > "$HOSTNAMES_FILE"; certs_apply
  [ ! -e "$HOSTS_DIR/a.example.com.pem" ] || exit 1
  [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/c.example.com.pem c.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
  [ "$(reloads)" = 3 ] || exit 1
  # haproxy stopped: files written, no reload (the next sync starts it).
  rm -f "$HOSTNAMES_FILE"; HAPROXY_UP=0 certs_apply; [ "$(reloads)" = 3 ] || exit 1
  [ "$(cat "$CRT_LIST")" = "$PEM" ] && [ -z "$(ls "$HOSTS_DIR"/*.pem 2>/dev/null)" ] || exit 1
  # haproxy rejects the hostname set: IP line alone, hostname PEMs gone, still reloaded.
  printf '%s\n' c.example.com > "$HOSTNAMES_FILE"
  : > "$STUB_LOG"
  haproxy() { echo "haproxy $*" >> "$STUB_LOG"; [ "$(wc -l < "$CRT_LIST" | tr -d ' ')" = 1 ]; }
  if certs_apply; then echo "a rejected hostname set must fail the apply"; exit 1; fi
  [ "$(cat "$CRT_LIST")" = "$PEM" ] && [ ! -e "$HOSTS_DIR/c.example.com.pem" ] || { cat "$CRT_LIST"; exit 1; }
  grep -q 'ERROR: haproxy rejects the hostname certificates' "$D/log" || exit 1
  [ "$(reloads)" = 0 ] || { echo "the IP-only list is what haproxy already has"; exit 1; }
  unset -f haproxy
) || fail "apply step"
ok "apply step: crt-list = IP certificate first, then '<pem> <name>' per valid listed name; PEMs 0600; stale / foreign PEMs dropped; stamp covers every PEM; reload only on a change; a rejected set falls back to the IP line"

# ── 4. lock placement: lego under the ACME lock only, apply under the sync lock only ──
(
  fresh locks; load
  printf '%s\n' a.example.com > "$HOSTNAMES_FILE"; dns a.example.com "$IP"
  CALLS="$D/calls"
  lego_obtain() { echo "ip-lego acme=${ACME:-0} sync=${SYNC:-0}" >> "$CALLS"; return "${IP_FAIL:-0}"; }
  lego_obtain_host() { echo "host-lego $1 acme=${ACME:-0} sync=${SYNC:-0}" >> "$CALLS"; }
  certs_apply() { echo "apply ${1:-hosts} acme=${ACME:-0} sync=${SYNC:-0}" >> "$CALLS"; }
  with_acme_lock() { ACME=1 "$@"; }
  with_sync_lock() { SYNC=1 "$@"; }
  : > "$CALLS"; cmd_renew || exit 1
  [ "$(tr '\n' ' ' < "$CALLS")" = "ip-lego acme=1 sync=0 host-lego a.example.com acme=1 sync=0 apply ip acme=0 sync=1 " ] || { cat "$CALLS"; exit 1; }
  # The IP renewal fails: the hostnames are still renewed and applied; renew fails.
  : > "$CALLS"; if IP_FAIL=1 cmd_renew; then echo "renew must fail with the IP renewal"; exit 1; fi
  [ "$(tr '\n' ' ' < "$CALLS")" = "ip-lego acme=1 sync=0 host-lego a.example.com acme=1 sync=0 apply ip acme=0 sync=1 " ] || { cat "$CALLS"; exit 1; }
  # No hostnames: renew is the IP renewal of before.
  rm -f "$HOSTNAMES_FILE"; : > "$CALLS"; cmd_renew || exit 1
  [ "$(tr '\n' ' ' < "$CALLS")" = "ip-lego acme=1 sync=0 apply ip acme=0 sync=1 " ] || { cat "$CALLS"; exit 1; }
  # certs: hostnames only; a list rewritten during the run gets one more pass.
  printf '%s\n' a.example.com > "$HOSTNAMES_FILE"; : > "$CALLS"; cmd_certs || exit 1
  [ "$(tr '\n' ' ' < "$CALLS")" = "host-lego a.example.com acme=1 sync=0 apply hosts acme=0 sync=1 " ] || { cat "$CALLS"; exit 1; }
  lego_obtain_host() { echo "host-lego $1" >> "$CALLS"; [ "$1" != a.example.com ] || printf '%s\n' a.example.com b.example.com > "$HOSTNAMES_FILE"; }
  dns b.example.com "$IP"; : > "$CALLS"; cmd_certs || exit 1
  [ "$(grep -c '^apply' "$CALLS")" = 2 ] && grep -q '^host-lego b.example.com' "$CALLS" || { cat "$CALLS"; exit 1; }
) || fail "lock placement"
grep -qE '^  certs\) cmd_certs ;;' "$HTTPS" || fail "netrun-https: no certs subcommand"
grep -qE '^  renew\) cmd_renew ;;' "$HTTPS" || fail "netrun-https: renew must not take the sync lock around lego"
ok "locks: IP + hostname lego under the ACME lock, outside the sync lock; one apply under the sync lock; renew = IP then hostnames (also when the IP renewal fails); certs re-runs on a list change"

# ── 5. with_acme_lock: held around the command, released after (flock hosts) ──
if command -v flock >/dev/null 2>&1; then
  (
    fresh flock; load
    held() { ! flock -n "$ACME_LOCK" true; }
    with_acme_lock held || { echo "ACME lock not held inside"; exit 1; }
    flock -n "$ACME_LOCK" true || { echo "ACME lock not released"; exit 1; }
    [ ! -e /proc/self/fd/8 ] || { echo "fd 8 leaked into the caller"; exit 1; }
  ) || fail "with_acme_lock"
  ok "with_acme_lock: flock held inside, released after, fd 8 never left open"
fi

# ── 6. sync: crt-list before any haproxy -c; base config migrated to the crt-list ──
(
  fresh sync; load
  NETRUN_HTTPS_RELOAD_MAX_AGE_H=0
  PROXY_DIR="$D/3proxy"; mkdir -p "$PROXY_DIR"
  printf 'socks -6 -a -p18100 -i45.32.10.20 -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\n' > "$PROXY_DIR/3proxy_18100.cfg"
  fix_accounting() { :; }; restart_cfg() { :; }
  reload_haproxy() { haproxy_check "$FRONTEND_DIR" || return 1; echo "systemctl reload haproxy" >> "$STUB_LOG"; }
  verify_frontends_listening() { return 0; }
  # A node set up before FO-08: `crt node.pem`, no crt-list yet.
  base_config_text | sed "s#ssl crt-list $CRT_LIST#ssl crt $PEM#" > "$HAPROXY_CFG"
  grep -q "ssl crt $PEM alpn" "$HAPROXY_CFG" || exit 1
  [ ! -e "$CRT_LIST" ] || exit 1
  # (a) haproxy rejects the new base config: the old one stays, the sync goes on.
  touch "$HAPROXY_REJECT"
  ( write_frontends() { FRONTENDS_CHANGED=0; }; cmd_sync ) || true
  grep -q "ssl crt $PEM alpn" "$HAPROXY_CFG" && [ ! -e "$HAPROXY_CFG.new" ] || { echo "a rejected base config went live"; exit 1; }
  grep -q 'WARNING: haproxy rejects the new base config' "$D/log" || exit 1
  [ "$(cat "$CRT_LIST")" = "$PEM" ] || { echo "no crt-list after a sync"; exit 1; }
  # (b) no crt-list yet: the haproxy stub rejects a config whose crt-list is missing.
  rm -f "$HAPROXY_REJECT" "$CRT_LIST" "$APPLIED_STAMP"; : > "$STUB_LOG"
  #     Migrated: the crt-list exists before the first haproxy -c, then one reload.
  cmd_sync || exit 1
  base_config_current || { diff <(base_config_text) "$HAPROXY_CFG"; exit 1; }
  grep -qx "    bind abns@netrun_tls accept-proxy ssl crt-list $CRT_LIST alpn http/1.1" "$HAPROXY_CFG" || exit 1
  [ "$(cat "$CRT_LIST")" = "$PEM" ] || exit 1
  [ "$(reloads)" = 1 ] || { cat "$STUB_LOG"; exit 1; }
  cmd_sync; [ "$(reloads)" = 1 ] || { echo "a migrated config reloaded again"; exit 1; }
  # (c) a hand-edited managed config converges back (one reload); a missing one is written.
  echo "# hand edit" >> "$HAPROXY_CFG"; cmd_sync; [ "$(reloads)" = 2 ] && base_config_current || exit 1
  rm -f "$HAPROXY_CFG"; cmd_sync; [ "$(reloads)" = 3 ] && base_config_current || exit 1
  # (d) a hostname PEM that appears (certs ran without the lock) reaches the crt-list on the next sync.
  printf '%s\n' a.example.com > "$HOSTNAMES_FILE"; mkcert a.example.com "$D/a"; mkdir -p "$HOSTS_DIR"
  cat "$D/a.crt" "$D/a.key" > "$HOSTS_DIR/a.example.com.pem"
  cmd_sync; [ "$(reloads)" = 4 ] && [ "$(sed -n 2p "$CRT_LIST")" = "$HOSTS_DIR/a.example.com.pem a.example.com" ] || { cat "$CRT_LIST"; exit 1; }
  rm -f "$HOSTNAMES_FILE"; cmd_sync; [ "$(reloads)" = 5 ] && [ "$(cat "$CRT_LIST")" = "$PEM" ] || exit 1
) || fail "sync: base config migration"
ok "sync: crt-list written before any haproxy -c; base config migrated to 'ssl crt-list' (validated first, one reload, then quiet); hand edits converge; listed PEMs join / leave the crt-list"

# ── 7. the script itself (set -euo pipefail): certs, renew, status ──
fresh e2e
printf '%s\n' a.example.com b.example.com c.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"
dns a.example.com "$IP"; dns b.example.com 9.9.9.9; dns c.example.com "$IP"
export NETRUN_HTTPS_RELOAD_VERIFY=0
if LEGO_FAIL=c.example.com bash "$HTTPS" certs > "$D/out" 2>&1; then cat "$D/out"; fail "e2e certs: a failed name must fail the run"; fi
grep -q 'skip b.example.com: its A record is 9.9.9.9' "$D/out" || { cat "$D/out"; fail "e2e certs: DNS skip not logged"; }
[ "$(lego_calls b.example.com)" = 0 ] || fail "e2e certs: lego called for a name pointing elsewhere"
[ "$(lego_calls a.example.com)" = 1 ] && [ "$(lego_calls c.example.com)" = 1 ] || fail "e2e certs: lego calls"
[ "$(cat "$D/tls/crt-list" | tr '\n' '|')" = "$D/tls/node.pem|$D/tls/hosts/a.example.com.pem a.example.com|" ] || { cat "$D/tls/crt-list"; fail "e2e certs: crt-list"; }
[ "$(reloads)" = 1 ] || fail "e2e certs: one reload"
: > "$STUB_LOG"
if bash "$HTTPS" certs > "$D/out" 2>&1; then cat "$D/out"; fail "e2e certs: c still backs off (exit 1)"; fi
grep -q 'skip c.example.com: its last ACME attempt failed' "$D/out" || { cat "$D/out"; fail "e2e certs: backoff not logged"; }
[ "$(reloads)" = 0 ] && [ -z "$(grep '^lego' "$STUB_LOG")" ] || { cat "$STUB_LOG"; fail "e2e certs: an unchanged run must not reload / call the CA"; }
# renew: IP certificate renewed (new PEM) + hostnames (c dropped); one reload.
printf '%s\n' a.example.com b.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"
LEGO_IP_SERIAL=2 bash "$HTTPS" renew > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e renew"; }
grep -q -- "--domains $IP --http --profile shortlived" "$STUB_LOG" || fail "e2e renew: IP renewal"
grep -q 'IPCERT 2' "$D/tls/node.pem" || fail "e2e renew: IP PEM not rebuilt"
[ "$(reloads)" = 1 ] || { cat "$STUB_LOG"; fail "e2e renew: one reload"; }
[ "$(lego_calls a.example.com)" = 0 ] && [ "$(lego_calls b.example.com)" = 0 ] || fail "e2e renew: a fresh / elsewhere-pointing name reached lego"
[ ! -e "$D/tls/hosts/c.example.com.error" ] || fail "e2e renew: the note of an unlisted name kept"
# renew with no hostname list at all.
rm -f "$NETRUN_HTTPS_HOSTNAMES_FILE"; : > "$STUB_LOG"
LEGO_IP_SERIAL=3 bash "$HTTPS" renew > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e renew without hostnames"; }
[ "$(grep -c '^lego' "$STUB_LOG")" = 1 ] && grep -q 'IPCERT 3' "$D/tls/node.pem" || fail "e2e renew without hostnames: IP only"
[ ! -e "$D/tls/hosts/a.example.com.pem" ] && [ "$(cat "$D/tls/crt-list")" = "$D/tls/node.pem" ] || fail "e2e renew: unlisted PEM kept"
# status lists the hostname certificates.
printf '%s\n' a.example.com b.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"
bash "$HTTPS" certs > /dev/null 2>&1 || fail "e2e certs: a again"
mkdir -p "$D/proxy"; mkcert ip.example "$D/ipc"; cat "$D/ipc.crt" "$D/ipc.key" > "$D/tls/node.pem"
NETRUN_PROXY_DIR="$D/proxy" bash "$HTTPS" status > "$D/status" 2>&1 || { cat "$D/status"; fail "e2e status"; }
grep -q '^host cert : a.example.com notAfter=' "$D/status" && grep -q '^host cert : b.example.com none — dns: A 9.9.9.9' "$D/status" \
  && grep -q '^crt-list  : 2 line(s)' "$D/status" || { cat "$D/status"; fail "e2e status"; }
ok "script: certs (DNS skip, failing name, crt-list, one reload, quiet re-run), renew (IP + hostnames, one reload; IP-only without a list), status lists hostname certificates"

echo "test_https_hostnames.sh — all $PASS checks passed"
