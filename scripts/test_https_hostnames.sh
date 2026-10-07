#!/usr/bin/env bash
# Audit FO-08 — netrun-https hostname certificates (SNI): the hostname list,
# the DNS gate (no CA call for a name that does not point here), one failing
# name never stopping the others, the crt-list (IP certificate first), stale
# PEM removal, reload only on a change, the base-config migration to the
# crt-list, and renew calling the hostname step. lego / haproxy / systemctl /
# getent / ip are stubs on PATH; certificates are real (openssl, self-signed).
# Part 1 sources the script's functions; part 2 runs the script itself
# (set -euo pipefail for real); part 3 (when a real haproxy is found:
# NETRUN_TEST_HAPROXY=<path>, else `haproxy` on PATH) checks the crt-list and
# a rejected hostname certificate with the real `haproxy -c`. No root needed.
#   bash scripts/test_https_hostnames.sh
#   NETRUN_TEST_HAPROXY=/opt/homebrew/opt/haproxy@2.8/bin/haproxy bash scripts/test_https_hostnames.sh
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
REAL_HAPROXY="${NETRUN_TEST_HAPROXY:-$(command -v haproxy 2>/dev/null || true)}"

# ── stubs ─────────────────────────────────────────────────────────
STUB="$TMP/bin"; mkdir -p "$STUB"
export STUB_LOG="$TMP/calls.log" DNS_MAP="$TMP/dns.map"
: > "$STUB_LOG"; : > "$DNS_MAP"
# lego: logs the call; LEGO_FAIL names fail like a refused HTTP-01; LEGO_NOOP
# names exit 0 leaving the files alone (lego 5 `run` deciding "not due"); an
# IP gets dummy files, a hostname a real self-signed certificate (LEGO_DAYS,
# 90). LEGO_LOCKCHECK=1: logs whether the sync lock is free while it runs;
# LEGO_ADD="<dom> <name>": the call for <dom> appends <name> to the list.
cat > "$STUB/lego" <<'EOF'
#!/usr/bin/env bash
echo "lego $*" >> "$STUB_LOG"
path="" dom=""
while [ $# -gt 0 ]; do
  case "$1" in --path) path="$2"; shift ;; --domains) dom="$2"; shift ;; esac
  shift
done
if [ "${LEGO_LOCKCHECK:-0}" = 1 ]; then
  if flock -n "$NETRUN_HTTPS_SYNC_LOCK" true; then echo "lock $dom free" >> "$STUB_LOG"; else echo "lock $dom held" >> "$STUB_LOG"; fi
fi
if [ -n "${LEGO_ADD:-}" ] && [ "${LEGO_ADD%% *}" = "$dom" ]; then echo "${LEGO_ADD#* }" >> "$NETRUN_HTTPS_HOSTNAMES_FILE"; fi
case " ${LEGO_FAIL:-} " in *" $dom "*)
  echo "[ERROR] acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: $dom: invalid response" >&2; exit 1 ;;
esac
case " ${LEGO_NOOP:-} " in *" $dom "*) exit 0 ;; esac
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
# by a -f config (or a PEM it names) is missing — as the real check does —
# or when a crt-list line names a host listed in $HAPROXY_REJECT_NAMES (one
# per line: "ee key too small", as haproxy says of an RSA-512 key).
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
      while read -r p n; do
        [ -n "$n" ] && [ -s "$HAPROXY_REJECT_NAMES" ] && grep -qxF "$n" "$HAPROXY_REJECT_NAMES" || continue
        echo "[ALERT]    (1) : config : parsing [$2:30] : 'bind abns@netrun_tls' in section 'frontend' : 'crt-list' : error processing line 2 in file '$l' : unable to load SSL certificate into SSL Context '$p': ee key too small."
        exit 1
      done < "$l"
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
export PATH="$STUB:$PATH" HAPROXY_REJECT="$TMP/haproxy.reject" HAPROXY_REJECT_NAMES="$TMP/haproxy.reject-names"
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
    NETRUN_HTTPS_SYNC_LOCK="$d/run/sync.lock" NETRUN_HTTPS_APPLIED_STAMP="$d/run/applied.sha" \
    NETRUN_HTTPS_HAPROXY_CFG="$d/haproxy.cfg" NETRUN_HTTPS_FRONTEND_DIR="$d/netrun.d"
  mkdir -p "$d/tls" "$d/lego/certificates"
  printf 'IPCERT 0\nIPKEY\n' > "$d/tls/node.pem"
  : > "$STUB_LOG"; : > "$DNS_MAP"; rm -f "$HAPROXY_REJECT" "$HAPROXY_REJECT_NAMES"
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
  grep -q '^acme: lego exit 1: .*unauthorized' "$HOSTS_DIR/c.example.com.acme-failed" || { echo "no ACME failure time"; exit 1; }
  grep -qx 'certificate for a.example.com obtained' "$D/log" || { cat "$D/log"; exit 1; }
  # Again at once: a is fresh (no CA call), c waits out its backoff — and a
  # name ONLY waiting is not a failure (renew's unit must not show "failed").
  : > "$STUB_LOG"
  certs_obtain "$IP" || { echo "a name only in its retry backoff failed certs_obtain"; exit 1; }
  [ "$(lego_calls a.example.com)" = 0 ] || { echo "a fresh certificate was renewed"; exit 1; }
  [ "$(lego_calls c.example.com)" = 0 ] || { echo "backoff ignored"; exit 1; }
  grep -q 'skip c.example.com: its last ACME attempt failed .*(backoff)' "$D/log" || exit 1
  # A "dns:" note in between never resets the ACME backoff (review nit): c's A
  # record flaps away and back; the note changes, the failure time stays.
  : > "$DNS_MAP"; dns a.example.com "$IP"; dns c.example.com 9.9.9.9
  certs_obtain "$IP" || exit 1
  grep -q '^dns: A 9.9.9.9' "$HOSTS_DIR/c.example.com.error" && [ -e "$HOSTS_DIR/c.example.com.acme-failed" ] || exit 1
  : > "$DNS_MAP"; dns a.example.com "$IP"; dns c.example.com "$IP"; : > "$STUB_LOG"
  certs_obtain "$IP" || exit 1
  [ "$(lego_calls c.example.com)" = 0 ] || { echo "a dns: note reset the ACME backoff"; exit 1; }
  NETRUN_HTTPS_ACME_RETRY_MIN=0 certs_obtain "$IP" 2>/dev/null; [ "$(lego_calls c.example.com)" = 1 ] || exit 1
  # c fixed + backoff over: obtained, its note and failure time gone, certs_obtain succeeds.
  unset LEGO_FAIL; touch -t 202001010000 "$HOSTS_DIR/c.example.com.acme-failed"; : > "$STUB_LOG"
  printf '%s\n' a.example.com c.example.com > "$HOSTNAMES_FILE"
  certs_obtain "$IP" || { echo "all good now"; exit 1; }
  [ "$(lego_calls c.example.com)" = 1 ] && [ ! -e "$HOSTS_DIR/c.example.com.error" ] && [ ! -e "$HOSTS_DIR/c.example.com.acme-failed" ] || exit 1
  # Renewal window: a certificate within NETRUN_HTTPS_HOST_RENEW_DAYS goes to
  # lego; what is logged is what happened to the file (lego 5 `run` decides).
  mkcert a.example.com "$LEGO_DIR/certificates/a.example.com" 20; : > "$STUB_LOG"; : > "$D/log"
  certs_obtain "$IP"; [ "$(lego_calls a.example.com)" = 1 ] || { echo "a 20-day certificate was not renewed"; exit 1; }
  grep -qx 'certificate for a.example.com renewed' "$D/log" || { cat "$D/log"; exit 1; }
  mkcert a.example.com "$LEGO_DIR/certificates/a.example.com" 20; : > "$STUB_LOG"; : > "$D/log"
  LEGO_NOOP=a.example.com certs_obtain "$IP" || exit 1
  [ "$(lego_calls a.example.com)" = 1 ] || exit 1
  grep -qx "lego left the certificate of a.example.com unchanged (not due by lego's own rules)" "$D/log" && ! grep -q 'renewed\|obtained' "$D/log" \
    || { cat "$D/log"; echo "lego did nothing but the log says obtained / renewed"; exit 1; }
) || fail "ACME step"
ok "ACME step: a name whose A record is not exactly the node IPv4 never reaches lego; one failing name never stops the others; fresh certs skipped; failed names back off (not a failure; a dns: note never resets it); obtained / renewed / unchanged logged from the file"

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
  # served.json (review): after the verified reload, the names whose lines
  # haproxy loaded, with each PEM's sha256 and the stamp.
  served_has() { grep -qF "{\"hostname\": \"$1\", \"pem\": \"$HOSTS_DIR/$1.pem\", \"sha256\": \"$(file_sha256 "$HOSTS_DIR/$1.pem")\"}" "$SERVED"; }
  served_has a.example.com && served_has c.example.com && ! grep -q f.example.com "$SERVED" || { cat "$SERVED"; echo "served.json"; exit 1; }
  [ "$(served_stamp)" = "$(cat "$APPLIED_STAMP")" ] && grep -q '"crtListBound": true' "$SERVED" || { cat "$SERVED"; exit 1; }
  if command -v node >/dev/null 2>&1; then node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$SERVED" || { echo "served.json is not JSON"; exit 1; }; fi
  # Unchanged: no reload, PEM untouched.
  touch -t 202001010000 "$HOSTS_DIR/a.example.com.pem"
  certs_apply; [ "$(reloads)" = 1 ] || { echo "unchanged apply reloaded"; exit 1; }
  [ -z "$(find "$HOSTS_DIR/a.example.com.pem" -newer "$CRT_LIST")" ] || { echo "PEM rewritten"; exit 1; }
  # A renewed certificate (same name): PEM rewritten, one reload, served.json follows.
  old_sha="$(file_sha256 "$HOSTS_DIR/a.example.com.pem")"
  mkcert a.example.com "$LEGO_DIR/certificates/a.example.com"; certs_apply
  [ "$(reloads)" = 2 ] || { echo "a renewed PEM did not reload"; exit 1; }
  served_has a.example.com && ! grep -q "$old_sha" "$SERVED" || { cat "$SERVED"; echo "served.json not rewritten"; exit 1; }
  # The stamp covers every PEM of the crt-list: a PEM swapped behind its back differs.
  want="$(haproxy_config_hash)"; cp "$HOSTS_DIR/c.example.com.pem" "$D/c.bak"; echo "# x" >> "$HOSTS_DIR/c.example.com.pem"
  [ "$(haproxy_config_hash)" != "$want" ] || { echo "the stamp does not cover the hostname PEMs"; exit 1; }
  cp "$D/c.bak" "$HOSTS_DIR/c.example.com.pem"
  # A name dropped from the list: its PEM goes, the crt-list shrinks, one reload.
  printf '%s\n' c.example.com > "$HOSTNAMES_FILE"; certs_apply
  [ ! -e "$HOSTS_DIR/a.example.com.pem" ] || exit 1
  [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/c.example.com.pem c.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
  [ "$(reloads)" = 3 ] || exit 1
  # haproxy stopped: files written, no reload (the next sync starts it); what
  # haproxy serves is unknown until then: no served.json.
  rm -f "$HOSTNAMES_FILE"; HAPROXY_UP=0 certs_apply; [ "$(reloads)" = 3 ] || exit 1
  [ "$(cat "$CRT_LIST")" = "$PEM" ] && [ -z "$(ls "$HOSTS_DIR"/*.pem 2>/dev/null)" ] || exit 1
  [ ! -e "$SERVED" ] || { echo "served.json kept while haproxy is down"; exit 1; }
  # haproxy rejects ONE hostname certificate (review fix 4): only that line goes
  # (PEM deleted, "haproxy: rejected: <reason>" noted), the others stay; the
  # apply fails (exit 1) but still reloads with the good ones.
  printf '%s\n' a.example.com c.example.com > "$HOSTNAMES_FILE"
  echo c.example.com > "$HAPROXY_REJECT_NAMES"
  : > "$STUB_LOG"; : > "$D/log"
  if certs_apply; then echo "a rejected hostname certificate must fail the apply"; exit 1; fi
  [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/a.example.com.pem a.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
  [ -e "$HOSTS_DIR/a.example.com.pem" ] && [ ! -e "$HOSTS_DIR/c.example.com.pem" ] || { ls "$HOSTS_DIR"; exit 1; }
  [ "$(cat "$HOSTS_DIR/c.example.com.error")" = "haproxy: rejected: ee key too small." ] || { cat "$HOSTS_DIR/c.example.com.error"; exit 1; }
  grep -q 'ERROR: haproxy rejects the certificate of c.example.com (ee key too small.)' "$D/log" || { cat "$D/log"; exit 1; }
  [ "$(reloads)" = 1 ] && served_has a.example.com && ! grep -q c.example.com "$SERVED" || { cat "$STUB_LOG"; exit 1; }
  # The next apply rebuilds c's PEM from lego's files and checks it again: still
  # rejected -> nothing changed, no reload.
  : > "$STUB_LOG"
  if certs_apply; then echo "still rejected"; exit 1; fi
  [ "$(reloads)" = 0 ] && [ ! -e "$HOSTS_DIR/c.example.com.pem" ] || { cat "$STUB_LOG"; exit 1; }
  # haproxy NOT running (review fix 1): the crt-list is still checked — a
  # rejected PEM never stays in it while haproxy is down.
  rm -f "$HAPROXY_REJECT_NAMES"; mkcert a.example.com "$LEGO_DIR/certificates/a.example.com"; HAPROXY_UP=0 certs_apply || exit 1
  [ "$(wc -l < "$CRT_LIST" | tr -d ' ')" = 3 ] || { cat "$CRT_LIST"; exit 1; }
  echo a.example.com > "$HAPROXY_REJECT_NAMES"; mkcert a.example.com "$LEGO_DIR/certificates/a.example.com"
  : > "$STUB_LOG"
  if HAPROXY_UP=0 certs_apply; then echo "a rejected certificate must fail the apply (haproxy down)"; exit 1; fi
  [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/c.example.com.pem c.example.com|" ] || { cat "$CRT_LIST"; echo "rejected PEM left in the crt-list while haproxy is down"; exit 1; }
  grep -q '^haproxy -c' "$STUB_LOG" && [ "$(reloads)" = 0 ] || { cat "$STUB_LOG"; exit 1; }
  grep -q '^haproxy: rejected' "$HOSTS_DIR/a.example.com.error" || exit 1
) || fail "apply step"
ok "apply step: crt-list = IP certificate first, then '<pem> <name>' per valid listed name; PEMs 0600; stale / foreign PEMs dropped; stamp covers every PEM; reload only on a change; served.json after a verified reload; a certificate haproxy rejects drops only its own line (noted), also with haproxy down"

# ── 4. lock placement: lego under the ACME lock only, apply under the sync lock only ──
(
  fresh locks; load
  printf '%s\n' a.example.com > "$HOSTNAMES_FILE"; dns a.example.com "$IP"
  CALLS="$D/calls"
  lego_obtain() { echo "ip-lego acme=${ACME:-0} sync=${SYNC:-0}" >> "$CALLS"; return "${IP_FAIL:-0}"; }
  # (a file appears, as after a real `lego run`; not a valid certificate: every pass asks again)
  lego_obtain_host() { echo "host-lego $1 acme=${ACME:-0} sync=${SYNC:-0}" >> "$CALLS"; mkdir -p "$LEGO_DIR/certificates"; echo "$1" > "$LEGO_DIR/certificates/$1.crt"; }
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
  lego_obtain_host() { echo "host-lego $1" >> "$CALLS"; echo "$1" > "$LEGO_DIR/certificates/$1.crt"; [ "$1" != a.example.com ] || printf '%s\n' a.example.com b.example.com > "$HOSTNAMES_FILE"; }
  dns b.example.com "$IP"; : > "$CALLS"; cmd_certs || exit 1
  [ "$(grep -c '^apply' "$CALLS")" = 2 ] && grep -q '^host-lego b.example.com' "$CALLS" || { cat "$CALLS"; exit 1; }
  # Each pass records the list it worked through (the agent compares it with the file).
  [ "$(tr '\n' ' ' < "$CERTS_APPLIED")" = "a.example.com b.example.com " ] || { cat "$CERTS_APPLIED"; exit 1; }
  rm -f "$HOSTNAMES_FILE"; cmd_certs || exit 1; [ ! -s "$CERTS_APPLIED" ] || exit 1
  # A failing apply (a rejected certificate) fails certs / renew, the other passes still run.
  certs_apply() { echo "apply ${1:-hosts}" >> "$CALLS"; return 1; }
  if cmd_certs; then echo "a failed apply must fail certs"; exit 1; fi
  if cmd_renew; then echo "a failed apply must fail renew"; exit 1; fi
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
    # The sync lock (review fix 2): it used to stay held by the shell's fd 9
    # after the command returned — `certs` ran lego holding it from pass 2 on.
    sync_held() { ! flock -n "$SYNC_LOCK" true; }
    with_sync_lock sync_held || { echo "sync lock not held inside"; exit 1; }
    flock -n "$SYNC_LOCK" true || { echo "sync lock still held after with_sync_lock returned"; exit 1; }
    [ ! -e /proc/self/fd/9 ] || { echo "fd 9 leaked into the caller"; exit 1; }
    # Its status comes back (a failing apply fails the run).
    if with_sync_lock false; then echo "with_sync_lock lost the status"; exit 1; fi
  ) || fail "with_acme_lock / with_sync_lock"
  ok "with_acme_lock / with_sync_lock: flock held inside, released after (fd 8 / 9 never left open), status passed on"
fi

# ── 6. sync: crt-list before any haproxy -c; base config migrated to the crt-list ──
(
  fresh sync; load
  NETRUN_HTTPS_RELOAD_MAX_AGE_H=0
  PROXY_DIR="$D/3proxy"; mkdir -p "$PROXY_DIR"
  printf 'socks -6 -a -p18100 -i45.32.10.20 -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\n' > "$PROXY_DIR/3proxy_18100.cfg"
  fix_accounting() { :; }; restart_cfg() { :; }
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
  # (e) review fix 8 — openssl merely FAILING keeps a line already in the
  # crt-list (no reload, no flap) and does not add a new one; an EXPIRED
  # certificate (a verdict) drops its line, one reload.
  printf '%s\n' a.example.com > "$HOSTNAMES_FILE"; cmd_sync; [ "$(reloads)" = 6 ] && [ "$(wc -l < "$CRT_LIST" | tr -d ' ')" = 2 ] || exit 1
  ( pem_expired() { return 2; }; cmd_sync ) || exit 1
  [ "$(reloads)" = 6 ] && [ "$(sed -n 2p "$CRT_LIST")" = "$HOSTS_DIR/a.example.com.pem a.example.com" ] || { cat "$CRT_LIST"; echo "an openssl error dropped a line"; exit 1; }
  grep -q 'cannot read the certificate of a.example.com (openssl failed) — its crt-list line kept' "$D/log" || { cat "$D/log"; exit 1; }
  printf '%s\n' a.example.com b.example.com > "$HOSTNAMES_FILE"; mkcert b.example.com "$D/b"; cat "$D/b.crt" "$D/b.key" > "$HOSTS_DIR/b.example.com.pem"
  ( pem_expired() { return 2; }; cmd_sync ) || exit 1
  [ "$(reloads)" = 6 ] && ! grep -q b.example.com "$CRT_LIST" || { cat "$CRT_LIST"; echo "a line added on an openssl error"; exit 1; }
  cmd_sync; [ "$(reloads)" = 7 ] && grep -q '^.*b.example.com.pem b.example.com$' "$CRT_LIST" || exit 1
  ( pem_expired() { [ "$1" = "$HOSTS_DIR/b.example.com.pem" ] && return 0; return 1; }; cmd_sync ) || exit 1
  [ "$(reloads)" = 8 ] && ! grep -q b.example.com "$CRT_LIST" || { cat "$CRT_LIST"; echo "an expired certificate kept"; exit 1; }
  grep -q 'the certificate of b.example.com has expired — dropped from the crt-list' "$D/log" || exit 1
  # pem_expired itself: a verdict from openssl, 2 when it cannot tell.
  pem_expired "$HOSTS_DIR/a.example.com.pem"; [ $? = 1 ] || exit 1
  pem_expired "$HOSTS_DIR/a.example.com.pem" $((200 * 86400)); [ $? = 0 ] || exit 1
  echo garbage > "$D/garbage.pem"; pem_expired "$D/garbage.pem"; [ $? = 2 ] || exit 1
  # ... also with an openssl that prints no verdict (LibreSSL): the exit status, confirmed.
  ( openssl() { local rc; command openssl "$@" > "$D/o" 2>/dev/null; rc=$?; grep -v 'Certificate will' "$D/o"; return "$rc"; }
    pem_expired "$HOSTS_DIR/a.example.com.pem"; [ $? = 1 ] || exit 1
    pem_expired "$HOSTS_DIR/a.example.com.pem" $((200 * 86400)); [ $? = 0 ] || exit 1
    pem_expired "$D/garbage.pem"; [ $? = 2 ] ) || { echo "pem_expired without a printed verdict"; exit 1; }
  # (f) review fix 1 — a PEM haproxy rejects already in the crt-list (left by
  # the old certs_apply while haproxy was down): the sync drops that line
  # alone and STARTS haproxy instead of dying on "config check failed".
  printf '%s\n' a.example.com b.example.com > "$HOSTNAMES_FILE"; echo b.example.com > "$HAPROXY_REJECT_NAMES"
  printf '%s\n%s\n%s\n' "$PEM" "$HOSTS_DIR/a.example.com.pem a.example.com" "$HOSTS_DIR/b.example.com.pem b.example.com" > "$CRT_LIST"
  ( pem_expired() { return 1; }; HAPROXY_UP=0 cmd_sync ) || { cat "$D/log"; echo "a rejected hostname PEM blocked the sync"; exit 1; }
  grep -q '^systemctl enable --now haproxy' "$STUB_LOG" || { cat "$STUB_LOG"; echo "haproxy not started"; exit 1; }
  [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/a.example.com.pem a.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
  grep -q '^haproxy: rejected: ee key too small' "$HOSTS_DIR/b.example.com.error" && [ ! -e "$HOSTS_DIR/b.example.com.pem" ] || exit 1
  # (g) the full check fails only WITH hostname lines although each passes on
  # its own: retried once with the IP line alone (logged loudly), stamped for
  # what haproxy really loaded; when even that fails, the crt-list is restored.
  rm -f "$HAPROXY_REJECT_NAMES"
  ( haproxy_check() { haproxy -c -q -f "${2:-$HAPROXY_CFG}" -f "$1" && [ "$(wc -l < "$CRT_LIST" | tr -d ' ')" = 1 ]; }
    rm -f "$APPLIED_STAMP"   # one reload due
    cmd_sync ) || { cat "$D/log"; exit 1; }
  [ "$(cat "$CRT_LIST")" = "$PEM" ] && [ "$(cat "$APPLIED_STAMP")" = "$(haproxy_config_hash)" ] || { cat "$CRT_LIST"; exit 1; }
  grep -q 'ERROR: haproxy -c passes only with the IP certificate alone' "$D/log" || exit 1
  printf '%s\n%s\n' "$PEM" "$HOSTS_DIR/a.example.com.pem a.example.com" > "$CRT_LIST"
  ( haproxy_check() { return 1; }; haproxy_check_crt "$FRONTEND_DIR" ) && exit 1
  [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/a.example.com.pem a.example.com|" ] || { cat "$CRT_LIST"; echo "crt-list not restored"; exit 1; }
  [ -e "$HOSTS_DIR/a.example.com.pem" ] || { echo "a PEM haproxy accepts was deleted"; exit 1; }
) || fail "sync: base config migration"
ok "sync: crt-list written before any haproxy -c; base config migrated to 'ssl crt-list' (validated first, one reload, then quiet); hand edits converge; listed PEMs join / leave the crt-list; an openssl error keeps a line (expired drops it); a rejected PEM never blocks the sync or haproxy's start; IP-only retry of the full check"

# ── 6b. setup (review fix 5): the crt-list exists before the base config that names it ──
(
  fresh setup; load
  SELF="$D/sbin-netrun-https"   # never the host's /usr/local/sbin copy
  CALLS="$D/calls"; : > "$CALLS"
  issue_or_renew() { echo issue >> "$CALLS"; }
  cmd_sync() { echo sync >> "$CALLS"; }
  install_units() { echo units >> "$CALLS"; }
  rm -f "$CRT_LIST"
  eval "orig_$(declare -f write_base_config)"
  write_base_config() { if [ -s "$CRT_LIST" ]; then echo "base crt-list=yes" >> "$CALLS"; else echo "base crt-list=no" >> "$CALLS"; fi; orig_write_base_config; }
  cmd_setup > /dev/null || exit 1
  [ "$(tr '\n' ' ' < "$CALLS")" = "base crt-list=yes issue sync units " ] || { cat "$CALLS"; exit 1; }
  [ "$(cat "$CRT_LIST")" = "$PEM" ] && base_config_current || exit 1
) || fail "setup: crt-list before the base config"
ok "setup: the crt-list is written before the base config that names it"

# ── 7. the script itself (set -euo pipefail): certs, renew, status ──
fresh e2e
(. "$TMP/lib.sh"; base_config_text > "$NETRUN_HTTPS_HAPROXY_CFG")
printf '%s\n' a.example.com b.example.com c.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"
dns a.example.com "$IP"; dns b.example.com 9.9.9.9; dns c.example.com "$IP"
export NETRUN_HTTPS_RELOAD_VERIFY=0
sha() { (. "$TMP/lib.sh"; file_sha256 "$1"); }
if LEGO_FAIL=c.example.com bash "$HTTPS" certs > "$D/out" 2>&1; then cat "$D/out"; fail "e2e certs: a failed name must fail the run"; fi
grep -q 'skip b.example.com: its A record is 9.9.9.9' "$D/out" || { cat "$D/out"; fail "e2e certs: DNS skip not logged"; }
[ "$(lego_calls b.example.com)" = 0 ] || fail "e2e certs: lego called for a name pointing elsewhere"
[ "$(lego_calls a.example.com)" = 1 ] && [ "$(lego_calls c.example.com)" = 1 ] || fail "e2e certs: lego calls"
[ "$(cat "$D/tls/crt-list" | tr '\n' '|')" = "$D/tls/node.pem|$D/tls/hosts/a.example.com.pem a.example.com|" ] || { cat "$D/tls/crt-list"; fail "e2e certs: crt-list"; }
[ "$(reloads)" = 1 ] || fail "e2e certs: one reload"
grep -qF "{\"hostname\": \"a.example.com\", \"pem\": \"$D/tls/hosts/a.example.com.pem\", \"sha256\": \"$(sha "$D/tls/hosts/a.example.com.pem")\"}" "$D/tls/served.json" \
  || { cat "$D/tls/served.json"; fail "e2e certs: served.json"; }
[ "$(tr '\n' ' ' < "$D/tls/certs-applied")" = "a.example.com b.example.com c.example.com " ] || fail "e2e certs: certs-applied"
: > "$STUB_LOG"
bash "$HTTPS" certs > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e certs: a name only in its retry backoff must not fail the run"; }
grep -q 'skip c.example.com: its last ACME attempt failed' "$D/out" || { cat "$D/out"; fail "e2e certs: backoff not logged"; }
[ "$(reloads)" = 0 ] && [ -z "$(grep '^lego' "$STUB_LOG")" ] || { cat "$STUB_LOG"; fail "e2e certs: an unchanged run must not reload / call the CA"; }
# renew while c only backs off (review fix 9): exit 0 (the unit is not "failed").
LEGO_IP_SERIAL=2 bash "$HTTPS" renew > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e renew: a name in its retry backoff failed renew"; }
grep -q 'IPCERT 2' "$D/tls/node.pem" && [ "$(reloads)" = 1 ] || { cat "$STUB_LOG"; fail "e2e renew (backoff): IP PEM + one reload"; }
# ... but a lego failure in this run still fails it.
rm -f "$D/tls/hosts/c.example.com.acme-failed"
if LEGO_FAIL=c.example.com bash "$HTTPS" renew > "$D/out" 2>&1; then cat "$D/out"; fail "e2e renew: a failed lego run must fail renew"; fi
# renew: IP certificate renewed (new PEM) + hostnames (c dropped); one reload.
printf '%s\n' a.example.com b.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"; : > "$STUB_LOG"
LEGO_IP_SERIAL=3 bash "$HTTPS" renew > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e renew"; }
grep -q -- "--domains $IP --http --profile shortlived" "$STUB_LOG" || fail "e2e renew: IP renewal"
grep -q 'IPCERT 3' "$D/tls/node.pem" || fail "e2e renew: IP PEM not rebuilt"
[ "$(reloads)" = 1 ] || { cat "$STUB_LOG"; fail "e2e renew: one reload"; }
[ "$(lego_calls a.example.com)" = 0 ] && [ "$(lego_calls b.example.com)" = 0 ] || fail "e2e renew: a fresh / elsewhere-pointing name reached lego"
[ ! -e "$D/tls/hosts/c.example.com.error" ] && [ ! -e "$D/tls/hosts/c.example.com.acme-failed" ] || fail "e2e renew: the notes of an unlisted name kept"
[ "$(tr '\n' ' ' < "$D/tls/certs-applied")" = "a.example.com b.example.com " ] || fail "e2e renew: certs-applied"
# renew with no hostname list at all.
rm -f "$NETRUN_HTTPS_HOSTNAMES_FILE"; : > "$STUB_LOG"
LEGO_IP_SERIAL=4 bash "$HTTPS" renew > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e renew without hostnames"; }
[ "$(grep -c '^lego' "$STUB_LOG")" = 1 ] && grep -q 'IPCERT 4' "$D/tls/node.pem" || fail "e2e renew without hostnames: IP only"
[ ! -e "$D/tls/hosts/a.example.com.pem" ] && [ "$(cat "$D/tls/crt-list")" = "$D/tls/node.pem" ] || fail "e2e renew: unlisted PEM kept"
grep -q '"hostnames": \[\]' "$D/tls/served.json" || { cat "$D/tls/served.json"; fail "e2e renew: served.json still lists a name"; }
# Review fix 2 — the sync lock is FREE while lego runs on certs' second pass
# (it used to stay held from the first apply on: lego under the sync lock).
if command -v flock >/dev/null 2>&1; then
  printf '%s\n' a.example.com d.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"; dns d.example.com "$IP"; dns e.example.com "$IP"; : > "$STUB_LOG"
  LEGO_LOCKCHECK=1 LEGO_ADD="d.example.com e.example.com" bash "$HTTPS" certs > "$D/out" 2>&1 || { cat "$D/out"; fail "e2e certs: two passes"; }
  grep -q 'the hostname list changed during the run — one more pass' "$D/out" && [ "$(lego_calls e.example.com)" = 1 ] || { cat "$D/out"; fail "e2e certs: no second pass"; }
  grep -qx 'lock e.example.com free' "$STUB_LOG" || { cat "$STUB_LOG"; fail "e2e certs: lego ran holding the sync lock on pass 2"; }
  ! grep -q '^lock .* held' "$STUB_LOG" || { cat "$STUB_LOG"; fail "e2e certs: sync lock held during lego"; }
fi
# status lists the hostname certificates and what is served.
printf '%s\n' a.example.com b.example.com > "$NETRUN_HTTPS_HOSTNAMES_FILE"
bash "$HTTPS" certs > /dev/null 2>&1 || fail "e2e certs: a again"
mkdir -p "$D/proxy"; mkcert ip.example "$D/ipc"; cat "$D/ipc.crt" "$D/ipc.key" > "$D/tls/node.pem"
NETRUN_PROXY_DIR="$D/proxy" bash "$HTTPS" status > "$D/status" 2>&1 || { cat "$D/status"; fail "e2e status"; }
grep -q '^host cert : a.example.com notAfter=' "$D/status" && grep -q '^host cert : b.example.com none — dns: A 9.9.9.9' "$D/status" \
  && grep -q '^crt-list  : 2 line(s)' "$D/status" && grep -q '^served    : a.example.com (verified reload ' "$D/status" || { cat "$D/status"; fail "e2e status"; }
ok "script: certs (DNS skip, failing name, crt-list, one reload, served.json, certs-applied, quiet re-run, backoff = exit 0), renew (IP + hostnames, one reload; backoff = exit 0, lego failure = exit 1; IP-only without a list), sync lock free while lego runs on pass 2, status"

# ── 8. real `haproxy -c` (review): the crt-list loads; a certificate haproxy ──
# rejects (RSA-512: "ee key too small") drops only its own line, with haproxy
# down too, and never blocks the sync / haproxy's start. Skipped without a
# real haproxy (NETRUN_TEST_HAPROXY=<path>, else `haproxy` on the PATH).
if [ -n "$REAL_HAPROXY" ] && [ "$REAL_HAPROXY" != "$STUB/haproxy" ] && "$REAL_HAPROXY" -v >/dev/null 2>&1; then
  (
    fresh real; load
    haproxy() { "$REAL_HAPROXY" "$@"; }
    # A test box is not root: no `user` / `group` (haproxy -c resolves them).
    eval "orig_$(declare -f base_config_text)"
    base_config_text() { orig_base_config_text | grep -vE '^ +(user|group) haproxy$'; }
    NETRUN_HTTPS_RELOAD_MAX_AGE_H=0
    PROXY_DIR="$D/3proxy"; mkdir -p "$PROXY_DIR"
    printf 'socks -6 -a -p18100 -i%s -e2001:db8::1\nproxy -6 -n -a -p8100 -i127.0.0.1 -e2001:db8::1\n' "$IP" > "$PROXY_DIR/3proxy_18100.cfg"
    fix_accounting() { :; }; restart_cfg() { :; }; verify_frontends_listening() { return 0; }
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$D/ip.key" -out "$D/ip.crt" -days 6 \
      -subj "/CN=$IP" -addext "subjectAltName=IP:$IP" >/dev/null 2>&1 || exit 1
    cat "$D/ip.crt" "$D/ip.key" > "$PEM"
    mkcert a.example.com "$LEGO_DIR/certificates/a.example.com"
    openssl req -x509 -newkey rsa:512 -nodes -keyout "$LEGO_DIR/certificates/w.example.com.key" -out "$LEGO_DIR/certificates/w.example.com.crt" \
      -days 90 -subj /CN=w.example.com -addext subjectAltName=DNS:w.example.com >/dev/null 2>&1 || { echo "SKIP: no RSA-512 key here"; exit 0; }
    host_cert_ok w.example.com "$LEGO_DIR/certificates/w.example.com.crt" "$LEGO_DIR/certificates/w.example.com.key" || { echo "openssl refuses the RSA-512 certificate"; exit 1; }
    cat "$LEGO_DIR/certificates/w.example.com.crt" "$LEGO_DIR/certificates/w.example.com.key" > "$D/w.pem"
    printf '%s\n%s\n' "$PEM" "$D/w.pem w.example.com" > "$D/probe"
    if crt_list_check "$D/probe"; then echo "SKIP: this haproxy / OpenSSL accepts RSA-512"; exit 0; fi
    crt_list_check "$D/probe" "$D/probe.out"; grep -q 'ee key too small' "$D/probe.out" || { cat "$D/probe.out"; exit 1; }
    # First setup on this box: the base config + frontends, haproxy down.
    printf '%s\n' a.example.com w.example.com > "$HOSTNAMES_FILE"
    write_crt_list; write_base_config
    HAPROXY_UP=0 cmd_sync || { cat "$D/log"; echo "first sync"; exit 1; }
    # certs' apply with haproxy DOWN (review fix 1): w checked anyway, dropped alone.
    : > "$STUB_LOG"
    if HAPROXY_UP=0 certs_apply; then echo "a rejected certificate must fail the apply"; exit 1; fi
    [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/a.example.com.pem a.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
    [ ! -e "$HOSTS_DIR/w.example.com.pem" ] && grep -q '^haproxy: rejected: .*ee key too small' "$HOSTS_DIR/w.example.com.error" || { cat "$HOSTS_DIR/w.example.com.error"; exit 1; }
    "$REAL_HAPROXY" -c -q -f "$HAPROXY_CFG" -f "$FRONTEND_DIR" || { echo "the real config does not pass haproxy -c"; exit 1; }
    grep -qx "    bind abns@netrun_tls accept-proxy ssl crt-list $CRT_LIST alpn http/1.1" "$HAPROXY_CFG" || exit 1
    # The state the old code could leave (w's line in the crt-list, haproxy
    # down): the sync drops it and starts haproxy instead of dying.
    cp "$D/w.pem" "$HOSTS_DIR/w.example.com.pem"
    printf '%s\n%s\n%s\n' "$PEM" "$HOSTS_DIR/a.example.com.pem a.example.com" "$HOSTS_DIR/w.example.com.pem w.example.com" > "$CRT_LIST"
    "$REAL_HAPROXY" -c -q -f "$HAPROXY_CFG" -f "$FRONTEND_DIR" 2>/dev/null && { echo "the bad crt-list passes haproxy -c?"; exit 1; }
    : > "$STUB_LOG"
    HAPROXY_UP=0 cmd_sync || { cat "$D/log"; echo "a rejected hostname PEM blocked the sync (real haproxy)"; exit 1; }
    grep -q '^systemctl enable --now haproxy' "$STUB_LOG" || { cat "$STUB_LOG"; exit 1; }
    [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/a.example.com.pem a.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
    "$REAL_HAPROXY" -c -q -f "$HAPROXY_CFG" -f "$FRONTEND_DIR" || exit 1
    # A good second name joins (a, b): the IP line first, both by SNI, haproxy -c passes.
    mkcert b.example.com "$LEGO_DIR/certificates/b.example.com"
    printf '%s\n' a.example.com b.example.com > "$HOSTNAMES_FILE"
    certs_apply || { cat "$D/log"; exit 1; }
    [ "$(cat "$CRT_LIST" | tr '\n' '|')" = "$PEM|$HOSTS_DIR/a.example.com.pem a.example.com|$HOSTS_DIR/b.example.com.pem b.example.com|" ] || { cat "$CRT_LIST"; exit 1; }
    "$REAL_HAPROXY" -c -q -f "$HAPROXY_CFG" -f "$FRONTEND_DIR" || exit 1
    echo "($("$REAL_HAPROXY" -v | head -n 1 | cut -c1-40))"
  ) || fail "real haproxy -c ($REAL_HAPROXY)"
  ok "real haproxy -c: crt-list (IP first, '<pem> <name>' per name) loads; an RSA-512 hostname certificate is dropped alone (noted), with haproxy down too; the sync recovers a crt-list holding it and starts haproxy"
else
  echo "skip: no real haproxy (NETRUN_TEST_HAPROXY) — section 8"
fi

# A fresh box's unattended-upgrades holds the dpkg lock at first boot: every
# apt-get in the setup waits for it (Johannesburg, 2026-10-08: HTTPS setup failed).
apt_lines="$(grep -E '^[^#]*apt-get ' "$HTTPS" || true)"
[ -n "$apt_lines" ] || fail "netrun-https.sh: no apt-get found (test out of date?)"
if printf '%s\n' "$apt_lines" | grep -v 'DPkg::Lock::Timeout' | grep -q .; then
  printf '%s\n' "$apt_lines"; fail "netrun-https.sh: apt-get without -o DPkg::Lock::Timeout"
fi
ok "setup: every apt-get waits for the dpkg lock (unattended-upgrades at first boot)"

echo "test_https_hostnames.sh — all $PASS checks passed"
