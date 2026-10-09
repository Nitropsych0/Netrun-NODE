#!/usr/bin/env bash
# NETRUN per-GB: netrun-radius against a real 3proxy, end to end, in a throwaway
# Linux network namespace (plan §7 P1; lane L1). Nothing outside the namespace is
# touched: no host routes, no nft, no systemd units, no ports on the host.
#
#   sudo scripts/test_pergb_radius_e2e.sh [--bin PATH] [--out DIR] [--keep]
#
# Binary: --bin, else $PERGB_3PROXY_BIN, else deploy/node/bin/3proxy-pergb,
# else /opt/netrun/pergb/bin/3proxy-pergb, else the stock deploy/node/bin/3proxy
# (the stock binary leaks its auth cache, which does not matter for this test).
#
# Inside the namespace: the per-GB /48 (2001:db8:aa::/48) is a local route on lo
# like on a node, targets 2001:db8:ffff::1 and 10.200.0.1 answer with the source
# address they see, the egress IPv4 is 10.200.0.2; netrun-radius runs under a
# socket-activation stand-in (tests/sockact.py) that keeps 127.0.0.1:1812 open
# across restarts, as systemd does.
#
# Checks (tests/e2e_driver.py): accept/reject, NAS-Port -> slot, Framed-IPv6 per
# connection, sticky, static across a restart and a crash, IPv4 Framed, a per-piece
# list (A13-I: its fixed address in its own /64, IPv4 from the primary IPv4, no
# -session/-rotate), ipv6_only reject, the probe login, a hung RADIUS = SINGLEBYTE_L then reject, restarts
# under load with no failed connection; then real Access-Requests are captured
# to $OUT/3proxy_captured.json (fixture for tests/test_proto.py).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RADIUS_DIR="$REPO/node_runtime/radius"
OUT="${OUT:-$REPO/.e2e-out}"
BIN="${PERGB_3PROXY_BIN:-}"
KEEP=0
BASE=31000
COUNT=4
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "e2e: $*" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || die "Linux only (network namespaces)"
[[ $EUID -eq 0 ]] || die "run as root (ip netns)"
command -v ip >/dev/null || die "iproute2 missing"
command -v python3 >/dev/null || die "python3 missing"

if [[ -z "$BIN" ]]; then
  for c in "$REPO/deploy/node/bin/3proxy-pergb" /opt/netrun/pergb/bin/3proxy-pergb "$REPO/deploy/node/bin/3proxy"; do
    if [[ -x "$c" ]]; then BIN="$c"; break; fi
  done
fi
[[ -n "$BIN" && -x "$BIN" ]] || die "no 3proxy binary (use --bin)"
case "$BIN" in
  */3proxy-pergb) AUTHCACHE="authcache none" ;;
  *) echo "e2e: WARNING: stock 3proxy ($BIN), not the per-GB build" >&2; AUTHCACHE="" ;;
esac

NS="nrrad-e2e-$$"
WORK="$(mktemp -d /tmp/nrrad-e2e.XXXXXX)"
mkdir -p "$OUT" "$WORK/log" "$WORK/state"
chmod 0755 "$WORK"
SOCKACT_PID=""
PROXY_PID=""

cleanup() {
  local rc=$?
  set +e
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null
  [[ -n "$SOCKACT_PID" ]] && kill "$SOCKACT_PID" 2>/dev/null
  sleep 0.5
  ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  cp -f "$WORK"/radius.log "$WORK"/3proxy.out "$OUT"/ 2>/dev/null
  cp -rf "$WORK/log" "$OUT/3proxy-log" 2>/dev/null
  if [[ $KEEP -eq 0 ]]; then rm -rf "$WORK"; else echo "e2e: kept $WORK"; fi
  exit $rc
}
trap cleanup EXIT

nsx() { ip netns exec "$NS" "$@"; }

echo "e2e: namespace $NS, binary $BIN, work $WORK"
ip netns add "$NS"
nsx ip link set lo up
nsx ip addr add 10.200.0.1/32 dev lo          # IPv4 target
nsx ip addr add 10.200.0.2/32 dev lo          # egress IPv4
nsx ip -6 addr add 2001:db8:ffff::1/128 dev lo nodad   # IPv6 target
nsx ip -6 route replace local 2001:db8:aa::/48 dev lo   # the per-GB /48, as on a node
nsx sysctl -qw net.ipv6.ip_nonlocal_bind=1 || true

SECRET="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)"
printf '%s\n' "$SECRET" >"$WORK/radius.secret"
chmod 0600 "$WORK/radius.secret"

# 3proxy cfg in the I4 layout (golden cfg of pergb_runtime.js, scaled down to $COUNT ports)
LAST=$((BASE + COUNT - 1))
CFG="$WORK/pergb_${BASE}.cfg"
{
  echo "# netrun-pergb v1 sp=$BASE first=$BASE last=$LAST ipv4=10.200.0.2 — test_pergb_radius_e2e.sh"
  echo "nserver 127.0.0.1"
  echo "nserver ::1"
  echo "timeouts 1 3 30 60 180 1800 15 60"
  echo "log $WORK/log/p${BASE}.log H"
  echo 'logformat "- +_G%Y%m%d%H%M%S.%. %N %p %E %U %C %c %i %e %R %r %I %O %n"'
  echo "logdump 262144 262144"
  if [[ -n "$AUTHCACHE" ]]; then echo "$AUTHCACHE"; fi
  echo "radius $SECRET 127.0.0.1"
  echo "auth radius"
  echo "deny * * * 25,465,587"
  echo "allow *"
  for ((p = BASE; p <= LAST; p++)); do
    if [[ $p -eq $BASE ]]; then echo "maxconn 20000"; elif [[ $p -eq $((BASE + 1)) ]]; then echo "maxconn 2000"; fi
    echo "socks -64 -a -p$p -i127.0.0.4 -e10.200.0.2 -e::1"
    echo "proxy -64 -n -a -p$p -i127.0.0.3 -e10.200.0.2 -e::1"
  done
} >"$CFG"

# netrun-radius under the socket-activation stand-in
nsx python3 -I "$RADIUS_DIR/tests/sockact.py" --listen 127.0.0.1:1812 --pidfile "$WORK/sockact.pid" -- \
  python3 -I "$RADIUS_DIR/netrun_radius.py" --state-dir "$WORK/state" --secret-file "$WORK/radius.secret" \
  --ctl-socket "$WORK/ctl.sock" --no-watchdog >"$WORK/radius.log" 2>&1 &
for _ in $(seq 1 100); do [[ -s "$WORK/sockact.pid" && -S "$WORK/ctl.sock" ]] && break; sleep 0.1; done
[[ -S "$WORK/ctl.sock" ]] || { cat "$WORK/radius.log" >&2; die "netrun-radius did not start"; }
SOCKACT_PID="$(cat "$WORK/sockact.pid")"

nsx "$BIN" "$CFG" >"$WORK/3proxy.out" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 50); do
  if nsx bash -c "exec 3<>/dev/tcp/127.0.0.4/$BASE" 2>/dev/null; then break; fi
  sleep 0.1
done
kill -0 "$PROXY_PID" 2>/dev/null || { cat "$WORK/3proxy.out" >&2; die "3proxy did not start"; }

set +e
nsx python3 -I "$RADIUS_DIR/tests/e2e_driver.py" --ctl "$WORK/ctl.sock" --sockact-pid "$SOCKACT_PID" \
  --secret-file "$WORK/radius.secret" --base "$BASE" --count "$COUNT" --out "$OUT"
RC=$?
set -e
echo "e2e: radius log tail:"; tail -n 20 "$WORK/radius.log" || true
if [[ $RC -ne 0 ]]; then
  echo "e2e: FAILED (driver rc=$RC)" >&2
  echo "--- 3proxy output" >&2; tail -n 40 "$WORK/3proxy.out" >&2 || true
  exit "$RC"
fi
echo "e2e: PASS"
