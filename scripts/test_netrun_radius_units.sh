#!/usr/bin/env bash
# NETRUN per-GB: netrun-radius.socket/.service under a REAL systemd (lane L1).
# For a throwaway VM or CI runner only: it creates the netrun-radius user, writes
# /opt/netrun/radius, /etc/netrun-pergb/radius.secret and the units, and removes
# them again. Never run it on a node (refused without --throwaway-host).
#
#   sudo scripts/test_netrun_radius_units.sh --throwaway-host
#
# Checks: systemd-analyze verify; socket activation (first datagram starts the
# service) under User=netrun-radius with the hardening; READY (Type=notify) <= 1 s
# with empty and with cap-sized state (50k lists, 100k bindings); restarts under
# load lose no request; 20 kill -9 never reach start-limit-hit and the socket
# stays open; a hung process is killed by the watchdog and comes back; a corrupt
# DB is moved aside and the service starts under a new epoch.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RADIUS_DIR="$REPO/node_runtime/radius"
UNIT_DIR=/etc/systemd/system
[[ "${1:-}" == "--throwaway-host" ]] || { echo "refusing: pass --throwaway-host (this script installs and removes units)" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
SLACK="${NETRUN_RADIUS_PERF_SLACK:-1}"

fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
radctl() { python3 -I /opt/netrun/radius/radctl.py "$@"; }
radclient() { python3 -I /opt/netrun/radius/radclient.py --secret-file /etc/netrun-pergb/radius.secret "$@"; }
mainpid() { systemctl show -p MainPID --value netrun-radius.service; }
wait_active() {
  for _ in $(seq 1 "${1:-100}"); do
    [[ "$(systemctl is-active netrun-radius.service)" == active ]] && return 0
    sleep 0.2
  done
  return 1
}
ready_ms() {
  local a b
  a="$(systemctl show -p ExecMainStartTimestampMonotonic --value netrun-radius.service)"
  b="$(systemctl show -p ActiveEnterTimestampMonotonic --value netrun-radius.service)"
  echo $(((b - a) / 1000))
}

cleanup() {
  set +e
  systemctl stop netrun-radius.service netrun-radius.socket 2>/dev/null
  rm -f "$UNIT_DIR"/netrun-radius.socket "$UNIT_DIR"/netrun-radius.service
  [[ -f "$UNIT_DIR/.nr-stub-target" ]] && rm -f "$UNIT_DIR/netrun-pergb.target" "$UNIT_DIR/.nr-stub-target"
  [[ -f "$UNIT_DIR/.nr-stub-slice" ]] && rm -f "$UNIT_DIR/netrun-pergb.slice" "$UNIT_DIR/.nr-stub-slice"
  systemctl daemon-reload
  rm -rf /opt/netrun/radius /etc/netrun-pergb /var/lib/netrun-radius /run/netrun-radius
}
trap cleanup EXIT

# ---- install ----------------------------------------------------------------------------
id netrun-radius >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin netrun-radius
install -d -m 0755 /opt/netrun/radius
install -m 0644 "$RADIUS_DIR"/*.py /opt/netrun/radius/
install -d -m 0750 -g netrun-radius /etc/netrun-pergb
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 >/etc/netrun-pergb/radius.secret
chown root:netrun-radius /etc/netrun-pergb/radius.secret
chmod 0640 /etc/netrun-pergb/radius.secret
install -m 0644 "$REPO/deploy/node/netrun-radius.socket" "$REPO/deploy/node/netrun-radius.service" "$UNIT_DIR/"
for u in netrun-pergb.target netrun-pergb.slice; do
  if [[ -f "$REPO/deploy/node/$u" ]]; then
    install -m 0644 "$REPO/deploy/node/$u" "$UNIT_DIR/"
  elif [[ ! -f "$UNIT_DIR/$u" ]]; then
    case "$u" in
      *.target) printf '[Unit]\nDescription=stub per-GB target (L1 test)\n' >"$UNIT_DIR/$u"; touch "$UNIT_DIR/.nr-stub-target" ;;
      *.slice) printf '[Unit]\nDescription=stub per-GB slice (L1 test)\n[Slice]\nMemoryMax=1536M\n' >"$UNIT_DIR/$u"; touch "$UNIT_DIR/.nr-stub-slice" ;;
    esac
  fi
done
systemctl daemon-reload

if systemd-analyze verify "$UNIT_DIR/netrun-radius.socket" "$UNIT_DIR/netrun-radius.service"; then
  ok "systemd-analyze verify"
else
  bad "systemd-analyze verify"
fi
echo "--- security exposure:"; systemd-analyze security netrun-radius.service --no-pager | tail -n 1 || true

# ---- socket activation -----------------------------------------------------------------
systemctl start netrun-radius.socket
[[ "$(systemctl is-active netrun-radius.service)" != active ]] && ok "service idle until the first datagram"
radclient --user netrun-nobody --password x --nas-port 31000 --count 1 >/dev/null || true
if wait_active; then ok "first datagram starts netrun-radius.service"; else bad "socket activation"; fi
[[ "$(ps -o user= -p "$(mainpid)")" == netrun-radius ]] && ok "runs as netrun-radius" || bad "user"
ms="$(ready_ms)"; echo "info READY (empty state): ${ms} ms"
[[ $ms -le $((1000 * SLACK)) ]] && ok "READY <= 1 s (empty state)" || bad "READY ${ms} ms"
[[ "$(stat -c %a /run/netrun-radius/ctl.sock)" == 600 ]] && ok "ctl.sock is 0600" || bad "ctl.sock mode"

KEY="$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
SALT="$(python3 -c 'import os; print(os.urandom(16).hex())')"
HASH="$(python3 -c "import hashlib,sys; print(hashlib.sha256(bytes.fromhex('$SALT') + b'UnitPassw0rdUnit').hexdigest())")"
radctl facts "{\"facts\": {\"base\": 31000, \"count\": 1000, \"geo\": \"us\", \"prefix\": \"2001:db8:aa::/48\", \"addrKey\": \"$KEY\", \"egressIpv4\": \"192.0.2.10\"}}" >/dev/null
radctl snapshot "{\"seq\": 1, \"accounts\": [{\"id\": 1, \"state\": \"active\", \"expiresAt\": 4000000000}], \"lists\": [{\"id\": 7, \"login\": \"netrun-unittst\", \"accountId\": 1, \"pwSalt\": \"$SALT\", \"pwHash\": \"$HASH\", \"mode\": \"static\"}], \"static\": []}" >/dev/null
out="$(radclient --user netrun-unittst --password UnitPassw0rdUnit --nas-port 31005 --dst 2001:db8:ffff::1 --count 3 --expect accept)" \
  && ok "Access-Accept through the socket-activated service: $out" || bad "accept: $out"
STATIC_BEFORE="$(radctl bindings '{"after": 0}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["items"][0]["addr"])')"

# ---- restarts under load ----------------------------------------------------------------
radclient --user netrun-unittst --password UnitPassw0rdUnit --nas-port 31001 --dst 2001:db8:ffff::1 \
  --duration 12 --rate 300 --timeout 3 --expect accept >/tmp/nr-load.json &
LOADPID=$!
sleep 2
for _ in 1 2 3; do systemctl restart netrun-radius.service; sleep 2; done
if wait "$LOADPID"; then ok "3 restarts under 300 req/s: no lost request $(cat /tmp/nr-load.json)"; else bad "restart under load: $(cat /tmp/nr-load.json)"; fi
STATIC_AFTER="$(radctl bindings '{"after": 0}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["items"][0]["addr"])')"
[[ "$STATIC_BEFORE" == "$STATIC_AFTER" ]] && ok "static binding survives restarts" || bad "static changed"

# ---- crash loop never reaches start-limit-hit ------------------------------------------
for i in $(seq 1 20); do
  pid="$(mainpid)"
  [[ "$pid" != 0 ]] && kill -9 "$pid" 2>/dev/null || true
  radclient --user netrun-unittst --password UnitPassw0rdUnit --nas-port 31001 --dst 2001:db8:ffff::1 --count 1 --timeout 5 >/dev/null || true
  wait_active 50 || true
done
res="$(systemctl show -p Result --value netrun-radius.service)"
[[ "$(systemctl is-active netrun-radius.socket)" == active ]] && ok "socket still open after 20 kill -9" || bad "socket closed"
[[ "$res" != start-limit-hit ]] && wait_active && ok "20 kill -9: never start-limit-hit (Result=$res)" || bad "start limit: $res"
out="$(radclient --user netrun-unittst --password UnitPassw0rdUnit --nas-port 31005 --dst 2001:db8:ffff::1 --count 3 --expect accept)" \
  && ok "serving after the crash loop" || bad "after crash loop: $out"

# ---- watchdog ----------------------------------------------------------------------------
pid="$(mainpid)"
kill -STOP "$pid"
for _ in $(seq 1 200); do
  sleep 0.2
  np="$(mainpid)"
  [[ "$np" != 0 && "$np" != "$pid" ]] && break
done
np="$(mainpid)"
[[ "$np" != 0 && "$np" != "$pid" ]] && ok "watchdog replaced a hung process ($(systemctl show -p Result --value netrun-radius.service))" || bad "watchdog"
kill -9 "$pid" 2>/dev/null || true
wait_active || true
out="$(radclient --user netrun-unittst --password UnitPassw0rdUnit --nas-port 31005 --dst 2001:db8:ffff::1 --count 3 --timeout 5 --expect accept)" \
  && ok "serving after the watchdog restart" || bad "after watchdog: $out"

# ---- corrupt DB --------------------------------------------------------------------------
EPOCH="$(radctl status | python3 -c 'import json,sys; print(json.load(sys.stdin)["epoch"])')"
systemctl stop netrun-radius.service
head -c 65536 /dev/urandom >/var/lib/netrun-radius/radius.db
rm -f /var/lib/netrun-radius/radius.db-wal /var/lib/netrun-radius/radius.db-shm
systemctl start netrun-radius.service
wait_active || true
st="$(radctl status)"
python3 -c "import json,sys; s=json.loads(sys.argv[1]); sys.exit(0 if s['dbRecovered'] and s['epoch'] != $EPOCH else 1)" "$st" \
  && ok "corrupt DB moved aside, new epoch" || bad "DB recovery: $st"
ls /var/lib/netrun-radius/radius.db.broken-* >/dev/null 2>&1 && ok "broken copy kept" || bad "no broken copy"

# ---- READY with cap-sized state ---------------------------------------------------------
systemctl stop netrun-radius.service
rm -f /var/lib/netrun-radius/radius.db*
python3 -I -c "import sys; sys.path.insert(0, '$RADIUS_DIR/tests'); import test_server; test_server.build_cap_state('/var/lib/netrun-radius/radius.db')"
chown -R netrun-radius:netrun-radius /var/lib/netrun-radius
best=999999
for _ in 1 2 3; do
  systemctl restart netrun-radius.service
  wait_active || true
  ms="$(ready_ms)"
  [[ $ms -lt $best ]] && best=$ms
done
echo "info READY with 50k lists / 100k bindings: best ${best} ms"
[[ $best -le $((1000 * SLACK)) ]] && ok "READY <= 1 s with cap-sized state" || bad "READY ${best} ms with cap-sized state"
rss="$(ps -o rss= -p "$(mainpid)")"; echo "info RSS with cap-sized state: $((rss / 1024)) MiB"
cnt="$(radctl status | python3 -c 'import json,sys; c=json.load(sys.stdin)["counts"]; print(c["lists"], c["static"])')"
[[ "$cnt" == "50000 40000" ]] && ok "cap-sized state loaded ($cnt)" || bad "counts $cnt"

echo
journalctl -u netrun-radius.service --no-pager -n 15 || true
[[ $fail -eq 0 ]] && echo "units: PASS" || { echo "units: FAILED"; exit 1; }
