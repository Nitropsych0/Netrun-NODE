#!/usr/bin/env bash
# NETRUN node watchdog v4 — run every 60 s by netrun-watchdog.timer; installed
# as /opt/netrun/scripts/watchdog_probe.sh by scripts/node_followup_v2.sh.
#
#   Agent liveness: GET http://127.0.0.1:8085/health answered (HTTP 200)
#   within PROBE_TIMEOUT. Without the agent key that is the liveness answer
#   {ok:true}; with it (read from the unit drop-in) the full payload, whose
#   egress self-checks are read too.
#
#   Tier 1 — RESTART_THRESHOLD (5) liveness failures in a row: ALERT +
#            `systemctl restart netrun-node-agent` (cooldown 10 min; 3proxy is
#            not touched, KillMode=process).
#   Tier 2 — REBOOT_THRESHOLD (20) liveness failures in a row AND the data
#            plane is down: reboot (cooldown 4 h). Data plane down = no 3proxy
#            listener at all, or the SOCKS5 greeting fails on every probed
#            local port (the first socks port of up to PROBE_PORTS batch cfgs).
#            Proxies that still answer are never cut by a reboot: ALERT only.
#   Egress — ipv6Egress.ok or ipv6EgressRouted.ok false EGRESS_THRESHOLD (5)
#            times in a row: ALERT + agent restart (cooldown 30 min). NEVER a
#            reboot: a dead route, BGP session or firewall rule survives one
#            (2026-10-08: both nodes were hard-rebooted while a firewall rule
#            blocked their IPv6 neighbour discovery, and came back without IPv6).
#
#   ALERT = `logger -p daemon.err -t netrun-watchdog "ALERT: …"` + the last
#   alert in $STATE_DIR/watchdog_alert.
#   A generation in progress (fresh genlock) is not an outage: nothing counts.
#
# v1 rebooted at 3 failures (daily reboots); v2 only restarted; v3 rebooted
# after 20 failures whatever the cause.
set -u

STATE_DIR="${NETRUN_WATCHDOG_STATE_DIR:-/var/lib/netrun}"
CFG_DIR="${NETRUN_PROXY_CFG_DIR:-/opt/netrun/proxyserver/3proxy}"
GENLOCK="${NETRUN_WATCHDOG_GENLOCK:-/opt/netrun/jobs/.generation.lock}"
HEALTH_URL="${NETRUN_WATCHDOG_URL:-http://127.0.0.1:8085/health}"
AGENT_KEY_FILE="${NETRUN_AGENT_KEY_FILE:-/etc/systemd/system/netrun-node-agent.service.d/20-api-key.conf}"
REBOOT_CMD="${NETRUN_WATCHDOG_REBOOT_CMD:-/sbin/reboot}"
STATE_FAIL="$STATE_DIR/watchdog_failures"
STATE_EGRESS_FAIL="$STATE_DIR/watchdog_egress_failures"
STATE_LAST_RESTART="$STATE_DIR/watchdog_last_restart"
STATE_LAST_EGRESS_RESTART="$STATE_DIR/watchdog_last_egress_restart"
STATE_LAST_REBOOT="$STATE_DIR/watchdog_last_reboot"
STATE_ALERT="$STATE_DIR/watchdog_alert"
LOG_TAG="netrun-watchdog"
RESTART_THRESHOLD=5
RESTART_COOLDOWN_SEC=600
REBOOT_THRESHOLD=20
REBOOT_COOLDOWN_SEC=14400
EGRESS_THRESHOLD=5
EGRESS_RESTART_COOLDOWN_SEC=1800
PROBE_PORTS=3
# Incident 2026-10-07: a 1500-proxy generation on a 2 vCPU node slows /health
# past 5 s; 15 s is still far below a dead agent.
PROBE_TIMEOUT=15
GENLOCK_MAX_AGE_SEC=1800

mkdir -p "$STATE_DIR" 2>/dev/null || true

num() { local v; v="$(cat "$1" 2>/dev/null || echo 0)"; v="${v//[^0-9]/}"; echo "${v:-0}"; }
note() { logger -t "$LOG_TAG" "$*" 2>/dev/null || true; }
alert() {
  logger -p daemon.err -t "$LOG_TAG" "ALERT: $*" 2>/dev/null || true
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" > "$STATE_ALERT" 2>/dev/null || true
}
now="$(date +%s)"

# A generation in progress is not an outage.
if [ -e "$GENLOCK" ]; then
  lock_age=$(( now - $(stat -c %Y "$GENLOCK" 2>/dev/null || stat -f %m "$GENLOCK" 2>/dev/null || echo 0) ))
  [ "$lock_age" -lt "$GENLOCK_MAX_AGE_SEC" ] && exit 0
fi

# restart_agent <cooldown file> <cooldown sec> <reason>
restart_agent() {
  local file="$1" cooldown="$2" why="$3" last elapsed
  last="$(num "$file")"
  elapsed=$((now - last))
  if [ "$elapsed" -lt "$cooldown" ]; then
    note "restart wanted ($why) but in cooldown ($elapsed/${cooldown}s)"
    return 0
  fi
  echo "$now" > "$file"
  alert "restarting netrun-node-agent: $why"
  systemctl restart netrun-node-agent || note "systemctl restart failed: $?"
}

# socks_greeting <ip> <port>: 0 when the port answers a SOCKS5 greeting.
socks_greeting() {
  local ip="$1" port="$2" reply
  [ -n "$ip" ] && [ -n "$port" ] || return 1
  case "$ip" in *:*) ip="[$ip]" ;; esac
  reply="$( { if command -v timeout >/dev/null 2>&1; then timeout 5 bash -c "$PROBE_SCRIPT" _ "$ip" "$port"; else bash -c "$PROBE_SCRIPT" _ "$ip" "$port"; fi; } 2>/dev/null)"
  [ "${reply:0:2}" = "05" ]
}
# The greeting (05 01 02: version 5, one method, username/password) on bash's
# /dev/tcp (an IPv6 host without brackets); the first two reply bytes as hex
# ("0502" from 3proxy).
PROBE_SCRIPT='h="${1#[}"; h="${h%]}"; exec 3<>"/dev/tcp/$h/$2" || exit 1
printf "\005\001\002" >&3
od -An -tx1 -N2 <&3 | tr -d " \n"'

# data_plane_down: 0 (true) when no proxy can be served. Prints why.
data_plane_down() {
  local cfgs listeners f ip port probed=0 line
  cfgs="$(ls "$CFG_DIR"/3proxy_*.cfg 2>/dev/null)"
  if [ -z "$cfgs" ]; then echo "no batch cfg on this node"; return 0; fi
  listeners="$(ss -Hltnp 2>/dev/null | grep -c '"3proxy"')"
  if [ "${listeners:-0}" -eq 0 ]; then echo "no 3proxy listener"; return 0; fi
  for f in $cfgs; do
    [ "$probed" -lt "$PROBE_PORTS" ] || break
    line="$(awk '/^[ \t]*socks[ \t]/ { p = ""; i = ""; for (k = 2; k <= NF; k++) { if ($k ~ /^-p[0-9]+$/) p = substr($k, 3); if ($k ~ /^-i/) i = substr($k, 3) } if (p != "") { print i, p; exit } }' "$f")"
    [ -n "$line" ] || continue
    ip="${line% *}"; port="${line#* }"
    [ -n "$ip" ] || ip=127.0.0.1
    probed=$((probed + 1))
    if socks_greeting "$ip" "$port"; then echo "$listeners 3proxy listeners, $ip:$port answers SOCKS"; return 1; fi
  done
  if [ "$probed" -eq 0 ]; then echo "$listeners 3proxy listeners, no socks port to probe"; return 1; fi
  echo "$listeners 3proxy listeners but the SOCKS greeting failed on $probed probed port(s)"
  return 0
}

key="$(sed -n 's/^Environment=NODE_AGENT_API_KEY=//p' "$AGENT_KEY_FILE" 2>/dev/null | tail -n1)"
body="$(mktemp 2>/dev/null || echo "$STATE_DIR/watchdog_body.$$")"
trap 'rm -f "$body"' EXIT
code="$(curl --silent --output "$body" --write-out '%{http_code}' --max-time "$PROBE_TIMEOUT" \
  ${key:+-H "X-API-KEY: $key"} "$HEALTH_URL" 2>/dev/null || true)"
current="$(num "$STATE_FAIL")"

if [ "$code" = "200" ]; then
  if [ "$current" -gt 0 ]; then note "recovery: was $current consecutive failures, now OK"; fi
  echo 0 > "$STATE_FAIL"
  # Egress self-checks (only in the keyed payload; absent = unknown = fine).
  egress="$(python3 -c '
import json, sys
try:
    h = json.load(open(sys.argv[1]))
except Exception:
    sys.exit()
bad = []
for k in ("ipv6Egress", "ipv6EgressRouted"):
    v = h.get(k)
    if isinstance(v, dict) and v.get("ok") is False:
        bad.append("%s %s" % (k, v.get("error") or "failed"))
print("; ".join(bad))' "$body" 2>/dev/null || true)"
  if [ -z "$egress" ]; then
    [ "$(num "$STATE_EGRESS_FAIL")" -gt 0 ] && note "egress recovered"
    echo 0 > "$STATE_EGRESS_FAIL"
    exit 0
  fi
  efail=$(( $(num "$STATE_EGRESS_FAIL") + 1 ))
  echo "$efail" > "$STATE_EGRESS_FAIL"
  note "egress self-check failed ($efail in a row): $egress"
  if [ "$efail" -ge "$EGRESS_THRESHOLD" ]; then
    restart_agent "$STATE_LAST_EGRESS_RESTART" "$EGRESS_RESTART_COOLDOWN_SEC" "egress failing $efail times in a row ($egress) — never a reboot for egress"
  fi
  exit 0
fi

new=$((current + 1))
echo "$new" > "$STATE_FAIL"
note "probe failed (HTTP ${code:-none}; $new in a row — restart@$RESTART_THRESHOLD, reboot@$REBOOT_THRESHOLD only with the data plane down)"

if [ "$new" -ge "$REBOOT_THRESHOLD" ]; then
  if why="$(data_plane_down)"; then
    last="$(num "$STATE_LAST_REBOOT")"
    elapsed=$((now - last))
    if [ "$elapsed" -ge "$REBOOT_COOLDOWN_SEC" ]; then
      alert "REBOOT — agent dead $new probes in a row and the data plane is down ($why)"
      echo "$now" > "$STATE_LAST_REBOOT"
      echo 0 > "$STATE_FAIL"
      $REBOOT_CMD
      exit 0
    fi
    note "reboot wanted ($why) but in cooldown ($elapsed/${REBOOT_COOLDOWN_SEC}s)"
  elif [ $(( (new - REBOOT_THRESHOLD) % 60 )) -eq 0 ]; then
    alert "agent dead $new probes in a row but proxies serve ($why) — no reboot"
  fi
fi

if [ "$new" -ge "$RESTART_THRESHOLD" ]; then
  restart_agent "$STATE_LAST_RESTART" "$RESTART_COOLDOWN_SEC" "/health failed $new times in a row"
fi
exit 0
