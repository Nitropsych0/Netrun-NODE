#!/usr/bin/env bash
# deploy/node/watchdog_probe.sh (watchdog v4, audit 2026-10-08): /health
# failing 5x → agent restart (cooldown); 20x → reboot ONLY when the data plane
# is down (no 3proxy listener, or no probed SOCKS port answers the greeting);
# proxies that answer are never rebooted away; an egress self-check failure
# → alert + restart, never a reboot; the agent key goes in the probe; a fresh
# genlock counts nothing. curl / ss / systemctl / logger / reboot are stubs;
# the SOCKS probe talks to a real local responder (python3). No root.
#   bash scripts/test_watchdog_probe.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
WD="$ROOT_DIR/deploy/node/watchdog_probe.sh"
TMP="$(mktemp -d)"
RESP_PID=""
trap '[ -n "$RESP_PID" ] && kill "$RESP_PID" 2>/dev/null; rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3"; exit 0; }
bash -n "$WD" || fail "bash -n watchdog_probe.sh"

# A SOCKS5 responder (answers 05 02 like 3proxy with auth strong) and a dead port.
python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(16)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    try:
        c.recv(3); c.sendall(b"\x05\x02")
    finally:
        c.close()
' > "$TMP/live_port" &
RESP_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$TMP/live_port" ] && break; sleep 0.2; done
LIVE="$(cat "$TMP/live_port")"; [ -n "$LIVE" ] || fail "responder did not start"
DEAD="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

STUB="$TMP/bin"; mkdir -p "$STUB"
export STUB_LOG="$TMP/calls.log" CURL_CODE_FILE="$TMP/curl_code" CURL_BODY_FILE="$TMP/curl_body" SS_FILE="$TMP/ss"
cat > "$STUB/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "$STUB_LOG"
out=""
while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift ;; esac; shift; done
[ -n "$out" ] && cat "$CURL_BODY_FILE" > "$out" 2>/dev/null
cat "$CURL_CODE_FILE"
EOF
cat > "$STUB/ss" <<'EOF'
#!/usr/bin/env bash
cat "$SS_FILE"
EOF
cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
EOF
cat > "$STUB/logger" <<'EOF'
#!/usr/bin/env bash
echo "logger $*" >> "$STUB_LOG"
EOF
cat > "$STUB/reboot" <<'EOF'
#!/usr/bin/env bash
echo "REBOOT" >> "$STUB_LOG"
EOF
chmod +x "$STUB"/*
export PATH="$STUB:$PATH"

export NETRUN_WATCHDOG_STATE_DIR="$TMP/state" NETRUN_PROXY_CFG_DIR="$TMP/cfg" \
       NETRUN_WATCHDOG_GENLOCK="$TMP/jobs/.generation.lock" NETRUN_AGENT_KEY_FILE="$TMP/20-api-key.conf" \
       NETRUN_WATCHDOG_REBOOT_CMD="$STUB/reboot"
mkdir -p "$TMP/cfg" "$TMP/jobs"
printf '[Service]\nEnvironment=NODE_AGENT_API_KEY=abc123\n' > "$NETRUN_AGENT_KEY_FILE"
cfg() { printf 'daemon\nflush\nusers u:CL:p\nsocks -6 -a -p%s -i127.0.0.1 -e2001:db8::1\n' "$2" > "$TMP/cfg/3proxy_$1.cfg"; }
listeners() { if [ "$1" = 0 ]; then : > "$SS_FILE"; else printf 'LISTEN 0 13 127.0.0.1:%s 0.0.0.0:* users:(("3proxy",pid=7,fd=5))\n' "$LIVE" > "$SS_FILE"; fi; }
health() { echo "$1" > "$CURL_CODE_FILE"; printf '%s' "${2:-}" > "$CURL_BODY_FILE"; }
reset() { rm -rf "$TMP/state"; : > "$STUB_LOG"; }
tick() { bash "$WD"; }
ticks() { local i; for ((i = 0; i < $1; i++)); do tick; done; }
count() { grep -c "$1" "$STUB_LOG" || true; }

# ── 1. healthy; the key is sent ───────────────────────────────────
reset; cfg 18100 "$LIVE"; listeners 1; health 200 '{"ok":true}'
tick
grep -q 'X-API-KEY: abc123' "$STUB_LOG" || fail "the agent key goes in the probe"
[ "$(cat "$TMP/state/watchdog_failures")" = 0 ] || fail "healthy: counter 0"
[ "$(count systemctl)" = 0 ] || fail "healthy: no restart"
ok "healthy /health: nothing done; the key from the unit drop-in is sent"

# ── 2. restart tier ───────────────────────────────────────────────
reset; health 000
ticks 4; [ "$(count 'systemctl restart')" = 0 ] || fail "restart before 5 failures"
tick;   [ "$(count 'systemctl restart')" = 1 ] || fail "restart at 5 failures"
grep -q 'ALERT: restarting netrun-node-agent' "$STUB_LOG" || fail "restart alert"
ticks 3; [ "$(count 'systemctl restart')" = 1 ] || fail "restart cooldown"
ok "5 failures: alert + one agent restart, then the cooldown"

# ── 3. 20 failures, proxies answer: never a reboot ────────────────
reset; health 000; cfg 18100 "$LIVE"; listeners 1
ticks 25
[ "$(count "^REBOOT$")" = 0 ] || fail "rebooted while SOCKS answers"
grep -q 'proxies serve' "$STUB_LOG" || fail "no-reboot alert"
ok "20+ failures but a SOCKS port answers: alert, no reboot"

# ── 4. listeners there, SOCKS dead on every probed port: reboot ──
reset; health 000; rm -f "$TMP"/cfg/*; cfg 18100 "$DEAD"; cfg 19600 "$DEAD"; listeners 1
ticks 19; [ "$(count "^REBOOT$")" = 0 ] || fail "reboot before 20"
tick;     [ "$(count "^REBOOT$")" = 1 ] || fail "reboot at 20 with dead SOCKS"
grep -q 'SOCKS greeting failed on 2 probed' "$STUB_LOG" || fail "reason names the probes: $(grep REBOOT -B1 "$STUB_LOG" | head -2)"
ok "20 failures and no probed SOCKS port answers: reboot"

# ── 5. no 3proxy listener at all: reboot, then the 4 h cooldown ──
reset; health 000; rm -f "$TMP"/cfg/*; cfg 18100 "$LIVE"; listeners 0
ticks 20; [ "$(count "^REBOOT$")" = 1 ] || fail "reboot with no listener"
grep -q 'no 3proxy listener' "$STUB_LOG" || fail "reason: no listener"
ticks 20; [ "$(count "^REBOOT$")" = 1 ] || fail "reboot cooldown"
ok "no 3proxy listener: reboot once, then the cooldown"

# ── 6. egress failures: restart + alert, never a reboot ──────────
reset; listeners 0; health 200 '{"success":true,"ipv6Egress":{"ok":true},"ipv6EgressRouted":{"ok":false,"error":"timeout"}}'
ticks 4; [ "$(count 'systemctl restart')" = 0 ] || fail "egress restart before 5"
tick;    [ "$(count 'systemctl restart')" = 1 ] || fail "egress restart at 5"
grep -q 'ALERT: restarting netrun-node-agent: egress failing 5 times in a row (ipv6EgressRouted timeout)' "$STUB_LOG" || fail "egress alert text"
ticks 40; [ "$(count "^REBOOT$")" = 0 ] || fail "egress failure rebooted"
[ "$(count 'systemctl restart')" = 1 ] || fail "egress restart cooldown (30 min)"
health 200 '{"success":true,"ipv6Egress":{"ok":true},"ipv6EgressRouted":{"ok":true}}'; tick
[ "$(cat "$TMP/state/watchdog_egress_failures")" = 0 ] || fail "egress counter reset"
ok "egress / IPv6 self-check failing: alert + one restart per 30 min, never a reboot"

# ── 7. a fresh genlock counts nothing ─────────────────────────────
reset; health 000; touch "$NETRUN_WATCHDOG_GENLOCK"
ticks 25
[ ! -e "$TMP/state/watchdog_failures" ] && [ "$(count systemctl)" = 0 ] && [ "$(count "^REBOOT$")" = 0 ] || fail "genlock: something counted"
rm -f "$NETRUN_WATCHDOG_GENLOCK"
ok "generation in progress: nothing counted, nothing done"

# followup installs this file (no heredoc copy left)
grep -q 'deploy/node/watchdog_probe.sh' "$ROOT_DIR/scripts/node_followup_v2.sh" || fail "followup installs the repo watchdog"
grep -q "<<'WATCHDOG'" "$ROOT_DIR/scripts/node_followup_v2.sh" && fail "followup still has the heredoc watchdog"
ok "node_followup_v2.sh installs deploy/node/watchdog_probe.sh"

echo "PASS ($PASS)"
