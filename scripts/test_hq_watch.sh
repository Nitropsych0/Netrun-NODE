#!/usr/bin/env bash
# deploy/node/netrun-hq-watch.sh with curl / timeout stubbed: one alert after
# HQ_FAILS bad checks, no verdict while the node's own internet is down,
# reminders, the «back» message, a failed send retried.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bin"
cat > "$W/bin/curl" <<'EOF'
#!/usr/bin/env bash
# stub: Telegram (url on stdin via -K -) → log the text; else the URL's code
printf '%s\n' "$*" >> "$STUB_DIR/argv"
for a in "$@"; do
  case "$a" in
    -K) cfg=$(cat); echo "$cfg" | grep -q api.telegram.org || exit 1
        for b in "$@"; do case "$b" in text=*) printf '%s\n' "${b#text=}" >> "$STUB_DIR/sent" ;; esac; done
        printf '%s' "${TG_CODE:-200}"; exit 0 ;;
  esac
done
url="${@: -1}"
case "$url" in
  *cdn-cgi/trace*) printf '%s' "${REF_CODE:-200}" ;;
  *) printf '%s' "${SITE_CODE:-200}" ;;
esac
EOF
cat > "$W/bin/timeout" <<'EOF'
#!/usr/bin/env bash
[ "${TCP_UP:-1}" = 1 ]
EOF
chmod +x "$W/bin/curl" "$W/bin/timeout"
# Audit S-NODE-3: the orchestrator-rendered file — new names, 0600
cat > "$W/conf" <<'EOF'
HQ_WATCH_TG_TOKEN=123:abc
HQ_WATCH_TG_CHAT=-100
HQ_WATCH_TG_TOPIC=8
NODE_LABEL=Chicago
EOF
chmod 600 "$W/conf"
export PATH="$W/bin:$PATH" STUB_DIR="$W" HQ_WATCH_CONF="$W/conf" HQ_WATCH_STATE_DIR="$W/state"
pass=0
fail() { echo "FAIL: $*"; exit 1; }
ok() { pass=$((pass + 1)); echo "ok: $*"; }
t=1000000
run() { t=$((t + 60)); HQ_NOW=$t bash "$HERE/deploy/node/netrun-hq-watch.sh"; }
sent() { [ -f "$W/sent" ] && wc -l < "$W/sent" | tr -d ' ' || echo 0; }

SITE_CODE=200 run; [ "$(sent)" = 0 ] && [ "$(cat "$W/state/state")" = "ok 0 0 0 0" ] || fail "all good: nothing sent"
ok "all good: silent"

export SITE_CODE=000 TCP_UP=0
run; run; [ "$(sent)" = 0 ] || fail "2 bad checks: no alert yet"
run; [ "$(sent)" = 1 ] && grep -q "Не отвечает" "$W/sent" && grep -q "ни сайт, ни SSH" "$W/sent" && grep -q "Chicago" "$W/sent" || fail "3rd bad check: host_down alert"
run; run; [ "$(sent)" = 1 ] || fail "one alert per episode"
ok "host down: one alert after 3 checks"

REF_CODE=000 run; REF_CODE=000 run; [ "$(sent)" = 1 ] || fail "own internet down: no verdict"
ok "own internet down: nothing judged"

for _ in $(seq 1 60); do run; done
[ "$(sent)" = 2 ] && tail -1 "$W/sent" | grep -q "Всё ещё" || fail "a reminder after 60 min ($(sent))"
ok "reminder after 60 min"

export SITE_CODE=200 TCP_UP=1
TG_CODE=500 run; [ "$(sent)" = 3 ] && grep -q "^host_down" "$W/state/state" || fail "a failed «back» send keeps the episode"
run; [ "$(sent)" = 4 ] && tail -1 "$W/sent" | grep -q "Снова отвечает" && [ "$(cat "$W/state/state")" = "ok 0 0 0 0" ] || fail "back message"
ok "back: one message, retried after a failed send"

export SITE_CODE=502 TCP_UP=1
run; run; run; tail -1 "$W/sent" | grep -q "сервер жив" || fail "site down, host up"
ok "site down with the host alive: its own text"

# --- Audit S-NODE-3 ---------------------------------------------------------
reset() { rm -rf "$W/state" "$W/sent" "$W/argv" "$W/err"; }
bad3() { export SITE_CODE=000 TCP_UP=0; run 2>>"$W/err"; run 2>>"$W/err"; run 2>>"$W/err"; }

# a config readable by group/others is refused: nothing sent, state untouched
reset; chmod 644 "$W/conf"
bad3
[ "$(sent)" = 0 ] && [ ! -e "$W/state/state" ] || fail "a 0644 config must be ignored (sent=$(sent))"
grep -q "must be 0600" "$W/err" || fail "a 0644 config must say why on stderr: $(cat "$W/err" 2>/dev/null)"
for m in 640 604 660 666; do reset; chmod $m "$W/conf"; bad3; [ "$(sent)" = 0 ] || fail "mode $m must be refused"; done
for m in 600 400; do reset; chmod $m "$W/conf"; bad3; [ "$(sent)" = 1 ] || fail "mode $m must be accepted (sent=$(sent))"; done
chmod 600 "$W/conf"
ok "a config that is not 0600/0400 is ignored (quiet no-op); 0600 and 0400 work"

# NODE_LABEL with spaces / quotes, as the orchestrator renders it, is sourced intact
reset
cat > "$W/conf" <<'EOF'
HQ_WATCH_TG_TOKEN=123:abc
HQ_WATCH_TG_CHAT=-100
NODE_LABEL='New York 1'
EOF
chmod 600 "$W/conf"
bad3
[ "$(sent)" = 1 ] && grep -q "New York 1" "$W/sent" || fail "NODE_LABEL with spaces must reach the message: $(cat "$W/sent" 2>/dev/null)"
ok "NODE_LABEL='New York 1' is sourced intact"

# the old TG_* names still work, with a deprecation warning
reset
cat > "$W/conf" <<'EOF'
TG_TOKEN=999:old
TG_CHAT=-200
TG_TOPIC=5
NODE_LABEL=Legacy
EOF
chmod 600 "$W/conf"
bad3
[ "$(sent)" = 1 ] && grep -q "Legacy" "$W/sent" || fail "the legacy TG_* names must still send"
grep -q "deprecated" "$W/err" && grep -q "TG_TOKEN" "$W/err" || fail "legacy names must warn: $(cat "$W/err")"
grep -q "message_thread_id=5" "$W/argv" || fail "legacy TG_TOPIC must reach the request"
grep -q "999:old" "$W/argv" && fail "the legacy token in argv"
ok "legacy TG_TOKEN / TG_CHAT / TG_TOPIC still read, with a deprecation warning"

# new names win over old ones; only the new names → no warning
reset
cat > "$W/conf" <<'EOF'
HQ_WATCH_TG_TOKEN=123:abc
HQ_WATCH_TG_CHAT=-100
HQ_WATCH_TG_TOPIC=8
TG_TOKEN=999:old
TG_CHAT=-200
EOF
chmod 600 "$W/conf"
bad3
grep -q "message_thread_id=8" "$W/argv" && grep -q "chat_id=-100" "$W/argv" && ! grep -q "chat_id=-200" "$W/argv" || fail "HQ_WATCH_TG_* must win over TG_*"
reset; cat > "$W/conf" <<'EOF'
HQ_WATCH_TG_TOKEN=123:abc
HQ_WATCH_TG_CHAT=-100
EOF
chmod 600 "$W/conf"; bad3
grep -q deprecated "$W/err" && fail "no warning when only the new names are used"
ok "HQ_WATCH_TG_* win; no warning without legacy names"

# token / chat missing → quiet no-op
reset; printf 'NODE_LABEL=x\n' > "$W/conf"; chmod 600 "$W/conf"; bad3
[ "$(sent)" = 0 ] || fail "no token: nothing sent"
ok "no token: quiet no-op"

# the token never appears in argv (curl gets it on stdin via -K -)
reset; printf 'HQ_WATCH_TG_TOKEN=123:abc\nHQ_WATCH_TG_CHAT=-100\n' > "$W/conf"; chmod 600 "$W/conf"; bad3
[ "$(sent)" = 1 ] && [ -s "$W/argv" ] && ! grep -q "123:abc" "$W/argv" || fail "the token must not be in curl's argv"
ok "the token never appears in curl's argv"

rm -f "$W/conf"; run; ok "no config: quiet no-op"
grep -q "123:abc" "$W/sent" && fail "the token never leaves curl's config"
echo "PASS ($pass)"
