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
cat > "$W/conf" <<'EOF'
TG_TOKEN=123:abc
TG_CHAT=-100
TG_TOPIC=8
NODE_LABEL=Chicago
EOF
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

rm -f "$W/conf"; run; ok "no config: quiet no-op"
grep -q "123:abc" "$W/sent" && fail "the token never leaves curl's config"
echo "PASS ($pass)"
