#!/usr/bin/env bash
# netrun-hq-watch — the node watches HQ (owner 2026-10-10, node audit).
#
# The bot, the site and the orchestrator share ONE server; when it dies nothing
# on it can tell anyone (the orchestrator's alerts go out through the bot). Every
# node checks it once a minute from outside — another provider — and posts to
# the admins' alerts topic through the Telegram Bot API itself:
#   * the reference first (HQ_REF_URL): with the node's own internet down
#     nothing is judged — Telegram would be unreachable anyway;
#   * site — HQ_URL answers 2xx/3xx within 15 s;
#   * host — a TCP connect to HQ_HOST:22 within 5 s;
#   * ok / site_down (the host answers) / host_down (neither); HQ_FAILS (3)
#     failed checks in a row → ONE alert, a reminder every HQ_REMIND_MIN (60)
#     minutes, ONE «back» message once both answer. A failed send is retried
#     on the next run.
# Config /etc/netrun/hq-watch.env (0600, root): TG_TOKEN, TG_CHAT, TG_TOPIC,
# NODE_LABEL; optional HQ_URL, HQ_HOST, HQ_REF_URL, HQ_FAILS, HQ_REMIND_MIN.
# No config → a quiet no-op. Run by netrun-hq-watch.timer.
set -u
CONF="${HQ_WATCH_CONF:-/etc/netrun/hq-watch.env}"
STATE_DIR="${HQ_WATCH_STATE_DIR:-/var/lib/netrun-hq-watch}"
[ -r "$CONF" ] || exit 0
# shellcheck source=/dev/null
. "$CONF"
[ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHAT:-}" ] || { echo "netrun-hq-watch: TG_TOKEN / TG_CHAT missing in $CONF" >&2; exit 0; }
HQ_URL="${HQ_URL:-https://netrun.world/}"
HQ_HOST="${HQ_HOST:-95.217.98.125}"
HQ_REF_URL="${HQ_REF_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
HQ_FAILS="${HQ_FAILS:-3}"
HQ_REMIND_MIN="${HQ_REMIND_MIN:-60}"
NODE_LABEL="${NODE_LABEL:-$(hostname)}"
NOW="${HQ_NOW:-$(date +%s)}"
STATE_FILE="$STATE_DIR/state"

http_ok() {
  local code
  code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "$1" 2>/dev/null)
  case "$code" in 2* | 3*) return 0 ;; esac
  return 1
}

tcp_ok() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# send <html> — the token rides in curl's config on stdin, never in argv.
send() {
  local args=(--data-urlencode "chat_id=$TG_CHAT" --data-urlencode "text=$1"
    --data-urlencode "parse_mode=HTML" --data-urlencode "disable_web_page_preview=true")
  [ -n "${TG_TOPIC:-}" ] && args+=(--data-urlencode "message_thread_id=$TG_TOPIC")
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TG_TOKEN" \
    | curl -s -m 20 -o /dev/null -w '%{http_code}' -K - "${args[@]}" 2>/dev/null | grep -qx 200
}

what() {
  case "$1" in
    host_down) printf 'сервер бота, сайта и оркестратора (%s) — ни сайт, ни SSH' "$HQ_HOST" ;;
    *) printf 'сайт %s — сервер жив (SSH отвечает)' "$HQ_URL" ;;
  esac
}

save() { mkdir -p "$STATE_DIR" && printf '%s %s %s %s %s\n' "$@" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"; }

st=ok fails=0 since=0 alerted=0 reminded=0
# shellcheck disable=SC2034
[ -r "$STATE_FILE" ] && read -r st fails since alerted reminded < "$STATE_FILE"

http_ok "$HQ_REF_URL" || exit 0 # our own internet is down: no verdict

if http_ok "$HQ_URL"; then
  cur=ok
elif tcp_ok "$HQ_HOST" 22; then
  cur=site_down
else
  cur=host_down
fi

if [ "$cur" = ok ]; then
  if [ "$alerted" != 0 ]; then
    send "✅ <b>Снова отвечает</b>: $(what "$st") — не отвечал ~$(((NOW - since) / 60)) мин (видно с ноды $NODE_LABEL)." \
      || exit 0 # retried on the next run
  fi
  save ok 0 0 0 0
  exit 0
fi

if [ "$st" = ok ]; then since=$NOW fails=1 alerted=0 reminded=0; else fails=$((fails + 1)); fi
if [ "$alerted" = 0 ]; then
  if [ "$fails" -ge "$HQ_FAILS" ]; then
    case "$cur" in
      host_down) tail='Бот, сайт и новые продажи стоят; купленные прокси работают (авторизация на нодах).' ;;
      *) tail='Бот и прокси работают, покупки на сайте — нет.' ;;
    esac
    send "🚨 <b>Не отвечает</b> $(what "$cur"): $fails проверки подряд с ноды $NODE_LABEL. $tail" \
      && alerted=$NOW reminded=$NOW
  fi
elif [ $((NOW - reminded)) -ge $((HQ_REMIND_MIN * 60)) ]; then
  send "⏳ Всё ещё не отвечает $(what "$cur") — уже ~$(((NOW - since) / 60)) мин (нода $NODE_LABEL)." && reminded=$NOW
fi
save "$cur" "$fails" "$since" "$alerted" "$reminded"
