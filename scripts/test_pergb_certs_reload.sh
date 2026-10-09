#!/usr/bin/env bash
# Tests for deploy/node/netrun-pergb-certs-reload.sh with stubbed systemctl/haproxy:
# reload only on a change, only while the per-GB haproxy runs, only when `haproxy -c`
# accepts; a write that lands during the reload gets its own reload; bounded loop.
# Usage: bash scripts/test_pergb_certs_reload.sh
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/node/netrun-pergb-certs-reload.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok - $*"; }

mkdir -p "$T/bin" "$T/tls" "$T/run"
# systemctl: is-active ← $T/active; reload → $T/reloads (+ runs $T/on_reload if present)
cat > "$T/bin/systemctl" <<EOF
#!/usr/bin/env bash
case "\$1" in
  is-active) [ -f "$T/active" ] ;;
  reload) echo "\$2" >> "$T/reloads"; [ -f "$T/on_reload" ] && bash "$T/on_reload"; [ ! -f "$T/reload_fails" ] ;;
  *) exit 2 ;;
esac
EOF
# haproxy -c: fails while $T/cfg_bad exists
printf '#!/usr/bin/env bash\n[ ! -f "%s/cfg_bad" ]\n' "$T" > "$T/bin/haproxy"
chmod +x "$T/bin/systemctl" "$T/bin/haproxy"
printf 'A\n' > "$T/tls/node.pem"; printf 'B\n' > "$T/tls/host.pem"
printf '%s\n%s [sni-filter us.proxy.netrun.lol]\n' "$T/tls/node.pem" "$T/tls/host.pem" > "$T/tls/crt-list"
export PATH="$T/bin:$PATH" NETRUN_HTTPS_TLS_DIR="$T/tls" NETRUN_PERGB_CERTS_STAMP="$T/run/stamp" \
       NETRUN_PERGB_HAPROXY_CFG="$T/haproxy.cfg" NETRUN_PERGB_CERTS_SETTLE=0
run() { bash "$SCRIPT" "$@" >/dev/null 2>&1; }
reloads() { [ -f "$T/reloads" ] && wc -l < "$T/reloads" | tr -d ' ' || echo 0; }

run; [ "$(reloads)" = 0 ] && [ ! -f "$T/run/stamp" ] || fail "haproxy stopped: no reload, no stamp"
ok "haproxy stopped → nothing reloaded"

touch "$T/active"
run --stamp; [ -s "$T/run/stamp" ] && [ "$(reloads)" = 0 ] || fail "--stamp writes the stamp only"
ok "--stamp records the state without a reload"

run; [ "$(reloads)" = 0 ] || fail "unchanged files must not reload"
ok "unchanged certificates → no reload"

printf 'B2\n' > "$T/tls/host.pem"
run; [ "$(reloads)" = 1 ] || fail "a changed PEM reloads once (got $(reloads))"
run; [ "$(reloads)" = 1 ] || fail "the second run with the same files must not reload"
ok "a changed PEM → one reload, then quiet"

# a write that lands during the reload (the path unit cannot start us again then)
printf 'printf "B3\\n" > "%s/tls/host.pem"; rm -f "%s/on_reload"\n' "$T" "$T" > "$T/on_reload"
printf 'B2b\n' > "$T/tls/host.pem"
run; [ "$(reloads)" = 3 ] || fail "a write during the reload gets its own reload (got $(reloads))"
s1="$(cat "$T/run/stamp")"; run; [ "$(reloads)" = 3 ] && [ "$(cat "$T/run/stamp")" = "$s1" ] || fail "stamp = the final files"
ok "a write during the reload → a second reload in the same run"

printf 'C\n' > "$T/tls/node.pem"; touch "$T/cfg_bad"
run; rc=$?; [ "$rc" = 1 ] && [ "$(reloads)" = 3 ] && [ "$(cat "$T/run/stamp")" = "$s1" ] || fail "haproxy -c failure: rc=$rc reloads=$(reloads)"
rm -f "$T/cfg_bad"; run; [ "$(reloads)" = 4 ] || fail "the next run after a fixed config reloads"
ok "haproxy -c rejects → no reload, stamp kept; the next run reloads"

touch "$T/reload_fails"; printf 'D\n' > "$T/tls/node.pem"; s2="$(cat "$T/run/stamp")"
run; rc=$?; [ "$rc" = 1 ] && [ "$(cat "$T/run/stamp")" = "$s2" ] || fail "a failed reload must keep the old stamp (rc=$rc)"
rm -f "$T/reload_fails"
ok "a failed reload → rc 1, the stamp is not moved"

n0="$(reloads)"; printf 'printf "%%s\\n" "$RANDOM$RANDOM" > "%s/tls/node.pem"\n' "$T" > "$T/on_reload"
run; [ $(( $(reloads) - n0 )) = 5 ] || fail "a file changing on every reload: at most 5 reloads per run (got $(( $(reloads) - n0 )))"
rm -f "$T/on_reload"
ok "endless writes → bounded at 5 reloads per run"

rm -f "$T/active"; run; [ ! -f "$T/run/stamp" ] || fail "stopped haproxy drops the stamp"
ok "haproxy stopped → the stamp is dropped (the next start stamps)"
echo "all passed"
