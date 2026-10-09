#!/usr/bin/env bash
# The per-GB haproxy cfg (pergb_runtime.js renderHaproxy; golden
# node_runtime/node_agent/testdata/pergb_haproxy.cfg.golden):
#   1. `haproxy -c` accepts the golden with a self-signed crt-list (any OS with
#      haproxy + openssl; off Linux the abstract socket becomes a unix socket);
#   2. live (Linux, root, ip netns; CI): haproxy runs the golden in a network
#      namespace with the egress 203.0.113.10 on lo — a TLS client on a shared
#      port reaches 127.0.0.3:<that port> decrypted, a SOCKS5 greeting reaches
#      127.0.0.4:<that port>, plain HTTP is rejected without reaching either,
#      and the log line carries the loopback tuple 3proxy logs (%bi:%bp).
# --require-all turns a skipped section into a failure.
#   bash scripts/test_pergb_haproxy.sh [--require-all]
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
GOLDEN="$ROOT_DIR/node_runtime/node_agent/testdata/pergb_haproxy.cfg.golden"
REQUIRE_ALL=0
[ "${1:-}" = "--require-all" ] && REQUIRE_ALL=1
TMP="$(mktemp -d)"
NS=""
cleanup() { [ -n "$NS" ] && ip netns del "$NS" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
skip() { [ "$REQUIRE_ALL" = 1 ] && fail "required section skipped: $1"; echo "skip: $1"; }

HAPROXY="$(command -v haproxy || true)"
if [ -z "$HAPROXY" ] || ! command -v openssl >/dev/null 2>&1; then
  skip "haproxy -c (needs haproxy and openssl)"
  echo "PASS ($PASS)"; exit 0
fi

cd "$TMP" || fail "cd $TMP"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout k.pem -out c.pem -days 2 \
  -subj /CN=203.0.113.10 >/dev/null 2>&1 || fail "openssl"
cat c.pem k.pem > node.pem
echo "$TMP/node.pem" > crt-list
mkdir -p run
# relative unix socket paths: the temp dir may be longer than sun_path allows
adapt() { # the golden for this machine: crt-list, run dir, (off Linux) no abns / user
  local s=(-e "s#/etc/netrun/tls/crt-list#$TMP/crt-list#" -e "s#stats socket /run/netrun-pergb/#stats socket unix@run/#")
  if [ "$(uname -s)" != Linux ]; then s+=(-e "s#abns@netrun_pergb_tls#unix@run/tls.sock#g"); fi
  if ! getent passwd haproxy >/dev/null 2>&1; then s+=(-e '/^    user haproxy$/d' -e '/^    group haproxy$/d'); fi
  sed "${s[@]}" "$@" "$GOLDEN"
}
adapt > check.cfg
out="$("$HAPROXY" -c -f check.cfg 2>&1)" || fail "haproxy -c rejects the golden: $out"
ok "haproxy -c accepts the per-GB golden ($("$HAPROXY" -v | head -n 1 | awk '{ print $3 }'))"

if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ] || ! ip netns list >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  skip "live routing (needs Linux, root, ip netns, python3)"
  echo "PASS ($PASS)"; exit 0
fi

NS="netrun-pergb-hap-$$"
ip netns add "$NS" || fail "ip netns add"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add 203.0.113.10/32 dev lo
adapt -e 's#^    log /dev/log local1 info#    log stdout format raw local1 info#' > live.cfg
cat > backends.py <<'PY'
# 3proxy-pergb stand-ins: 127.0.0.3:<p> (HTTP proxy) and 127.0.0.4:<p> (SOCKS)
import socket, sys, threading
log = open(sys.argv[1], "a", buffering=1)
def serve(addr, port, kind):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((addr, port)); s.listen(64)
    while True:
        c, peer = s.accept()
        try:
            c.settimeout(3)
            first = c.recv(64)
            log.write(f"{kind} {port} {peer[0]}:{peer[1]} {first[:8].hex()}\n")
            c.sendall(f"{kind}:{port}:{peer[0]}\n".encode())
        except OSError:
            pass
        c.close()
for p in range(31000, 31005):
    threading.Thread(target=serve, args=("127.0.0.3", p, "http"), daemon=True).start()
    threading.Thread(target=serve, args=("127.0.0.4", p, "socks"), daemon=True).start()
open(sys.argv[2], "w").write("up")
threading.Event().wait()
PY
cat > client.py <<'PY'
import socket, ssl, sys
kind, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection(("203.0.113.10", port), timeout=5)
try:
    if kind == "tls":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=None)
        s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
    elif kind == "socks":
        s.sendall(b"\x05\x01\x00")
    else:
        s.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
    print(s.recv(128).decode().strip() or "closed")
except (OSError, ssl.SSLError) as e:
    print(f"closed ({type(e).__name__})")
PY
ip netns exec "$NS" python3 backends.py "$TMP/backend.log" "$TMP/backends.up" & BACK=$!
ip netns exec "$NS" "$HAPROXY" -db -f live.cfg > "$TMP/haproxy.log" 2>&1 & HAP=$!
for _ in $(seq 1 50); do [ -s backends.up ] && ip netns exec "$NS" python3 -c 'import socket; socket.create_connection(("203.0.113.10", 31004), timeout=0.2)' 2>/dev/null && break; sleep 0.1; done
r1="$(ip netns exec "$NS" python3 client.py tls 31003)"
r2="$(ip netns exec "$NS" python3 client.py socks 31001)"
r3="$(ip netns exec "$NS" python3 client.py plain 31002)"
r4="$(ip netns exec "$NS" python3 client.py socks 31000)"
sleep 0.5
kill "$HAP" "$BACK" 2>/dev/null; wait "$HAP" 2>/dev/null
[ "$r1" = "http:31003:127.0.0.1" ] || fail "TLS on 31003 -> $r1 (want http:31003 via 127.0.0.3); haproxy: $(tail -n 5 haproxy.log)"
[ "$r2" = "socks:31001:127.0.0.1" ] || fail "SOCKS5 on 31001 -> $r2"
[ "$r4" = "socks:31000:127.0.0.1" ] || fail "SOCKS5 on the base port -> $r4"
case "$r3" in closed*) ;; *) fail "plain HTTP must be rejected, got: $r3" ;; esac
grep -q '^http 31003 127.0.0.1:' backend.log || fail "the HTTP backend saw no TLS-terminated session: $(cat backend.log)"
grep -q '^http 31003 .* 434f4e4e45435420$' backend.log || fail "the HTTP backend got the decrypted CONNECT: $(cat backend.log)"
grep -q ' 31002 ' backend.log && fail "plain HTTP reached a backend: $(cat backend.log)"
bp="$(awk '$1 == "socks" && $2 == 31001 { print $3 }' backend.log)"
grep -Eq "^203\.0\.113\.10:[0-9]+ 31001 ${bp//./\\.} [0-9]+ [0-9]+ [0-9]+$" haproxy.log \
  || fail "no log line '%ci:%cp %fp %bi:%bp %Tt %B %U' joining the client to the loopback tuple $bp: $(cat haproxy.log)"
ok "live: TLS -> 127.0.0.3:<port> decrypted, SOCKS5 -> 127.0.0.4:<port> (base port too), plain HTTP rejected, log joins client to the loopback tuple"
echo "PASS ($PASS)"
