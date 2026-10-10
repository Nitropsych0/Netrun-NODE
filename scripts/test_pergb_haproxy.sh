#!/usr/bin/env bash
# The per-GB haproxy cfg (pergb_runtime.js renderHaproxy; golden
# node_runtime/node_agent/testdata/pergb_haproxy.cfg.golden):
#   1. `haproxy -c` accepts the golden with a self-signed crt-list (any OS with
#      haproxy + openssl; off Linux the abstract socket becomes a unix socket);
#   2. live routing (Linux, root, ip netns, python3; CI): haproxy runs the
#      golden in a network namespace with the egress 203.0.113.10 on lo and
#      stand-in backends on 127.0.0.3/4:31000-31004 — a TLS client on a shared
#      port reaches 127.0.0.3:<that port> decrypted, a SOCKS5 greeting reaches
#      127.0.0.4:<that port>, a plain HTTP-proxy request (CONNECT, absolute-URI
#      GET, OPTIONS, a first packet split inside the method) reaches
#      127.0.0.3:<that port> as sent, anything else (text, an SSH banner,
#      binary, a lower-case method, the HTTP/2 preface) is rejected at once and
#      a method that never completes at the inspect-delay, without reaching
#      either backend; the log line carries the loopback tuple 3proxy logs
#      (%bi:%bp);
#   3. end to end (as 2, plus the committed deploy/node/bin/3proxy-pergb or
#      $PERGB_3PROXY_BIN): the golden 3proxy cfg (its ports 31005-31009) behind
#      the same haproxy, a RADIUS stand-in on 127.0.0.1:1812 (one login;
#      node_runtime/radius/proto.py) and an origin on 198.51.100.20:8080 —
#      plain HTTP CONNECT and absolute-URI GET / POST with the login work,
#      without a login or with a wrong password they get 407 exactly like
#      over TLS, TLS and SOCKS5 work as before; RADIUS gets the same
#      Access-Request from the plain and the TLS path (NAS-Port = the dialed
#      port, NAS-IP 127.0.0.3, client = a hop source 127.0.1.x), 3proxy writes the same
#      record (the meter's input) and haproxy's line joins the client to it
#      (attribution).
# --require-all turns a skipped section into a failure.
#   bash scripts/test_pergb_haproxy.sh [--require-all]
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
GOLDEN="$ROOT_DIR/node_runtime/node_agent/testdata/pergb_haproxy.cfg.golden"
GOLDEN_3PROXY="$ROOT_DIR/node_runtime/node_agent/testdata/pergb_31000.cfg.golden"
RADIUS_LIB="$ROOT_DIR/node_runtime/radius"
BIN3="${PERGB_3PROXY_BIN:-$ROOT_DIR/deploy/node/bin/3proxy-pergb}"
REQUIRE_ALL=0
[ "${1:-}" = "--require-all" ] && REQUIRE_ALL=1
TMP="$(mktemp -d)"
NS=""
cleanup() { [ -n "$NS" ] && { ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$NS" 2>/dev/null; }; rm -rf "$TMP"; }
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
  skip "end to end through 3proxy-pergb (needs Linux, root, ip netns, python3)"
  echo "PASS ($PASS)"; exit 0
fi

NS="netrun-pergb-hap-$$"
ip netns add "$NS" || fail "ip netns add"
nsx() { ip netns exec "$NS" "$@"; }
nsx ip link set lo up
nsx ip addr add 203.0.113.10/32 dev lo
nsx ip addr add 198.51.100.20/32 dev lo   # the origin of section 3
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
# one connection to 203.0.113.10:<port>: what the backend answered, else
# "closed" (+ "-slow" when the close took longer than 2 s) — or, for
# kind "stall", the seconds until haproxy closed it
import socket, ssl, sys, time
kind, port = sys.argv[1], int(sys.argv[2])
SEND = {
    "socks": b"\x05\x01\x00",
    "connect": b"CONNECT 198.51.100.20:8080 HTTP/1.1\r\nHost: 198.51.100.20:8080\r\n\r\n",
    "get": b"GET http://198.51.100.20:8080/abs HTTP/1.1\r\nHost: 198.51.100.20:8080\r\n\r\n",
    "options": b"OPTIONS http://198.51.100.20:8080/ HTTP/1.1\r\nHost: 198.51.100.20:8080\r\n\r\n",
    "text": b"hello world\r\n",
    "ssh": b"SSH-2.0-OpenSSH_9.6\r\n",
    "binary": bytes(range(16)),
    "lower": b"get http://198.51.100.20:8080/ HTTP/1.1\r\n\r\n",
    "h2": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
}
t0 = time.monotonic()
s = socket.create_connection(("203.0.113.10", port), timeout=10)
try:
    if kind == "tls":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=None)
        s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
    elif kind == "split":  # the first packet ends inside the method
        for part in (b"CO", b"NN", b"ECT 198.51.100.20:8080 HTTP/1.1\r\n\r\n"):
            s.sendall(part); time.sleep(0.3)
    elif kind == "stall":  # a method that never completes
        s.sendall(b"GE")
        try:
            got = s.recv(128).decode().strip() or "closed"
        except OSError:
            got = "closed"
        print(f"{got} {time.monotonic() - t0:.1f}"); sys.exit(0)
    else:
        s.sendall(SEND[kind])
    got = s.recv(128).decode().strip()
    print(got or ("closed" if time.monotonic() - t0 < 2 else "closed-slow"))
except (OSError, ssl.SSLError) as e:
    print(f"closed ({type(e).__name__})" if time.monotonic() - t0 < 2 else "closed-slow")
PY
nsx python3 backends.py "$TMP/backend.log" "$TMP/backends.up" & BACK=$!
nsx "$HAPROXY" -db -f live.cfg > "$TMP/haproxy.log" 2>&1 & HAP=$!
for _ in $(seq 1 50); do [ -s backends.up ] && nsx python3 -c 'import socket; socket.create_connection(("203.0.113.10", 31004), timeout=0.2)' 2>/dev/null && break; sleep 0.1; done
r1="$(nsx python3 client.py tls 31003)"
r2="$(nsx python3 client.py socks 31001)"
r4="$(nsx python3 client.py socks 31000)"
h1="$(nsx python3 client.py connect 31002)"
h2="$(nsx python3 client.py get 31004)"
h3="$(nsx python3 client.py options 31001)"
h4="$(nsx python3 client.py split 31000)"
g=()
for k in text ssh binary lower h2; do g+=("$k=$(nsx python3 client.py "$k" 31002)"); done
st="$(nsx python3 client.py stall 31003)"
sleep 0.5
kill "$BACK" 2>/dev/null
# the hop leaves from one of the 8 loopback sources of its backend
# (pergb_runtime.HOP_SOURCES: 127.0.1.<k> to the HTTP proxy, 127.0.2.<k> to SOCKS)
HTTP_SRC='127\.0\.1\.[1-8]'
SOCKS_SRC='127\.0\.2\.[1-8]'
[[ "$r1" =~ ^http:31003:${HTTP_SRC}$ ]] || fail "TLS on 31003 -> $r1 (want http:31003 via 127.0.0.3 from 127.0.1.x); haproxy: $(tail -n 5 haproxy.log)"
[[ "$r2" =~ ^socks:31001:${SOCKS_SRC}$ ]] || fail "SOCKS5 on 31001 -> $r2"
[[ "$r4" =~ ^socks:31000:${SOCKS_SRC}$ ]] || fail "SOCKS5 on the base port -> $r4"
[[ "$h1" =~ ^http:31002:${HTTP_SRC}$ ]] || fail "plain HTTP CONNECT on 31002 -> $h1 (want the HTTP proxy 127.0.0.3:31002)"
[[ "$h2" =~ ^http:31004:${HTTP_SRC}$ ]] || fail "absolute-URI GET on 31004 -> $h2"
[[ "$h3" =~ ^http:31001:${HTTP_SRC}$ ]] || fail "absolute-URI OPTIONS on 31001 -> $h3"
[[ "$h4" =~ ^http:31000:${HTTP_SRC}$ ]] || fail "a CONNECT split inside the method on the base port -> $h4"
# leastconn over equal (idle) servers rotates: the hop really spreads
srcs="$(printf '%s\n' "$r1" "$h1" "$h2" "$h3" "$h4" | cut -d: -f3 | sort -u | wc -l)"
[ "$srcs" -ge 2 ] || fail "every HTTP hop left from one source ($r1 $h1 $h2 $h3 $h4): the 6976-per-port cap is back"
for x in "${g[@]}"; do
  case "${x#*=}" in "closed"|"closed ("*) ;; *) fail "${x%%=*} must be rejected at once, got: ${x#*=}" ;; esac
done
read -r st_what st_secs <<< "$st"
[ "$st_what" = closed ] && awk -v s="$st_secs" 'BEGIN { exit !(s >= 3 && s <= 9) }' \
  || fail "an incomplete method must be dropped at the 5 s inspect-delay, got: $st"
grep -Eq '^http 31003 127\.0\.1\.[1-8]:' backend.log || fail "the HTTP backend saw no TLS-terminated session: $(cat backend.log)"
grep -q '^http 31003 .* 434f4e4e45435420$' backend.log || fail "the HTTP backend got the decrypted CONNECT: $(cat backend.log)"
grep -q '^http 31002 .* 434f4e4e45435420$' backend.log || fail "the HTTP backend got the plain CONNECT as sent: $(cat backend.log)"
grep -q '^http 31004 .* 4745542068747470$' backend.log || fail "the HTTP backend got the plain 'GET http': $(cat backend.log)"
grep -q '^http 31000 .* 434f4e4e45435420$' backend.log || fail "the split CONNECT arrived whole: $(cat backend.log)"
[ "$(grep -c ' 31002 ' backend.log)" = 1 ] || fail "only the CONNECT may reach a backend on 31002 (the rejected kinds must not): $(cat backend.log)"
[ "$(grep -c '^http 31003 ' backend.log)" = 1 ] || fail "the stalled method reached a backend: $(cat backend.log)"
[ "$(grep -c '^socks ' backend.log)" = 2 ] && [ "$(grep -c '^socks .* 050100$' backend.log)" = 2 ] \
  || fail "the SOCKS backend must see the two SOCKS5 greetings and nothing else: $(cat backend.log)"
bp="$(awk '$1 == "socks" && $2 == 31001 { print $3 }' backend.log)"
grep -Eq "^203\.0\.113\.10:[0-9]+ 31001 ${bp//./\\.} [0-9]+ [0-9]+ [0-9]+$" haproxy.log \
  || fail "no log line '%ci:%cp %fp %bi:%bp %Tt %B %U' joining the client to the loopback tuple $bp: $(cat haproxy.log)"
hp="$(awk '$1 == "http" && $2 == 31002 { print $3 }' backend.log)"
grep -Eq "^203\.0\.113\.10:[0-9]+ 31002 ${hp//./\\.} [0-9]+ [0-9]+ [0-9]+$" haproxy.log \
  || fail "no log line joining the plain HTTP client to the loopback tuple $hp: $(cat haproxy.log)"
ok "live: TLS -> 127.0.0.3:<port> decrypted, SOCKS5 -> 127.0.0.4:<port> (base port too), plain HTTP (CONNECT, absolute GET/OPTIONS, split first packet) -> 127.0.0.3:<port> as sent, text/SSH/binary/lower-case/h2 rejected at once and a stalled method at the inspect-delay, log joins client to the loopback tuple"

# ── 3. end to end through 3proxy-pergb ──────────────────────────────────────
# the committed binary is x86-64 Linux; node reads 3proxy's records with the meter's parser
if [ ! -x "$BIN3" ] || { [ -z "${PERGB_3PROXY_BIN:-}" ] && [ "$(uname -m)" != x86_64 ]; } || ! command -v node >/dev/null 2>&1; then
  kill "$HAP" 2>/dev/null; wait "$HAP" 2>/dev/null
  skip "end to end through 3proxy-pergb (needs a runnable $BIN3 and node)"
  echo "PASS ($PASS)"; exit 0
fi
SECRET="$(awk '$1 == "radius" { print $2 }' "$GOLDEN_3PROXY")"
LOGIN="netrun-plainhttp"
PW="PlainHttpPassw0rd"
mkdir -p 3plog
# the golden cfg, its ports 31005-31009 only (31000-31004 are the stand-ins'), logs here
sed "s#^log /var/log/netrun-pergb/#log $TMP/3plog/#" "$GOLDEN_3PROXY" | awk '
  /^(socks|proxy) / { if (match($0, /-p[0-9]+/)) { p = substr($0, RSTART + 2, RLENGTH - 2) + 0; if (p >= 31005 && p <= 31009) print } next }
  { print }' > pergb_31000.cfg
grep -q "^log $TMP/3plog/p31000.log H$" pergb_31000.cfg || fail "the 3proxy cfg log line was not adapted: $(head -n 8 pergb_31000.cfg)"
[ "$(grep -c '^proxy ' pergb_31000.cfg)" = 5 ] || fail "the 3proxy cfg must keep 5 HTTP listeners: $(grep '^proxy ' pergb_31000.cfg)"
cat > radius.py <<'PY'
# netrun-radius stand-in: Accept (Framed-IP-Address = the egress IPv4, as
# netrun-radius answers an IPv4 destination) for one login, Reject otherwise;
# every Access-Request is logged as JSON (password and session id left out)
import json, socket, sys
sys.path.insert(0, sys.argv[1])
import proto
secret, logf, upf, user, pw = sys.argv[2].encode(), sys.argv[3], sys.argv[4], sys.argv[5].encode(), sys.argv[6].encode()
log = open(logf, "a", buffering=1)
NAMES = {4: "nas_ip", 5: "nas_port", 6: "service_type", 8: "client", 14: "dst", 15: "login_service", 16: "dst_port", 30: "called", 32: "nas_id", 61: "nas_port_type", 95: "nas_ip6", 98: "dst6", 168: "client6"}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 1812))
open(upf, "w").write("up")
while True:
    data, peer = s.recvfrom(4096)
    try:
        req = proto.decode_request(data)
        got = proto.decode_password(req.password_enc, secret, req.authenticator)
    except proto.ProtoError:
        continue
    rec = {"user": (req.username or b"").decode("latin1"), "accept": req.username == user and got == pw}
    for t, v in proto.reply_attrs(req.raw):
        name = NAMES.get(t)
        if name is None or name in rec:
            continue
        if t in (4, 8, 14):
            rec[name] = socket.inet_ntop(socket.AF_INET, v)
        elif t in (95, 98, 168):
            rec[name] = socket.inet_ntop(socket.AF_INET6, v)
        elif t in (5, 6, 15, 16, 61):
            rec[name] = int.from_bytes(v, "big")
        else:
            rec[name] = v.decode("latin1")
    log.write(json.dumps(rec, sort_keys=True) + "\n")
    s.sendto(proto.accept_v4(req, secret, socket.inet_aton("203.0.113.10")) if rec["accept"] else proto.reject(req, secret), peer)
PY
cat > origin.py <<'PY'
# the origin 198.51.100.20:8080: answers every request with the address it
# came from, the request line and the body
import socket, sys, threading
def handle(c, peer):
    try:
        c.settimeout(5)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                return
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        n = 0
        for h in lines[1:]:
            k, _, v = h.partition(b":")
            if k.strip().lower() == b"content-length":
                n = int(v.strip())
        while len(rest) < n:
            d = c.recv(4096)
            if not d:
                break
            rest += d
        body = f"origin peer={peer[0]} line={lines[0].decode('latin1')} body={rest[:n].decode('latin1')}\n".encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    except OSError:
        pass
    finally:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("198.51.100.20", 8080)); s.listen(64)
open(sys.argv[1], "w").write("up")
while True:
    c, peer = s.accept()
    threading.Thread(target=handle, args=(c, peer), daemon=True).start()
PY
cat > e2e.py <<'PY'
# e2e.py <how> <port> [user pass]: one proxied request through 203.0.113.10:<port>;
# prints "<proxy status line>|<the origin's line or nothing>"
# how: connect | get | post (plain HTTP), tls-connect | tls-get (HTTPS proxy), socks
import base64, socket, ssl, struct, sys
how, port = sys.argv[1], int(sys.argv[2])
user, pw = (sys.argv[3], sys.argv[4]) if len(sys.argv) > 4 else (None, None)
TARGET = "198.51.100.20:8080"
auth = "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(f"{user}:{pw}".encode()).decode() if user else ""
def head(s):
    b = b""
    while b"\r\n\r\n" not in b:
        d = s.recv(1)  # byte by byte: the tunnel's data stays in the socket
        if not d:
            break
        b += d
    return b.decode("latin1").split("\r\n", 1)[0]
def rest(s, st=" 200 "):
    if " 200 " not in st + " ":
        s.settimeout(3)  # a refusal: whatever follows, without waiting for a keep-alive
    b = b""
    while True:
        try:
            d = s.recv(4096)
        except (OSError, ssl.SSLError):
            break
        if not d:
            break
        b += d
    return next((l for l in b.decode("latin1").split("\n") if l.startswith("origin ")), "")
def origin_get(s, path):
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {TARGET}\r\nConnection: close\r\n\r\n".encode())
    st = head(s)
    return st, rest(s)
s = socket.create_connection(("203.0.113.10", port), timeout=10)
try:
    if how.startswith("tls-"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=None)
        how = how[4:]
    if how == "connect":
        s.sendall(f"CONNECT {TARGET} HTTP/1.1\r\nHost: {TARGET}\r\n{auth}\r\n".encode())
        st = head(s)
        line = origin_get(s, "/tunnel")[1] if " 200 " in st + " " else rest(s, st)
        print(f"{st}|{line}")
    elif how in ("get", "post"):
        body = "hello=1" if how == "post" else ""
        s.sendall(f"{how.upper()} http://{TARGET}/abs?x=1 HTTP/1.1\r\nHost: {TARGET}\r\n{auth}Connection: close\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode())
        st = head(s)
        print(f"{st}|{rest(s, st)}")
    elif how == "socks":
        s.sendall(b"\x05\x01\x02")
        if s.recv(2) != b"\x05\x02":
            print("socks: no user/pass method|"); sys.exit(0)
        u, p = user.encode(), pw.encode()
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        a = s.recv(2)
        if len(a) != 2 or a[1] != 0:
            print("socks: auth refused|"); sys.exit(0)
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("198.51.100.20") + struct.pack("!H", 8080))
        r = s.recv(10)
        if len(r) < 2 or r[1] != 0:
            print(f"socks: connect refused {r.hex()}|"); sys.exit(0)
        print(f"socks: ok|{origin_get(s, '/socks')[1]}")
except (OSError, ssl.SSLError) as e:
    print(f"error {type(e).__name__}: {e}|")
PY
nsx python3 -I radius.py "$RADIUS_LIB" "$SECRET" "$TMP/radius.log" "$TMP/radius.up" "$LOGIN" "$PW" > radius.out 2>&1 &
nsx python3 -I origin.py "$TMP/origin.up" > origin.out 2>&1 &
nsx "$BIN3" "$TMP/pergb_31000.cfg" > 3proxy.out 2>&1 &
for _ in $(seq 1 50); do
  [ -s radius.up ] && [ -s origin.up ] && nsx python3 -c 'import socket; socket.create_connection(("127.0.0.3", 31009), timeout=0.2); socket.create_connection(("127.0.0.4", 31005), timeout=0.2)' 2>/dev/null && break
  sleep 0.1
done
[ -s radius.up ] || fail "the RADIUS stand-in did not start: $(cat radius.out)"
nsx python3 -c 'import socket; socket.create_connection(("127.0.0.3", 31009), timeout=1)' 2>/dev/null || fail "3proxy-pergb did not start: $(tail -n 20 3proxy.out)"
e2e() { nsx python3 -I e2e.py "$@"; }
ORIGIN="origin peer=203\.0\.113\.10 line="
expect() { # name, output, regex
  [[ "$2" =~ $3 ]] || fail "$1: got '$2', want /$3/; 3proxy: $(tail -n 5 3proxy.out) radius: $(tail -n 3 radius.log 2>/dev/null)"
}
S200='^HTTP/1\.[01] 200 '
S407='^HTTP/1\.[01] 407 [^|]*\|$'
expect "plain CONNECT with the login" "$(e2e connect 31006 "$LOGIN" "$PW")" "${S200}.*\|${ORIGIN}GET /tunnel HTTP/1\.1 body=$"
expect "plain CONNECT without a login" "$(e2e connect 31006)" "$S407"
expect "plain CONNECT with a wrong password" "$(e2e connect 31006 "$LOGIN" wrong-password)" "$S407"
expect "plain absolute-URI GET with the login" "$(e2e get 31008 "$LOGIN" "$PW")" "${S200}.*\|${ORIGIN}GET (http://198\.51\.100\.20:8080)?/abs\?x=1 HTTP/1\.[01] body=$"
expect "plain absolute-URI POST with the login" "$(e2e post 31009 "$LOGIN" "$PW")" "${S200}.*\|${ORIGIN}POST (http://198\.51\.100\.20:8080)?/abs\?x=1 HTTP/1\.[01] body=hello=1$"
expect "plain absolute-URI GET without a login" "$(e2e get 31008)" "$S407"
expect "plain absolute-URI GET with a wrong password" "$(e2e get 31008 "$LOGIN" wrong-password)" "$S407"
expect "TLS CONNECT with the login" "$(e2e tls-connect 31007 "$LOGIN" "$PW")" "${S200}.*\|${ORIGIN}GET /tunnel HTTP/1\.1 body=$"
expect "TLS CONNECT without a login" "$(e2e tls-connect 31007)" "$S407"
expect "TLS CONNECT with a wrong password" "$(e2e tls-connect 31007 "$LOGIN" wrong-password)" "$S407"
expect "TLS absolute-URI GET with the login" "$(e2e tls-get 31008 "$LOGIN" "$PW")" "${S200}.*\|${ORIGIN}GET (http://198\.51\.100\.20:8080)?/abs\?x=1 HTTP/1\.[01] body=$"
expect "SOCKS5 with the login" "$(e2e socks 31005 "$LOGIN" "$PW")" "^socks: ok\|${ORIGIN}GET /socks HTTP/1\.1 body=$"
expect "SOCKS5 with a wrong password" "$(e2e socks 31005 "$LOGIN" wrong-password)" "^socks: (auth|connect) refused[^|]*\|$"
ok "e2e: plain HTTP CONNECT / absolute GET / POST through 3proxy-pergb with the login, 407 without one or with a wrong password — the same as over TLS; SOCKS5 unchanged"

# RADIUS saw the plain and the TLS CONNECT alike (only the dialed port differs);
# 3proxy logged them alike; haproxy's line joins the plain client to 3proxy's record
sleep 1
kill "$HAP" 2>/dev/null; wait "$HAP" 2>/dev/null
# 3proxy's records through the meter's own parser (pergb_meter.parseRecord)
cat > records.js <<'JS'
const fs = require("fs");
const path = require("path");
const meter = require(process.argv[2]);
const out = [];
for (const f of fs.readdirSync(process.argv[3])) {
  for (const line of fs.readFileSync(path.join(process.argv[3], f), "utf8").split("\n")) {
    if (!line) continue;
    const r = meter.parseRecord(line);
    out.push(r ? { ok: true, ...r } : { ok: false, line });
  }
}
process.stdout.write(JSON.stringify(out));
JS
node records.js "$ROOT_DIR/node_runtime/node_agent/pergb_meter.js" "$TMP/3plog" > records.json || fail "the meter parser: $(cat records.json)"
cat > check.py <<'PY'
import json, re, sys
tmp, login = sys.argv[1], sys.argv[2]
def die(msg):
    print(msg); sys.exit(1)
radius = [json.loads(l) for l in open(f"{tmp}/radius.log")]
def one(port, accept):
    r = [x for x in radius if x.get("nas_port") == port and x["user"] == login and x["accept"] is accept]
    return r[0] if r else die(f"no {'accepted' if accept else 'rejected'} Access-Request from port {port}: {radius}")
plain, tls = one(31006, True), one(31007, True)
for want in (("nas_port", 31006), ("nas_ip", "127.0.0.3"), ("dst", "198.51.100.20")):
    if plain.get(want[0]) != want[1]:
        die(f"plain HTTP Access-Request: {want[0]} = {plain.get(want[0])}, want {want[1]}: {plain}")
# the client is the hop's loopback source (one of 127.0.1.1-8), per connection
for r in (plain, tls):
    if not re.fullmatch(r"127\.0\.1\.[1-8]", str(r.get("client"))):
        die(f"Access-Request client {r.get('client')} is no hop source 127.0.1.x: {r}")
strip = lambda r: {k: v for k, v in r.items() if k not in ("nas_port", "client")}
if strip(plain) != strip(tls):
    die(f"the plain and the TLS CONNECT differ beyond NAS-Port:\n plain {plain}\n tls   {tls}")
one(31006, False)  # the wrong password went to RADIUS too
one(31008, False)
recs = json.load(open(f"{tmp}/records.json"))  # {ok: false, line} = a line the meter skips
def rec(port):
    r = [x for x in recs if x["ok"] and x["port"] == port and x["user"] == login and x["dstIp"] == "198.51.100.20" and x["inBytes"] > 0 and x["outBytes"] > 0]
    return r[0] if r else die(f"no 3proxy record with bytes for {login} on {port}: {recs}")
p3, t3 = rec(31006), rec(31007)
for k in ("service", "user", "login", "localIp", "bound", "dstIp", "dstPort"):
    if p3[k] != t3[k]:
        die(f"3proxy records differ in {k}: plain {p3} / tls {t3}")
if (p3["login"], p3["localIp"], p3["bound"]) != (login, "127.0.0.3", "203.0.113.10") or not re.fullmatch(r"127\.0\.1\.[1-8]", p3["clientIp"]):
    die(f"3proxy record of the plain CONNECT: {p3}")
rec(31008); rec(31009)
hap = open(f"{tmp}/haproxy.log").read()
if not re.search(r"^203\.0\.113\.10:\d+ 31006 %s:%d \d+ \d+ \d+$" % (re.escape(p3["clientIp"]), p3["clientPort"]), hap, re.M):
    die(f"no haproxy line '<client> 31006 {p3['clientIp']}:{p3['clientPort']} ...' for the plain CONNECT 3proxy logged:\n{hap}")
print(f"radius {plain} | 3proxy {p3['service']} {p3['port']} {p3['clientIp']}:{p3['clientPort']} -> {p3['localIp']} as {p3['login']}")
PY
res="$(python3 -I check.py "$TMP" "$LOGIN")" || fail "$res"
echo "  $res"
ok "e2e: RADIUS gets the same Access-Request from plain HTTP as from TLS (NAS-Port = the dialed port, NAS-IP 127.0.0.3, client = the hop source 127.0.1.x; a wrong password reaches RADIUS), 3proxy logs the same record, haproxy's line joins the client to it"
echo "PASS ($PASS)"
