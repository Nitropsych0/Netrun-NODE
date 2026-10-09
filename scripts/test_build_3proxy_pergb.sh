#!/usr/bin/env bash
# The per-GB 3proxy (deploy/node/bin/3proxy-pergb, plan D15):
#   1. the patch applies cleanly to the pinned upstream 3proxy 0.9.3 tarball,
#      and the committed .sha256 names the committed binary;
#   2. reproducible: scripts/build_3proxy_pergb.sh --check rebuilds it in Docker
#      and gets the pinned sha256 (needs docker);
#   3. the golden per-GB cfg (testdata/pergb_31000.cfg.golden: `authcache none`,
#      `auth radius`, the 0.9.3 ACL names, 1000 listeners) parses and serves
#      (Linux);
#   4. 100k distinct logins through RADIUS in a network namespace: the patched
#      binary's RSS stays flat, the stock binary (deploy/node/bin/3proxy, same
#      cfg) grows — its auth cache keeps one entry per login (Linux, root).
# Sections whose tools are missing are skipped; --require-all turns a skip into
# a failure (CI: .github/workflows/pergb-linux.yml).
#   bash scripts/test_build_3proxy_pergb.sh [--require-all] [--skip-build | --rebuilt DIR]
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
PATCH="$ROOT_DIR/deploy/node/3proxy-pergb/netrun-pergb.patch"
PERGB_BIN="$ROOT_DIR/deploy/node/bin/3proxy-pergb"
PERGB_SUMS="$ROOT_DIR/deploy/node/bin/3proxy-pergb.sha256"
STOCK_BIN="$ROOT_DIR/deploy/node/bin/3proxy"
GOLDEN="$ROOT_DIR/node_runtime/node_agent/testdata/pergb_31000.cfg.golden"
TARBALL_URL="https://github.com/3proxy/3proxy/archive/refs/tags/0.9.3.tar.gz"
TARBALL_SHA256="$(sed -n 's/^TARBALL_SHA256="\([0-9a-f]*\)"$/\1/p' "$ROOT_DIR/scripts/build_3proxy_pergb.sh")"
N_PATCHED="${PERGB_SMOKE_N:-100000}"
N_STOCK="${PERGB_SMOKE_N_STOCK:-40000}"
WARMUP="${PERGB_SMOKE_WARMUP:-5000}"

REQUIRE_ALL=0
SKIP_BUILD=0
REBUILT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --require-all) REQUIRE_ALL=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --rebuilt) REBUILT="$2"; shift ;;  # a build_3proxy_pergb.sh --out DIR made in this run
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

TMP="$(mktemp -d)"
NS=""
cleanup() {
  [ -n "$NS" ] && ip netns del "$NS" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
skip() {
  if [ "$REQUIRE_ALL" = 1 ]; then fail "required section skipped: $1"; fi
  echo "skip: $1"
}
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# ── 1. the patch and the pinned hash ──────────────────────────────
[ -n "$TARBALL_SHA256" ] || fail "no TARBALL_SHA256 in build_3proxy_pergb.sh"
if command -v curl >/dev/null 2>&1 && command -v patch >/dev/null 2>&1; then
  curl -fsSL --retry 3 -o "$TMP/3proxy.tar.gz" "$TARBALL_URL" || fail "download $TARBALL_URL"
  [ "$(sha256_of "$TMP/3proxy.tar.gz")" = "$TARBALL_SHA256" ] || fail "tarball sha256 differs from the pinned one"
  mkdir -p "$TMP/src" && tar -xzf "$TMP/3proxy.tar.gz" -C "$TMP/src" || fail "untar"
  out="$(cd "$TMP/src/3proxy-0.9.3" && patch -p1 --no-backup-if-mismatch < "$PATCH" 2>&1)" || fail "patch does not apply: $out"
  printf '%s\n' "$out" | grep -Eiq 'fuzz|offset|hunk.*(failed|ignored)' && fail "patch applies only with fuzz/offset: $out"
  grep -q 'if(!strcmp((char \*) \*(argv + 1), "none")) return 0;' "$TMP/src/3proxy-0.9.3/src/conf.c" || fail "authcache none in conf.c"
  grep -q 'IP_BIND_ADDRESS_NO_PORT' "$TMP/src/3proxy-0.9.3/src/common.c" || fail "IP_BIND_ADDRESS_NO_PORT in common.c"
  ok "the patch applies cleanly to 3proxy 0.9.3 (sha256 $TARBALL_SHA256)"
else
  skip "patch check (needs curl and patch)"
fi
[ -f "$PERGB_BIN" ] && [ -f "$PERGB_SUMS" ] || fail "missing $PERGB_BIN or its .sha256"
pinned="$(cut -d' ' -f1 "$PERGB_SUMS")"
[[ "$pinned" =~ ^[0-9a-f]{64}$ ]] || fail "bad pinned sha256: $pinned"
[ "$(sha256_of "$PERGB_BIN")" = "$pinned" ] || fail "the committed binary does not match its pinned sha256"
grep -Eq '^[0-9a-f]{64}  3proxy-pergb$' "$PERGB_SUMS" || fail "the .sha256 is not a sha256sum line for 3proxy-pergb"
[ "$(sha256_of "$PERGB_BIN")" != "$(sha256_of "$STOCK_BIN")" ] || fail "3proxy-pergb is the stock binary"
ok "deploy/node/bin/3proxy-pergb matches the pinned $pinned"

# ── 2. reproducible ───────────────────────────────────────────────
if [ -n "$REBUILT" ]; then
  got="$(sha256_of "$REBUILT/3proxy-pergb")"
  [ "$got" = "$pinned" ] || fail "NOT reproducible: the rebuild in $REBUILT is $got, pinned $pinned"
  ok "rebuilt in Docker (build_3proxy_pergb.sh --out): sha256 equals the pinned one"
elif [ "$SKIP_BUILD" = 1 ]; then
  echo "skip: rebuild (--skip-build)"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  bash "$ROOT_DIR/scripts/build_3proxy_pergb.sh" --check || fail "the rebuild differs from the pinned binary"
  ok "rebuilt in Docker: sha256 equals the pinned one"
else
  skip "reproducible rebuild (needs docker)"
fi

# ── 3. the golden cfg parses and serves ───────────────────────────
linux_bin_ok() { [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] && [ -x "$1" ]; }
SECRET="SmokeSecretSmokeSecretSmokeSecret0123456"
# The golden cfg with the egress on loopback and the log in $TMP.
smoke_cfg() {
  sed -e 's/203\.0\.113\.10/127.0.0.1/g' -e "s#/var/log/netrun-pergb/#$1/#" \
      -e "s/GoldenSecretGoldenSecretGoldenSecret0123/$SECRET/" "$GOLDEN"
}
wait_port() { # addr port
  python3 - "$1" "$2" <<'WAIT'
import socket, sys, time
for _ in range(100):
    try:
        socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=0.2).close(); sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
WAIT
}
if linux_bin_ok "$PERGB_BIN" && command -v python3 >/dev/null 2>&1; then
  mkdir -p "$TMP/log3"
  smoke_cfg "$TMP/log3" > "$TMP/parse.cfg"
  grep -q '^authcache none$' "$TMP/parse.cfg" || fail "golden has authcache none"
  "$PERGB_BIN" "$TMP/parse.cfg" > "$TMP/parse.out" 2>&1 & P=$!
  wait_port 127.0.0.4 31499 || { cat "$TMP/parse.out"; kill "$P" 2>/dev/null; fail "3proxy-pergb does not serve the golden cfg"; }
  wait_port 127.0.0.3 31000 || { kill "$P" 2>/dev/null; fail "HTTP listener"; }
  kill "$P"; wait "$P" 2>/dev/null
  grep -Eiq 'failed|unknown|invalid' "$TMP/parse.out" && fail "parse errors: $(cat "$TMP/parse.out")"
  ok "the golden cfg (authcache none, auth radius, 0.9.3 ACL, 1000 listeners) parses and listens"
else
  skip "golden cfg parse (needs Linux x86_64 and python3)"
fi

# ── 4. 100k distinct logins: RSS flat (patched) vs growing (stock) ──
if linux_bin_ok "$PERGB_BIN" && [ "$(id -u)" = 0 ] && ip netns list >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  NS="netrun-pergb-smoke-$$"
  ip netns add "$NS" || fail "ip netns add"
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" sysctl -qw net.ipv4.ip_local_port_range="1024 65000" net.ipv4.tcp_tw_reuse=1 >/dev/null || true
  cat > "$TMP/radius.py" <<'RAD'
# Accept-everything RADIUS (RFC 2865 response authenticator), Framed-IP-Address 127.0.0.1.
import hashlib, socket, struct, sys
secret = sys.argv[1].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.bind(("127.0.0.1", 1812))
open(sys.argv[2], "w").write("up")
attrs = bytes([8, 6]) + socket.inet_aton("127.0.0.1")
while True:
    d, a = s.recvfrom(4096)
    if len(d) < 20 or d[0] != 1:
        continue
    hdr = struct.pack("!BBH", 2, d[1], 20 + len(attrs))
    s.sendto(hdr + hashlib.md5(hdr + d[4:20] + attrs + secret).digest() + attrs, a)
RAD
  # The destination closes first: TIME_WAIT lands on its side, so neither
  # binary runs out of source ports on 127.0.0.1 during the run.
  cat > "$TMP/sink.py" <<'SINK'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9999)); s.listen(4096)
open(sys.argv[1], "w").write("up")
while True:
    c, _ = s.accept()
    c.close()
SINK
  cat > "$TMP/load.py" <<'LOAD'
# N SOCKS5 sessions with distinct logins (user/pass auth) through 127.0.0.4:31000..31009.
# A shared CI runner also hosts the RADIUS stub, the sink and this client, so a
# session gets ONE retry (same login) before it counts as failed; the failure
# reasons go to stderr so a real 3proxy problem is visible, not just a count.
import asyncio, collections, socket, struct, sys
start, n, conc = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
ok = 0
why = collections.Counter()
async def attempt(i):
    r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.4", 31000 + i % 10), 5)
    try:
        user = f"netrun-smoke{i:08d}-session-s{i:05d}".encode()
        w.write(b"\x05\x01\x02"); await w.drain()
        if await asyncio.wait_for(r.readexactly(2), 5) != b"\x05\x02":
            raise ValueError("method")
        w.write(bytes([1, len(user)]) + user + bytes([8]) + b"password"); await w.drain()
        if (await asyncio.wait_for(r.readexactly(2), 5))[1] != 0:
            raise ValueError("auth")
        w.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 9999)); await w.drain()
        rep = await asyncio.wait_for(r.readexactly(10), 5)
        if rep[1] != 0:
            raise ValueError(f"socks_reply_{rep[1]}")
    finally:
        w.close()
async def one(i):
    global ok
    for k in (1, 2):
        try:
            await attempt(i)
            ok += 1
            return
        except Exception as exc:
            if k == 2:
                why[f"{type(exc).__name__}:{exc}"[:60]] += 1
async def main():
    sem = asyncio.Semaphore(conc)
    async def guarded(i):
        async with sem:
            await one(i)
    await asyncio.gather(*(guarded(i) for i in range(start, start + n)))
asyncio.run(main())
if why:
    print("load failures: " + ", ".join(f"{k} x{v}" for k, v in why.most_common(5)), file=sys.stderr)
print(ok)
LOAD
  rss_kb() { awk '/^VmRSS:/ { print $2 }' "/proc/$1/status"; }
  # run_smoke <binary> <label> <n> -> "r0 r1 ok_warm ok_main"
  run_smoke() {
    local bin="$1" label="$2" n="$3" logd="$TMP/log-$2" p r0 r1 w m
    mkdir -p "$logd"
    smoke_cfg "$logd" > "$TMP/$label.cfg"
    ip netns exec "$NS" "$bin" "$TMP/$label.cfg" > "$TMP/$label.out" 2>&1 & p=$!
    ip netns exec "$NS" python3 - <<'WAIT' || { cat "$TMP/$label.out" >&2; kill "$p"; return 1; }
import socket, time, sys
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.4", 31009), timeout=0.2).close(); sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
WAIT
    w="$(ip netns exec "$NS" python3 "$TMP/load.py" 0 "$WARMUP" 32)"
    sleep 2; r0="$(rss_kb "$p")"
    m="$(ip netns exec "$NS" python3 "$TMP/load.py" "$WARMUP" "$n" 32)"
    sleep 2; r1="$(rss_kb "$p")"
    kill "$p" 2>/dev/null; wait "$p" 2>/dev/null
    echo "$r0 $r1 $w $m"
  }
  ip netns exec "$NS" python3 "$TMP/radius.py" "$SECRET" "$TMP/radius.up" & RADP=$!
  ip netns exec "$NS" python3 "$TMP/sink.py" "$TMP/sink.up" & SINKP=$!
  for _ in $(seq 1 50); do [ -s "$TMP/radius.up" ] && [ -s "$TMP/sink.up" ] && break; sleep 0.1; done
  t0=$SECONDS
  res="$(run_smoke "$PERGB_BIN" pergb "$N_PATCHED")" && [ -n "$res" ] || fail "patched smoke did not run"
  read -r p0 p1 pw pm <<< "$res"
  t1=$SECONDS
  res="$(run_smoke "$STOCK_BIN" stock "$N_STOCK")" && [ -n "$res" ] || fail "stock smoke did not run"
  read -r s0 s1 sw sm <<< "$res"
  t2=$SECONDS
  kill "$RADP" "$SINKP" 2>/dev/null
  echo "  patched: RSS ${p0} -> ${p1} kB after $pw + $pm/$N_PATCHED distinct logins ($((t1 - t0)) s)"
  echo "  stock:   RSS ${s0} -> ${s1} kB after $sw + $sm/$N_STOCK distinct logins ($((t2 - t1)) s)"
  # The gate is about the leak, not throughput: at ~3k auths/s on a shared
  # runner the python RADIUS stub misses some answers (SOCKS reply 2) and the
  # single-threaded sink some accepts (reply 5) — both seen in CI, both outside
  # 3proxy. 95 % still proves the logins really authenticated through RADIUS.
  [ "$pm" -ge $((N_PATCHED * 95 / 100)) ] || fail "patched: only $pm/$N_PATCHED sessions succeeded"
  # the stock run only has to authenticate enough distinct logins for its leak
  # to show (the RSS gate below); the stock binary also lacks IP_BIND_ADDRESS_NO_PORT
  [ "$sm" -ge $((N_STOCK * 75 / 100)) ] || fail "stock: only $sm/$N_STOCK sessions succeeded"
  pg=$((p1 - p0)); sg=$((s1 - s0))
  [ "$pg" -lt 3072 ] || fail "patched RSS grew by $pg kB over $N_PATCHED logins (auth cache not off?)"
  [ "$sg" -gt 4096 ] && [ "$sg" -gt $((2 * (pg > 0 ? pg : 0))) ] || fail "stock RSS grew only $sg kB over $N_STOCK logins: the smoke does not show the leak"
  ok "100k distinct logins: patched RSS +${pg} kB (flat), stock +${sg} kB over ${N_STOCK} (one cache entry per login)"
else
  skip "RSS smoke (needs Linux x86_64, root, ip netns, python3)"
fi

echo "PASS ($PASS)"
