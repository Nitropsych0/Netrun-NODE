#!/usr/bin/env bash
# Wave IPV6-ROTATION — end-to-end smoke of node_runtime/node_agent/egress.js
# with the REAL kernel (iproute2 + nftables NAT + conntrack), inside two
# network namespaces joined by a veth on a documentation /64.
#
# FOR A THROW-AWAY LINUX BOX ONLY (root, nft, iproute2, python3, node). Do not
# run it on a live proxy node: it creates and deletes namespaces and veths, and
# a production node is no place for experiments. Nothing outside the two
# namespaces is touched; everything is removed on exit.
#
#   ns "inet": 2001:db8:ffff:1::2/64 and a TCP server that answers every line
#              with the client's source address (a fake «what is my IP» site).
#   ns "node": 2001:db8:ffff:1::1/64, a default route (the module finds its
#              interface through it, as on a node), an ANCHOR address added the
#              generator's way (/128, nodad) and a fake PROXY_ROOT whose one
#              3proxy cfg carries `socks ... -p30000 ... -e<anchor>`. The egress
#              module runs here against the real ip/nft through a small driver;
#              every driver call is a fresh process, so each step also proves
#              the start-up path (re-add + rebuild from egress_state.json).
#   A python client bound to the anchor plays 3proxy's upstream connect.
#
# Checks: no state → the site sees the anchor; rotate → the new address; a
# connection opened before a rotation keeps its address; the GC deletes a
# drained address from the NIC; per_connection → pool addresses (several
# different ones), never the anchor; reset → the anchor again, the pool kept
# idle. After a rotate and after per_connection, the ruleset as
# `nft list ruleset > /etc/nftables.conf` saves it loads into an EMPTY third
# namespace (what nftables.service does at boot) and the boot drop-in's
# `nft delete table ip6 netrun_egress` removes the table there.
#
#   sudo bash scripts/smoke_egress_rotation.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
EGRESS_JS="$ROOT_DIR/node_runtime/node_agent/egress.js"
NS_NODE="egsmoke-node-$$"
NS_INET="egsmoke-inet-$$"
NS_CHK="egsmoke-chk-$$"
VETH_NODE="egn$$"
VETH_INET="egi$$"
NODE_IP="2001:db8:ffff:1::1"
INET_IP="2001:db8:ffff:1::2"
# as the generator writes it: leading zeros, no "::"
ANCHOR_RAW="2001:0db8:ffff:0001:a0a0:0b1b:0c2c:0d3d"
PORT=30000
ECHO_PORT=7777
POOL_SIZE=8
TMP=""
ECHO_PID=""
HOLD_PID=""

PASS=0
fail() { echo "FAIL: $1" >&2; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

# Every step may fail (half-built setup): `|| true` so set -e cannot stop the
# trap before the namespaces are gone. `ip netns del` only drops the name: a
# process still inside keeps the namespace alive, so every process in it is
# killed first, whoever started it.
cleanup() {
  local ns pids
  if [ -n "$HOLD_PID" ]; then kill "$HOLD_PID" 2>/dev/null || true; fi
  if [ -n "$ECHO_PID" ]; then kill "$ECHO_PID" 2>/dev/null || true; fi
  for ns in "$NS_NODE" "$NS_INET" "$NS_CHK"; do
    pids="$(ip netns pids "$ns" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      echo "$pids" | xargs -r kill 2>/dev/null || true
      sleep 0.2
      echo "$pids" | xargs -r kill -9 2>/dev/null || true
    fi
    ip netns del "$ns" 2>/dev/null || true
  done
  if [ -n "$TMP" ]; then rm -rf "$TMP" || true; fi
}
trap cleanup EXIT

[ "$(uname -s)" = Linux ] || fail "Linux only (network namespaces + nftables)"
[ "$(id -u)" = 0 ] || fail "run as root"
for c in ip nft python3 node; do command -v "$c" >/dev/null 2>&1 || fail "missing command: $c"; done
[ -f "$EGRESS_JS" ] || fail "missing $EGRESS_JS"
TMP="$(mktemp -d)"

in_node() { ip netns exec "$NS_NODE" "$@"; }
in_inet() { ip netns exec "$NS_INET" "$@"; }
jget() { python3 -c "import json, sys; d = json.load(sys.stdin); print($1)"; }

ANCHOR="$(node -e 'process.stdout.write(require(process.argv[1]).normalizeIpv6(process.argv[2]) || "")' "$EGRESS_JS" "$ANCHOR_RAW")"
[ -n "$ANCHOR" ] || fail "could not normalise the anchor"

# ── the two namespaces ───────────────────────────────────────────────────
ip netns add "$NS_NODE"
ip netns add "$NS_INET"
ip link add "$VETH_NODE" type veth peer name "$VETH_INET"
ip link set "$VETH_NODE" netns "$NS_NODE"
ip link set "$VETH_INET" netns "$NS_INET"
in_node ip link set lo up
in_inet ip link set lo up
in_node ip link set "$VETH_NODE" up
in_inet ip link set "$VETH_INET" up
in_node ip -6 addr add "$NODE_IP/64" dev "$VETH_NODE" nodad
in_inet ip -6 addr add "$INET_IP/64" dev "$VETH_INET" nodad
in_node ip -6 route add default via "$INET_IP" dev "$VETH_NODE"
in_node ip -6 addr add "$ANCHOR_RAW" dev "$VETH_NODE" nodad

mkdir -p "$TMP/root/3proxy"
cat > "$TMP/root/3proxy/3proxy_${PORT}.cfg" <<EOF
daemon
auth strong
flush
users smoke:CL:smoke
allow smoke *
deny *
socks -6 -a -p${PORT} -i127.0.0.1 -e${ANCHOR_RAW}
proxy -6 -n -a -p$((PORT - 10000)) -i127.0.0.1 -e${ANCHOR_RAW}
EOF

cat > "$TMP/echo.py" <<'PY'
import socket, socketserver, sys

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for _ in self.rfile:
            self.wfile.write((self.client_address[0] + "\n").encode())
            self.wfile.flush()

class Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True

Server(("::", int(sys.argv[1])), Handler).serve_forever()
PY

# whoami.py SRC DST PORT [FLAG]: bind to SRC (3proxy's -e), print the address
# the site sees; with FLAG, keep the connection open until FLAG exists and ask
# again on the SAME connection.
cat > "$TMP/whoami.py" <<'PY'
import os, socket, sys, time

src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
flag = sys.argv[4] if len(sys.argv) > 4 else None
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind((src, 0))
s.settimeout(5)
s.connect((dst, port))
f = s.makefile("rw")

def ask():
    f.write("?\n")
    f.flush()
    return f.readline().strip()

print(ask(), flush=True)
if flag:
    deadline = time.time() + 60
    while not os.path.exists(flag):
        if time.time() > deadline:
            sys.exit("flag never appeared")
        time.sleep(0.05)
    print(ask(), flush=True)
PY

# driver.js CMD [PORT] [DRAIN_SEC]: one egress call in a fresh process.
cat > "$TMP/driver.js" <<'JS'
"use strict";
const egress = require(process.env.EGRESS_JS);
const [cmd, port, drain] = process.argv.slice(2);
const svc = egress.createEgressService({ log: { log() {}, error: (m) => console.error(m) } });
(async () => {
  await svc.init();
  if (!svc.isAvailable()) throw new Error(`egress unavailable: ${svc.status().reason}`);
  const ports = port ? [Number(port)] : [];
  const opts = drain === undefined ? {} : { drainSec: Number(drain) };
  let out;
  if (cmd === "status") out = svc.status();
  else if (cmd === "rotate") out = await svc.rotate(ports, opts);
  else if (cmd === "per_connection" || cmd === "static") out = await svc.setMode(ports, cmd, opts);
  else if (cmd === "reset") out = await svc.reset(ports, opts);
  else if (cmd === "gc") out = await svc.gcTick();
  else if (cmd === "state") out = svc.snapshot();
  else throw new Error(`unknown command ${cmd}`);
  process.stdout.write(`${JSON.stringify(out)}\n`);
})().catch((err) => {
  console.error((err && err.stack) || err);
  process.exit(1);
});
JS

egress() {
  in_node env EGRESS_JS="$EGRESS_JS" NODE_AGENT_PROXY_ROOT="$TMP/root" \
    EGRESS_POOL_SIZE="$POOL_SIZE" EGRESS_DRAIN_SEC=600 node "$TMP/driver.js" "$@"
}
seen() { in_node python3 "$TMP/whoami.py" "$ANCHOR" "$INET_IP" "$ECHO_PORT"; }
# grep -c reads all input: with -q an early exit could SIGPIPE `ip` and
# pipefail would turn a match into a failure.
on_nic() { in_node ip -6 -o addr show dev "$VETH_NODE" | grep -cw -- "inet6 $1/[0-9]*" >/dev/null; }
# The saved ruleset must load at boot (nftables.service: `nft -f` into an
# empty ruleset), or the node boots with no tables at all; then the drop-in's
# delete. A fresh namespace each time stands in for the booted kernel.
roundtrip() {
  in_node nft list ruleset > "$TMP/ruleset.nft" || fail "$1: nft list ruleset"
  grep -q '^table ip6 netrun_egress {' "$TMP/ruleset.nft" || fail "$1: the dump lacks table ip6 netrun_egress"
  ip netns add "$NS_CHK"
  ip netns exec "$NS_CHK" nft -c -f "$TMP/ruleset.nft" || fail "$1: nft -c rejects the saved ruleset"
  ip netns exec "$NS_CHK" nft -f "$TMP/ruleset.nft" || fail "$1: the saved ruleset does not load into an empty ruleset"
  ip netns exec "$NS_CHK" nft delete table ip6 netrun_egress || fail "$1: the drop-in's delete failed"
  ! ip netns exec "$NS_CHK" nft list table ip6 netrun_egress >/dev/null 2>&1 || fail "$1: the table survived the delete"
  ip netns del "$NS_CHK"
  ok "$1: the saved ruleset loads at boot; the drop-in's delete removes the table"
}

# Not through in_inet: `$!` must be python's own pid (ip netns exec execs it),
# not a subshell's whose kill would leave python running.
ip netns exec "$NS_INET" python3 "$TMP/echo.py" "$ECHO_PORT" &
ECHO_PID=$!
for _ in $(seq 1 50); do seen >/dev/null 2>&1 && break; sleep 0.1; done
seen >/dev/null 2>&1 || fail "the echo server never answered"

# ── 1. start-up on a clean node ──────────────────────────────────────────
st="$(egress status)" || fail "egress status"
[ "$(echo "$st" | jget 'd["available"]')" = True ] || fail "module unavailable: $st"
[ "$(echo "$st" | jget 'd["iface"]')" = "$VETH_NODE" ] || fail "iface is not the default-route device: $st"
[ "$(echo "$st" | jget 'd["prefix"]')" = "2001:db8:ffff:1::/64" ] || fail "prefix: $st"
in_node nft list table ip6 netrun_egress >/dev/null || fail "table ip6 netrun_egress missing"
ok "start-up: default-route iface, its /64, table ip6 netrun_egress in place"

got="$(seen)"
[ "$got" = "$ANCHOR" ] || fail "no state: the site saw $got, not the anchor $ANCHOR"
ok "no state: the site sees the anchor"

# ── 2. rotate ────────────────────────────────────────────────────────────
r="$(egress rotate "$PORT")" || fail "rotate"
[ "$(echo "$r" | jget 'd["ok"]')" = True ] || fail "rotate not ok: $r"
NEW1="$(echo "$r" | jget 'd["items"][0]["new_ipv6"]')"
case "$NEW1" in 2001:db8:ffff:1:*) ;; *) fail "rotated address outside the /64: $NEW1" ;; esac
on_nic "$NEW1" || fail "$NEW1 is not on the NIC"
got="$(seen)"
[ "$got" = "$NEW1" ] || fail "after rotate the site saw $got, not $NEW1"
ok "rotate: the site sees the new address $NEW1"
roundtrip "rotate (map element)"

# ── 3. a live connection keeps its address across a rotation ─────────────
ip netns exec "$NS_NODE" python3 "$TMP/whoami.py" "$ANCHOR" "$INET_IP" "$ECHO_PORT" "$TMP/go" > "$TMP/hold.out" &
HOLD_PID=$!
for _ in $(seq 1 50); do [ -s "$TMP/hold.out" ] && break; sleep 0.1; done
r="$(egress rotate "$PORT" 0)" || fail "second rotate"
NEW2="$(echo "$r" | jget 'd["items"][0]["new_ipv6"]')"
[ "$(echo "$r" | jget 'd["items"][0]["old_ipv6"]')" = "$NEW1" ] || fail "old_ipv6 is not $NEW1: $r"
touch "$TMP/go"
wait "$HOLD_PID" || fail "the held connection broke"
HOLD_PID=""
[ "$(sed -n 1p "$TMP/hold.out")" = "$NEW1" ] && [ "$(sed -n 2p "$TMP/hold.out")" = "$NEW1" ] \
  || fail "the open connection moved: $(tr '\n' ' ' < "$TMP/hold.out")"
got="$(seen)"
[ "$got" = "$NEW2" ] || fail "a new connection saw $got, not $NEW2"
ok "rotate: an open connection keeps $NEW1, new connections get $NEW2"

# ── 4. GC: drain_sec 0 → the old address leaves the NIC ──────────────────
gc="$(egress gc)" || fail "gc"
[ "$(echo "$gc" | jget 'd["deleted"]')" = 1 ] || fail "gc: $gc"
! on_nic "$NEW1" || fail "$NEW1 still on the NIC after the GC"
on_nic "$NEW2" || fail "the GC removed the current address $NEW2"
on_nic "$ANCHOR" || fail "the GC removed the anchor"
ok "gc: the drained address is deleted, the current one and the anchor stay"

# ── 5. per_connection ────────────────────────────────────────────────────
r="$(egress per_connection "$PORT")" || fail "per_connection"
[ "$(echo "$r" | jget 'd["items"][0]["new_ipv6"]')" = pool ] || fail "per_connection: $r"
POOL="$(egress state | jget '" ".join(d["pool"])')"
[ "$(echo "$POOL" | wc -w | tr -d ' ')" = "$POOL_SIZE" ] || fail "pool size: $POOL"
for a in $POOL; do on_nic "$a" || fail "pool member $a is not on the NIC"; done
distinct=""
for _ in $(seq 1 24); do
  got="$(seen)"
  [ "$got" != "$ANCHOR" ] || fail "per_connection: a connection left from the anchor"
  case " $POOL " in *" $got "*) ;; *) fail "per_connection: $got is not a pool member" ;; esac
  case " $distinct " in *" $got "*) ;; *) distinct="$distinct $got" ;; esac
done
n="$(echo "$distinct" | wc -w | tr -d ' ')"
[ "$n" -ge 2 ] || fail "24 connections used only $n pool address(es)"
ok "per_connection: 24 connections over $n different pool addresses, never the anchor"
roundtrip "per_connection (dyn set, numgen pool rule)"

# ── 6. reset ─────────────────────────────────────────────────────────────
r="$(egress reset "$PORT" 0)" || fail "reset"
[ "$(echo "$r" | jget 'd["items"][0]["mode"]')" = None ] || fail "reset: $r"
got="$(seen)"
[ "$got" = "$ANCHOR" ] || fail "after reset the site saw $got, not the anchor"
st="$(egress state)"
[ "$(echo "$st" | jget 'len(d["pool"])')" = "$POOL_SIZE" ] || fail "the idle pool was not kept: $st"
[ "$(echo "$st" | jget 'd["pool_idle_since"] is not None')" = True ] || fail "the pool has no idle clock: $st"
ok "reset: the site sees the anchor again; the pool is kept idle (it drains after EGRESS_POOL_REFRESH_SEC)"

echo "smoke_egress_rotation.sh — all $PASS checks passed"
