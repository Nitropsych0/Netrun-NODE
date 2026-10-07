#!/usr/bin/env bash
# Wave IPV6-ROTATION — end-to-end smoke of node_runtime/node_agent/egress.js
# with the REAL kernel (iproute2 + proxy NDP + nftables NAT + conntrack),
# inside two network namespaces joined by a veth on a documentation /64.
#
# Needs root, nft, iproute2, python3, node. Everything happens inside
# throw-away namespaces: the veth pair is created inside them (never in the
# host's namespace), the sysctls the module and this script write are the
# namespaces' own (net.* is per namespace), the module's state and its
# persisted sysctl file go to a temp dir (never /etc/sysctl.d), and
# everything is removed on exit — processes left in a namespace are killed
# before it is deleted. The host's addresses, neighbour table, nftables
# ruleset and sysctls are not touched.
#
#   ns "inet": 2001:db8:ffff:1::2/64 and a TCP server that answers every line
#              with the client's source address (a fake «what is my IP» site).
#              On-link with the node, like the provider's router: it finds
#              the node's rotated addresses through neighbour discovery.
#   ns "node": 2001:db8:ffff:1::1/64 — the host's own (primary) address,
#              added the way SLAAC / netplan add one: no nodad flag (DAD is
#              off on the veth instead, as 98-netrun-ipv6.conf turns it off
#              on a node) — forwarding on (as the installers leave
#              a node), a default route (the module finds its interface
#              through it, as on a node), an ANCHOR address added the
#              generator's way (/128, nodad) and a fake PROXY_ROOT whose one
#              3proxy cfg carries `socks ... -p30000 ... -e<anchor>`. The egress
#              module runs here against the real ip/nft through a small driver;
#              every driver call is a fresh process, so each step also proves
#              the start-up path (sysctls, proxy re-add, table rebuild).
#   A python client bound to the anchor plays 3proxy's upstream connect.
#
# Checks: the module turns proxy NDP on (all/<if>.proxy_ndp=1,
# <if>.proxy_delay=0, forwarding=1) and writes the sysctl file; no state → the
# site sees the anchor; the exit guard (chain exit_guard, input hook): with a
# listener on [::]:22 in "node", a TCP connect from "inet" to [anchor]:22 or
# to a closed anchor port gets no answer at all (timeout: no SYN-ACK, no
# RST), a ping to the anchor no reply and unsolicited UDP to it never gets
# past the chain, while the node's own address still accepts :22 and answers
# ping and the anchor's upstream connection to the "inet" site still works;
# EGRESS_EXIT_GUARD=off removes the chain (:22 on the anchor answers again)
# and the next start puts it back; rotate → the new address, which is a proxy entry and
# NOT a NIC address; a connection opened before a rotation keeps its address;
# the GC deletes a drained proxy entry; unsolicited packets to a rotated
# address reach the forward hook and the table's forward guard drops them;
# the "inet" side's unicast reachability probe for a rotated address is
# answered; an address left on the NIC by the version before proxy NDP moves
# to a proxy entry under an open connection; per_connection → pool
# addresses (several different ones, proxy entries, not on the NIC), never
# the anchor; reset → the anchor again, the pool kept idle. Every step after
# the exit-guard one runs with the guard on, so the replies of every upstream
# connection (the de-NATed ones of rotated and pool addresses included) and
# the unicast reachability probe pass it. After a rotate
# and after per_connection, the ruleset as `nft list ruleset >
# /etc/nftables.conf` saves it (exit guard included) loads into an EMPTY third
# namespace (what nftables.service does at boot) and the boot drop-in's `nft
# delete table ip6 netrun_egress` removes the table there.
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
PREFIX="2001:db8:ffff:1::/64"
# as the generator writes it: leading zeros, no "::"
ANCHOR_RAW="2001:0db8:ffff:0001:a0a0:0b1b:0c2c:0d3d"
PORT=30000
ECHO_PORT=7777
POOL_SIZE=8
TMP=""
ECHO_PID=""
HOLD_PID=""
LISTEN_PID=""

PASS=0
fail() { echo "FAIL: $1" >&2; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

# Every step may fail (half-built setup): `|| true` so set -e cannot stop the
# trap before the namespaces are gone. `ip netns del` only drops the name: a
# process still inside keeps the namespace (and its veth, conntrack, nft)
# alive, so every process in it is killed first, whoever started it. The veth
# pair lives only inside the namespaces and goes with them.
cleanup() {
  local ns pids
  trap - EXIT INT TERM HUP
  if [ -n "$HOLD_PID" ]; then kill "$HOLD_PID" 2>/dev/null || true; fi
  if [ -n "$ECHO_PID" ]; then kill "$ECHO_PID" 2>/dev/null || true; fi
  if [ -n "$LISTEN_PID" ]; then kill "$LISTEN_PID" 2>/dev/null || true; fi
  for ns in "$NS_NODE" "$NS_INET" "$NS_CHK"; do
    pids="$(ip netns pids "$ns" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      echo "$pids" | xargs -r kill 2>/dev/null || true
      sleep 0.2
      pids="$(ip netns pids "$ns" 2>/dev/null || true)"
      if [ -n "$pids" ]; then echo "$pids" | xargs -r kill -9 2>/dev/null || true; sleep 0.1; fi
    fi
    ip netns del "$ns" 2>/dev/null || true
  done
  if [ -n "$TMP" ]; then rm -rf "$TMP" || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

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
# created inside "node", its peer moved straight into "inet": the pair never
# exists in the host's namespace (no udev/networkd reaction there)
ip -n "$NS_NODE" link add "$VETH_NODE" type veth peer name "$VETH_INET" netns "$NS_INET"
# a node as the installers leave it (99-netrun.conf); a fresh namespace starts
# from the kernel defaults
in_node sysctl -qw net.ipv6.conf.all.forwarding=1
in_node ip link set lo up
in_inet ip link set lo up
in_node ip link set "$VETH_NODE" up
in_inet ip link set "$VETH_INET" up
# the host's own address: no nodad flag (that flag marks anchors), DAD off
# on the interface so it is usable at once
in_node sysctl -qw net.ipv6.conf.all.accept_dad=0
in_node sysctl -qw "net.ipv6.conf.$VETH_NODE.accept_dad=0"
in_node ip -6 addr add "$NODE_IP/64" dev "$VETH_NODE"
in_inet ip -6 addr add "$INET_IP/64" dev "$VETH_INET" nodad
in_node ip -6 route add default via "$INET_IP" dev "$VETH_NODE"
in_node ip -6 addr add "$ANCHOR_RAW" dev "$VETH_NODE" nodad

mkdir -p "$TMP/root/3proxy" "$TMP/sysctl.d"
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

# has_addr.py MODE ADDR < listing: exit 0 when ADDR is in an `ip -6 -o addr
# show` (MODE addr) or `ip -6 neigh show proxy` (MODE neigh) listing; reads
# all of stdin (an early exit could SIGPIPE `ip` under pipefail).
cat > "$TMP/has_addr.py" <<'PY'
import ipaddress, sys

mode, want = sys.argv[1], ipaddress.ip_address(sys.argv[2])
found = False
for line in sys.stdin:
    f = line.split()
    if mode == "neigh":
        tokens = f[:1]
    else:
        tokens = [f[i + 1].split("/")[0] for i in range(len(f) - 1) if f[i] == "inet6"]
    for t in tokens:
        try:
            found = found or ipaddress.ip_address(t) == want
        except ValueError:
            pass
sys.exit(0 if found else 1)
PY

# udp.py DST COUNT: COUNT datagrams to DST port 9 (nobody listens).
cat > "$TMP/udp.py" <<'PY'
import socket, sys

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
for _ in range(int(sys.argv[2])):
    s.sendto(b"netrun-smoke", (sys.argv[1], 9))
PY

# listen.py PORT: a TCP server on [::]:PORT that accepts and closes (sshd's
# place: on a node sshd listens on [::]:22, so on every anchor too).
cat > "$TMP/listen.py" <<'PY'
import socket, sys

s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", int(sys.argv[1])))
s.listen(64)
while True:
    c, _ = s.accept()
    c.close()
PY

# tcpprobe.py DST PORT: what a port scanner sees — "open" (SYN-ACK),
# "refused" (RST), "timeout" (no answer: filtered) or "error:<errno>".
cat > "$TMP/tcpprobe.py" <<'PY'
import socket, sys

try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()
    print("open")
except ConnectionRefusedError:
    print("refused")
except socket.timeout:
    print("timeout")
except OSError as e:
    print("error:%s" % e.errno)
PY

# ping6.py DST: exit 0 when DST answers an ICMPv6 echo request within 1.5 s
# (three requests; a raw socket, the kernel fills in the checksum).
cat > "$TMP/ping6.py" <<'PY'
import ipaddress, os, select, socket, struct, sys, time

dst = sys.argv[1]
want = ipaddress.ip_address(dst)
ident = os.getpid() & 0xFFFF
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
deadline = time.time() + 1.5
sent = 0
next_send = 0.0
while time.time() < deadline:
    now = time.time()
    if sent < 3 and now >= next_send:
        sent += 1
        s.sendto(struct.pack("!BBHHH", 128, 0, 0, ident, sent) + b"netrun-smoke", (dst, 0))
        next_send = now + 0.4
    r, _, _ = select.select([s], [], [], 0.1)
    if not r:
        continue
    data, addr = s.recvfrom(2048)
    if len(data) >= 8 and data[0] == 129 and struct.unpack("!H", data[4:6])[0] == ident \
            and ipaddress.ip_address(addr[0].split("%")[0]) == want:
        sys.exit(0)
sys.exit(1)
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

# The module's sysctl file goes to the temp dir, never /etc/sysctl.d; no
# nftables.service drop-in (the driver never calls start() anyway). The exit
# guard is on (the default) unless a call is made as `EXIT_GUARD=off egress`.
SYSCTL_CONF="$TMP/sysctl.d/99-netrun-egress.conf"
egress() {
  in_node env EGRESS_JS="$EGRESS_JS" NODE_AGENT_PROXY_ROOT="$TMP/root" \
    EGRESS_POOL_SIZE="$POOL_SIZE" EGRESS_DRAIN_SEC=600 \
    EGRESS_SYSCTL_CONF="$SYSCTL_CONF" EGRESS_NFT_DROPIN=off \
    EGRESS_EXIT_GUARD="${EXIT_GUARD:-on}" \
    node "$TMP/driver.js" "$@"
}
seen() { in_node python3 "$TMP/whoami.py" "$ANCHOR" "$INET_IP" "$ECHO_PORT"; }
on_nic() {
  local list
  list="$(in_node ip -6 -o addr show dev "$VETH_NODE")" || fail "ip addr show failed"
  printf '%s\n' "$list" | python3 "$TMP/has_addr.py" addr "$1"
}
proxied() {
  local list
  list="$(in_node ip -6 neigh show proxy dev "$VETH_NODE")" || fail "ip neigh show proxy failed"
  printf '%s\n' "$list" | python3 "$TMP/has_addr.py" neigh "$1"
}
node_sysctl() { in_node cat "/proc/sys/$1"; }
# packets counted by a chain of the smoke's own table
counter_of() {
  in_node nft list chain ip6 egsmoke "$1" | sed -n 's/.* counter packets \([0-9][0-9]*\) .*/\1/p'
}
# what a scanner in "inet" sees on DST PORT (tcpprobe.py)
probe() { in_inet python3 "$TMP/tcpprobe.py" "$1" "$2"; }
# the state ("REACHABLE", "STALE", ...) of the inet side's neighbour entry
nud_state() { in_inet ip -6 neigh show "$1" dev "$VETH_INET" | awk 'NF { print $NF }'; }
# The saved ruleset must load at boot (nftables.service: `nft -f` into an
# empty ruleset), or the node boots with no tables at all; then the drop-in's
# delete. A fresh namespace each time stands in for the booted kernel.
roundtrip() {
  in_node nft list ruleset > "$TMP/ruleset.nft" || fail "$1: nft list ruleset"
  grep -q '^table ip6 netrun_egress {' "$TMP/ruleset.nft" || fail "$1: the dump lacks table ip6 netrun_egress"
  grep -q 'chain exit_guard {' "$TMP/ruleset.nft" || fail "$1: the dump lacks chain exit_guard"
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
[ "$(echo "$st" | jget 'd["prefix"]')" = "$PREFIX" ] || fail "prefix: $st"
in_node nft list table ip6 netrun_egress >/dev/null || fail "table ip6 netrun_egress missing"
in_node nft list chain ip6 netrun_egress forward_guard | grep -q "ip6 daddr $PREFIX drop" \
  || fail "the forward guard for $PREFIX is missing: $(in_node nft list chain ip6 netrun_egress forward_guard 2>&1 | tr '\n' ' ')"
ok "start-up: default-route iface, its /64, table ip6 netrun_egress with the forward guard"

for kv in conf/all/proxy_ndp=1 "conf/$VETH_NODE/proxy_ndp=1" "neigh/$VETH_NODE/proxy_delay=0" \
  conf/all/forwarding=1 "conf/$VETH_NODE/forwarding=1"; do
  got="$(node_sysctl "net/ipv6/${kv%%=*}")"
  [ "$got" = "${kv#*=}" ] || fail "net.ipv6.${kv%%=*} is $got, want ${kv#*=}"
done
want_conf="$(node -e 'process.stdout.write(require(process.argv[1]).sysctlConfText(process.argv[2]))' "$EGRESS_JS" "$VETH_NODE")"
[ -f "$SYSCTL_CONF" ] && [ "$(cat "$SYSCTL_CONF")" = "$want_conf" ] || fail "the persisted sysctl file differs: $(cat "$SYSCTL_CONF" 2>&1)"
ok "start-up: proxy NDP on (all/$VETH_NODE proxy_ndp=1, proxy_delay=0, forwarding=1), persisted to the sysctl file"

got="$(seen)"
[ "$got" = "$ANCHOR" ] || fail "no state: the site saw $got, not the anchor $ANCHOR"
ok "no state: the site sees the anchor"

# ── 1b. exit guard ───────────────────────────────────────────────────────
# A port scan of an exit address must look like a home line: nothing answers
# (no SYN-ACK, no RST, no echo reply), while the node's own address still does.
[ "$(echo "$st" | jget 'd["exit_guard"]')" = True ] || fail "the exit guard is not on by default: $st"
[ "$(echo "$st" | jget '" ".join(d["primary"])')" = "$NODE_IP" ] || fail "exit guard primary is not $NODE_IP: $st"
guard="$(in_node nft list chain ip6 netrun_egress exit_guard 2>&1)" || fail "chain exit_guard missing: $guard"
printf '%s\n' "$guard" | grep -qE 'hook input priority (filter - 10|-10);' \
  || fail "chain exit_guard is not at input priority filter - 10: $(printf '%s' "$guard" | tr '\n' ' ')"
for want in "ip6 daddr != $PREFIX accept" "ip6 daddr $NODE_IP accept" \
  "ct state established,related accept" "icmpv6 type echo-request drop"; do
  printf '%s\n' "$guard" | grep -qF -- "$want" || fail "chain exit_guard lacks \"$want\": $(printf '%s' "$guard" | tr '\n' ' ')"
done
# Not through in_node: `$!` must be python's own pid (see the echo server).
ip netns exec "$NS_NODE" python3 "$TMP/listen.py" 22 &
LISTEN_PID=$!
for _ in $(seq 1 50); do [ "$(probe "$NODE_IP" 22)" = open ] && break; sleep 0.1; done
got="$(probe "$NODE_IP" 22)"
[ "$got" = open ] || fail "the node's own address $NODE_IP:22 is $got, want open"
got="$(probe "$ANCHOR" 22)"
[ "$got" = timeout ] || fail "[$ANCHOR]:22 (a listener on [::]:22) is $got, want timeout: dropped, no SYN-ACK, no RST"
got="$(probe "$ANCHOR" 23)"
[ "$got" = timeout ] || fail "[$ANCHOR]:23 (closed) is $got, want timeout: no RST"
in_inet python3 "$TMP/ping6.py" "$NODE_IP" || fail "the node's own address $NODE_IP answers no ping"
! in_inet python3 "$TMP/ping6.py" "$ANCHOR" || fail "the anchor $ANCHOR answered a ping"
# unsolicited UDP: two counting chains bracket the guard (priority filter - 10)
in_node nft -f - <<EOF || fail "could not add the input counting chains"
table ip6 egsmoke {
	chain before {
		type filter hook input priority -20; policy accept;
		ip6 daddr $ANCHOR udp dport 9 counter
	}
	chain after {
		type filter hook input priority 10; policy accept;
		ip6 daddr $ANCHOR udp dport 9 counter
	}
}
EOF
in_inet python3 "$TMP/udp.py" "$ANCHOR" 5
sleep 0.5
before="$(counter_of before)"
after="$(counter_of after)"
in_node nft delete table ip6 egsmoke
[ -n "$before" ] && [ "$before" -ge 1 ] || fail "unsolicited UDP to $ANCHOR never reached the input hook (${before:-?})"
[ "$after" = 0 ] || fail "the exit guard let ${after:-?} of $before UDP packet(s) to $ANCHOR through"
got="$(seen)"
[ "$got" = "$ANCHOR" ] || fail "under the exit guard the site saw $got, not the anchor (upstream replies dropped?)"
ok "exit guard: [anchor]:22 and a closed port time out (no RST), no ping reply, $before unsolicited UDP dropped; $NODE_IP:22 open and pinged; upstream from the anchor works"

r="$(EXIT_GUARD=off egress status)" || fail "status with EGRESS_EXIT_GUARD=off"
[ "$(echo "$r" | jget 'd["exit_guard"]')" = False ] || fail "EGRESS_EXIT_GUARD=off: $r"
! in_node nft list chain ip6 netrun_egress exit_guard >/dev/null 2>&1 || fail "EGRESS_EXIT_GUARD=off left chain exit_guard"
got="$(probe "$ANCHOR" 22)"
[ "$got" = open ] || fail "guard off: [$ANCHOR]:22 is $got, want open"
egress status >/dev/null || fail "status with the guard on again"
in_node nft list chain ip6 netrun_egress exit_guard >/dev/null || fail "the next start did not put chain exit_guard back"
got="$(probe "$ANCHOR" 22)"
[ "$got" = timeout ] || fail "guard on again: [$ANCHOR]:22 is $got, want timeout"
kill "$LISTEN_PID" 2>/dev/null || true
wait "$LISTEN_PID" 2>/dev/null || true
LISTEN_PID=""
ok "exit guard: EGRESS_EXIT_GUARD=off drops the chain ([anchor]:22 answers), the next start restores it"

# ── 2. rotate ────────────────────────────────────────────────────────────
r="$(egress rotate "$PORT")" || fail "rotate"
[ "$(echo "$r" | jget 'd["ok"]')" = True ] || fail "rotate not ok: $r"
NEW1="$(echo "$r" | jget 'd["items"][0]["new_ipv6"]')"
case "$NEW1" in 2001:db8:ffff:1:*) ;; *) fail "rotated address outside the /64: $NEW1" ;; esac
proxied "$NEW1" || fail "$NEW1 has no proxy entry"
! on_nic "$NEW1" || fail "$NEW1 was added to the NIC"
got="$(seen)"
[ "$got" = "$NEW1" ] || fail "after rotate the site saw $got, not $NEW1"
ok "rotate: the site sees the new address $NEW1 (a proxy entry, not a NIC address)"
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

# ── 4. GC: drain_sec 0 → the old proxy entry goes ────────────────────────
gc="$(egress gc)" || fail "gc"
[ "$(echo "$gc" | jget 'd["deleted"]')" = 1 ] || fail "gc: $gc"
! proxied "$NEW1" || fail "$NEW1 still has a proxy entry after the GC"
proxied "$NEW2" || fail "the GC removed the current address $NEW2"
on_nic "$ANCHOR" || fail "the GC removed the anchor"
ok "gc: the drained proxy entry is deleted, the current one and the anchor stay"

# ── 5. forward guard ─────────────────────────────────────────────────────
# Unsolicited packets to a rotated address (no conntrack entry to de-NAT them)
# are not for a local address, so the node would forward them back out the
# on-link /64. Two counting chains of the smoke's own table bracket the
# module's guard (priority filter = 0): "before" proves they reach the
# forward hook, "after" must see none of them.
in_node nft -f - <<EOF || fail "could not add the counting chains"
table ip6 egsmoke {
	chain before {
		type filter hook forward priority -10; policy accept;
		ip6 daddr $NEW2 counter
	}
	chain after {
		type filter hook forward priority 10; policy accept;
		ip6 daddr $NEW2 counter
	}
}
EOF
in_inet python3 "$TMP/udp.py" "$NEW2" 5
sleep 0.5
before="$(counter_of before)"
after="$(counter_of after)"
[ -n "$before" ] && [ "$before" -ge 1 ] || fail "unsolicited packets to $NEW2 never reached the forward hook (${before:-?})"
[ "$after" = 0 ] || fail "the forward guard let ${after:-?} of $before packet(s) to $NEW2 through"
in_node nft delete table ip6 egsmoke
got="$(seen)"
[ "$got" = "$NEW2" ] || fail "after the forward-guard check the site saw $got, not $NEW2"
ok "forward guard: $before unsolicited packet(s) to $NEW2 reached the forward hook, none got past it"

# ── 6. the router's unicast reachability probe is answered ───────────────
# A router probes a stale neighbour entry with a UNICAST solicitation to the
# address itself; for a proxied address that takes the node's forwarding
# path, where only net.ipv6.conf.all.proxy_ndp hands it to neighbour
# discovery. Make the inet side probe NEW2 now: its entry stale, the first
# probe after 1 s, and the last TCP confirmation (the check above) older
# than that, so DELAY cannot turn REACHABLE without a probe.
mac="$(in_node ip -o link show dev "$VETH_NODE" | awk '{ for (i = 1; i < NF; i++) if ($i == "link/ether") print $(i + 1) }')"
[ -n "$mac" ] || fail "no MAC on $VETH_NODE"
in_inet sysctl -qw "net.ipv6.neigh.$VETH_INET.delay_first_probe_time=1"
sleep 1.5
in_inet ip -6 neigh replace "$NEW2" lladdr "$mac" dev "$VETH_INET" nud stale
in_inet python3 "$TMP/udp.py" "$NEW2" 1
state=""
for _ in $(seq 1 80); do
  state="$(nud_state "$NEW2")"
  case "$state" in REACHABLE|FAILED|INCOMPLETE) break ;; esac
  sleep 0.1
done
[ "$state" = REACHABLE ] || fail "the unicast probe for $NEW2 went unanswered (inet's entry: ${state:-none})"
ok "nud: the unicast reachability probe for $NEW2 is answered (entry REACHABLE again)"

# ── 7. upgrade from the version that put addresses on the NIC ────────────
# What that version left: NEW2 on the NIC (/128, nodad) and no proxy entry.
# A connection open through it must survive the start-up move.
in_node ip -6 neigh del proxy "$NEW2" dev "$VETH_NODE"
in_node ip -6 addr add "$NEW2/128" dev "$VETH_NODE" nodad
! proxied "$NEW2" || fail "setup: $NEW2 still has a proxy entry"
got="$(seen)"
[ "$got" = "$NEW2" ] || fail "setup: from the NIC the site saw $got, not $NEW2"
ip netns exec "$NS_NODE" python3 "$TMP/whoami.py" "$ANCHOR" "$INET_IP" "$ECHO_PORT" "$TMP/go2" > "$TMP/hold2.out" &
HOLD_PID=$!
for _ in $(seq 1 50); do [ -s "$TMP/hold2.out" ] && break; sleep 0.1; done
st="$(egress state)" || fail "start-up with a NIC address in the state"
[ "$(echo "$st" | jget 'd["ports"]["'"$PORT"'"]["current"]')" = "$NEW2" ] || fail "the move lost the port's address: $st"
proxied "$NEW2" || fail "$NEW2 got no proxy entry"
! on_nic "$NEW2" || fail "$NEW2 is still on the NIC"
on_nic "$ANCHOR" || fail "the move removed the anchor"
touch "$TMP/go2"
wait "$HOLD_PID" || fail "the connection open across the move broke"
HOLD_PID=""
[ "$(sed -n 1p "$TMP/hold2.out")" = "$NEW2" ] && [ "$(sed -n 2p "$TMP/hold2.out")" = "$NEW2" ] \
  || fail "the open connection moved: $(tr '\n' ' ' < "$TMP/hold2.out")"
got="$(seen)"
[ "$got" = "$NEW2" ] || fail "after the move the site saw $got, not $NEW2"
ok "upgrade: $NEW2 moved from the NIC to a proxy entry under an open connection"

# ── 8. per_connection ────────────────────────────────────────────────────
r="$(egress per_connection "$PORT")" || fail "per_connection"
[ "$(echo "$r" | jget 'd["items"][0]["new_ipv6"]')" = pool ] || fail "per_connection: $r"
POOL="$(egress state | jget '" ".join(d["pool"])')"
[ "$(echo "$POOL" | wc -w | tr -d ' ')" = "$POOL_SIZE" ] || fail "pool size: $POOL"
for a in $POOL; do
  proxied "$a" || fail "pool member $a has no proxy entry"
  ! on_nic "$a" || fail "pool member $a was added to the NIC"
done
distinct=""
for _ in $(seq 1 24); do
  got="$(seen)"
  [ "$got" != "$ANCHOR" ] || fail "per_connection: a connection left from the anchor"
  case " $POOL " in *" $got "*) ;; *) fail "per_connection: $got is not a pool member" ;; esac
  case " $distinct " in *" $got "*) ;; *) distinct="$distinct $got" ;; esac
done
n="$(echo "$distinct" | wc -w | tr -d ' ')"
[ "$n" -ge 2 ] || fail "24 connections used only $n pool address(es)"
ok "per_connection: 24 connections over $n different pool addresses (proxy entries), never the anchor"
roundtrip "per_connection (dyn set, numgen pool rule, forward and exit guards)"

# ── 9. reset ─────────────────────────────────────────────────────────────
r="$(egress reset "$PORT" 0)" || fail "reset"
[ "$(echo "$r" | jget 'd["items"][0]["mode"]')" = None ] || fail "reset: $r"
got="$(seen)"
[ "$got" = "$ANCHOR" ] || fail "after reset the site saw $got, not the anchor"
st="$(egress state)"
[ "$(echo "$st" | jget 'len(d["pool"])')" = "$POOL_SIZE" ] || fail "the idle pool was not kept: $st"
[ "$(echo "$st" | jget 'd["pool_idle_since"] is not None')" = True ] || fail "the pool has no idle clock: $st"
ok "reset: the site sees the anchor again; the pool is kept idle (it drains after EGRESS_POOL_REFRESH_SEC)"

echo "smoke_egress_rotation.sh — all $PASS checks passed"
