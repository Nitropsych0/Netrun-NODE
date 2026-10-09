#!/usr/bin/env bash
# NETRUN per-GB (lane L3): the agent's socket listing and kills against a REAL
# Linux kernel and iproute2 `ss` (plan V11). For a throwaway VM or CI runner:
# it starts a transient systemd scope and local TCP servers; nothing is
# installed. Refused without --throwaway-host.
#
#   sudo scripts/test_pergb_agent_linux.sh --throwaway-host
#
# Checks: `ss` has the cgroup filter (iproute2 >= 5.9); pergb_kill.js lists
# the sockets of exactly one cgroup with tcp_info bytes (parseSs on real
# output, IPv4 and IPv6); `ss -K` with an exact 4-tuple inside that cgroup
# closes exactly that connection — the same tuple outside the cgroup and the
# other connections stay up; the fallback (no cgroup filter, address filter
# only) kills exactly too; the IPv4 local-port count of the guard on real
# `ss -Htan` output.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="$REPO/node_runtime/node_agent"
[[ "${1:-}" == "--throwaway-host" ]] || { echo "refusing: pass --throwaway-host" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
command -v ss >/dev/null && command -v systemd-run >/dev/null && command -v node >/dev/null && command -v python3 >/dev/null \
  || { echo "needs ss, systemd-run, node, python3" >&2; exit 2; }

fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
WORK="$(mktemp -d)"
UNIT="netrun-pergb-ltest-$$"
cleanup() {
  systemctl stop "$UNIT.scope" >/dev/null 2>&1 || true
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  [[ -n "${OUT_PID:-}" ]] && kill "$OUT_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# 1. ss cgroup filter
if ss -Htn state established cgroup / >/dev/null 2>&1; then ok "ss has the cgroup filter ($(ss -V 2>&1 | head -1))"; else bad "ss lacks the cgroup filter (V11): the agent falls back to address filters"; fi

# 2. servers on 127.0.0.1 and ::1 that keep every connection open
cat > "$WORK/server.py" <<'PY'
import socket, sys, threading, time
def serve(fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr); s.listen(64)
    while True:
        c, _ = s.accept()
        def hold(c=c):
            try:
                c.sendall(b"x" * 5000)
                while c.recv(65536):
                    pass
            except OSError:
                pass
        threading.Thread(target=hold, daemon=True).start()
for fam, addr in ((socket.AF_INET, ("127.0.0.1", int(sys.argv[1]))), (socket.AF_INET6, ("::1", int(sys.argv[1])))):
    threading.Thread(target=serve, args=(fam, addr), daemon=True).start()
while True:
    time.sleep(1)
PY
PORT=$((20000 + RANDOM % 20000))
python3 "$WORK/server.py" "$PORT" &
SRV_PID=$!
sleep 0.5

# 3. a client in a transient scope (its own cgroup) with 3 connections, and one outside it
cat > "$WORK/client.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); out = sys.argv[2]
socks = []
for fam, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    s = socket.socket(fam, socket.SOCK_STREAM); s.connect((host, port)); s.sendall(b"hello" * 100); socks.append(s)
with open(out, "w") as fh:
    for s in socks:
        l = s.getsockname(); fh.write("%s %d\n" % (l[0], l[1]))
while True:
    time.sleep(0.2)
    alive = []
    for s in socks:
        try:
            s.setblocking(False)
            d = s.recv(65536)
            alive.append("1" if d != b"" else "0")
        except BlockingIOError:
            alive.append("1")
        except OSError:
            alive.append("0")
    with open(out + ".alive", "w") as fh:
        fh.write("".join(alive))
PY
systemd-run --quiet --scope --unit "$UNIT" python3 "$WORK/client.py" "$PORT" "$WORK/in" &
for _ in $(seq 1 50); do [[ -s "$WORK/in" ]] && break; sleep 0.1; done
python3 "$WORK/client.py" "$PORT" "$WORK/out" &
OUT_PID=$!
for _ in $(seq 1 50); do [[ -s "$WORK/out" ]] && break; sleep 0.1; done
CG="$(systemctl show -p ControlGroup --value "$UNIT.scope")"
[[ -n "$CG" ]] && ok "scope cgroup $CG" || bad "no cgroup for $UNIT.scope"

# 4. the agent's killer on the real ss
cat > "$WORK/run.js" <<'JS'
const k = require(process.env.AGENT + "/pergb_kill.js");
const rt = require(process.env.AGENT + "/pergb_runtime.js");
const fs = require("fs");
const guards = require(process.env.AGENT + "/pergb_guards.js");
(async () => {
  const cg = process.env.CG;
  const port = Number(process.env.PORT);
  const lines = fs.readFileSync(process.env.WORK + "/in", "utf-8").trim().split("\n").map((l) => l.split(" "));
  const killer = k.createKiller({ run: rt.execCapture, log: console, units: () => [{ unit: "scope", cgroup: cg }], fallbackFilter: () => ["(", "dport", "=", `:${port}`, ")"], ctx: () => ({}) });
  const socks = await killer.listSockets();
  const mine = socks.filter((s) => s.pport === port);
  const res = { cgroupFilter: await killer.probeCgroup(), listed: mine.length, withBytes: mine.filter((s) => s.sent >= 500 && s.received >= 5000).length, v6: mine.filter((s) => s.local === "::1").length };
  // kill exactly the first connection, inside the cgroup
  const [ip, lport] = lines[0];
  const target = mine.find((s) => s.local === (ip.startsWith("::ffff:") ? ip.slice(7) : ip) && s.lport === Number(lport));
  res.killed = target ? await killer.killSockets([target]) : -1;
  // the same 4-tuple OUTSIDE this cgroup cannot exist; a tuple of the outside client with the cgroup filter must not be killed
  const outLines = fs.readFileSync(process.env.WORK + "/out", "utf-8").trim().split("\n").map((l) => l.split(" "));
  const [oip, oport] = outLines[0];
  res.killedOutside = await killer.killSockets([{ local: oip, lport: Number(oport), peer: oip, pport: port, cgroup: cg }]);
  // fallback (no cgroup filter): the IPv6 one, by its exact tuple
  killer._resetProbe();
  const [ip6, lport6] = lines[2];
  res.killed6 = await killer.killSockets([{ local: ip6, lport: Number(lport6), peer: "::1", pport: port, cgroup: null }]);
  // the guard's IPv4 local-port count on real ss -Htan output
  const r = await rt.execCapture("ss", ["-Htan", "src", "127.0.0.1", "and", "sport", "ge", ":1024", "and", "sport", "le", ":65535"]);
  res.ports = guards.countLocalPorts(r.stdout, "127.0.0.1", 1024, 65535);
  console.log(JSON.stringify(res));
})();
JS
sleep 0.5
export AGENT CG PORT WORK
OUT="$(node "$WORK/run.js")"
echo "$OUT"
sleep 0.6
get() { python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])" "$OUT" "$1"; }
[[ "$(get listed)" == 3 ]] && ok "3 sockets of the scope listed by cgroup" || bad "listed $(get listed), want 3"
[[ "$(get withBytes)" == 3 ]] && ok "tcp_info bytes_sent / bytes_received parsed" || bad "bytes parsed on $(get withBytes) sockets"
[[ "$(get v6)" == 1 ]] && ok "IPv6 socket parsed" || bad "IPv6 sockets $(get v6)"
[[ "$(get killed)" == 1 ]] && ok "ss -K inside the cgroup killed exactly 1" || bad "killed $(get killed)"
[[ "$(get killedOutside)" == 0 ]] && ok "a socket outside the cgroup is never killed" || bad "killed outside: $(get killedOutside)"
[[ "$(get killed6)" == 1 ]] && ok "fallback (address filter only) killed the IPv6 tuple" || bad "fallback killed $(get killed6)"
[[ "$(get ports)" -ge 4 ]] && ok "guard port count on real ss output ($(get ports))" || bad "port count $(get ports)"
alive_in="$(cat "$WORK/in.alive" 2>/dev/null || true)"
alive_out="$(cat "$WORK/out.alive" 2>/dev/null || true)"
[[ "$alive_in" == "010" ]] && ok "in the scope: the 2 targeted connections closed, the other is up ($alive_in)" || bad "scope connections alive: $alive_in (want 010)"
[[ "$alive_out" == "111" ]] && ok "outside the scope: all connections up ($alive_out)" || bad "outside connections alive: $alive_out (want 111)"

exit "$fail"
