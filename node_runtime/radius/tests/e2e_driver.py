"""Driver for scripts/test_pergb_radius_e2e.sh (runs inside the test network namespace).

It talks SOCKS5 to 127.0.0.4:<port> and HTTP CONNECT to 127.0.0.3:<port> of a real
3proxy (per-GB binary or the stock 0.9.3), which asks netrun-radius on
127.0.0.1:1812. The target server answers every connection with the source
address it sees, so each check reads the Framed address 3proxy bound.

    python3 -I e2e_driver.py --ctl CTL --sockact-pid PID --base 31000 --count 4 \
        --secret-file F --out DIR [--target6 2001:db8:ffff::1] [--target4 10.200.0.1] [--egress4 10.200.0.2]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import ctl  # noqa: E402
import proto  # noqa: E402
import tag  # noqa: E402

PREFIX = "2001:db8:aa::/48"
PW = "E2ePassw0rdE2ePa"
PROBE_PW = "E2eProbePassw0rd"
TARGET_PORT = 8080
RESULTS = []
SOCKS_HOST = "127.0.0.4"  # 3proxy-pergb socks listeners
HTTP_HOST = "127.0.0.3"  # 3proxy-pergb proxy (HTTP CONNECT) listeners
HTTP_OFFSET = 0  # fake3proxy dry runs listen for HTTP on port + offset


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("ok   " if cond else "FAIL ") + name + (" -- " + str(detail) if detail else ""), flush=True)
    return cond


# ---- target server ---------------------------------------------------------------------


def serve_target(addrs):
    socks = []
    for a in addrs:
        fam = socket.AF_INET6 if ":" in a else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a, TARGET_PORT))
        s.listen(1024)
        socks.append(s)

    def loop(s):
        while True:
            c, peer = s.accept()
            try:
                c.sendall((peer[0] + "\n").encode())
            except OSError:
                pass
            finally:
                c.close()

    for s in socks:
        threading.Thread(target=loop, args=(s,), daemon=True).start()


# ---- clients ---------------------------------------------------------------------------


class ProxyError(Exception):
    pass


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        chunk = s.recv(n - len(b))
        if not chunk:
            raise ProxyError("closed after %d of %d bytes" % (len(b), n))
        b += chunk
    return b


def _read_line(s):
    b = b""
    while not b.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            break
        b += chunk
    return b.decode().strip()


def socks5(port, user, password, dst, dst_port=TARGET_PORT, timeout=10.0):
    """SOCKS5 CONNECT through 127.0.0.4:port; returns the source address the target saw."""
    s = socket.create_connection((SOCKS_HOST, port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x02")
        if _recv_exact(s, 2) != b"\x05\x02":
            raise ProxyError("no user/pass method")
        u, p = user.encode(), password.encode()
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        _recv_exact(s, 2)
        ip = ipaddress.ip_address(dst)
        atyp = b"\x04" if ip.version == 6 else b"\x01"
        s.sendall(b"\x05\x01\x00" + atyp + ip.packed + struct.pack("!H", dst_port))
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise ProxyError("socks reply %d" % head[1])
        _recv_exact(s, 16 + 2 if head[3] == 4 else 4 + 2)
        line = _read_line(s)
        if not line:
            raise ProxyError("no data from the target")
        return ipaddress.ip_address(line)
    finally:
        s.close()


def http_connect(port, user, password, dst, dst_port=TARGET_PORT, timeout=10.0):
    s = socket.create_connection((HTTP_HOST, port + HTTP_OFFSET), timeout=timeout)
    try:
        host = "[%s]" % dst if ":" in dst else dst
        cred = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        s.sendall(
            (
                "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n"
                % (host, dst_port, host, dst_port, cred)
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1)
            if not chunk:
                raise ProxyError("closed during the CONNECT reply")
            head += chunk
        status = head.split(b"\r\n", 1)[0].decode()
        if " 200 " not in status + " ":
            raise ProxyError(status)
        return ipaddress.ip_address(_read_line(s))
    finally:
        s.close()


def fails(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return False
    except (ProxyError, OSError):
        return True


# ---- RADIUS setup ----------------------------------------------------------------------


def pw_fields(password, salt=None):
    salt = salt or os.urandom(16)
    return {"pwSalt": salt.hex(), "pwHash": hashlib.sha256(salt + password.encode()).hexdigest()}


class Env:
    def __init__(self, a):
        self.a = a
        self.key = os.urandom(32)
        self.tagger = tag.Tagger(self.key)
        self.prefix = ipaddress.IPv6Network(PREFIX)
        self.seq = 0

    def call(self, req, expect_ok=True):
        r = ctl.call(self.a.ctl, req)
        if expect_ok and "error" in r:
            raise SystemExit("ctl %s failed: %s" % (req.get("op"), r))
        return r

    def facts(self, **over):
        probe_salt = os.urandom(16)
        f = {
            "base": self.a.base,
            "count": self.a.count,
            "geo": "us",
            "family": "dualstack",
            "egressIpv4": self.a.egress4,
            "prefix": PREFIX,
            "subnets": [0, 0xFFFE],
            "addrKey": base64.b64encode(self.key).decode(),
            "probe": {
                "pwSalt": probe_salt.hex(),
                "pwHash": hashlib.sha256(probe_salt + PROBE_PW.encode()).hexdigest(),
                "canary": [[self.a.target6, TARGET_PORT], [self.a.target4, TARGET_PORT]],
            },
            "reserves": {"staticPct": 5, "stickyPct": 15},
            "logdumpBytes": 262144,
        }
        f.update(over)
        return self.call({"op": "facts", "facts": f})

    def snapshot(self):
        self.seq += 1
        acc = {
            "id": 900000001,
            "state": "active",
            "expiresAt": int(time.time()) + 86400,
            "limit": {"epoch": 1, "bytes": 1 << 40, "allowance": 1 << 40, "full": True},
            "staticCap": 100,
            "stickyExclCap": 2000,
            "trial": False,
        }
        lists = [
            dict(
                {
                    "id": 101,
                    "login": "netrun-e2erota",
                    "accountId": 900000001,
                    "pwRev": 1,
                    "status": "active",
                    "mode": "rotate",
                    "ttlSec": None,
                },
                **pw_fields(PW),
            ),
            dict(
                {
                    "id": 102,
                    "login": "netrun-e2estik",
                    "accountId": 900000001,
                    "pwRev": 1,
                    "status": "active",
                    "mode": "sticky",
                    "ttlSec": 600,
                },
                **pw_fields(PW),
            ),
            dict(
                {
                    "id": 103,
                    "login": "netrun-e2estat",
                    "accountId": 900000001,
                    "pwRev": 1,
                    "status": "active",
                    "mode": "static",
                    "ttlSec": None,
                },
                **pw_fields(PW),
            ),
            dict(
                {
                    "id": 104,
                    "login": "netrun-e2eblok",
                    "accountId": 900000001,
                    "pwRev": 1,
                    "status": "blocked",
                    "mode": "rotate",
                    "ttlSec": None,
                },
                **pw_fields(PW),
            ),
        ]
        return self.call({"op": "snapshot", "seq": self.seq, "accounts": [acc], "lists": lists, "static": []})

    def list_of(self, addr):
        if addr.version != 6 or addr not in self.prefix:
            return None
        return self.tagger.list_of(int(addr) & ((1 << 64) - 1))

    def wait_ctl(self, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return ctl.call(self.a.ctl, {"op": "status"}, timeout=2)
            except OSError:
                time.sleep(0.05)
        raise SystemExit("netrun-radius ctl did not come back")

    def wait_down(self, timeout=10.0):
        """Wait until netrun-radius has exited (its ctl socket is gone)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                ctl.call(self.a.ctl, {"op": "status"}, timeout=1)
            except OSError:
                return
            time.sleep(0.05)
        raise SystemExit("netrun-radius did not stop")

    def restart(self, sig=signal.SIGHUP):
        before = self.wait_ctl()
        os.kill(self.a.sockact_pid, sig)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            time.sleep(0.1)
            try:
                st = ctl.call(self.a.ctl, {"op": "status"}, timeout=2)
            except OSError:
                continue
            if st["uptimeSec"] < before["uptimeSec"] or st["uptimeSec"] < 5:
                return st
        raise SystemExit("restart did not happen")


# ---- checks ----------------------------------------------------------------------------


def run_checks(env: Env):
    a = env.a
    b = a.base
    t6, t4 = a.target6, a.target4

    # accept / reject
    src = socks5(b, "netrun-e2erota", PW, t6)
    check("accept: rotation via SOCKS5 gets a tagged source in the /48", env.list_of(src) == 101, src)
    check("reject: wrong password", fails(socks5, b, "netrun-e2erota", "wrong-password", t6))
    check("reject: unknown login", fails(socks5, b, "netrun-nosuchx", PW, t6))
    check("reject: blocked list", fails(socks5, b, "netrun-e2eblok", PW, t6))
    check("reject: bad params", fails(socks5, b, "netrun-e2erota-bogus", PW, t6))
    rej = env.call({"op": "rejects"})["lists"]
    check("reject reasons are recorded per list", rej.get("104", {}).get("reason") == "list_off", rej)

    # Framed-IPv6 per connection (rotation)
    nets = set()
    for _ in range(12):
        s = socks5(b, "netrun-e2erota", PW, t6)
        nets.add((int(s) >> 64) & 0xFFFF)
        if env.list_of(s) != 101:
            check("rotation sources carry the list tag", False, s)
    check("rotation: a distinct /64 per connection", len(nets) == 12, len(nets))

    # sticky by port and by session
    s1 = socks5(b + 1, "netrun-e2estik", PW, t6)
    s2 = socks5(b + 1, "netrun-e2estik", PW, t6)
    s3 = socks5(b + 2, "netrun-e2estik", PW, t6)
    check("sticky: same source on the same port", s1 == s2, (s1, s2))
    check("sticky: another port is another slot", ((int(s1) >> 64) & 0xFFFF) != ((int(s3) >> 64) & 0xFFFF), (s1, s3))
    k1 = socks5(b, "netrun-e2erota-session-job1-ttl-30m", PW, t6)
    k2 = socks5(b + 3, "netrun-e2erota-session-job1-ttl-30m", PW, t6)
    check("sticky: session param holds across ports", k1 == k2, (k1, k2))

    # static, NAS-Port -> slot
    st1 = socks5(b + 2, "netrun-e2estat", PW, t6)
    st0 = socks5(b, "netrun-e2erota-static", PW, t6)
    feed = env.call({"op": "bindings", "after": 0})["items"]
    slots = {(i["listId"], i["slot"]): i["addr"] for i in feed if i["op"] == "add"}
    check("NAS-Port reaches RADIUS: static on base+2 is slot p2", slots.get((103, "p2")) == str(st1), slots)
    check("base port with explicit -static is slot p0", slots.get((101, "p0")) == str(st0), slots)

    # HTTP CONNECT path
    nodst_before = env.call({"op": "status"})["noDst"]
    try:
        h = http_connect(b, "netrun-e2erota", PW, t6)
        check("HTTP CONNECT through 127.0.0.3 gets a tagged source", env.list_of(h) == 101, h)
    except (ProxyError, OSError) as e:
        check("HTTP CONNECT through 127.0.0.3 gets a tagged source", False, e)
    nodst = env.call({"op": "status"})["noDst"] - nodst_before
    print("info HTTP CONNECT Access-Requests without a destination: %d" % nodst, flush=True)

    # IPv4 destination
    v4 = socks5(b, "netrun-e2erota", PW, t4)
    check("IPv4 destination leaves from the egress IPv4 (Framed-IP-Address)", str(v4) == a.egress4, v4)
    try:
        hv4 = http_connect(b + 1, "netrun-e2estik", PW, t4)
        check("IPv4 destination over HTTP CONNECT", str(hv4) == a.egress4, hv4)
    except (ProxyError, OSError) as e:
        check("IPv4 destination over HTTP CONNECT", False, e)

    # static across a RADIUS restart
    env.restart(signal.SIGHUP)
    check("static survives a graceful RADIUS restart", socks5(b + 2, "netrun-e2estat", PW, t6) == st1)
    check("sticky survives a graceful RADIUS restart", socks5(b + 1, "netrun-e2estik", PW, t6) == s1)
    env.restart(signal.SIGUSR1)
    time.sleep(0.3)
    check("static survives a RADIUS crash (kill -9)", socks5(b + 2, "netrun-e2estat", PW, t6) == st1)

    # probe
    pr = socks5(b, "netrun-svcprobe", PROBE_PW, t6)
    check("probe login works towards the canary", env.list_of(pr) == 0, pr)
    check("probe login refused elsewhere", fails(socks5, b, "netrun-svcprobe", PROBE_PW, t6, dst_port=TARGET_PORT + 1))

    # ipv6_only
    env.facts(family="ipv6_only", egressIpv4=None)
    check("ipv6_only: an IPv4 destination is rejected", fails(socks5, b, "netrun-e2erota", PW, t4))
    check("ipv6_only: IPv6 still works", env.list_of(socks5(b, "netrun-e2erota", PW, t6)) == 101)
    env.facts()

    # RADIUS hung (socket held, nobody reads): SINGLEBYTE_L then reject
    os.kill(a.sockact_pid, signal.SIGUSR2)
    env.wait_down()
    t0 = time.monotonic()
    dead_failed = fails(socks5, b, "netrun-e2erota", PW, t6, timeout=20)
    dt = time.monotonic() - t0
    check("dead RADIUS: the connection fails", dead_failed)
    check("dead RADIUS: after SINGLEBYTE_L (~3 s)", 2.5 <= dt <= 8, "%.2f s" % dt)
    os.kill(a.sockact_pid, signal.SIGHUP)
    env.wait_ctl()
    time.sleep(0.3)
    check("RADIUS back: accepts again", env.list_of(socks5(b, "netrun-e2erota", PW, t6)) == 101)

    restart_under_load(env)


def load_while(env: Env, signals, workers=16):
    """Run SOCKS5 load while restarting netrun-radius with each signal in turn."""
    a = env.a
    stop = threading.Event()
    stats = {"ok": 0, "fail": 0, "errors": []}
    lock = threading.Lock()

    def worker(i):
        users = ["netrun-e2erota", "netrun-e2estik", "netrun-e2estat"]
        k = 0
        while not stop.is_set():
            k += 1
            user = users[(i + k) % 3]
            port = a.base + (i + k) % a.count
            dst = a.target6 if k % 4 else a.target4
            try:
                socks5(port, user, PW, dst, timeout=15)
                with lock:
                    stats["ok"] += 1
            except (ProxyError, OSError) as e:
                with lock:
                    stats["fail"] += 1
                    if len(stats["errors"]) < 10:
                        stats["errors"].append("%s %s: %s" % (user, port, e))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(workers)]
    for t in threads:
        t.start()
    time.sleep(2)
    for sig in signals:
        env.restart(sig)
        time.sleep(1.5)
    time.sleep(2)
    stop.set()
    for t in threads:
        t.join(30)
    return stats


def restart_under_load(env: Env):
    # graceful restarts (systemctl restart = SIGTERM): the socket keeps queueing, nothing is lost
    st = load_while(env, [signal.SIGHUP] * 3)
    check(
        "restart under load: 3 graceful restarts, no failed connection (%d ok)" % st["ok"],
        st["fail"] == 0 and st["ok"] > 200,
        st,
    )
    # crashes (kill -9): at most the one request being processed is lost per crash
    st = load_while(env, [signal.SIGUSR1] * 2)
    check(
        "crash under load: at most one lost request per kill -9 (%d ok, %d failed)" % (st["ok"], st["fail"]),
        st["fail"] <= 2 and st["ok"] > 200,
        st,
    )


# ---- capture of real 3proxy Access-Requests ---------------------------------------------


def capture(env: Env, out_dir: str):
    """Replace RADIUS by a recorder on 127.0.0.1:1812 and save real 3proxy requests."""
    a = env.a
    os.kill(a.sockact_pid, signal.SIGTERM)
    env.wait_down()
    with open(a.secret_file, "rb") as fh:
        secret = fh.read().strip()
    rec = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host, _, port = a.radius.rpartition(":")
    for _ in range(100):  # the supervisor releases the socket when it exits
        try:
            rec.bind((host, int(port)))
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise SystemExit("cannot bind %s for the capture" % a.radius)
    rec.settimeout(6)
    cases = [
        ("socks", a.base, "netrun-e2erota", PW, a.target6),
        ("socks", a.base + 1, "netrun-e2estik-session-s00042-ttl-30m", PW, a.target6),
        ("socks", a.base + 2, "NETRUN-E2ESTAT", "a" * 40, a.target4),
        ("http", a.base, "netrun-e2erota-country-us", PW, a.target6),
        ("http", a.base + 3, "netrun-e2estat-static", "x", a.target4),
    ]
    packets = []
    for kind, port, user, pw, dst in cases:
        result = {}

        def client(kind, port, user, pw, dst, result):
            try:
                (socks5 if kind == "socks" else http_connect)(port, user, pw, dst, timeout=10)
            except (ProxyError, OSError) as e:
                result["err"] = str(e)

        t = threading.Thread(target=client, args=(kind, port, user, pw, dst, result), daemon=True)
        t.start()
        try:
            data, peer = rec.recvfrom(4096)
        except socket.timeout:
            check("capture %s %s" % (kind, user), False, "no Access-Request")
            continue
        req = proto.decode_request(data)
        rec.sendto(proto.reject(req, secret), peer)
        t.join(10)
        packets.append(
            {
                "via": kind,
                "hex": data.hex(),
                "username": user,
                "password": pw,
                "nasPort": port,
                "dst": dst,
                "dstPort": TARGET_PORT,
            }
        )
        got_pw = proto.decode_password(req.password_enc, secret, req.authenticator).decode(errors="replace")
        dst_ok = req.dst_addr is not None and str(ipaddress.ip_address(req.dst_addr)) == dst
        check(
            "capture %s: user, password, NAS-Port decode" % kind,
            req.username.decode() == user and got_pw == pw and req.nas_port == port,
            (req.username, req.nas_port),
        )
        print("info capture %s: destination attribute %s" % (kind, "present" if dst_ok else "MISSING"), flush=True)
    rec.close()
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "3proxy_captured.json"), "w") as fh:
        json.dump({"secret": secret.decode(), "source": "3proxy e2e capture", "packets": packets}, fh, indent=1)


def main():
    global SOCKS_HOST, HTTP_HOST, HTTP_OFFSET
    p = argparse.ArgumentParser()
    p.add_argument("--ctl", required=True)
    p.add_argument("--sockact-pid", type=int, required=True)
    p.add_argument("--secret-file", required=True)
    p.add_argument("--base", type=int, default=31000)
    p.add_argument("--count", type=int, default=4)
    p.add_argument("--target6", default="2001:db8:ffff::1")
    p.add_argument("--target4", default="10.200.0.1")
    p.add_argument("--egress4", default="10.200.0.2")
    p.add_argument("--out", required=True)
    p.add_argument("--socks-host", default=SOCKS_HOST)
    p.add_argument("--http-host", default=HTTP_HOST)
    p.add_argument("--http-offset", type=int, default=0)
    p.add_argument("--no-target", action="store_true", help="dry run against fake3proxy.py")
    p.add_argument("--radius", default="127.0.0.1:1812", help="where 3proxy sends Access-Requests (capture phase)")
    a = p.parse_args()
    SOCKS_HOST, HTTP_HOST, HTTP_OFFSET = a.socks_host, a.http_host, a.http_offset
    os.makedirs(a.out, exist_ok=True)
    if not a.no_target:
        serve_target([a.target6, a.target4])
    env = Env(a)
    env.wait_ctl(20)
    env.facts()
    env.snapshot()
    try:
        run_checks(env)
    finally:
        try:
            capture(env, a.out)
        except Exception as e:  # the capture is a bonus, the checks above are the test
            check("capture", False, e)
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)), flush=True)
    with open(os.path.join(a.out, "e2e_results.json"), "w") as fh:
        json.dump([{"check": n, "ok": ok, "detail": str(d)} for n, ok, d in RESULTS], fh, indent=1)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
