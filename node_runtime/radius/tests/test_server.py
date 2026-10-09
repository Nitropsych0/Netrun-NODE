"""Process-level tests: socket activation, READY time with cap-sized state, load, signals."""

from __future__ import annotations

import json
import os
import random
import signal
import socket
import subprocess
import sys
import time
import unittest

import rtest
from rtest import BASE, account, plist

import ctl
import proto
import sockact
import state

SERVER = os.path.join(rtest.RADIUS_DIR, "netrun_radius.py")
PW = "Passw0rdPassw0rd"
# CI runners are slower and noisier than a node; NETRUN_RADIUS_PERF_SLACK=2 doubles the time budgets
SLACK = float(os.environ.get("NETRUN_RADIUS_PERF_SLACK", "1"))


class Proc(unittest.TestCase):
    def setUp(self):
        self.dir = rtest.tmpdir(self)
        self.secret_file = os.path.join(self.dir, "radius.secret")
        with open(self.secret_file, "wb") as fh:
            fh.write(rtest.SECRET + b"\n")
        self.state_dir = os.path.join(self.dir, "state")
        self.ctl_path = os.path.join(self.dir, "ctl.sock")
        self.sock = sockact.bind_udp("127.0.0.1:0")
        self.addCleanup(self.sock.close)
        self.port = self.sock.getsockname()[1]
        self.notify_path = os.path.join(self.dir, "notify.sock")
        self.notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.notify.bind(self.notify_path)
        self.addCleanup(self.notify.close)
        self.procs = []
        self.addCleanup(self._kill_all)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(("127.0.0.1", 0))
        self.addCleanup(self.client.close)

    def _kill_all(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
            p.wait()

    def start(self, extra_env=None, watchdog=False, timeout=15.0):
        env = dict(os.environ)
        env["NOTIFY_SOCKET"] = self.notify_path
        env.update(extra_env or {})
        args = [
            sys.executable,
            "-I",
            SERVER,
            "--state-dir",
            self.state_dir,
            "--secret-file",
            self.secret_file,
            "--ctl-socket",
            self.ctl_path,
        ]
        if not watchdog:
            args.append("--no-watchdog")
        t0 = time.monotonic()
        p = sockact.spawn(self.sock, args, env=env)
        self.procs.append(p)
        self.wait_notify("READY=1", timeout)
        return p, time.monotonic() - t0

    def wait_notify(self, what, timeout):
        self.notify.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while True:
            msg = self.notify.recv(4096).decode()
            if what in msg.split("\n"):
                return msg
            if time.monotonic() > deadline:
                raise AssertionError("no %s" % what)

    def push_basics(self, lists=None):
        self.assertEqual(ctl.call(self.ctl_path, {"op": "facts", "facts": rtest.facts()}), {"ok": True})
        lists = lists or [plist(10, "statica", 1, PW, mode="static"), plist(11, "rotaaaa", 1, PW)]
        r = ctl.call(
            self.ctl_path, {"op": "snapshot", "seq": 1, "accounts": [account(1)], "lists": lists, "static": []}
        )
        self.assertNotIn("error", r)

    def send(self, user, port=BASE, ident=1):
        pkt, ra = rtest.request(user, PW, port=port, ident=ident)
        self.client.sendto(pkt, ("127.0.0.1", self.port))
        return ra

    def recv(self, ra, timeout=5.0):
        self.client.settimeout(timeout)
        data, _ = self.client.recvfrom(4096)
        return rtest.Reply(data, ra)

    def ask(self, user, port=BASE):
        return self.recv(self.send(user, port))


class SocketActivation(Proc):
    def test_queued_datagrams_are_answered_after_a_restart(self):
        p, _ = self.start()
        self.push_basics()
        static_addr = self.ask("netrun-statica", BASE + 7).addr
        self.assertIsNotNone(static_addr)
        time.sleep(0.3)  # let the batched writer commit the binding
        p.kill()
        p.wait()
        ras = {}
        for i in range(50):
            ras[i % 256] = self.send("netrun-rotaaaa", ident=i % 256)
        p2, _ = self.start()
        got = 0
        self.client.settimeout(10)
        while got < 50:
            data, _ = self.client.recvfrom(4096)
            r = rtest.Reply(data, ras[data[1]])
            self.assertTrue(r.valid and r.accepted)
            got += 1
        self.assertEqual(self.ask("netrun-statica", BASE + 7).addr, static_addr)
        st = ctl.call(self.ctl_path, {"op": "status"})
        self.assertFalse(st["dbRecovered"])
        p2.send_signal(signal.SIGTERM)
        self.assertEqual(p2.wait(10), 0)
        self.assertFalse(os.path.exists(self.ctl_path))

    def test_secret_reload_and_watchdog(self):
        p, _ = self.start(extra_env={"WATCHDOG_USEC": "10000000"}, watchdog=True)
        self.wait_notify("WATCHDOG=1", 5)
        self.push_basics()
        self.assertTrue(self.ask("netrun-rotaaaa").accepted)
        with open(self.secret_file, "wb") as fh:
            fh.write(b"An0therSecretAn0therSecretAn0therSecret1")
        os.utime(self.secret_file, (time.time() + 5, time.time() + 5))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            pkt, ra = rtest.request("netrun-rotaaaa", PW, secret=b"An0therSecretAn0therSecretAn0therSecret1")
            self.client.sendto(pkt, ("127.0.0.1", self.port))
            r = rtest.Reply(self.client.recvfrom(4096)[0], ra, b"An0therSecretAn0therSecretAn0therSecret1")
            if r.valid and r.accepted:
                break
            time.sleep(0.5)
        else:
            self.fail("the new secret was not picked up")
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)

    def test_listen_flag_without_activation(self):
        env = dict(os.environ, NOTIFY_SOCKET=self.notify_path)
        args = [
            sys.executable,
            "-I",
            SERVER,
            "--listen",
            "127.0.0.1:0",
            "--state-dir",
            self.state_dir,
            "--secret-file",
            self.secret_file,
            "--ctl-socket",
            self.ctl_path,
            "--no-watchdog",
        ]
        p = subprocess.Popen(args, env=env)
        self.procs.append(p)
        self.wait_notify("READY=1", 15)
        self.assertIn("epoch", ctl.call(self.ctl_path, {"op": "status"}))
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)


def build_cap_state(path: str, n_lists=50_000, n_static=40_000, n_sticky=60_000, n_accounts=25_000):
    """Write a cap-sized radius.db directly (fast bulk insert)."""
    st = state.Store(path)
    st.open()
    conn = st.conn
    rng = random.Random(1)
    conn.execute("BEGIN")
    f = rtest.facts()
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('facts', ?)", (json.dumps(f),))
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('seq', '77')")
    conn.executemany(
        "INSERT INTO accounts(id, state, expires_at, limit_json, static_cap, sticky_excl_cap, trial, local_blocked) VALUES (?,?,?,?,?,?,?,?)",
        [
            (
                a,
                "active",
                4e9,
                json.dumps({"epoch": 1, "bytes": 1 << 34, "allowance": 1 << 34, "full": True}),
                100,
                2000,
                0,
                0,
            )
            for a in range(n_accounts)
        ],
    )
    salt = "00" * 16
    conn.executemany(
        "INSERT INTO lists(id, login, account_id, pw_salt, pw_hash, pw_rev, status, mode, ttl_sec) VALUES (?,?,?,?,?,?,?,?,?)",
        [(i, "netrun-l%07d" % i, i % n_accounts, salt, "11" * 32, 1, "active", "sticky", 3600) for i in range(n_lists)],
    )
    prefix = rtest.PREFIX_INT
    rows = []
    for i in range(n_static):
        net = i
        addr = prefix | (net << 64) | rng.randrange(1 << 32, 1 << 64)
        rows.append(
            (
                i % n_lists,
                "p%d" % (i // n_lists),
                "static",
                addr.to_bytes(16, "big"),
                net,
                (i % n_lists) % n_accounts,
                0,
                1e9,
                None,
                1e9,
            )
        )
    for j in range(n_sticky):
        net = n_static + (j // 3) % 20000
        lid = (j * 7919) % n_lists
        addr = prefix | (net << 64) | rng.randrange(1 << 32, 1 << 64)
        rows.append((lid, "s:k%d" % j, "sticky", addr.to_bytes(16, "big"), net, lid % n_accounts, 1, 1e9, 4e9, 1e9))
    conn.executemany(
        "INSERT INTO bindings(list_id, slot, kind, addr, net, account_id, shared, created_at, expires_at, last_used_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.execute("COMMIT")
    st.close()


class CapSizedState(Proc):
    def test_ready_within_one_second(self):
        os.makedirs(self.state_dir)
        build_cap_state(os.path.join(self.state_dir, "radius.db"))
        best = None
        for _ in range(2):  # a warm page cache is what a restart sees
            p, elapsed = self.start()
            st = ctl.call(self.ctl_path, {"op": "status"})
            p.send_signal(signal.SIGTERM)
            p.wait(10)
            best = elapsed if best is None else min(best, elapsed)
        self.assertEqual(st["counts"]["lists"], 50_000)
        self.assertEqual(st["counts"]["static"], 40_000)
        self.assertGreater(st["counts"]["sticky"], 55_000)  # a few same-account /64 collisions are dropped
        self.assertEqual(st["seq"], 77)
        print("\n  READY with 50k lists / 100k bindings: %.0f ms" % (best * 1000), file=sys.stderr)
        self.assertLess(best, 1.0 * SLACK)


class Load(unittest.TestCase):
    def test_in_process_throughput_one_core(self):
        eng = rtest.make_engine(self)
        lists = [
            plist(
                i,
                "l%06d" % i,
                i % 50,
                PW,
                mode=("rotate", "sticky", "static")[i % 3],
                ttlSec=600 if i % 3 == 1 else None,
            )
            for i in range(1, 601)
        ]
        r = eng.dispatch(
            {
                "op": "snapshot",
                "seq": 1,
                "accounts": [account(a, staticCap=100_000) for a in range(50)],
                "lists": lists,
                "static": [],
            }
        )
        self.assertNotIn("error", r)
        rng = random.Random(2)
        pkts = []
        for k in range(30000):
            i = rng.randint(1, 600)
            port = BASE + rng.randint(0, 999) if k % 4 else BASE
            pkt, _ = rtest.request("netrun-l%06d" % i, PW, port=port, ident=k % 256)
            pkts.append(pkt)
        handle = eng.handle
        t0 = time.perf_counter()
        for pkt in pkts:
            out = handle(pkt)
            assert out is not None and out[0] == proto.ACCESS_ACCEPT, out
        dt = time.perf_counter() - t0
        rate = len(pkts) / dt
        p50, p99 = eng.latency()
        print("\n  in-process: %.0f req/s, p50 %.3f ms, p99 %.3f ms" % (rate, p50, p99), file=sys.stderr)
        self.assertGreaterEqual(rate * SLACK, 6000)
        self.assertLess(p99, 2.0 * SLACK)


class UdpLoad(Proc):
    def test_udp_round_trips(self):
        self.start()
        lists = [plist(i, "l%06d" % i, 1, PW, mode="rotate") for i in range(1, 101)]
        self.push_basics(lists)
        n = 3000
        pkts = [rtest.request("netrun-l%06d" % (1 + k % 100), PW, ident=k % 256) for k in range(n)]
        # sequential round trips: client-observed latency
        rtts = []
        self.client.settimeout(5)
        for pkt, _ra in pkts[:1000]:
            t0 = time.perf_counter()
            self.client.sendto(pkt, ("127.0.0.1", self.port))
            data, _ = self.client.recvfrom(4096)
            rtts.append(time.perf_counter() - t0)
            self.assertEqual(data[0], proto.ACCESS_ACCEPT)
        rtts.sort()
        p99 = rtts[int(len(rtts) * 0.99)] * 1000
        # pipelined: 64 in flight
        t0 = time.perf_counter()
        sent = recvd = 0
        while recvd < n:
            while sent < n and sent - recvd < 64:
                self.client.sendto(pkts[sent][0], ("127.0.0.1", self.port))
                sent += 1
            self.client.recvfrom(4096)
            recvd += 1
        rate = n / (time.perf_counter() - t0)
        st = ctl.call(self.ctl_path, {"op": "status"})
        print(
            "\n  UDP: rtt p99 %.3f ms, pipelined %.0f req/s, server p99 %s ms" % (p99, rate, st["latency"]["p99Ms"]),
            file=sys.stderr,
        )
        self.assertLess(p99, 2.0 * SLACK)
        self.assertLess(st["latency"]["p99Ms"], 2.0 * SLACK)
        self.assertGreaterEqual(rate * SLACK, 6000)
        self.assertEqual(st["counters"]["accepts"], 1000 + n)


if __name__ == "__main__":
    unittest.main()
