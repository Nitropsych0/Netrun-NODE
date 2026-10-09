from __future__ import annotations

import hashlib
import ipaddress
import os
import unittest

import rtest
from rtest import BASE, DST4, DST6, ask, account, plist

PW = "Passw0rdPassw0rd"
L_PRIME = 262144 + 65536


def setup_state(eng, lists=None, accounts=None, seq=1):
    accounts = accounts or [account(1), account(2)]
    lists = lists or [
        plist(10, "rotaaaa", 1, mode="rotate"),
        plist(11, "stickyy", 1, mode="sticky", ttlSec=1800),
        plist(12, "statica", 1, mode="static"),
        plist(20, "otheraa", 2, mode="rotate"),
    ]
    r = eng.dispatch({"op": "snapshot", "seq": seq, "accounts": accounts, "lists": lists, "static": []})
    assert "error" not in r, r
    return r


class Basics(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock)
        setup_state(self.eng)

    def reason_of(self, user, **kw):
        before = dict(self.eng.reject_counts)
        r = ask(self.eng, user, **kw)
        self.assertTrue(r.valid)
        if r.accepted:
            return None
        diff = [k for k, v in self.eng.reject_counts.items() if v != before.get(k)]
        self.assertEqual(len(diff), 1, diff)
        self.assertEqual(r.attrs, [])  # Access-Reject never carries attributes
        return diff[0]

    def test_accept_rotation(self):
        r = ask(self.eng, "netrun-rotaaaa")
        self.assertTrue(r.valid and r.accepted)
        self.assertEqual(len(r.attrs), 1)
        self.assertEqual(r.attrs[0][0], 168)
        self.assertIn(r.addr, ipaddress.IPv6Network(rtest.PREFIX))
        iid = int(r.addr) & ((1 << 64) - 1)
        self.assertEqual(self.eng.alloc.tagger.list_of(iid), 10)

    def test_rotation_gives_a_new_64_per_connection(self):
        nets = {ask(self.eng, "netrun-rotaaaa").net for _ in range(50)}
        self.assertEqual(len(nets), 50)

    def test_reject_reasons(self):
        self.assertEqual(self.reason_of("netrun-nosuchx"), "bad_login")
        self.assertEqual(self.reason_of("netrun-rotaaaa", password="nope"), "bad_login")
        self.assertEqual(self.reason_of("netrun-rotaaaa-foo"), "bad_params")
        self.assertEqual(self.reason_of("netrun-rotaaaa-country-de"), "bad_params")
        self.assertEqual(self.reason_of("netrun-rotaaaa", port=BASE - 1), "bad_params")
        self.assertEqual(self.reason_of("netrun-rotaaaa", port=BASE + 1000), "bad_params")
        self.assertEqual(self.reason_of("someone-else"), "bad_login")
        self.assertIsNone(self.reason_of("netrun-rotaaaa", port=BASE + 999))
        self.assertIsNone(self.reason_of("NETRUN-ROTAAAA-COUNTRY-US"))

    def test_list_and_account_states(self):
        e = self.eng
        e.dispatch(
            {
                "op": "apply",
                "baseSeq": 1,
                "seq": 2,
                "accounts": [],
                "lists": [plist(10, "rotaaaa", 1, status="blocked")],
            }
        )
        self.assertEqual(self.reason_of("netrun-rotaaaa"), "list_off")
        e.dispatch({"op": "apply", "baseSeq": 2, "seq": 3, "accounts": [account(1, state="blocked")], "lists": []})
        self.assertEqual(self.reason_of("netrun-stickyy"), "account_off")
        e.dispatch(
            {"op": "apply", "baseSeq": 3, "seq": 4, "accounts": [account(1, expiresAt=self.clock() - 1)], "lists": []}
        )
        self.assertEqual(self.reason_of("netrun-stickyy"), "account_off")
        e.dispatch({"op": "apply", "baseSeq": 4, "seq": 5, "accounts": [account(1)], "lists": []})
        self.assertIsNone(self.reason_of("netrun-stickyy"))
        e.dispatch({"op": "local_block", "accountId": 1, "blocked": True})
        self.assertEqual(self.reason_of("netrun-stickyy"), "quota")
        self.assertIsNone(self.reason_of("netrun-otheraa"))
        e.dispatch({"op": "local_block", "accountId": 1, "blocked": False})
        self.assertIsNone(self.reason_of("netrun-stickyy"))

    def test_list_without_account(self):
        self.eng.dispatch({"op": "apply", "baseSeq": 1, "seq": 2, "accounts": [], "lists": [plist(30, "orphana", 99)]})
        self.assertEqual(self.reason_of("netrun-orphana"), "account_off")

    def test_per_list_last_reject(self):
        ask(self.eng, "netrun-rotaaaa", password="x")
        self.clock.advance(5)
        ask(self.eng, "netrun-rotaaaa-bogus")
        rej = self.eng.dispatch({"op": "rejects"})["lists"]
        self.assertEqual(rej["10"]["reason"], "bad_params")
        self.assertEqual(rej["10"]["count"], 2)
        self.assertEqual(rej["10"]["at"], self.clock())
        st = self.eng.dispatch({"op": "status"})
        self.assertEqual(st["rejects"]["bad_login"], 1)
        self.assertEqual(st["rejects"]["bad_params"], 1)

    def test_sticky_by_port_and_session(self):
        a = ask(self.eng, "netrun-stickyy", port=BASE + 5)
        b = ask(self.eng, "netrun-stickyy", port=BASE + 5)
        c = ask(self.eng, "netrun-stickyy", port=BASE + 6)
        self.assertEqual(a.addr, b.addr)
        self.assertNotEqual(a.net, c.net)
        s1 = ask(self.eng, "netrun-stickyy-session-job1")
        s2 = ask(self.eng, "netrun-stickyy-session-job1", port=BASE + 9)
        self.assertEqual(s1.addr, s2.addr)
        # the base port rotates a bare login even on a sticky list
        self.assertNotEqual(ask(self.eng, "netrun-stickyy").net, ask(self.eng, "netrun-stickyy").net)

    def test_sticky_ttl_param_and_change(self):
        a = ask(self.eng, "netrun-rotaaaa-session-x-ttl-10m")
        self.clock.advance(500)
        b = ask(self.eng, "netrun-rotaaaa-session-x-ttl-1h")
        self.assertEqual(a.addr, b.addr)
        self.clock.advance(3100)  # created + 3600
        c = ask(self.eng, "netrun-rotaaaa-session-x-ttl-1h")
        self.assertNotEqual(c.net, a.net)

    def test_static_and_base_port_explicit_param(self):
        a = ask(self.eng, "netrun-statica", port=BASE + 3)
        self.clock.advance(86400 * 40)
        self.assertEqual(ask(self.eng, "netrun-statica", port=BASE + 3).addr, a.addr)
        p0 = ask(self.eng, "netrun-rotaaaa-static")  # base port, explicit -static -> slot p0
        self.assertEqual(ask(self.eng, "netrun-rotaaaa-static").addr, p0.addr)
        self.assertIn((10, "p0"), self.eng.alloc.bindings)

    def test_static_cap_reason(self):
        self.eng.dispatch({"op": "apply", "baseSeq": 1, "seq": 2, "accounts": [account(1, staticCap=2)], "lists": []})
        ask(self.eng, "netrun-statica", port=BASE + 1)
        ask(self.eng, "netrun-statica", port=BASE + 2)
        self.assertEqual(self.reason_of("netrun-statica", port=BASE + 3), "static_cap")

    def test_trial_sticky_is_shared(self):
        self.eng.dispatch({"op": "apply", "baseSeq": 1, "seq": 2, "accounts": [account(1, trial=True)], "lists": []})
        ask(self.eng, "netrun-stickyy", port=BASE + 1)
        b = self.eng.alloc.bindings[(11, "p1")]
        self.assertTrue(b.shared)

    def test_ipv4_destination(self):
        r = ask(self.eng, "netrun-statica", port=BASE + 1, dst=DST4)
        self.assertTrue(r.accepted)
        self.assertEqual(r.attrs, [(8, ipaddress.IPv4Address(rtest.EGRESS4).packed)])
        self.assertNotIn((12, "p1"), self.eng.alloc.bindings)  # an IPv4 connection holds no /64
        self.eng.dispatch({"op": "ipv4_admission", "open": False})
        self.assertEqual(self.reason_of("netrun-rotaaaa", dst=DST4), "capacity")
        self.assertIsNone(self.reason_of("netrun-rotaaaa", dst=DST6))
        self.eng.dispatch({"op": "ipv4_admission", "open": True})
        self.assertIsNone(self.reason_of("netrun-rotaaaa", dst=DST4))

    def test_ipv6_only_rejects_ipv4(self):
        self.eng.dispatch({"op": "facts", "facts": rtest.facts(family="ipv6_only", egressIpv4=None)})
        self.assertEqual(self.reason_of("netrun-rotaaaa", dst=DST4), "bad_params")
        self.assertIsNone(self.reason_of("netrun-rotaaaa", dst=DST6))

    def test_no_destination_is_ipv6_and_counted(self):
        r = ask(self.eng, "netrun-rotaaaa", dst=None)
        self.assertTrue(r.accepted)
        self.assertEqual(r.addr.version, 6)
        self.assertEqual(self.eng.dispatch({"op": "status"})["noDst"], 1)

    def test_admission(self):
        e = self.eng
        e.dispatch({"op": "admission", "open": True, "softAccounts": [1]})
        self.assertEqual(self.reason_of("netrun-rotaaaa"), "capacity")
        self.assertIsNone(self.reason_of("netrun-otheraa"))
        e.dispatch({"op": "admission", "open": False, "softAccounts": []})
        self.assertEqual(self.reason_of("netrun-otheraa"), "capacity")
        e.dispatch({"op": "admission", "open": True})
        self.assertIsNone(self.reason_of("netrun-rotaaaa"))
        st = e.dispatch({"op": "status"})
        self.assertEqual(st["admission"], {"open": True, "soft": []})

    def test_no_facts_rejects(self):
        eng = rtest.make_engine(self, with_facts=False)
        r = ask(eng, "netrun-rotaaaa")
        self.assertTrue(r.valid)
        self.assertFalse(r.accepted)
        self.assertEqual(eng.reject_counts["not_ready"], 1)

    def test_no_secret_drops(self):
        eng = rtest.make_engine(self, secret=None)
        pkt, _ = rtest.request("netrun-rotaaaa")
        self.assertIsNone(eng.handle(pkt))
        self.assertEqual(eng.counters["noSecret"], 1)

    def test_wrong_client_secret_is_bad_login(self):
        r = ask(self.eng, "netrun-rotaaaa", secret=b"wrong")
        self.assertFalse(r.valid)  # the reply is signed with our secret
        self.assertEqual(self.eng.reject_counts["bad_login"], 1)

    def test_garbage_is_dropped(self):
        self.assertIsNone(self.eng.handle(b"\x01\x02"))
        self.assertIsNone(self.eng.handle(os.urandom(300)))
        self.assertGreaterEqual(self.eng.counters["malformed"], 1)

    def test_latency_is_recorded(self):
        for _ in range(20):
            ask(self.eng, "netrun-rotaaaa")
        st = self.eng.dispatch({"op": "status"})
        self.assertIsNotNone(st["latency"]["p99Ms"])
        self.assertGreaterEqual(st["latency"]["p99Ms"], st["latency"]["p50Ms"])


class DeadmanAndNear(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock)
        setup_state(self.eng)

    def hb(self, near):
        r = self.eng.dispatch({"op": "heartbeat", "at": self.clock(), "near": {str(k): v for k, v in near.items()}})
        self.assertEqual(r, {"ok": True})

    def test_near_reservations(self):
        self.hb({1: 3 * 2 * L_PRIME + 10})
        for _ in range(3):
            self.assertTrue(ask(self.eng, "netrun-rotaaaa").accepted)
        self.assertFalse(ask(self.eng, "netrun-rotaaaa").accepted)
        self.assertEqual(self.eng.reject_counts["quota"], 1)
        self.assertTrue(ask(self.eng, "netrun-otheraa").accepted)  # not near
        ns = self.eng.dispatch({"op": "near_stats"})["accounts"]
        self.assertEqual(ns["1"]["reserved"], 3 * 2 * L_PRIME)
        self.assertEqual(ns["1"]["ipv4Accepts"], 0)
        self.assertEqual(ns["1"]["since"], self.clock())
        # the next heartbeat resets the reservations; IPv4 accepts are counted since near-mode start
        self.clock.advance(1)
        self.hb({1: 2 * 2 * L_PRIME})
        self.assertTrue(ask(self.eng, "netrun-rotaaaa", dst=DST4).accepted)
        self.assertTrue(ask(self.eng, "netrun-rotaaaa", dst=DST4).accepted)
        self.assertFalse(ask(self.eng, "netrun-rotaaaa").accepted)
        ns = self.eng.dispatch({"op": "near_stats"})["accounts"]
        self.assertEqual(ns["1"]["ipv4Accepts"], 2)
        self.assertEqual(ns["1"]["since"], self.clock() - 1)
        # leaving near mode clears the counters
        self.hb({})
        self.assertEqual(self.eng.dispatch({"op": "near_stats"})["accounts"], {})
        self.assertTrue(ask(self.eng, "netrun-rotaaaa").accepted)

    def test_zero_headroom_rejects(self):
        self.hb({1: 0})
        self.assertFalse(ask(self.eng, "netrun-rotaaaa").accepted)

    def test_deadman(self):
        self.hb({1: 10 << 20})  # near-limit account with 10 MiB headroom
        self.clock.advance(14)
        self.assertTrue(ask(self.eng, "netrun-rotaaaa").accepted)
        self.clock.advance(2)  # heartbeat 16 s old
        self.assertFalse(ask(self.eng, "netrun-rotaaaa").accepted)
        self.assertTrue(ask(self.eng, "netrun-otheraa").accepted)  # others are served
        self.clock.advance(60)
        self.assertTrue(ask(self.eng, "netrun-otheraa").accepted)
        st = self.eng.dispatch({"op": "status"})
        self.assertTrue(st["deadman"]["active"])
        self.assertAlmostEqual(st["deadman"]["heartbeatAgeSec"], 76, places=3)
        self.hb({1: 10 << 20})
        self.assertTrue(ask(self.eng, "netrun-rotaaaa").accepted)

    def test_deadman_rate_times_staleness(self):
        self.hb({1: 2_000_000_000})  # 2 GB headroom at 50 MB/s lasts 40 s
        self.clock.advance(16)
        self.assertTrue(ask(self.eng, "netrun-rotaaaa").accepted)
        self.clock.advance(25)  # 41 s
        self.assertFalse(ask(self.eng, "netrun-rotaaaa").accepted)

    def test_deadman_env(self):
        eng = rtest.make_engine(self, clock=self.clock, env={"PERGB_DEADMAN_AFTER_SEC": "5", "PERGB_DEADMAN_RATE": "1"})
        setup_state(eng)
        eng.dispatch({"op": "heartbeat", "at": 0, "near": {"1": 10 << 20}})
        self.clock.advance(6)
        self.assertTrue(ask(eng, "netrun-rotaaaa").accepted)  # 10 MiB - 1 B/s * 6 s > 0


class Probe(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        salt = os.urandom(16)
        self.eng = rtest.make_engine(
            self,
            clock=self.clock,
            probe={
                "pwSalt": salt.hex(),
                "pwHash": hashlib.sha256(salt + b"ProbePassword123").hexdigest(),
                "canary": [["2001:db8:ffff::1", 443], ["198.51.100.7", 80]],
            },
        )

    def test_probe(self):
        r = ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=DST6, dst_port=443)
        self.assertTrue(r.accepted)
        self.assertEqual(self.eng.alloc.tagger.list_of(int(r.addr) & ((1 << 64) - 1)), 0)
        self.clock.advance(1)
        r4 = ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=DST4, dst_port=80)
        self.assertEqual(r4.attrs, [(8, ipaddress.IPv4Address(rtest.EGRESS4).packed)])
        self.assertEqual(self.eng.counters["probeAccepts"], 2)

    def test_probe_only_towards_the_canary(self):
        self.assertFalse(ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=DST6, dst_port=444).accepted)
        other = ipaddress.IPv6Address("2001:db8:ffff::2").packed
        self.assertFalse(ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=other, dst_port=443).accepted)
        self.assertFalse(ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=None).accepted)
        self.assertFalse(ask(self.eng, "netrun-svcprobe", "wrong", dst=DST6).accepted)

    def test_probe_rate_limit(self):
        ok = sum(ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=DST6).accepted for _ in range(10))
        self.assertEqual(ok, 2)
        self.clock.advance(1)
        ok = sum(ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=DST6).accepted for _ in range(10))
        self.assertEqual(ok, 2)

    def test_probe_ignores_admission(self):
        self.eng.dispatch({"op": "admission", "open": False})
        self.assertTrue(ask(self.eng, "netrun-svcprobe", "ProbePassword123", dst=DST6).accepted)


if __name__ == "__main__":
    unittest.main()
