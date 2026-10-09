from __future__ import annotations

import json
import os
import socket
import stat
import unittest

import rtest
from rtest import BASE, account, ask, plist

import ctl


def T(accounts=(), lists=()):
    return {"accounts": list(accounts), "lists": list(lists)}


class SeqAndTransitions(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock)
        self.lists = [
            plist(10, "aaaaaaa", 1, mode="static"),
            plist(11, "bbbbbbb", 1, mode="sticky", ttlSec=600),
            plist(20, "ccccccc", 2),
        ]
        self.accounts = [account(1), account(2)]
        r = self.eng.dispatch(
            {"op": "snapshot", "seq": 5, "accounts": self.accounts, "lists": self.lists, "static": []}
        )
        self.assertEqual(r["seq"], 5)
        self.assertEqual(r["epoch"], self.eng.epoch)
        self.assertEqual(r["transitions"], T())

    def test_apply_requires_the_current_seq(self):
        r = self.eng.dispatch(
            {"op": "apply", "baseSeq": 4, "seq": 6, "accounts": [account(1, state="blocked")], "lists": []}
        )
        self.assertEqual(r, {"error": "seq_mismatch", "epoch": self.eng.epoch, "seq": 5})
        self.assertEqual(self.eng.accounts[1].state, "active")  # nothing applied
        r = self.eng.dispatch({"op": "apply", "baseSeq": 5, "seq": 6, "accounts": [], "lists": []})
        self.assertEqual(r, {"epoch": self.eng.epoch, "seq": 6, "transitions": T()})
        r = self.eng.dispatch({"op": "apply", "baseSeq": 5, "seq": 7, "accounts": [], "lists": []})
        self.assertEqual(r["error"], "seq_mismatch")
        self.assertEqual(r["seq"], 6)
        # a snapshot always resets the seq
        r = self.eng.dispatch(
            {"op": "snapshot", "seq": 100, "accounts": self.accounts, "lists": self.lists, "static": []}
        )
        self.assertEqual(r["seq"], 100)
        self.assertEqual(self.eng.dispatch({"op": "status"})["seq"], 100)

    def test_transitions_on_apply(self):
        e = self.eng
        r = e.dispatch(
            {
                "op": "apply",
                "baseSeq": 5,
                "seq": 6,
                "accounts": [account(2, state="blocked")],
                "lists": [
                    plist(10, "aaaaaaa", 1, mode="static", status="blocked"),
                    dict(plist(11, "bbbbbbb", 1, mode="sticky", ttlSec=600), pwRev=2),
                ],
            }
        )
        self.assertEqual(
            r["transitions"], T([{"id": 2, "why": "blocked"}], [{"id": 10, "why": "blocked"}, {"id": 11, "why": "pw"}])
        )
        r = e.dispatch(
            {
                "op": "apply",
                "baseSeq": 6,
                "seq": 7,
                "accounts": [account(2, state="released")],
                "lists": [dict(plist(20, "ccccccc", 2), status="deleted")],
            }
        )
        self.assertEqual(r["transitions"], T([{"id": 2, "why": "released"}], [{"id": 20, "why": "deleted"}]))
        self.assertNotIn(20, e.lists)
        self.assertFalse(ask(e, "netrun-ccccccc").accepted)
        # repeating the same state is not a transition
        r = e.dispatch({"op": "apply", "baseSeq": 7, "seq": 8, "accounts": [account(2, state="released")], "lists": []})
        self.assertEqual(r["transitions"], T())

    def test_snapshot_gives_the_same_transitions_as_missed_deltas(self):
        lists = [
            plist(10, "aaaaaaa", 1, mode="static", status="blocked"),
            dict(plist(11, "bbbbbbb", 1, mode="sticky", ttlSec=600), pwRev=3),
        ]  # list 20 is gone (deleted while partitioned)
        r = self.eng.dispatch(
            {
                "op": "snapshot",
                "seq": 9,
                "accounts": [account(1), account(2, state="blocked")],
                "lists": lists,
                "static": [],
            }
        )
        self.assertEqual(
            r["transitions"],
            T(
                [{"id": 2, "why": "blocked"}],
                [{"id": 10, "why": "blocked"}, {"id": 11, "why": "pw"}, {"id": 20, "why": "deleted"}],
            ),
        )

    def test_snapshot_into_an_empty_state_reports_blocked_things(self):
        eng = rtest.make_engine(self)
        r = eng.dispatch(
            {
                "op": "snapshot",
                "seq": 1,
                "accounts": [account(1, state="blocked")],
                "lists": [plist(10, "aaaaaaa", 1, status="blocked"), plist(11, "bbbbbbb", 1)],
                "static": [],
            }
        )
        self.assertEqual(r["transitions"], T([{"id": 1, "why": "blocked"}], [{"id": 10, "why": "blocked"}]))

    def test_local_block_survives_a_snapshot(self):
        self.eng.dispatch({"op": "local_block", "accountId": 1, "blocked": True})
        self.eng.dispatch({"op": "snapshot", "seq": 6, "accounts": self.accounts, "lists": self.lists, "static": []})
        self.assertTrue(self.eng.accounts[1].local_blocked)
        acc = {a["id"]: a for a in self.eng.dispatch({"op": "accounts"})["accounts"]}
        self.assertTrue(acc[1]["localBlocked"])
        self.assertEqual(acc[1]["limit"], account(1)["limit"])
        self.assertEqual(
            self.eng.dispatch({"op": "local_block", "accountId": 99, "blocked": True})["error"], "unknown_account"
        )

    def test_logins(self):
        got = {x["id"]: x for x in self.eng.dispatch({"op": "logins"})["lists"]}
        self.assertEqual(
            got[10],
            {"id": 10, "login": "netrun-aaaaaaa", "accountId": 1, "status": "active", "pwRev": 1, "mode": "static"},
        )
        # a bare login id is normalised
        self.eng.dispatch(
            {
                "op": "apply",
                "baseSeq": 5,
                "seq": 6,
                "accounts": [],
                "lists": [dict(plist(30, "ddddddd", 1), login="DDDDDDD")],
            }
        )
        self.assertEqual(self.eng.lists[30].login, "netrun-ddddddd")

    def test_bad_requests(self):
        e = self.eng
        self.assertEqual(e.dispatch({"op": "nope"})["error"], "unknown_op")
        self.assertEqual(e.dispatch({"x": 1})["error"], "bad_request")
        self.assertEqual(
            e.dispatch({"op": "apply", "baseSeq": 5, "seq": 6, "lists": [{"id": 1}]})["error"], "bad_request"
        )
        self.assertEqual(
            e.dispatch({"op": "facts", "facts": rtest.facts(prefix="2001:db8::/32")})["error"], "bad_request"
        )
        self.assertEqual(e.dispatch({"op": "facts", "facts": rtest.facts(addrKey="AAAA")})["error"], "bad_request")
        dup = [plist(40, "eeeeeee", 1), plist(41, "eeeeeee", 1)]
        self.assertEqual(e.dispatch({"op": "apply", "baseSeq": 5, "seq": 6, "lists": dup})["error"], "bad_request")
        self.assertEqual(e.seq, 5)
        bad_login = [dict(plist(42, "svcxxxx", 1))]
        self.assertEqual(
            e.dispatch({"op": "apply", "baseSeq": 5, "seq": 6, "lists": bad_login})["error"], "bad_request"
        )


class StaticBindings(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock)
        self.lists = [plist(10, "aaaaaaa", 1, mode="static"), plist(20, "ccccccc", 2, mode="static")]
        self.eng.dispatch(
            {"op": "snapshot", "seq": 1, "accounts": [account(1), account(2)], "lists": self.lists, "static": []}
        )

    def feed(self, after=0, limit=1000):
        return self.eng.dispatch({"op": "bindings", "after": after, "limit": limit})

    def test_feed_add_and_release(self):
        a = ask(self.eng, "netrun-aaaaaaa", port=BASE + 1)
        ask(self.eng, "netrun-aaaaaaa", port=BASE + 1)  # same binding, no new event
        ask(self.eng, "netrun-aaaaaaa-session-s01000")  # a line slot (I2) follows the static list
        f = self.feed()
        self.assertEqual(
            [(i["op"], i["listId"], i["slot"], i["reason"]) for i in f["items"]],
            [
                ("add", 10, "p1", "first_use"),
                ("add", 10, "s:s01000", "first_use"),
            ],
        )
        self.assertEqual(f["items"][0]["addr"], str(a.addr))
        self.assertEqual(f["last"], f["items"][-1]["seq"])
        self.assertEqual(self.feed(after=f["last"]), {"items": [], "last": f["last"]})
        self.eng.dispatch({"op": "apply", "baseSeq": 1, "seq": 2, "lists": [dict(self.lists[0], status="deleted")]})
        f2 = self.feed(after=f["last"])
        self.assertEqual(
            sorted((i["op"], i["slot"], i["reason"]) for i in f2["items"]),
            [
                ("release", "p1", "list_deleted"),
                ("release", "s:s01000", "list_deleted"),
            ],
        )
        page = self.feed(after=0, limit=1)
        self.assertEqual(len(page["items"]), 1)

    def test_static_comes_back_after_block_and_release(self):
        # A8: static is derived, nothing is retained or dropped; a top-up gives the same IP
        a = ask(self.eng, "netrun-ccccccc", port=BASE + 2)
        for seq, state in ((2, "blocked"), (3, "active"), (4, "released"), (5, "active")):
            self.eng.dispatch({"op": "apply", "baseSeq": seq - 1, "seq": seq, "accounts": [account(2, state=state)]})
            if state == "active":
                self.assertEqual(ask(self.eng, "netrun-ccccccc", port=BASE + 2).addr, a.addr)
            else:
                self.assertFalse(ask(self.eng, "netrun-ccccccc", port=BASE + 2).accepted)
        self.assertEqual([i["op"] for i in self.feed()["items"]], ["add"])

    def test_snapshot_static_merge(self):
        a = ask(self.eng, "netrun-aaaaaaa", port=BASE + 1)
        tagger = self.eng.alloc.tagger
        free_net = self.eng.alloc.cand.items[0]
        orch_addr = str(rtest.ipaddress.IPv6Address(self.eng.alloc.new_addr(free_net, 10)))
        wrong_tag = str(rtest.ipaddress.IPv6Address(self.eng.alloc.new_addr(free_net, 11)))
        other_prefix = "2001:db8:bb:1::" + "1234:5678"
        static = [
            {"listId": 10, "slot": "p1", "addr": "2001:db8:aa:1::1:2"},  # RADIUS keeps its own
            {"listId": 10, "slot": "p5", "addr": orch_addr},  # adopted
            {"listId": 10, "slot": "p6", "addr": wrong_tag},
            {"listId": 10, "slot": "p7", "addr": other_prefix},
            {"listId": 99, "slot": "p1", "addr": orch_addr},
        ]
        r = self.eng.dispatch(
            {"op": "snapshot", "seq": 2, "accounts": [account(1), account(2)], "lists": self.lists, "static": static}
        )
        self.assertEqual(
            r["static"], {"adopted": 1, "kept": 1, "refused": {"bad_tag": 1, "outside_prefix": 1, "no_list": 1}}
        )
        self.assertEqual(ask(self.eng, "netrun-aaaaaaa", port=BASE + 1).addr, a.addr)
        self.assertEqual(str(ask(self.eng, "netrun-aaaaaaa", port=BASE + 5).addr), orch_addr)
        self.assertIsNotNone(tagger)

    def test_prefix_change_releases_everything(self):
        ask(self.eng, "netrun-aaaaaaa", port=BASE + 1)
        self.eng.dispatch({"op": "facts", "facts": rtest.facts(prefix="2001:db8:bb::/48")})
        self.assertEqual(len(self.eng.alloc.static), 0)
        self.assertEqual(self.feed()["items"][-1]["reason"], "prefix_changed")
        r = ask(self.eng, "netrun-aaaaaaa", port=BASE + 1)
        self.assertIn(r.addr, rtest.ipaddress.IPv6Network("2001:db8:bb::/48"))


class ExcludedAndReserve(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock)

    def test_excluded_op(self):
        e = self.eng
        r = e.dispatch({"op": "excluded", "nets": list(range(0, 1000)), "complete": True, "scanId": "a"})
        self.assertEqual(r, {"ok": True, "excluded": 1000, "removed": 0})
        self.clock.advance(700)
        e.dispatch({"op": "excluded", "nets": [], "complete": True, "scanId": "b"})
        self.clock.advance(700)
        r = e.dispatch({"op": "excluded", "nets": [], "complete": True, "scanId": "c"})
        self.assertEqual(r["error"], "excluded_shrink")
        self.assertEqual(r["excluded"], 1000)
        self.assertEqual(r["wouldRemove"], 1000)
        r = e.dispatch({"op": "excluded", "nets": ["ffff", "0x"], "complete": False})
        self.assertEqual(r["error"], "bad_request")
        st = e.dispatch({"op": "status"})["alloc"]
        self.assertEqual(st["excluded"], 1000)
        self.assertEqual(st["candidates"], 0xFFFF - 1000)

    def test_reserve_and_release_ops(self):
        e = self.eng
        e.dispatch({"op": "facts", "facts": rtest.facts(subnets=[0, 99], minFree64ForPerpiece=50)})
        r = e.dispatch({"op": "reserve_nets", "count": 10, "owner": "perpiece", "ref": "gen-1"})
        self.assertEqual(r["ref"], "gen-1")
        self.assertEqual(len(r["nets"]), 10)
        self.assertEqual(e.dispatch({"op": "reserve_nets", "count": 10, "owner": "perpiece", "ref": "gen-1"}), r)
        self.assertEqual(e.dispatch({"op": "reserve_nets", "count": 41, "ref": "gen-2"})["error"], "capacity")
        self.assertEqual(
            len(e.dispatch({"op": "reserve_nets", "count": 41, "ref": "gen-2", "force": True})["nets"]), 41
        )
        self.assertEqual(
            e.dispatch({"op": "reserve_nets", "count": 1, "ref": "x", "owner": "pergb"})["error"], "bad_request"
        )
        rel = e.dispatch({"op": "release_nets", "nets": r["nets"], "ref": "dep-1"})
        self.assertEqual(rel, {"released": 10, "coolDownUntil": None})  # A6: no cool-down
        st = e.dispatch({"op": "status"})["alloc"]
        self.assertEqual(st["reserved"], 41)
        self.assertEqual(st["coolDown"], 0)
        self.assertEqual(st["candidates"], 100 - 41)
        # durable across a restart: reservations, the release record
        e.flush()
        e2 = rtest.make_engine(self, clock=self.clock, path=e._test_dir, with_facts=False)
        self.assertEqual(len(e2.alloc.reserved), 41)
        self.assertEqual(e2.dispatch({"op": "release_nets", "nets": r["nets"], "ref": "dep-1"})["released"], 10)
        self.assertEqual(e2.dispatch({"op": "reserve_nets", "count": 10, "ref": "gen-1"})["nets"], r["nets"])


class UnixSocket(unittest.TestCase):
    def setUp(self):
        self.eng = rtest.make_engine(self)
        self.path = os.path.join(self.eng._test_dir, "ctl.sock")
        self.srv = ctl.CtlServer(self.path, self.eng)
        self.srv.start()
        self.addCleanup(self.srv.stop)

    def test_round_trip_and_mode(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        r = ctl.call(self.path, {"op": "status"})
        self.assertEqual(r["epoch"], self.eng.epoch)
        self.assertTrue(r["ready"])

    def test_large_snapshot_over_the_socket(self):
        lists = [plist(i, "l%06d" % i, 1) for i in range(3000)]
        r = ctl.call(self.path, {"op": "snapshot", "seq": 3, "accounts": [account(1)], "lists": lists, "static": []})
        self.assertEqual(r["seq"], 3)
        self.assertEqual(len(ctl.call(self.path, {"op": "logins"})["lists"]), 3000)

    def test_garbage_line(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        s.sendall(b"{not json\n")
        reply = json.loads(s.recv(65536).decode())
        s.close()
        self.assertEqual(reply["error"], "bad_request")

    def test_internal_errors_are_contained(self):
        def boom(self_, req):
            raise RuntimeError("x")

        self.eng.OPS = dict(self.eng.OPS, status=boom)
        self.assertEqual(ctl.call(self.path, {"op": "status"})["error"], "internal")
        self.assertIn("accounts", ctl.call(self.path, {"op": "accounts"}))  # the server keeps serving

    def test_stale_socket_file_is_replaced(self):
        self.srv.stop()
        self.assertFalse(os.path.exists(self.path))
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(self.path)  # a socket file nobody listens on, as after a crash
        stale.close()
        srv2 = ctl.CtlServer(self.path, self.eng)
        srv2.start()
        self.addCleanup(srv2.stop)
        self.assertIn("epoch", ctl.call(self.path, {"op": "status"}))


if __name__ == "__main__":
    unittest.main()
