"""Per-piece proxies on RADIUS (amendment A13, frozen contract A13-I)."""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import sqlite3
import unittest

import rtest
from rtest import BASE, DST4, DST6, account, ask, plist

import alloc as alloc_lib
from tag import IID_MIN, encrypt

PW = "Passw0rdPassw0rd"
PRIMARY4 = "203.0.113.10"
HERE = os.path.dirname(os.path.abspath(__file__))


def piece_account(aid, **over):
    a = {"id": aid, "kind": "piece", "state": "active", "expiresAt": 4_000_000_000}
    a.update(over)
    return a


def piece(lid, login_id, aid, net, **over):
    d = plist(lid, login_id, aid, mode="static", kind="piece", pieceNet=net, lineCount=1)
    d.pop("ttlSec", None)
    d.update(over)
    return d


def expected_addr(key: bytes, prefix: str, list_id: int, net: int) -> str:
    """The A13-I derivation, written out independently of alloc.py."""
    seed = b"netrun-pergb-pick-r\x00piece\x00" + list_id.to_bytes(4, "big") + b"\x00\x00"
    for j in range(64):
        d = hmac.digest(key, seed + j.to_bytes(4, "big"), "sha256")
        iid = encrypt(key, list_id, (d[0] << 8) | d[1])
        if iid >= IID_MIN:
            base = int(ipaddress.IPv6Network(prefix).network_address)
            return str(ipaddress.IPv6Address(base | (net << 64) | iid))
    raise AssertionError("unreachable")


class PieceBase(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock, primaryIpv4=PRIMARY4, egressIpv4s=["198.51.100.20"])
        self.seq = 0

    def call(self, op, **body):
        body["op"] = op
        return self.eng.dispatch(body)

    def reserve(self, ref, count=1):
        r = self.call("reserve_nets", count=count, owner="perpiece", ref=ref)
        self.assertNotIn("error", r, r)
        return r["nets"]

    def snapshot(self, accounts, lists, static=()):
        self.seq += 1
        r = self.call("snapshot", seq=self.seq, accounts=accounts, lists=lists, static=list(static))
        self.assertNotIn("error", r, r)
        return r

    def apply(self, accounts=(), lists=()):
        r = self.call("apply", baseSeq=self.seq, seq=self.seq + 1, accounts=list(accounts), lists=list(lists))
        self.assertNotIn("error", r, r)
        self.seq += 1
        return r

    def reason_of(self, user, **kw):
        before = dict(self.eng.reject_counts)
        r = ask(self.eng, user, **kw)
        self.assertTrue(r.valid)
        if r.accepted:
            return None
        diff = [k for k, v in self.eng.reject_counts.items() if v != before.get(k)]
        self.assertEqual(len(diff), 1, diff)
        return diff[0]


class PieceAccess(PieceBase):
    def setUp(self):
        super().setUp()
        [self.net] = self.reserve("piece:order_1")
        [self.net2] = self.reserve("piece:order_2")
        r = self.snapshot(
            [piece_account(100), piece_account(101), account(1)],
            [
                piece(500, "pieceaa", 100, self.net),
                piece(501, "piecebb", 101, self.net2),
                plist(10, "rotaaaa", 1, mode="rotate"),
            ],
        )
        self.ack = r["pieces"]

    def test_ack_carries_the_addresses(self):
        self.assertEqual(self.ack["accepted"], 2)
        self.assertEqual(self.ack["rejected"], [])
        want = expected_addr(rtest.KEY, rtest.PREFIX, 500, self.net)
        self.assertEqual(self.ack["addrs"]["500"], want)
        # an unchanged record does not repeat it
        r = self.snapshot(
            [piece_account(100), piece_account(101), account(1)],
            [piece(500, "pieceaa", 100, self.net), piece(501, "piecebb", 101, self.net2)],
        )
        self.assertEqual(r["pieces"]["addrs"], {})

    def test_fixed_address_in_its_own_64_on_every_port(self):
        want = ipaddress.IPv6Address(expected_addr(rtest.KEY, rtest.PREFIX, 500, self.net))
        for port in (BASE, BASE + 1, BASE + 517, BASE + 999):
            r = ask(self.eng, "netrun-pieceaa", port=port)
            self.assertTrue(r.accepted)
            self.assertEqual(r.addr, want)
            self.assertEqual(r.net, self.net)
        self.clock.advance(7 * 86400)
        self.assertEqual(ask(self.eng, "netrun-pieceaa").addr, want)
        iid = int(want) & ((1 << 64) - 1)
        self.assertEqual(self.eng.alloc.tagger.list_of(iid), 500)  # attribution by tag, like per-GB

    def test_country_is_the_only_param(self):
        self.assertIsNone(self.reason_of("netrun-pieceaa-country-us"))
        for user in (
            "netrun-pieceaa-session-abc",
            "netrun-pieceaa-session-s01000",
            "netrun-pieceaa-rotate",
            "netrun-pieceaa-ttl-10m",
            "netrun-pieceaa-static",
            "netrun-pieceaa-session-abc-ttl-1h",
            "netrun-pieceaa-country-de",
        ):
            self.assertEqual(self.reason_of(user), "bad_params", user)
        self.assertEqual(self.eng.dispatch({"op": "rejects"})["lists"]["500"]["reason"], "bad_params")

    def test_ipv4_goes_out_from_the_primary_ipv4(self):
        r = ask(self.eng, "netrun-pieceaa", dst=DST4)
        self.assertTrue(r.accepted)
        self.assertEqual(str(r.addr), PRIMARY4)
        g = ask(self.eng, "netrun-rotaaaa", dst=DST4)
        self.assertEqual(str(g.addr), "198.51.100.20", "per-GB keeps its own IPv4s")
        # the guard closes the primary IPv4 (its local ports): pieces refuse IPv4, per-GB goes on
        self.call("ipv4_admission", open=True, addrs={PRIMARY4: False, "198.51.100.20": True})
        self.assertEqual(self.reason_of("netrun-pieceaa", dst=DST4), "capacity")
        self.assertIsNone(self.reason_of("netrun-rotaaaa", dst=DST4))
        self.assertIsNone(self.reason_of("netrun-pieceaa", dst=DST6))
        self.call("ipv4_admission", open=False)
        self.assertIsNone(self.reason_of("netrun-pieceaa", dst=DST4), "the per-GB set closed, not the primary")
        self.assertEqual(self.reason_of("netrun-rotaaaa", dst=DST4), "capacity")

    def test_ipv4_without_the_primary_fact_and_on_ipv6_only(self):
        self.call("facts", facts=rtest.facts())  # an older agent: no primaryIpv4
        r = ask(self.eng, "netrun-pieceaa", dst=DST4)
        self.assertEqual(str(r.addr), rtest.EGRESS4, "option A: egressIpv4 is the primary IPv4")
        self.call("facts", facts=rtest.facts(family="ipv6_only", primaryIpv4=PRIMARY4))
        self.assertEqual(self.reason_of("netrun-pieceaa", dst=DST4), "bad_params")
        self.assertIsNone(self.reason_of("netrun-pieceaa", dst=DST6))

    def test_never_quota_blocked(self):
        r = self.call("local_block", accountId=100, blocked=True)
        self.assertEqual(r, {"ok": True, "ignored": "piece"})
        self.assertFalse(self.eng.accounts[100].local_blocked)
        self.assertIsNone(self.reason_of("netrun-pieceaa"))
        # a deadman heartbeat naming the account (headroom 0) does not touch a piece
        self.call("heartbeat", at=self.clock(), near={"100": 0, "1": 0})
        self.clock.advance(60)
        self.assertIsNone(self.reason_of("netrun-pieceaa"))
        self.assertEqual(self.reason_of("netrun-rotaaaa"), "quota")
        # a limit sent with a piece account is dropped
        self.apply(accounts=[piece_account(100, limit={"epoch": 1, "bytes": 1, "allowance": 1, "full": True})])
        accts = {a["id"]: a for a in self.call("accounts")["accounts"]}
        self.assertEqual((accts[100]["kind"], accts[100]["limit"]), ("piece", None))
        self.assertEqual(accts[1]["kind"], "pergb")
        self.assertIsNone(self.reason_of("netrun-pieceaa"))

    def test_expiry_and_states(self):
        self.apply(accounts=[piece_account(100, expiresAt=self.clock() + 10)])
        self.assertIsNone(self.reason_of("netrun-pieceaa"))
        self.clock.advance(10)
        self.assertEqual(self.reason_of("netrun-pieceaa"), "account_off")
        self.apply(accounts=[piece_account(100, state="blocked", expiresAt=self.clock() + 100)])
        self.assertEqual(self.reason_of("netrun-pieceaa"), "account_off")
        r = self.apply(lists=[piece(501, "piecebb", 101, self.net2, status="blocked")])
        self.assertEqual(r["transitions"]["lists"], [{"id": 501, "why": "blocked"}])
        self.assertEqual(self.reason_of("netrun-piecebb"), "list_off")
        self.assertEqual(self.reason_of("netrun-piecebb", password="nope"), "bad_login")

    def test_released_net_is_never_served(self):
        r = self.call("release_nets", nets=[self.net], ref="piece-rel:order_1")
        self.assertEqual(r["released"], 1)
        self.assertEqual(self.reason_of("netrun-pieceaa"), "list_off")
        self.assertIn(self.net, self.eng.alloc.cand)  # back in the shared pool (A6)

    def test_per_gb_never_draws_a_piece_64(self):
        a = self.eng.alloc
        self.assertNotIn(self.net, a.cand)
        for n in range(400):
            r = ask(self.eng, "netrun-rotaaaa", port=BASE + n % 1000)
            self.assertNotIn(r.net, (self.net, self.net2))
        a.check_invariants()

    def test_logins_and_status(self):
        got = {x["id"]: x for x in self.call("logins")["lists"]}
        self.assertEqual(got[500]["kind"], "piece")
        self.assertEqual(got[500]["pieceNet"], self.net)
        self.assertEqual(got[500]["mode"], "static")
        self.assertEqual(got[10]["kind"], "pergb")
        self.assertNotIn("pieceNet", got[10])
        st = self.call("status")
        self.assertEqual(st["counts"]["pieces"], 2)
        self.assertEqual(st["pieces"]["lists"], 2)
        self.assertEqual(st["facts"]["primaryIpv4"], PRIMARY4)
        res = self.call("reserved")
        self.assertIn([self.net, "piece:order_1"], res["nets"])
        self.assertEqual(res["count"], 2)

    def test_pergb_modes_fields_are_ignored(self):
        r = self.apply(
            lists=[piece(500, "pieceaa", 100, self.net, stickyPauseSec=5, ttlSec=60, linkEpoch=3, timerAnchor=5)]
        )
        self.assertEqual(r["pieces"]["rejected"], [])
        p = self.eng.lists[500]
        self.assertEqual((p.mode, p.ttl, p.pause, p.link_epoch), ("static", None, None, 0))
        self.assertEqual(
            str(ask(self.eng, "netrun-pieceaa").addr), expected_addr(rtest.KEY, rtest.PREFIX, 500, self.net)
        )

    def test_kind_mismatch_at_runtime_is_account_off(self):
        # an account delta that turns the piece account into a per-GB one
        self.apply(accounts=[account(100)])
        self.assertEqual(self.reason_of("netrun-pieceaa"), "account_off")


class PieceRecordChecks(PieceBase):
    def test_not_reserved_and_foreign_refs_are_refused(self):
        [gen] = self.reserve("gen:20000:abc")  # a 3proxy batch's /64
        free = next(n for n in range(10, 100) if n in self.eng.alloc.cand)
        r = self.snapshot(
            [piece_account(100)],
            [
                piece(500, "pieceaa", 100, free),
                piece(501, "piecebb", 100, gen),
                piece(502, "piececc", 100, 0xFFFF),
            ],
        )
        errs = {x["id"]: x["error"] for x in r["pieces"]["rejected"]}
        self.assertEqual(
            errs, {500: "piece_net_not_reserved", 501: "piece_net_not_piece", 502: "piece_net_outside_pool"}
        )
        self.assertEqual(r["pieces"]["accepted"], 0)
        self.assertNotIn(500, self.eng.lists)
        self.assertEqual(self.reason_of("netrun-pieceaa"), "bad_login")
        st = self.call("status")
        self.assertEqual(len(st["pieces"]["lastRejected"]), 3)
        self.assertEqual(st["pieces"]["lastRejectedAt"], self.clock())
        rej = {x["id"]: x for x in r["pieces"]["rejected"]}
        self.assertEqual(rej[501]["ref"], "gen:20000:abc")
        self.assertEqual(rej[500]["pieceNet"], free)
        self.assertEqual(rej[500]["login"], "netrun-pieceaa")

    def test_outside_the_configured_pool(self):
        self.call("facts", facts=rtest.facts(subnets="8000-fffe", primaryIpv4=PRIMARY4))
        r = self.snapshot([piece_account(100)], [piece(500, "pieceaa", 100, 0x10)])
        self.assertEqual(r["pieces"]["rejected"][0]["error"], "piece_net_outside_pool")

    def test_one_net_never_serves_two_pieces(self):
        [n1] = self.reserve("piece:order_1")
        # two new pieces on one /64: neither is installed
        r = self.snapshot([piece_account(100)], [piece(500, "pieceaa", 100, n1), piece(501, "piecebb", 100, n1)])
        self.assertEqual(sorted(x["id"] for x in r["pieces"]["rejected"]), [500, 501])
        self.assertTrue(all(x["error"] == "piece_net_duplicate" for x in r["pieces"]["rejected"]))
        # the incumbent keeps it, the newcomer is refused
        self.snapshot([piece_account(100)], [piece(500, "pieceaa", 100, n1)])
        r = self.snapshot([piece_account(100)], [piece(501, "piecebb", 100, n1), piece(500, "pieceaa", 100, n1)])
        self.assertEqual(r["pieces"]["rejected"], [dict(self._dup(501, "netrun-piecebb", n1), heldBy=500)])
        self.assertIn(500, self.eng.lists)
        # a delta: a new piece on a /64 an installed piece holds
        r = self.apply(lists=[piece(502, "piececc", 100, n1)])
        self.assertEqual(r["pieces"]["rejected"], [dict(self._dup(502, "netrun-piececc", n1), heldBy=500)])
        self.assertNotIn(502, self.eng.lists)
        # two newcomers in one delta
        [n2] = self.reserve("piece:order_2")
        r = self.apply(lists=[piece(503, "piecedd", 100, n2), piece(504, "pieceee", 100, n2)])
        self.assertEqual(sorted(x["id"] for x in r["pieces"]["rejected"]), [503, 504])
        # a blocked piece still holds its /64 (unique among all piece lists)
        self.apply(lists=[piece(500, "pieceaa", 100, n1, status="blocked")])
        r = self.apply(lists=[piece(505, "pieceff", 100, n1)])
        self.assertEqual(r["pieces"]["rejected"][0]["error"], "piece_net_duplicate")
        # deleting the holder frees the /64 for a new piece
        self.apply(lists=[piece(500, "pieceaa", 100, n1, status="deleted")])
        r = self.apply(lists=[piece(505, "pieceff", 100, n1)])
        self.assertEqual(r["pieces"]["rejected"], [])
        self.assertIsNone(self.reason_of("netrun-pieceff"))

    @staticmethod
    def _dup(lid, login, net):
        return {"id": lid, "login": login, "kind": "piece", "pieceNet": net, "error": "piece_net_duplicate"}

    def test_a_refused_delta_keeps_the_previous_record(self):
        [n1] = self.reserve("piece:order_1")
        self.snapshot([piece_account(100)], [piece(500, "pieceaa", 100, n1)])
        before = ask(self.eng, "netrun-pieceaa").addr
        free = next(n for n in range(10, 100) if n in self.eng.alloc.cand)
        r = self.apply(lists=[piece(500, "pieceaa", 100, free)])
        self.assertEqual(r["pieces"]["rejected"][0]["error"], "piece_net_not_reserved")
        self.assertEqual(r["transitions"]["lists"], [])
        self.assertEqual(self.eng.lists[500].piece_net, n1)
        self.assertEqual(ask(self.eng, "netrun-pieceaa").addr, before)

    def test_a_snapshot_removes_a_piece_it_refuses(self):
        [n1] = self.reserve("piece:order_1")
        self.snapshot([piece_account(100)], [piece(500, "pieceaa", 100, n1)])
        self.call("release_nets", nets=[n1], ref="rel-1")
        r = self.snapshot([piece_account(100)], [piece(500, "pieceaa", 100, n1)])
        self.assertEqual(r["transitions"]["lists"], [{"id": 500, "why": "rejected"}])
        self.assertNotIn(500, self.eng.lists)
        self.assertEqual(self.call("status")["counts"]["pieces"], 0)

    def test_a_piece_that_cannot_serve_needs_no_reservation(self):
        # list blocked, or account not active: nothing is served, the record is kept
        free = next(n for n in range(10, 100) if n in self.eng.alloc.cand)
        r = self.snapshot(
            [piece_account(100, state="released"), piece_account(101)],
            [piece(500, "pieceaa", 100, free), piece(501, "piecebb", 101, free + 1, status="blocked")],
        )
        self.assertEqual(r["pieces"]["rejected"], [])
        self.assertEqual(self.reason_of("netrun-pieceaa"), "account_off")
        self.assertEqual(self.reason_of("netrun-piecebb"), "list_off")
        # re-activated by an account delta without a reservation: the runtime check refuses it
        self.apply(accounts=[piece_account(100)])
        self.assertEqual(self.reason_of("netrun-pieceaa"), "list_off")

    def test_account_kind_mismatch(self):
        [n1] = self.reserve("piece:order_1")
        r = self.snapshot(
            [piece_account(100), account(1)],
            [piece(500, "pieceaa", 1, n1), plist(10, "rotaaaa", 100), plist(11, "rotbbbb", 1)],
        )
        errs = {x["id"]: (x["error"], x["accountKind"]) for x in r["pieces"]["rejected"]}
        self.assertEqual(errs, {500: ("account_kind_mismatch", "pergb"), 10: ("account_kind_mismatch", "piece")})
        self.assertEqual(sorted(self.eng.lists), [11])
        # an account the op does not carry is judged from the installed state
        r = self.apply(lists=[plist(12, "rotcccc", 100)])
        self.assertEqual(r["pieces"]["rejected"][0]["error"], "account_kind_mismatch")
        # and a list whose account has not arrived yet is accepted
        r = self.apply(lists=[piece(501, "piecebb", 777, n1)])
        self.assertEqual(r["pieces"]["rejected"], [])
        self.assertEqual(self.reason_of("netrun-piecebb"), "account_off")

    def test_shape_errors_refuse_the_op(self):
        acc = [piece_account(100)]
        for bad, why in (
            (piece(500, "pieceaa", 100, 5, mode="timer"), "mode"),
            (piece(500, "pieceaa", 100, 5, lineCount=2), "lineCount"),
            (piece(500, "pieceaa", 100, 5, pieceNet=None), "pieceNet"),
            (piece(500, "pieceaa", 100, 5, pieceNet="8a3f"), "pieceNet"),
            (piece(500, "pieceaa", 100, 5, pieceNet=0x10000), "pieceNet"),
            (piece(500, "pieceaa", 100, 5, kind="bulk"), "kind"),
            (plist(10, "rotaaaa", 100, pieceNet=5), "pieceNet"),
        ):
            r = self.call("snapshot", seq=99, accounts=acc, lists=[bad], static=[])
            self.assertEqual(r["error"], "bad_request", why)
            self.assertIn(why, r["detail"])
        r = self.call("snapshot", seq=99, accounts=[piece_account(100, kind="x")], lists=[], static=[])
        self.assertEqual(r["error"], "bad_request")

    def test_static_bindings_for_a_piece_are_refused(self):
        [n1] = self.reserve("piece:order_1")
        r = self.snapshot(
            [piece_account(100)],
            [piece(500, "pieceaa", 100, n1)],
            static=[{"listId": 500, "slot": "p0", "addr": "2001:db8:aa:5::1"}],
        )
        self.assertEqual(r["static"]["refused"], {"piece": 1})

    def test_kind_change_releases_per_gb_lines(self):
        self.snapshot([account(1)], [plist(10, "statica", 1, mode="static")])
        ask(self.eng, "netrun-statica", port=BASE + 3)
        self.assertIn((10, "p3"), self.eng.alloc.static)
        [n1] = self.reserve("piece:order_1")
        self.apply(accounts=[piece_account(1)], lists=[piece(10, "statica", 1, n1)])
        self.assertNotIn((10, "p3"), self.eng.alloc.static)
        self.assertIsNone(self.reason_of("netrun-statica"))
        self.eng.alloc.check_invariants()


class ReserveExact(PieceBase):
    def test_restore_known_reservations(self):
        nets = self.reserve("piece:order_1", count=3)
        self.call("release_nets", nets=nets, ref="rel-1")
        r = self.call("reserve_nets", owner="perpiece", ref="piece:order_1", nets=nets, count=3)
        self.assertEqual((r["nets"], r["restored"]), (nets, 3))
        for n in nets:
            self.assertEqual(self.eng.alloc.reserved[n], "piece:order_1")
            self.assertNotIn(n, self.eng.alloc.cand)
        again = self.call("reserve_nets", owner="perpiece", ref="piece:order_1", nets=nets)
        self.assertEqual((again["nets"], again["restored"]), (nets, 0))
        # the count-based call with the same ref still answers its nets
        self.assertEqual(self.call("reserve_nets", count=3, ref="piece:order_1")["nets"], nets)
        self.eng.alloc.check_invariants()

    def test_conflicts_change_nothing(self):
        [other] = self.reserve("piece:order_9")
        self.call("excluded", nets=[40], complete=False, scanId="s1")
        free = next(n for n in range(100, 200) if n in self.eng.alloc.cand)
        r = self.call("reserve_nets", owner="perpiece", ref="piece:order_1", nets=[free, other, 40, 0xFFFF])
        self.assertEqual(r["error"], "net_unavailable")
        self.assertEqual(r["count"], 3)
        self.assertEqual(
            r["nets"],
            [
                {"net": other, "why": "reserved", "ref": "piece:order_9"},
                {"net": 40, "why": "per_piece_scan"},
                {"net": 0xFFFF, "why": "outside_pool"},
            ],
        )
        self.assertNotIn(free, self.eng.alloc.reserved)

    def test_bad_requests(self):
        for body in (
            {"ref": "r", "nets": []},
            {"ref": "r", "nets": ["8a3f"]},
            {"ref": "r", "nets": [True]},
            {"ref": "r", "nets": [1, 2], "count": 3},
            {"ref": "r", "nets": [1], "owner": "pergb"},
        ):
            self.assertEqual(self.call("reserve_nets", **body)["error"], "bad_request", body)

    def test_no_capacity_floor(self):
        nets = self.reserve("piece:order_1", count=2)
        self.call("release_nets", nets=nets, ref="rel")
        self.call("facts", facts=rtest.facts(minFree64ForPerpiece=65535, primaryIpv4=PRIMARY4))
        self.assertEqual(self.call("reserve_nets", count=1, ref="piece:new")["error"], "capacity")
        r = self.call("reserve_nets", ref="piece:order_1", nets=nets)
        self.assertEqual(r["restored"], 2)


class PiecePersistence(PieceBase):
    def test_pieces_survive_a_restart(self):
        [n1] = self.reserve("piece:order_1")
        self.snapshot([piece_account(100, limit={"bytes": 5})], [piece(500, "pieceaa", 100, n1)])
        addr = ask(self.eng, "netrun-pieceaa").addr
        self.eng.flush()
        self.eng.store.close()
        e2 = rtest.make_engine(self, clock=self.clock, path=self.eng._test_dir, with_facts=False, seed=5)
        self.assertEqual(e2.lists[500].kind, "piece")
        self.assertEqual(e2.lists[500].piece_net, n1)
        self.assertEqual(e2.accounts[100].kind, "piece")
        self.assertIsNone(e2.accounts[100].limit)
        self.assertEqual(e2.dispatch({"op": "status"})["counts"]["pieces"], 1)
        self.assertEqual(ask(e2, "netrun-pieceaa").addr, addr)

    def test_schema_2_is_migrated_in_place(self):
        d = rtest.tmpdir(self)
        path = os.path.join(d, "radius.db")
        db = sqlite3.connect(path)
        for stmt in (
            "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)",
            "CREATE TABLE accounts(id INTEGER PRIMARY KEY, state TEXT NOT NULL, expires_at REAL,"
            " limit_json TEXT, trial INTEGER NOT NULL DEFAULT 0, local_blocked INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE lists(id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, account_id INTEGER NOT NULL,"
            " pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL, pw_rev INTEGER NOT NULL, status TEXT NOT NULL,"
            " mode TEXT NOT NULL, ttl_sec INTEGER, timer_anchor REAL, link_epoch INTEGER NOT NULL DEFAULT 0,"
            " line_epochs TEXT, sticky_pause INTEGER)",
            "CREATE TABLE nets(net INTEGER PRIMARY KEY, scan INTEGER NOT NULL DEFAULT 0, reserved_ref TEXT,"
            " reserved_at REAL)",
        ):
            db.execute(stmt)
        pwf = rtest.pw_fields(PW)
        db.execute("INSERT INTO meta VALUES ('epoch', '4294967999'), ('seq', '17'), ('schema', '2')")
        db.execute(
            "INSERT INTO meta VALUES ('facts', ?)",
            (json.dumps(rtest.facts(primaryIpv4=PRIMARY4)),),
        )
        db.execute("INSERT INTO accounts VALUES (1, 'active', 4000000000, NULL, 0, 0)")
        db.execute(
            "INSERT INTO lists VALUES (10, 'netrun-rotaaaa', 1, ?, ?, 1, 'active', 'per_request', NULL, 0, 0, NULL,"
            " NULL)",
            (pwf["pwSalt"], pwf["pwHash"]),
        )
        db.execute("INSERT INTO nets VALUES (77, 0, 'piece:order_5', 1.0)")
        db.commit()
        db.close()
        eng = rtest.make_engine(self, clock=self.clock, path=d, with_facts=False)
        self.assertEqual((eng.epoch, eng.seq), (4294967999, 17))
        self.assertFalse(eng.db_recovered)
        self.assertEqual(eng.store.migrated, "2->3")
        self.assertEqual(eng.lists[10].kind, "pergb")
        self.assertEqual(eng.accounts[1].kind, "pergb")
        self.assertEqual(eng.alloc.reserved[77], "piece:order_5")
        r = ask(eng, "netrun-rotaaaa", password=PW)
        self.assertTrue(r.accepted)
        # and the migrated file is schema 3 now: a piece on the kept reservation
        r = eng.dispatch(
            {"op": "snapshot", "seq": 18, "accounts": [piece_account(100)], "lists": [piece(500, "pieceaa", 100, 77)]}
        )
        self.assertEqual(r["pieces"]["rejected"], [])
        eng.flush()
        eng.store.close()
        e2 = rtest.make_engine(self, clock=self.clock, path=d, with_facts=False)
        self.assertIsNone(e2.store.migrated)
        self.assertEqual(e2.lists[500].piece_net, 77)


class SharedVectors(unittest.TestCase):
    def test_piece_vectors(self):
        with open(os.path.join(HERE, "piece_vectors.json")) as f:
            doc = json.load(f)
        n = 0
        for case in doc["cases"]:
            key = base64.b64decode(case["key"])
            a = alloc_lib.Allocator()
            net = ipaddress.IPv6Network(case["prefix"])
            a.configure(int(net.network_address), str(net), 0, 0xFFFE, key, 0.0)
            for v in case["vectors"]:
                self.assertEqual(expected_addr(key, case["prefix"], v["listId"], v["pieceNet"]), v["addr"])
                self.assertEqual(str(ipaddress.IPv6Address(a.piece_addr(v["listId"], v["pieceNet"]))), v["addr"])
                self.assertEqual("%016x" % a.piece_iid(v["listId"]), v["iid"])
                n += 1
        self.assertGreaterEqual(n, 12)


if __name__ == "__main__":
    unittest.main()
