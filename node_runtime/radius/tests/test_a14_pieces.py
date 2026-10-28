"""A14-P: a per-piece proxy on any /64 of the pool blocks, shared with per-GB."""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import unittest

import rtest
from rtest import BASE, account, ask, plist
from test_piece import PRIMARY4, PW, PieceBase, expected_addr, piece_account

WIDE = "2001:db8:8000::/33"  # a second, wider block (routed beside the primary /48)


def piece64(lid, login_id, aid, net64, **over):
    d = plist(lid, login_id, aid, mode="static", kind="piece", pieceNet64=net64, lineCount=1)
    d.pop("ttlSec", None)
    d.update(over)
    return d


def addr_in(net64: str, key: bytes, list_id: int) -> ipaddress.IPv6Address:
    """The A13-I host part (the list's tag) on the given /64, derived independently."""
    host = int(ipaddress.IPv6Address(expected_addr(key, rtest.PREFIX, list_id, 0))) & ((1 << 64) - 1)
    return ipaddress.IPv6Address(int(ipaddress.IPv6Network(net64).network_address) | host)


class PoolBlocksFacts(unittest.TestCase):
    def test_the_primary_48_is_always_a_block(self):
        eng = rtest.make_engine(self)
        self.assertEqual(eng.dispatch({"op": "status"})["pool"]["blocks"], [rtest.PREFIX])

    def test_extra_blocks_are_listed_sorted(self):
        eng = rtest.make_engine(self, poolBlocks=[WIDE, "2001:db8:1::/56"])
        self.assertEqual(
            eng.dispatch({"op": "status"})["pool"]["blocks"], ["2001:db8:1::/56", rtest.PREFIX, WIDE]
        )
        self.assertIn("pieceNet64", eng.dispatch({"op": "status"})["features"])

    def test_bad_blocks_are_refused(self):
        eng = rtest.make_engine(self)
        for bad in (["2001:db8::/28"], ["2001:db8:1::/57"], ["2001:db8:aa::/40"], ["nope"], "2001:db8::/33"):
            r = eng.dispatch({"op": "facts", "facts": rtest.facts(poolBlocks=bad)})
            self.assertEqual(r.get("error"), "bad_request", bad)


class A14Pieces(PieceBase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(
            self, clock=self.clock, primaryIpv4=PRIMARY4, egressIpv4s=["198.51.100.20"], poolBlocks=[WIDE]
        )
        self.seq = 0

    def test_a_piece_on_a_64_of_the_wide_block(self):
        net64 = "2001:db8:f00d:1234::/64"
        r = self.snapshot([piece_account(100)], [piece64(500, "pieceaa", 100, net64)])
        self.assertEqual(r["pieces"]["rejected"], [])
        want = addr_in(net64, rtest.KEY, 500)
        self.assertEqual(r["pieces"]["addrs"]["500"], str(want))
        for port in (BASE, BASE + 999):
            got = ask(self.eng, "netrun-pieceaa", port=port)
            self.assertTrue(got.accepted)
            self.assertEqual(got.addr, want)
        # nothing was reserved: the pool stays whole for per-GB
        self.assertEqual(self.eng.alloc.reserved, {})

    def test_pieces_share_a_64_with_each_other_and_with_per_gb(self):
        net = 77
        net64 = "2001:db8:aa:%x::/64" % net
        r = self.snapshot(
            [piece_account(100), piece_account(101), account(1)],
            [piece64(500, "pieceaa", 100, net64), piece64(501, "piecebb", 101, net64), plist(10, "rotaaaa", 1)],
        )
        self.assertEqual(r["pieces"]["rejected"], [])
        a, b = r["pieces"]["addrs"]["500"], r["pieces"]["addrs"]["501"]
        self.assertNotEqual(a, b)
        self.assertEqual(ipaddress.IPv6Network(a + "/64", strict=False), ipaddress.IPv6Network(net64))
        self.assertIn(net, self.eng.alloc.cand)  # per-GB still draws from it

    def test_outside_the_blocks_or_on_an_excluded_64_is_refused(self):
        [reserved] = self.reserve("piece:order_1")  # an A13-I piece's /64
        r = self.snapshot(
            [piece_account(100), piece_account(101), piece_account(102)],
            [
                piece64(500, "pieceaa", 100, "2001:db9::/64"),
                piece64(501, "piecebb", 101, "2001:db8:aa:%x::/64" % reserved),
                piece64(502, "piececc", 102, "2001:db8:aa:ffff::/64"),
            ],
        )
        errors = {x["id"]: x["error"] for x in r["pieces"]["rejected"]}
        self.assertEqual(
            errors,
            {
                500: "piece_net64_outside_pool",
                501: "piece_net64_excluded",
                502: "piece_net64_outside_pool",
            },
        )

    def test_a_block_that_leaves_the_pool_stops_its_pieces(self):
        net64 = "2001:db8:f00d:1::/64"
        self.snapshot([piece_account(100)], [piece64(500, "pieceaa", 100, net64)])
        self.assertTrue(ask(self.eng, "netrun-pieceaa").accepted)
        self.assertEqual(self.eng.dispatch({"op": "facts", "facts": rtest.facts(primaryIpv4=PRIMARY4)}), {"ok": True})
        self.assertEqual(self.reason_of("netrun-pieceaa"), "list_off")

    def test_exactly_one_of_piece_net_and_piece_net64(self):
        both = piece64(500, "pieceaa", 100, "2001:db8:aa:1::/64", pieceNet=1)
        r = self.call("snapshot", seq=1, accounts=[piece_account(100)], lists=[both])
        self.assertEqual(r.get("error"), "bad_request")
        for bad in ("2001:db8:aa:1::/63", "2001:db8:aa:1::1/64", 5):
            r = self.call("snapshot", seq=1, accounts=[piece_account(100)], lists=[piece64(500, "pieceaa", 100, bad)])
            self.assertEqual(r.get("error"), "bad_request", bad)

    def test_survives_a_restart(self):
        net64 = "2001:db8:f00d:2::/64"
        self.snapshot([piece_account(100)], [piece64(500, "pieceaa", 100, net64)])
        self.eng.flush()
        self.eng.store.close()
        e2 = rtest.make_engine(self, clock=self.clock, path=self.eng._test_dir, with_facts=False)
        self.assertEqual(e2.lists[500].view()["pieceNet64"], net64)
        self.assertEqual(ask(e2, "netrun-pieceaa").addr, addr_in(net64, rtest.KEY, 500))


class SchemaThree(unittest.TestCase):
    def test_schema_3_is_migrated_in_place(self):
        d = rtest.tmpdir(self)
        eng = rtest.make_engine(self, path=d)
        eng.flush()
        eng.store.close()
        db = sqlite3.connect(os.path.join(d, "radius.db"))
        # back to a schema-3 file: no piece_net64 column
        db.execute("ALTER TABLE lists DROP COLUMN piece_net64")
        db.execute("UPDATE meta SET v = '3' WHERE k = 'schema'")
        db.commit()
        db.close()
        e2 = rtest.make_engine(self, path=d, with_facts=False)
        self.assertEqual(e2.store.migrated, "3->4")
        self.assertFalse(e2.db_recovered)
        e2.store.close()


if __name__ == "__main__":
    unittest.main()
