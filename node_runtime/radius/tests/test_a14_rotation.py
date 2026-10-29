"""A14 stage 1b: per-GB draws from every pool block, not only the /48."""

from __future__ import annotations

import ipaddress
import random
import unittest

import rtest
from alloc import NET_COUNT, WIDE_LU_MAX, Allocator
from rtest import BASE, account, ask, plist
from test_engine import setup_state

T0 = 1_800_000_000.0
WIDE = "2001:db8:8000::/33"  # 2^31 /64s: practically every pick lands here
SMALL = "2001:db8:1:100::/56"  # 256 /64s


def block(text):
    n = ipaddress.IPv6Network(text)
    return int(n.network_address) >> 64, n.prefixlen


def in_net(addr: int, text: str) -> bool:
    return ipaddress.IPv6Address(addr) in ipaddress.IPv6Network(text)


def mk(blocks=(), lo=0, hi=0xFFFE, seed=3, key=rtest.KEY):
    clock = rtest.FakeClock(T0)
    a = Allocator(rng=random.Random(seed), clock=clock)
    a.configure(rtest.PREFIX_INT, rtest.PREFIX, lo, hi, key, clock(), blocks=[block(b) for b in blocks])
    return a, clock


class WidePool(unittest.TestCase):
    def test_rotation_spreads_over_the_wide_block(self):
        a, clock = mk([WIDE])
        nets = set()
        for _ in range(500):
            addr = a.rotate_addr(7, clock())
            n = a.net_of(addr)
            self.assertTrue(in_net(addr, WIDE))
            self.assertGreaterEqual(n, NET_COUNT)
            self.assertEqual(n, addr >> 64)
            self.assertEqual(a.tagger.list_of(addr & ((1 << 64) - 1)), 7)
            nets.add(n)
        self.assertGreater(len(nets), 490)  # 2^31 /64s: practically no repeats
        a.check_invariants()

    def test_picks_are_uniform_over_all_candidates(self):
        a, clock = mk([SMALL], lo=0, hi=255)  # 256 /64s of the /48 + 256 of the /56
        wide = sum(in_net(a.rotate_addr(7, clock()), SMALL) for _ in range(4000))
        self.assertTrue(1700 < wide < 2300, wide)
        st = a.stats(clock())
        self.assertEqual((st["candidates"], st["free"], st["extraBlocks"], st["extra64"]), (512, 512, 1, 256))

    def test_without_blocks_nothing_changes(self):
        a, clock = mk()
        b, _ = mk(seed=3)
        for i in range(200):
            self.assertEqual(a.rotate_addr(5, clock()), b.rotate_addr(5, clock()))
            self.assertTrue(in_net(a.static_line(5, "p%d" % i, 1, clock()).addr, rtest.PREFIX))
        self.assertEqual(a.stats(clock())["extra64"], 0)

    def test_static_and_timer_lines_derive_over_the_whole_pool(self):
        a, clock = mk([WIDE])
        b, _ = mk([WIDE], seed=99)
        for i in range(30):
            sa = a.static_line(9, "p%d" % i, 1, clock())
            self.assertTrue(in_net(sa.addr, WIDE))
            self.assertEqual(sa.addr, b.static_line(9, "p%d" % i, 1, clock()).addr)
        t = a.timer_line(9, "p1", 1, 600, T0 - 30, (), clock())
        self.assertTrue(in_net(t.addr, WIDE))
        self.assertIs(a.timer_line(9, "p1", 1, 600, T0 - 30, (), clock()), t)
        lk = a.link_line(9, "p2", 1, (1,), clock())
        self.assertTrue(in_net(lk.addr, WIDE))
        a.check_invariants()

    def test_sticky_on_a_wide_64(self):
        a, clock = mk([WIDE])
        ln = a.sticky_line(4, "s:x", 1, 600, clock())
        self.assertTrue(in_net(ln.addr, WIDE))
        clock.advance(10)
        self.assertIs(a.sticky_line(4, "s:x", 1, 600, clock()), ln)
        a.check_invariants()

    def test_a_block_that_leaves_takes_its_lines(self):
        a, clock = mk([WIDE], lo=0, hi=255)
        wide_static = next(
            ln for ln in (a.static_line(3, "p%d" % i, 1, clock()) for i in range(50)) if in_net(ln.addr, WIDE)
        )
        sticky = a.sticky_line(3, "s:a", 1, 600, clock())
        a.timer_line(3, "p0", 1, 600, T0, (), clock())
        a.events.clear()
        a.configure(rtest.PREFIX_INT, rtest.PREFIX, 0, 255, rtest.KEY, clock())  # the block is gone
        self.assertNotIn((3, wide_static.slot), a.static)
        self.assertIn(("release", 3, wide_static.slot, wide_static.addr, "pool_changed", clock()), a.events)
        if in_net(sticky.addr, WIDE):
            self.assertNotIn((3, "s:a"), a.sticky)
        self.assertEqual(a.mode, {})  # derived over another pool: recomputed
        for ln in a.static.values():
            self.assertTrue(in_net(ln.addr, rtest.PREFIX))
        for _ in range(100):
            self.assertTrue(in_net(a.rotate_addr(3, clock()), rtest.PREFIX))
        a.check_invariants()

    def test_avoid_by_wide_net(self):
        a, clock = mk([SMALL], lo=0, hi=255)  # 256 /64s of the /48 + 256 of the /56
        base, _ = block(SMALL)
        a.avoid_apply([(base + i, "example.com", T0 + 600) for i in range(256)], [], False, clock())
        for _ in range(50):
            self.assertTrue(in_net(a.rotate_addr(2, clock(), site="example.com"), rtest.PREFIX))
        self.assertEqual(a.avoid_stats(clock())["avoidedPairs"], 256)

    def test_last_used_of_wide_64s_is_bounded(self):
        a, clock = mk([WIDE])
        for i in range(WIDE_LU_MAX + 50):
            a._touch((block(WIDE)[0]) + i, T0)
        self.assertEqual(len(a.wide_lu), WIDE_LU_MAX)

    def test_adopt_a_wide_static(self):
        a, clock = mk([WIDE])
        ln = a.static_line(6, "p1", 1, clock())
        a.release_list(6, "x", clock())
        self.assertEqual(a.adopt_static(6, "p1", 1, ln.addr, clock()), "adopted")
        self.assertEqual(a.adopt_static(6, "p2", 1, int(ipaddress.IPv6Address("2001:db9::1:2:3:4")), clock()), "outside_prefix")


class EngineWidePool(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock, poolBlocks=[WIDE])
        setup_state(
            self.eng,
            lists=[plist(10, "rotaaaa", 1, mode="rotate"), plist(12, "statica", 1, mode="static")],
            accounts=[account(1)],
        )

    def test_feature_and_status(self):
        st = self.eng.dispatch({"op": "status"})
        self.assertIn("poolWide", st["features"])
        self.assertEqual(st["alloc"]["extraBlocks"], 1)
        self.assertEqual(st["alloc"]["extra64"], 1 << 31)

    def test_rotation_and_static_answer_from_the_wide_block(self):
        seen = {ask(self.eng, "netrun-rotaaaa").addr for _ in range(30)}
        self.assertTrue(all(a in ipaddress.IPv6Network(WIDE) for a in seen))
        self.assertEqual(len(seen), 30)
        first = ask(self.eng, "netrun-statica", port=BASE + 4).addr
        self.assertIn(first, ipaddress.IPv6Network(WIDE))
        self.assertEqual(ask(self.eng, "netrun-statica", port=BASE + 4).addr, first)

    def test_a_wide_static_survives_a_restart(self):
        first = ask(self.eng, "netrun-statica", port=BASE + 7).addr
        self.eng.flush()
        eng2 = rtest.make_engine(self, clock=self.clock, path=self.eng._test_dir, poolBlocks=[WIDE])
        self.assertEqual(ask(eng2, "netrun-statica", port=BASE + 7).addr, first)
        eng2.alloc.check_invariants()

    def test_avoid_takes_net64(self):
        until = self.clock() + 600
        wide64 = "2001:db8:8000:1::/64"
        r = self.eng.dispatch(
            {
                "op": "avoid",
                "entries": [
                    {"net64": wide64, "site": "example.com", "until": until},
                    {"net64": "2001:db8:aa:12::/64", "site": "example.com", "until": until},
                    {"net": 0x13, "site": "example.com", "until": until},
                ],
            }
        )
        self.assertEqual(r["pairs"], 3)
        av = self.eng.alloc.avoid["example.com"]
        self.assertEqual(set(av), {block(wide64)[0], 0x12, 0x13})
        r = self.eng.dispatch({"op": "avoid", "removed": [{"net64": wide64, "site": "example.com"}]})
        self.assertEqual(r["pairs"], 2)
        for bad in ("2001:db8:8000::/63", "nope", 5):
            r = self.eng.dispatch({"op": "avoid", "entries": [{"net64": bad, "site": "a.com", "until": until}]})
            self.assertEqual(r.get("error"), "bad_request", bad)


if __name__ == "__main__":
    unittest.main()
