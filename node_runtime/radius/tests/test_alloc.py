"""Allocator: the shared pool (A1, A6, A8), timer / link / pause lines (A10, A11), avoid (A12)."""

from __future__ import annotations

import random
import unittest

import rtest
from alloc import NET_SELF, STICKY_MAX_DEFER, Allocator, AllocError, CtlRefused

T0 = 1_800_000_000.0


def mk(lo=0, hi=0xFFFE, seed=3, clock=None, key=rtest.KEY):
    clock = clock or rtest.FakeClock(T0)
    a = Allocator(rng=random.Random(seed), clock=clock)
    a.configure(rtest.PREFIX_INT, rtest.PREFIX, lo, hi, key, clock())
    return a, clock


def sticky(a, clock, lid, slot, acct=1, ttl=600):
    return a.sticky_line(lid, slot, acct, ttl, clock())


def static(a, clock, lid, slot, acct=1):
    return a.static_line(lid, slot, acct, clock())


class Pool(unittest.TestCase):
    def test_only_pool_ids_never_ffff_or_excluded(self):
        a, clock = mk(lo=0x8000, hi=0xFFFF)
        self.assertEqual(a.hi, 0xFFFE)
        self.assertEqual(a.pool_size(), 0x7FFF)
        a.apply_scan(range(0x8000, 0x8100), True, "s1", clock())
        seen = set()
        for i in range(3000):
            seen.add(a.net_of(a.rotate_addr(i, clock())))
        for i in range(300):
            seen.add(sticky(a, clock, i, "p1", acct=i).net)
            seen.add(static(a, clock, i, "p2", acct=i).net)
            seen.add(a.timer_line(i, "p3", i, 600, 0, (0, 0), clock()).net)
            seen.add(a.link_line(i, "p4", i, (0, 0), clock()).net)
        self.assertTrue(all(0x8100 <= n <= 0xFFFE for n in seen), sorted(seen)[:5])
        self.assertNotIn(NET_SELF, seen)
        a.check_invariants(clock())

    def test_full_pool_default(self):
        a, clock = mk()
        self.assertEqual(a.pool_size(), 0xFFFF)  # 0000..fffe
        self.assertEqual(len(a.cand), 0xFFFF)
        self.assertNotIn(NET_SELF, a.cand)
        self.assertEqual(a.stats(clock())["free"], 0xFFFF)

    def test_hosts_are_tagged_and_above_2_32(self):
        a, clock = mk(seed=9)
        addrs = [a.rotate_addr(77, clock()) for _ in range(500)]
        addrs += [sticky(a, clock, 78, "p%d" % i).addr for i in range(200)]
        addrs += [static(a, clock, 79, "p%d" % i).addr for i in range(200)]
        addrs += [a.timer_line(80, "p%d" % i, 1, 60, 0, (0, 0), clock()).addr for i in range(100)]
        for addr in addrs:
            iid = addr & ((1 << 64) - 1)
            self.assertGreaterEqual(iid, 1 << 32)
            self.assertEqual(addr >> 80, rtest.PREFIX_INT >> 80)
            self.assertIn(a.tagger.list_of(iid), (77, 78, 79, 80))

    def test_rotation_spreads_over_64s(self):
        a, clock = mk()
        nets = [a.net_of(a.rotate_addr(1, clock())) for _ in range(2000)]
        self.assertGreater(len(set(nets)), 1950)
        for i in range(1, len(nets)):
            self.assertNotEqual(nets[i - 1], nets[i])

    def test_empty_pool_is_capacity(self):
        a, clock = mk(lo=0, hi=9)
        a.apply_scan(range(10), False, None, clock())
        for fn in (
            lambda: a.rotate_addr(1, clock()),
            lambda: static(a, clock, 1, "p1"),
            lambda: sticky(a, clock, 1, "p1"),
            lambda: a.timer_line(1, "p1", 1, 60, 0, (0, 0), clock()),
        ):
            with self.assertRaises(AllocError) as cm:
                fn()
            self.assertEqual(cm.exception.reason, "capacity")


class SharedPool(unittest.TestCase):
    """A8: nothing is reserved for a per-GB customer; the same /64 serves everyone."""

    def test_no_exclusivity_and_no_caps(self):
        a, clock = mk(lo=0, hi=3)  # four /64s for everything
        for acct in range(50):
            for i in range(20):
                self.assertIsNotNone(static(a, clock, acct, "p%d" % i, acct=acct))
                self.assertIsNotNone(sticky(a, clock, acct, "s:x%d" % i, acct=acct))
        for _ in range(100):
            self.assertIn(a.net_of(a.rotate_addr(9, clock())), range(4))
        self.assertEqual(len(a.static), 1000)
        self.assertEqual(len(a.sticky), 1000)
        a.check_invariants(clock())

    def test_one_list_spreads_its_lines(self):
        a, clock = mk(lo=0, hi=999)
        nets = [static(a, clock, 5, "p%d" % i).net for i in range(200)]
        self.assertGreater(len(set(nets)), 195)
        snets = [sticky(a, clock, 6, "s:k%d" % i).net for i in range(200)]
        self.assertGreater(len(set(snets)), 195)


class Static(unittest.TestCase):
    def test_deterministic_across_allocators_and_rng(self):
        a, clock = mk(seed=1)
        b, _ = mk(seed=99)
        for i in range(50):
            self.assertEqual(static(a, clock, 7, "p%d" % i).addr, static(b, clock, 7, "p%d" % i).addr)
        self.assertEqual(static(a, clock, 7, "s:job").addr, static(b, clock, 7, "s:job").addr)
        self.assertNotEqual(static(a, clock, 7, "p1").addr, static(a, clock, 8, "p1").addr)
        c, _ = mk(key=bytes(range(1, 33)))
        self.assertNotEqual(static(c, clock, 7, "p1").addr, static(a, clock, 7, "p1").addr)

    def test_same_address_after_forgetting(self):
        a, clock = mk()
        first = static(a, clock, 3, "p9").addr
        a.release_list(3, "list_deleted", clock())
        self.assertNotIn((3, "p9"), a.static)
        self.assertEqual(static(a, clock, 3, "p9").addr, first)

    def test_per_piece_takes_the_64_then_the_next_probe(self):
        a, clock = mk()
        ln = static(a, clock, 4, "p1")
        old_net, old_addr = ln.net, ln.addr
        a.events.clear()
        a.apply_scan([old_net], False, None, clock())
        moved = a.static[(4, "p1")]
        self.assertNotEqual(moved.net, old_net)
        self.assertEqual([e[0] for e in a.events], ["release", "add"])
        self.assertEqual(a.events[0][3], old_addr)
        self.assertEqual(a.events[0][4], "excluded")
        self.assertEqual(a.events[1][4], "moved")
        self.assertEqual(a.events[1][3], moved.addr)
        # the same move on a fresh allocator with the /64 already excluded
        b, _ = mk(seed=77)
        b.apply_scan([old_net], False, None, clock())
        self.assertEqual(static(b, clock, 4, "p1").addr, moved.addr)
        a.check_invariants(clock())

    def test_reserve_moves_a_static_line(self):
        a, clock = mk(lo=0, hi=1)  # two /64s
        ln = static(a, clock, 4, "p1")
        other = 1 - ln.net
        nets = a.reserve(1, "r", clock(), min_free=0)
        self.assertEqual(nets, [other])  # reserve prefers the /64 no line sits on
        nets2 = a.reserve(1, "r2", clock(), min_free=0, force=True)
        self.assertEqual(nets2, [ln.net])
        self.assertNotIn((4, "p1"), a.static)  # no candidate left: forgotten with a release event
        self.assertEqual(a.events[-1][0], "release")

    def test_adopt_rules(self):
        a, clock = mk()
        good = a.addr_of(0x1234, a.tagger.make_iid(9, random.Random(1).getrandbits))
        self.assertEqual(a.adopt_static(9, "p1", 1, good, clock()), "adopted")
        self.assertEqual(a.static[(9, "p1")].addr, good)
        self.assertEqual(a.adopt_static(9, "p1", 1, good + 1, clock()), "kept")
        self.assertEqual(a.adopt_static(10, "p1", 1, good, clock()), "bad_tag")  # tag of list 9
        self.assertEqual(a.adopt_static(9, "p2", 1, good ^ (1 << 100), clock()), "outside_prefix")
        a.apply_scan([0x2222], False, None, clock())
        bad_net = a.addr_of(0x2222, a.tagger.make_iid(9, random.Random(2).getrandbits))
        self.assertEqual(a.adopt_static(9, "p3", 1, bad_net, clock()), "excluded")
        self.assertEqual(a.adopt_static(9, "p4", 1, a.addr_of(0x1234, 5), clock()), "bad_tag")
        # sharing is fine (A8): a second list adopts into the same /64
        other = a.addr_of(0x1234, a.tagger.make_iid(11, random.Random(3).getrandbits))
        self.assertEqual(a.adopt_static(11, "p1", 2, other, clock()), "adopted")
        a.check_invariants(clock())


class Sticky(unittest.TestCase):
    def test_ttl_semantics(self):
        a, clock = mk()
        b = sticky(a, clock, 1, "p1", ttl=600)
        clock.advance(300)
        self.assertEqual(sticky(a, clock, 1, "p1", ttl=600).addr, b.addr)
        # another ttl keeps the IP and counts from the first connection
        self.assertEqual(sticky(a, clock, 1, "p1", ttl=1200).expires_at, T0 + 1200)
        clock.advance(1000)
        c = sticky(a, clock, 1, "p1", ttl=1200)
        self.assertNotEqual(c.addr, b.addr)
        self.assertNotEqual(c.net, b.net)  # a different /64 after expiry
        a.check_invariants(clock())

    def test_shorter_ttl_that_already_ran_out(self):
        a, clock = mk()
        b = sticky(a, clock, 1, "p1", ttl=3600)
        clock.advance(120)
        self.assertNotEqual(sticky(a, clock, 1, "p1", ttl=60).addr, b.addr)

    def test_sweeper_expiry_and_heap(self):
        a, clock = mk()
        for i in range(100):
            sticky(a, clock, 1, "s:%d" % i, ttl=30 + i)
        clock.advance(80)
        self.assertEqual(a.expire_sticky(clock()), 51)  # ttl 30..80 expired (expires_at <= now)
        self.assertEqual(len(a.sticky), 49)
        a.check_invariants(clock())

    def test_memory_bounds_evict_instead_of_refusing(self):
        a, clock = mk()
        a.max_sticky_per_account = 10
        first = sticky(a, clock, 1, "s:first", acct=7)
        for i in range(20):
            clock.advance(1)
            self.assertIsNotNone(sticky(a, clock, 1, "s:%d" % i, acct=7))
        self.assertEqual(a.acct_sticky[7], 10)
        self.assertNotIn((1, "s:first"), a.sticky)
        self.assertEqual(a.evicted, 11)
        a.max_sticky = 15
        for i in range(10):
            sticky(a, clock, 2, "s:%d" % i, acct=8)
        self.assertEqual(len(a.sticky), 15)
        a.check_invariants(clock())
        self.assertNotEqual(sticky(a, clock, 1, "s:first", acct=7).addr, first.addr)


class Timer(unittest.TestCase):
    def test_windows_from_the_anchor(self):
        a, clock = mk()
        anchor = T0 - 30
        x = a.timer_line(1, "p1", 1, 300, anchor, (0, 0), clock()).addr
        clock.advance(269)
        self.assertEqual(a.timer_line(1, "p1", 1, 300, anchor, (0, 0), clock()).addr, x)
        clock.advance(1)  # the window ends at anchor + 300
        y = a.timer_line(1, "p1", 1, 300, anchor, (0, 0), clock()).addr
        self.assertNotEqual(y, x)
        # every line of a list changes at the same moment, deterministically
        b, _ = mk(seed=42)
        self.assertEqual(b.timer_line(1, "p1", 1, 300, anchor, (0, 0), clock()).addr, y)

    def test_link_epochs_change_at_once(self):
        a, clock = mk()
        x = a.timer_line(1, "p1", 1, 3600, T0, (0, 0), clock()).addr
        self.assertNotEqual(a.timer_line(1, "p1", 1, 3600, T0, (1, 0), clock()).addr, x)
        y = a.timer_line(1, "p2", 1, 3600, T0, (1, 0), clock()).addr
        self.assertNotEqual(a.timer_line(1, "p2", 1, 3600, T0, (1, 3), clock()).addr, y)

    def test_pause_postpones_a_busy_line(self):
        a, clock = mk()
        x = a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5).addr
        clock.advance(58)
        a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5)
        clock.advance(3)  # past the tick at T0+60, busy (3 s gap)
        self.assertEqual(a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5).addr, x)
        clock.advance(4)
        self.assertEqual(a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5).addr, x)
        clock.advance(6)  # a quiet gap: switches to the window's address
        y = a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5).addr
        self.assertNotEqual(y, x)
        self.assertEqual(y, mk(seed=5)[0].timer_line(1, "p1", 1, 60, T0, (0, 0), clock()).addr)

    def test_pause_never_postpones_a_link_change(self):
        a, clock = mk()
        x = a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=10).addr
        clock.advance(1)
        self.assertNotEqual(a.timer_line(1, "p1", 1, 60, T0, (1, 0), clock(), pause=10).addr, x)

    def test_pause_cap_switches_a_line_that_is_never_quiet(self):
        a, clock = mk()
        x = a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5).addr
        t = 0
        addrs = []
        while t < 60 + STICKY_MAX_DEFER + 10:
            clock.advance(2)
            t += 2
            addrs.append((t, a.timer_line(1, "p1", 1, 60, T0, (0, 0), clock(), pause=5).addr))
        held = [tt for tt, ad in addrs if ad == x]
        self.assertGreaterEqual(max(held), 60 + STICKY_MAX_DEFER - 2)
        self.assertLess(max(held), 60 + STICKY_MAX_DEFER + 2)
        self.assertNotEqual(addrs[-1][1], x)


class PauseAndLink(unittest.TestCase):
    def test_per_request_pause(self):
        a, clock = mk()
        x = a.pause_line(1, "p1", 1, 5, clock()).addr
        clock.advance(4)
        self.assertEqual(a.pause_line(1, "p1", 1, 5, clock()).addr, x)
        clock.advance(4.9)
        self.assertEqual(a.pause_line(1, "p1", 1, 5, clock()).addr, x)
        clock.advance(5)  # quiet
        y = a.pause_line(1, "p1", 1, 5, clock()).addr
        self.assertNotEqual(y, x)
        # another line of the list is independent
        self.assertNotEqual(a.pause_line(1, "p2", 1, 5, clock()).addr, y)

    def test_per_request_pause_cap(self):
        a, clock = mk()
        x = a.pause_line(1, "p1", 1, 10, clock()).addr
        same = 0
        for _ in range(100):
            clock.advance(3)
            if a.pause_line(1, "p1", 1, 10, clock()).addr == x:
                same += 1
            else:
                break
        self.assertEqual(same, STICKY_MAX_DEFER // 3)

    def test_link_lines(self):
        a, clock = mk()
        x = a.link_line(1, "p1", 1, (0, 0), clock()).addr
        clock.advance(86400 * 3)
        self.assertEqual(a.link_line(1, "p1", 1, (0, 0), clock()).addr, x)
        self.assertNotEqual(a.link_line(1, "p1", 1, (1, 0), clock()).addr, x)
        b, _ = mk(seed=11)
        self.assertEqual(b.link_line(1, "p1", 1, (0, 0), clock()).addr, x)

    def test_idle_mode_lines_are_pruned(self):
        a, clock = mk()
        a.pause_line(1, "p1", 1, 5, clock())
        a.link_line(1, "p2", 1, (0, 0), clock())
        a.timer_line(1, "p3", 1, 60, T0, (0, 0), clock())
        clock.advance(3600)
        self.assertEqual(a.prune_mode_lines(clock()), 3)
        self.assertEqual(len(a.mode), 0)
        a.check_invariants(clock())


class Avoid(unittest.TestCase):
    def test_redraw_skips_avoided_nets(self):
        a, clock = mk(lo=0, hi=9)
        until = clock() + 600
        a.avoid_apply([(n, "example.com", until) for n in range(8)], [], False, clock())
        nets = [a.net_of(a.rotate_addr(1, clock(), "example.com")) for _ in range(300)]
        self.assertTrue(set(nets) <= {8, 9}, set(nets))
        self.assertGreater(a.avoid_stats(clock())["picksAvoided1h"], 0)
        other = {a.net_of(a.rotate_addr(1, clock(), "other.org")) for _ in range(300)}
        self.assertGreater(len(other), 5)

    def test_exhausted_takes_the_last_draw(self):
        a, clock = mk(lo=0, hi=3)
        a.avoid_apply([(n, "blocker.io", clock() + 600) for n in range(4)], [], False, clock())
        a.rotate_addr(1, clock(), "blocker.io")
        st = a.avoid_stats(clock())
        self.assertEqual(st["exhausted1h"], 1)
        self.assertEqual(st["exhaustedSites"], {"blocker.io": 1})

    def test_expiry_removal_full_and_cap(self):
        a, clock = mk()
        a.avoid_apply(
            [(1, "a.com", clock() + 10), (2, "a.com", clock() + 100), (3, "b.com", clock() + 50)], [], False, clock()
        )
        self.assertEqual(a.avoid_n, 3)
        a.avoid_apply([], [(2, "a.com")], False, clock())
        self.assertEqual(a.avoid_n, 2)
        clock.advance(20)
        a.expire_sticky(clock())  # the sweeper also trims expired avoid entries
        self.assertEqual(a.avoid, {"b.com": {3: T0 + 50}})
        a.avoid_apply([(5, "c.com", clock() + 99)], [], True, clock())
        self.assertEqual(a.avoid, {"c.com": {5: T0 + 20 + 99}})
        a.avoid_max = 10
        a.avoid_apply([(n, "d.com", clock() + 1000 + n) for n in range(20)], [], False, clock())
        self.assertEqual(a.avoid_n, 10)
        self.assertNotIn("c.com", a.avoid)  # the soonest expiry went first
        self.assertEqual(min(a.avoid["d.com"]), 10)
        a.check_invariants(clock())


class ExcludedGuard(unittest.TestCase):
    def test_shrink_guard(self):
        a, clock = mk()
        a.apply_scan(range(1000), True, "a", clock())
        a.apply_scan(range(995), True, "b", clock())
        self.assertEqual(len(a.scan), 1000)  # the first complete scan without them
        clock.advance(300)
        a.apply_scan(range(995), True, "c", clock())
        self.assertEqual(len(a.scan), 1000)  # not 10 min yet
        clock.advance(301)
        _, removed = a.apply_scan(range(997), True, "d", clock())
        self.assertEqual(removed, 3)  # 995, 996 came back in "d"; 997..999 missing for 10 min
        self.assertEqual(max(a.scan), 996)
        self.assertIn(998, a.cand)
        a.check_invariants(clock())

    def test_incomplete_scan_is_add_only(self):
        a, clock = mk()
        a.apply_scan(range(10), True, "a", clock())
        clock.advance(700)
        a.apply_scan([], False, "b", clock())
        clock.advance(700)
        a.apply_scan([], False, "c", clock())
        self.assertEqual(len(a.scan), 10)

    def test_large_removal_is_refused(self):
        a, clock = mk()
        a.apply_scan(range(1000), True, "a", clock())
        clock.advance(700)
        a.apply_scan(range(100), True, "b", clock())
        clock.advance(700)
        with self.assertRaises(CtlRefused) as cm:
            a.apply_scan(list(range(100)) + [5000], True, "c", clock())
        self.assertEqual(cm.exception.code, "excluded_shrink")
        self.assertIn(5000, a.scan)
        clock.advance(700)
        _, removed = a.apply_scan(list(range(100)) + [5000], True, "d", clock(), force=True)
        self.assertEqual(removed, 900)

    def test_same_scan_id_counts_once(self):
        a, clock = mk()
        a.apply_scan(range(10), True, "a", clock())
        clock.advance(700)
        a.apply_scan([], True, "b", clock())
        clock.advance(700)
        a.apply_scan([], True, "b", clock())
        self.assertEqual(len(a.scan), 10)


class ReserveRelease(unittest.TestCase):
    def test_reserve_is_idempotent_per_ref(self):
        a, clock = mk()
        n1 = a.reserve(10, "job-1", clock(), min_free=0)
        self.assertEqual(a.reserve(10, "job-1", clock(), min_free=0), n1)
        self.assertEqual(len(set(n1)), 10)
        for n in n1:
            self.assertNotIn(n, a.cand)
        with self.assertRaises(CtlRefused) as cm:
            a.reserve(11, "job-1", clock(), min_free=0)
        self.assertEqual(cm.exception.code, "ref_conflict")

    def test_reserve_never_returns_a_just_rotated_64(self):
        a, clock = mk(lo=0, hi=199)
        rotated = {a.net_of(a.rotate_addr(3, clock())) for _ in range(60)}
        nets = a.reserve(100, "r", clock(), min_free=0)
        self.assertFalse(set(nets) & rotated)
        clock.advance(61)
        self.assertEqual(len(a.reserve(len(a.cand), "r2", clock(), min_free=0)), 100)

    def test_reserve_capacity_floor_and_force(self):
        a, clock = mk(lo=0, hi=99)
        with self.assertRaises(CtlRefused) as cm:
            a.reserve(10, "x", clock(), min_free=95)
        self.assertEqual(cm.exception.code, "capacity")
        self.assertEqual(len(a.reserve(10, "x", clock(), min_free=95, force=True)), 10)

    def test_reserved_nets_survive_scans(self):
        a, clock = mk()
        nets = a.reserve(5, "r", clock(), min_free=0)
        a.apply_scan([], True, "a", clock())
        clock.advance(700)
        a.apply_scan([], True, "b", clock())
        for n in nets:
            self.assertIn(n, a.reserved)
            self.assertNotIn(n, a.cand)

    def test_release_returns_the_64s_at_once(self):
        a, clock = mk()
        nets = a.reserve(3, "r", clock(), min_free=0)
        self.assertEqual(a.release_nets(nets, "rel-1", clock()), 3)
        self.assertEqual(a.release_nets(nets, "rel-1", clock()), 3)  # idempotent per ref
        self.assertEqual(a.release_nets(nets, "rel-2", clock()), 0)  # not reserved any more: a no-op
        for n in nets:
            self.assertNotIn(n, a.reserved)
            self.assertIn(n, a.cand)  # A6: no cool-down
        a.check_invariants(clock())

    def test_release_by_net_whatever_the_ref(self):
        a, clock = mk()
        nets = a.reserve(2, "gen:31000:abc", clock(), min_free=0)
        self.assertEqual(a.release_nets(nets[:1], "deprovision:31000:zzz", clock()), 1)
        self.assertIn(nets[0], a.cand)
        self.assertIn(nets[1], a.reserved)

    def test_release_of_a_scan_found_net_keeps_it_excluded(self):
        a, clock = mk()
        nets = a.reserve(1, "r", clock(), min_free=0)
        a.apply_scan(nets, True, "s", clock())
        self.assertEqual(a.release_nets(nets, "rel", clock()), 1)
        self.assertNotIn(nets[0], a.cand)  # still named by per-piece: leaves through the scans


class Configure(unittest.TestCase):
    def test_prefix_change_forgets_everything(self):
        a, clock = mk()
        static(a, clock, 1, "p1")
        sticky(a, clock, 1, "p2")
        a.timer_line(1, "p3", 1, 60, T0, (0, 0), clock())
        a.events.clear()
        a.configure(rtest.PREFIX_INT + (1 << 80), "2001:db8:ab::/48", 0, 0xFFFE, rtest.KEY, clock())
        self.assertEqual((len(a.static), len(a.sticky), len(a.mode)), (0, 0, 0))
        self.assertEqual([(e[0], e[4]) for e in a.events], [("release", "prefix_changed")])
        a.check_invariants(clock())

    def test_same_facts_again_keep_every_line(self):
        a, clock = mk()
        st = static(a, clock, 1, "p1")
        se = sticky(a, clock, 1, "s:k")
        pz = a.pause_line(1, "p2", 1, 5, clock())
        a.events.clear()
        a.configure(rtest.PREFIX_INT, rtest.PREFIX, 0, 0xFFFE, rtest.KEY, clock())
        self.assertIs(a.static[(1, "p1")], st)
        self.assertIs(a.sticky[(1, "s:k")], se)
        self.assertIs(a.mode[(1, "p2")], pz)  # a facts re-push (agent restart) keeps the pause state
        self.assertEqual(a.events, [])
        a.check_invariants(clock())

    def test_smaller_pool_drops_the_outside_lines(self):
        a, clock = mk()
        lines = [static(a, clock, 1, "p%d" % i) for i in range(50)]
        a.configure(rtest.PREFIX_INT, rtest.PREFIX, 0, 0x7FFF, rtest.KEY, clock())
        for ln in lines:
            self.assertEqual((1, ln.slot) in a.static, ln.net <= 0x7FFF)
        a.check_invariants(clock())


class Fuzz(unittest.TestCase):
    def test_random_operations_keep_invariants(self):
        rng = random.Random(5)
        a, clock = mk(lo=0, hi=299, seed=6)
        for step in range(4000):
            op = rng.random()
            lid = rng.randrange(20)
            slot = "p%d" % rng.randrange(30)
            if op < 0.2:
                a.rotate_addr(lid, clock(), rng.choice([None, "a.com", "b.com"]))
            elif op < 0.35:
                static(a, clock, lid, slot, acct=lid % 5)
            elif op < 0.5:
                sticky(a, clock, lid, "s:%s" % slot, acct=lid % 5, ttl=rng.choice([30, 60, 600]))
            elif op < 0.6:
                a.timer_line(
                    lid, slot, lid % 5, rng.choice([30, 60]), T0, (0, rng.randrange(2)), clock(), rng.choice([None, 5])
                )
            elif op < 0.65:
                a.pause_line(lid, slot, lid % 5, 5, clock())
            elif op < 0.7:
                a.link_line(lid, slot, lid % 5, (rng.randrange(3), 0), clock())
            elif op < 0.75:
                try:
                    a.reserve(rng.randrange(1, 4), "r%d" % step, clock(), min_free=50)
                except CtlRefused:
                    pass
            elif op < 0.8 and a.reserved:
                a.release_nets(rng.sample(sorted(a.reserved), 1), "rel%d" % step, clock())
            elif op < 0.85:
                a.apply_scan(rng.sample(range(300), 5), False, None, clock())
            elif op < 0.88:
                a.release_list(lid, "list_deleted", clock())
            elif op < 0.9:
                a.avoid_apply([(rng.randrange(300), "a.com", clock() + 30)], [], False, clock())
            else:
                clock.advance(rng.choice([1, 5, 30, 120]))
                a.expire_sticky(clock())
                a.prune_mode_lines(clock())
            if step % 200 == 0:
                a.check_invariants(clock())
        a.check_invariants(clock())


if __name__ == "__main__":
    unittest.main()
