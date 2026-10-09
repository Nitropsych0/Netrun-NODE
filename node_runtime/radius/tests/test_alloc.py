from __future__ import annotations

import random
import unittest

import rtest
from alloc import COOLDOWN_SEC, NET_SELF, Allocator, AllocError, CtlRefused

T0 = 1_800_000_000.0


def mk(lo=0, hi=0xFFFE, seed=3, clock=None):
    clock = clock or rtest.FakeClock(T0)
    a = Allocator(rng=random.Random(seed), clock=clock)
    a.configure(rtest.PREFIX_INT, rtest.PREFIX, lo, hi, rtest.KEY, clock())
    return a, clock


def sticky(a, clock, lid, slot, acct=1, ttl=600, cap=2000, pct=15):
    return a.bind_sticky(lid, slot, acct, ttl, clock(), cap, pct)


def static(a, clock, lid, slot, acct=1, cap=100, pct=5):
    return a.bind_static(lid, slot, acct, clock(), cap, pct)


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
        self.assertTrue(all(0x8100 <= n <= 0xFFFE for n in seen), sorted(seen)[:5])
        self.assertNotIn(NET_SELF, seen)
        a.check_invariants(clock())

    def test_full_pool_default(self):
        a, clock = mk()
        self.assertEqual(a.pool_size(), 0xFFFF)  # 0000..fffe
        self.assertEqual(len(a.free), 0xFFFF)
        self.assertNotIn(NET_SELF, a.cand)

    def test_hosts_are_tagged_and_above_2_32(self):
        a, clock = mk(seed=9)
        addrs = [a.rotate_addr(77, clock()) for _ in range(500)]
        addrs += [sticky(a, clock, 78, "p%d" % i).addr for i in range(200)]
        addrs += [static(a, clock, 79, "p%d" % i, cap=1000).addr for i in range(200)]
        for addr in addrs:
            iid = addr & ((1 << 64) - 1)
            self.assertGreaterEqual(iid, 1 << 32)
            self.assertEqual(addr >> 80, rtest.PREFIX_INT >> 80)
            self.assertIn(a.tagger.list_of(iid), (77, 78, 79))

    def test_rotation_spreads_over_64s(self):
        a, clock = mk()
        nets = {a.net_of(a.rotate_addr(1, clock())) for _ in range(200)}
        self.assertGreater(len(nets), 190)


class RotationAndStatic(unittest.TestCase):
    def test_rotation_never_on_a_static_64(self):
        a, clock = mk(lo=0, hi=15)
        statics = {static(a, clock, 1, "p%d" % i).net for i in range(10)}
        for _ in range(2000):
            self.assertNotIn(a.net_of(a.rotate_addr(2, clock())), statics)
        # free exhausted by sticky bindings: rotation falls back to sticky /64s, never static ones
        for i in range(6):
            sticky(a, clock, 3, "p%d" % i, acct=50 + i, pct=0)
        self.assertEqual(len(a.free), 0)
        for _ in range(500):
            self.assertNotIn(a.net_of(a.rotate_addr(2, clock())), statics)
        a.check_invariants(clock())

    def test_rotation_with_only_static_64s_is_capacity(self):
        a, clock = mk(lo=0, hi=3)
        for i in range(4):
            a.bind_static(1, "p%d" % i, 1, clock(), 100, 0)
        with self.assertRaises(AllocError) as cm:
            a.rotate_addr(2, clock())
        self.assertEqual(cm.exception.reason, "capacity")

    def test_static_is_exclusive_and_stable(self):
        a, clock = mk()
        b1 = static(a, clock, 5, "p3")
        clock.advance(86400 * 30)
        b2 = static(a, clock, 5, "p3")
        self.assertIs(b1, b2)
        self.assertEqual(a.holds[b1.net].n, 1)
        self.assertEqual(a.events[-1][0:5], ("add", 5, "p3", b1.addr, "first_use"))

    def test_static_cap(self):
        a, clock = mk()
        for i in range(3):
            static(a, clock, 5, "p%d" % i, acct=9, cap=3)
        with self.assertRaises(AllocError) as cm:
            static(a, clock, 5, "p9", acct=9, cap=3)
        self.assertEqual(cm.exception.reason, "static_cap")
        static(a, clock, 6, "p9", acct=10, cap=3)  # another account is fine

    def test_static_reserve(self):
        a, clock = mk(lo=0, hi=99)  # 100 candidates, 5 % reserve
        for i in range(95):
            static(a, clock, 1, "p%d" % i, cap=1000)
        self.assertEqual(len(a.free), 5)
        static(a, clock, 1, "p95", cap=1000)  # free 5 is not < 5 % of 100
        with self.assertRaises(AllocError) as cm:
            static(a, clock, 1, "p96", cap=1000)  # free 4 < 5
        self.assertEqual(cm.exception.reason, "capacity")

    def test_best_of_8_prefers_least_recently_used(self):
        a, clock = mk(lo=0, hi=63, seed=11)
        for n in range(64):
            a.last_used[n] = int(T0) - 1000 if n == 17 else int(T0)
        hits = 0
        for i in range(40):
            b = static(a, clock, 1, "p%d" % i, cap=1000, pct=0)
            if b.net == 17:
                hits += 1
                break
        self.assertEqual(hits, 1)


class Sticky(unittest.TestCase):
    def test_ttl_semantics(self):
        a, clock = mk()
        b = sticky(a, clock, 1, "p1", ttl=600)
        created = b.created_at
        clock.advance(300)
        self.assertIs(sticky(a, clock, 1, "p1", ttl=600), b)
        self.assertEqual(b.expires_at, created + 600)
        # a live slot asked with another ttl keeps the IP: expires = created + new ttl
        same = sticky(a, clock, 1, "p1", ttl=3600)
        self.assertIs(same, b)
        self.assertEqual(b.expires_at, created + 3600)
        clock.advance(3300)  # now created + 3600
        nb = sticky(a, clock, 1, "p1", ttl=3600)
        self.assertIsNot(nb, b)
        self.assertNotEqual(nb.net, b.net)  # a new binding in a different /64

    def test_shorter_ttl_that_already_ran_out_gives_a_new_binding(self):
        a, clock = mk()
        b = sticky(a, clock, 1, "p1", ttl=3600)
        clock.advance(700)
        nb = sticky(a, clock, 1, "p1", ttl=600)
        self.assertIsNot(nb, b)
        self.assertNotEqual(nb.net, b.net)

    def test_sweeper_expiry_and_different_64(self):
        a, clock = mk(lo=0, hi=1)
        b = sticky(a, clock, 1, "p1", ttl=60)
        old = b.net
        clock.advance(61)
        self.assertEqual(a.expire_sticky(clock()), 1)
        self.assertEqual(len(a.bindings), 0)
        nb = sticky(a, clock, 1, "p1", ttl=60, pct=0)
        self.assertNotEqual(nb.net, old)

    def test_exclusive_until_cap_then_shared(self):
        a, clock = mk()
        bs = [sticky(a, clock, 1, "p%d" % i, cap=5) for i in range(12)]
        self.assertTrue(all(not b.shared for b in bs[:5]))
        self.assertTrue(all(b.shared for b in bs[5:]))
        self.assertEqual(a.acct_excl_sticky[1], 5)
        self.assertEqual(len({b.net for b in bs}), 12)  # rule 5
        a.check_invariants(clock())

    def test_trial_accounts_are_always_shared(self):
        a, clock = mk()
        bs = [sticky(a, clock, 1, "p%d" % i, cap=0) for i in range(5)]
        self.assertTrue(all(b.shared for b in bs))

    def test_exclusive_until_reserve_then_shared(self):
        a, clock = mk(lo=0, hi=99)  # sticky reserve 15 % of 100
        bs = [sticky(a, clock, i, "p1", acct=i) for i in range(85)]
        self.assertTrue(all(not b.shared for b in bs))
        self.assertEqual(len(a.free), 15)
        b = sticky(a, clock, 200, "p1", acct=200)
        self.assertTrue(b.shared)
        # under the reserve shared bindings pack onto held /64s instead of taking free ones
        self.assertEqual(len(a.free), 15)
        a.check_invariants(clock())

    def test_rule5_across_accounts_and_kinds(self):
        a, clock = mk(lo=0, hi=31)
        for acct in range(1, 6):
            for i in range(6):
                sticky(a, clock, acct, "p%d" % i, acct=acct, cap=0)
            static(a, clock, acct, "p99", acct=acct)
        for acct in range(1, 6):
            nets = [b.net for b in a.bindings.values() if b.account_id == acct]
            self.assertEqual(len(nets), len(set(nets)), acct)
        self.assertEqual(a.stats(clock())["sameAccount64"], 0)
        a.check_invariants(clock())

    def test_rule5_exception_only_when_nothing_else(self):
        a, clock = mk(lo=0, hi=7)
        bs = [sticky(a, clock, 1, "p%d" % i, cap=0) for i in range(8)]
        self.assertEqual(len({b.net for b in bs}), 8)
        self.assertEqual(a.same_account_events, 0)
        sticky(a, clock, 1, "p8", cap=0)
        self.assertEqual(a.same_account_events, 1)
        self.assertEqual(a.stats(clock())["sameAccount64"], 1)

    def test_shared_never_on_static(self):
        a, clock = mk(lo=0, hi=9)
        statics = {static(a, clock, 1, "p%d" % i, acct=1, pct=0).net for i in range(5)}
        for acct in range(2, 30):
            b = sticky(a, clock, acct, "p1", acct=acct, cap=0)
            self.assertNotIn(b.net, statics)

    def test_static_over_live_sticky_converts_in_place(self):
        a, clock = mk()
        b = sticky(a, clock, 1, "p1")
        s = static(a, clock, 1, "p1")
        self.assertIs(s, b)
        self.assertEqual(s.kind, "static")
        self.assertIsNone(s.expires_at)
        self.assertEqual(a.events[-1][4], "converted")
        a.check_invariants(clock())

    def test_sticky_request_on_a_static_slot_keeps_the_static(self):
        a, clock = mk()
        s = static(a, clock, 1, "p1")
        self.assertIs(sticky(a, clock, 1, "p1"), s)
        self.assertEqual(s.kind, "static")


class SafetyCaps(unittest.TestCase):
    def test_sticky_per_account_cap(self):
        a, clock = mk()
        a.max_sticky_per_account = 5
        for i in range(5):
            sticky(a, clock, 1, "s:%d" % i)
        with self.assertRaises(AllocError) as cm:
            sticky(a, clock, 1, "s:new")
        self.assertEqual(cm.exception.reason, "capacity")
        sticky(a, clock, 2, "s:new", acct=2)
        sticky(a, clock, 1, "s:0")  # an existing slot is still served
        clock.advance(601)
        a.expire_sticky(clock())
        sticky(a, clock, 1, "s:new")  # room again after expiry

    def test_node_wide_binding_cap(self):
        a, clock = mk()
        a.max_bindings = 4
        for i in range(4):
            sticky(a, clock, i, "p1", acct=i)
        with self.assertRaises(AllocError):
            sticky(a, clock, 9, "p1", acct=9)
        with self.assertRaises(AllocError):
            static(a, clock, 9, "p2", acct=9)

    def test_heap_expiry_honours_ttl_changes(self):
        a, clock = mk()
        b = sticky(a, clock, 1, "p1", ttl=600)
        clock.advance(300)
        sticky(a, clock, 1, "p1", ttl=3600)
        clock.advance(400)  # past the first expiry, before the new one
        self.assertEqual(a.expire_sticky(clock()), 0)
        self.assertIn((1, "p1"), a.bindings)
        clock.advance(3000)
        self.assertEqual(a.expire_sticky(clock()), 1)
        self.assertNotIn(b.key(), a.bindings)
        self.assertEqual(len(a.sticky_heap), 0)

    def test_prev_net_is_pruned_in_order(self):
        a, clock = mk()
        for i in range(10):
            b = sticky(a, clock, 1, "p%d" % i, ttl=60)
            a.release(b, "test", clock())
            clock.advance(10)
        self.assertEqual(len(a.prev_net), 10)
        clock.advance(3600 - 55)  # releases at +0..+90 s, now +3645 s: the first five are over
        a.expire_sticky(clock())
        self.assertEqual(len(a.prev_net), 5)


class Excluded(unittest.TestCase):
    def test_shrink_guard(self):
        a, clock = mk()
        nets = list(range(100, 300))
        a.apply_scan(nets, True, "s1", clock())
        self.assertEqual(a.excluded_count(clock()), 200)
        self.assertNotIn(150, a.free)
        # incomplete scans are add-only
        a.apply_scan([5], False, "s2", clock())
        self.assertIn(5, a.scan)
        # one complete scan without 150 removes nothing
        clock.advance(60)
        a.apply_scan([n for n in nets if n != 150] + [5], True, "s3", clock())
        self.assertIn(150, a.scan)
        # a second one less than 10 min after the first: still nothing
        clock.advance(200)
        a.apply_scan([n for n in nets if n != 150] + [5], True, "s4", clock())
        self.assertIn(150, a.scan)
        # >= 10 min after the anchor: removed
        clock.advance(600)
        _, removed = a.apply_scan([n for n in nets if n != 150] + [5], True, "s5", clock())
        self.assertEqual(removed, 1)
        self.assertNotIn(150, a.scan)
        self.assertIn(150, a.free)

    def test_reappearing_net_restarts_the_count(self):
        a, clock = mk()
        a.apply_scan([1, 2, 3], True, "a", clock())
        clock.advance(700)
        a.apply_scan([1, 2], True, "b", clock())  # 3 missing (anchor b)
        clock.advance(100)
        a.apply_scan([3], False, "c", clock())  # 3 seen again by an incomplete scan
        clock.advance(600)
        a.apply_scan([1, 2], True, "d", clock())
        self.assertIn(3, a.scan)

    def test_same_scan_id_counts_once(self):
        a, clock = mk()
        a.apply_scan([1, 2], True, "a", clock())
        clock.advance(700)
        a.apply_scan([1], True, "b", clock())
        clock.advance(700)
        a.apply_scan([1], True, "b", clock())
        self.assertIn(2, a.scan)

    def test_large_removal_is_refused(self):
        a, clock = mk()
        a.apply_scan(range(1000), True, "a", clock())
        clock.advance(700)
        a.apply_scan(range(100), True, "b", clock())  # 900 missing (2 % limit = 20)
        clock.advance(700)
        with self.assertRaises(CtlRefused) as cm:
            a.apply_scan(list(range(100)) + [5000], True, "c", clock())
        self.assertEqual(cm.exception.code, "excluded_shrink")
        self.assertEqual(cm.exception.extra["wouldRemove"], 900)
        self.assertEqual(len(a.scan), 1001)  # nothing removed, the addition kept
        self.assertIn(5000, a.scan)
        # an explicit force passes the same confirmed removal
        clock.advance(700)
        _, removed = a.apply_scan(list(range(100)) + [5000], True, "d", clock(), force=True)
        self.assertEqual(removed, 900)

    def test_exclusion_releases_bindings_on_that_64(self):
        a, clock = mk()
        b = static(a, clock, 1, "p1")
        s = sticky(a, clock, 2, "p1", acct=2)
        a.apply_scan([b.net, s.net], False, None, clock())
        self.assertNotIn((1, "p1"), a.bindings)
        self.assertNotIn((2, "p1"), a.bindings)
        self.assertEqual(a.events[-1][0], "release")
        self.assertEqual(a.events[-1][4], "excluded")
        a.check_invariants(clock())


class ReserveRelease(unittest.TestCase):
    def test_reserve_is_idempotent_per_ref(self):
        a, clock = mk()
        n1 = a.reserve(10, "job-1", clock(), min_free=0)
        n2 = a.reserve(10, "job-1", clock(), min_free=0)
        self.assertEqual(n1, n2)
        self.assertEqual(len(set(n1)), 10)
        for n in n1:
            self.assertNotIn(n, a.free)
            self.assertNotIn(n, a.cand)
        with self.assertRaises(CtlRefused) as cm:
            a.reserve(11, "job-1", clock(), min_free=0)
        self.assertEqual(cm.exception.code, "ref_conflict")

    def test_reserve_never_returns_bound_or_just_rotated(self):
        a, clock = mk(lo=0, hi=199)
        bound = {static(a, clock, 1, "p%d" % i, cap=1000, pct=0).net for i in range(50)}
        bound |= {sticky(a, clock, 2, "p%d" % i, acct=2).net for i in range(50)}
        rotated = {a.net_of(a.rotate_addr(3, clock())) for _ in range(60)}
        nets = a.reserve(40, "r", clock(), min_free=0)
        self.assertFalse(set(nets) & bound)
        self.assertFalse(set(nets) & rotated)
        clock.advance(61)
        more = a.reserve(len(a.free), "r2", clock(), min_free=0)
        self.assertFalse(set(more) & bound)

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
            self.assertNotIn(n, a.free)

    def test_release_cools_down_for_24h(self):
        a, clock = mk()
        nets = a.reserve(3, "r", clock(), min_free=0)
        count, until = a.release_nets(nets, "rel-1", clock())
        self.assertEqual(count, 3)
        self.assertEqual(until, clock() + COOLDOWN_SEC)
        self.assertEqual(a.release_nets(nets, "rel-1", clock()), (count, until))  # idempotent
        for n in nets:
            self.assertNotIn(n, a.reserved)
            self.assertNotIn(n, a.free)
        clock.advance(COOLDOWN_SEC - 1)
        a.expire_cooldowns(clock())
        self.assertNotIn(nets[0], a.free)
        clock.advance(2)
        self.assertEqual(a.expire_cooldowns(clock()), 3)
        for n in nets:
            self.assertIn(n, a.free)

    def test_release_of_a_scan_found_net_still_cools_down(self):
        a, clock = mk()
        a.apply_scan([77], True, "a", clock())
        a.release_nets([77], "x", clock())
        clock.advance(700)
        a.apply_scan([], True, "b", clock())
        clock.advance(700)
        a.apply_scan([], True, "c", clock())
        self.assertNotIn(77, a.scan)
        self.assertNotIn(77, a.free)  # cool-down still holds it
        clock.advance(COOLDOWN_SEC)
        a.expire_cooldowns(clock())
        self.assertIn(77, a.free)


class Adoption(unittest.TestCase):
    def test_adopt_rules(self):
        a, clock = mk()
        b = static(a, clock, 7, "p1")
        addr = b.addr
        # RADIUS keeps its own binding
        self.assertEqual(a.adopt_static(7, "p1", 1, addr ^ 1, clock()), "kept")
        a.release(b, "test", clock())
        self.assertEqual(a.adopt_static(7, "p1", 1, addr, clock()), "adopted")
        self.assertEqual(a.bindings[(7, "p1")].addr, addr)
        # wrong list in the tag, other prefix, excluded /64
        self.assertEqual(a.adopt_static(8, "p1", 1, addr, clock()), "bad_tag")
        self.assertEqual(a.adopt_static(7, "p2", 1, addr ^ (1 << 100), clock()), "outside_prefix")
        other = a.new_addr(500, 7)
        a.apply_scan([500], False, None, clock())
        self.assertEqual(a.adopt_static(7, "p3", 1, other, clock()), "excluded")
        a.check_invariants(clock())

    def test_adopt_evicts_sticky_but_not_static(self):
        a, clock = mk()
        s = sticky(a, clock, 2, "p1", acct=2)
        want = a.new_addr(s.net, 7)
        self.assertEqual(a.adopt_static(7, "p1", 1, want, clock()), "adopted")
        self.assertNotIn((2, "p1"), a.bindings)
        other = a.new_addr(s.net, 8)
        self.assertEqual(a.adopt_static(8, "p1", 3, other, clock()), "conflict")
        a.check_invariants(clock())


class Fuzz(unittest.TestCase):
    def test_random_operations_keep_invariants(self):
        a, clock = mk(lo=0, hi=255, seed=21)
        rng = random.Random(4)
        for step in range(4000):
            op = rng.random()
            acct = rng.randint(1, 12)
            lid = acct * 10 + rng.randint(0, 2)
            slot = "p%d" % rng.randint(0, 30)
            try:
                if op < 0.3:
                    a.rotate_addr(lid, clock())
                elif op < 0.6:
                    a.bind_sticky(lid, slot, acct, rng.choice([60, 600, 3600]), clock(), rng.choice([0, 3, 2000]), 15)
                elif op < 0.75:
                    a.bind_static(lid, slot, acct, clock(), 20, 5)
                elif op < 0.8:
                    a.release_list(lid, "list_deleted", clock())
                elif op < 0.85:
                    a.apply_scan(rng.sample(range(256), 5), False, None, clock())
                elif op < 0.88:
                    a.reserve(rng.randint(1, 3), "ref%d" % step, clock(), min_free=0)
                elif op < 0.9:
                    a.release_nets(rng.sample(range(256), 3), "rel%d" % step, clock())
                else:
                    clock.advance(rng.choice([1, 30, 300]))
                    a.expire_sticky(clock())
                    a.expire_cooldowns(clock())
            except (AllocError, CtlRefused):
                pass
            if step % 200 == 0:
                a.check_invariants(clock())
        a.check_invariants(clock())


if __name__ == "__main__":
    unittest.main()
