"""Address allocator: the one allocator of record for the /64s of a per-GB pool.

Pool (amendment A1) = subnet ids lo..hi of the node's routed /48, never ffff
(the node's own /64). Default 0000-fffe.

excluded = /64s held by per-piece:
  - scan    : found by the agent's scan (cfg anchors, ipv6 lists, egress state).
              Shrink guard: additions apply at once; a /64 leaves only after two
              complete scans >= 10 min apart both lack it; an incomplete scan is
              add-only; a push that would remove more than 2 % is refused.
  - reserved: handed to per-piece through reserve_nets; only release_nets frees it.
  - cooldown: released by per-piece; back in the pool 24 h later.
candidates = pool - excluded;  free = candidates holding no binding.

Picks
  - rotation: the least recently used of 4 random free /64s (fallback: any
    candidate without a static binding),
    a fresh tagged host per connection, nothing stored; stamps last_used.
  - static: exclusive, best of 8 free /64s by oldest last_used; refused with
    static_cap at the account's cap and with capacity under the static reserve.
  - sticky: exclusive while the account holds fewer than sticky_excl_cap exclusive
    sticky /64s and free > the sticky reserve; otherwise a shared /64 that holds no
    static binding and no binding of the same account.
Rule 5: two bindings of one account never share a /64 while any other /64 can be
used; the exception is counted (sameAccount64).
"""

from __future__ import annotations

import heapq
import os
from collections import OrderedDict
import random
import time
from array import array

from tag import Tagger

NET_SELF = 0xFFFF
NET_COUNT = 1 << 16
SCAN_CONFIRM_SEC = 600  # two complete scans at least this far apart
SCAN_SHRINK_MAX = 0.02  # refuse a push that removes more than 2 % of scan entries
RESERVE_ROTATED_MIN_AGE = 60  # reserve_nets never returns a /64 used in the last 60 s
COOLDOWN_SEC = 24 * 3600
RESERVE_MAX = 5000
BEST_OF = 8
ROTATE_BEST_OF = 4
SHARED_SAMPLE = 32
SHARED_SOFT_MAX = 32  # bindings per shared /64 before a fresh one is preferred
PREV_NET_TTL = 3600
PREV_NET_MAX = 200_000
# Safety caps (not tunable by customers): session ids are customer-chosen, so live
# sticky bindings must stay bounded for MemoryMax. Refusals are reason "capacity".
MAX_BINDINGS = 250_000
MAX_STICKY_PER_ACCOUNT = 20_000
STATIC = "static"
STICKY = "sticky"


class AllocError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class CtlRefused(Exception):
    def __init__(self, code: str, **extra):
        super().__init__(code)
        self.code = code
        self.extra = extra


class Binding:
    __slots__ = (
        "list_id",
        "slot",
        "kind",
        "addr",
        "net",
        "account_id",
        "shared",
        "created_at",
        "expires_at",
        "last_used_at",
    )

    def __init__(self, list_id, slot, kind, addr, net, account_id, shared, created_at, expires_at, last_used_at):
        self.list_id = list_id
        self.slot = slot
        self.kind = kind
        self.addr = addr
        self.net = net
        self.account_id = account_id
        self.shared = shared
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_used_at = last_used_at

    def key(self):
        return (self.list_id, self.slot)


class NetHold:
    """Who holds a /64: its bindings, static count, per-account counts, shared flag."""

    __slots__ = ("binds", "static", "accounts", "shared", "dups")

    def __init__(self):
        self.binds = []
        self.static = 0
        self.accounts = {}
        self.shared = False
        self.dups = 0  # accounts with two or more bindings here (rule-5 exceptions)

    @property
    def n(self) -> int:
        return len(self.binds)


class _IndexedSet:
    """list + index map: O(1) add, remove and uniform random pick."""

    __slots__ = ("items", "index")

    def __init__(self, items=()):
        self.items = list(items)
        self.index = {v: i for i, v in enumerate(self.items)}

    def __len__(self):
        return len(self.items)

    def __contains__(self, v):
        return v in self.index

    def add(self, v):
        if v not in self.index:
            self.index[v] = len(self.items)
            self.items.append(v)

    def discard(self, v):
        i = self.index.pop(v, None)
        if i is None:
            return
        last = self.items.pop()
        if i < len(self.items):
            self.items[i] = last
            self.index[last] = i

    def pick(self, rng):
        return self.items[rng.randrange(len(self.items))]


def _u32_array():
    for code in ("I", "L"):
        a = array(code)
        if a.itemsize == 4:
            return array(code, bytes(4 * NET_COUNT))
    return array("Q", bytes(8 * NET_COUNT))


class Allocator:
    def __init__(self, rng=None, clock=time.time):
        self.rng = rng or random.Random(os.urandom(16))
        self.clock = clock
        self.prefix = None  # int: the /48 network address
        self.prefix_str = None
        self.lo = 0
        self.hi = NET_SELF - 1
        self.tagger = None
        # excluded sources
        self.scan = set()
        self.reserved = {}  # net -> ref
        self.reserved_at = {}  # net -> ts
        self.cooldown = {}  # net -> until (unix)
        self.reservations = {}  # ref -> [nets]
        self.reservation_at = {}  # ref -> ts
        self.releases = {}  # ref -> (count, until)
        self.scan_missing = {}  # scan-found net -> first complete scan that lacked it
        self.last_scan_id = None
        # derived sets
        self.cand = _IndexedSet()
        self.free = _IndexedSet()
        self.shared_nets = _IndexedSet()
        self.holds = {}  # net -> NetHold
        # bindings
        self.bindings = {}  # (list_id, slot) -> Binding
        self.by_list = {}  # list_id -> {slot: Binding}
        self.acct_static = {}
        self.acct_excl_sticky = {}
        self.acct_sticky = {}
        self.sticky_heap = []  # (expires_at, list_id, slot); stale entries are skipped
        self.max_bindings = MAX_BINDINGS
        self.max_sticky_per_account = MAX_STICKY_PER_ACCOUNT
        self.n_static = 0
        self.n_sticky = 0
        self.last_used = _u32_array()
        self.prev_net = OrderedDict()  # (list_id, slot) -> (net, until), oldest first
        self.same_account_events = 0
        self.same64 = 0  # /64s where one account holds two or more bindings
        # persistence journal, drained by the engine's flush
        self.dirty_bindings = {}  # key -> Binding | None
        self.events = []  # (op, list_id, slot, addr, reason, at)
        self.dirty_nets = set()
        self.dirty_refs = set()

    # ---- configuration -------------------------------------------------------------

    @property
    def configured(self) -> bool:
        return self.prefix is not None and self.tagger is not None

    def configure(self, prefix: int, prefix_str: str, lo: int, hi: int, key: bytes, now: float | None = None):
        """Set the pool. A new prefix drops every binding; a smaller pool drops the outside ones."""
        now = self.clock() if now is None else now
        hi = min(hi, NET_SELF - 1)
        if lo < 0 or lo > hi:
            raise ValueError("bad pool range")
        if self.prefix is not None and prefix != self.prefix:
            for b in list(self.bindings.values()):
                self.release(b, "prefix_changed", now)
        self.prefix = prefix
        self.prefix_str = prefix_str
        self.tagger = Tagger(key) if (self.tagger is None or self.tagger.key != key) else self.tagger
        self.lo, self.hi = lo, hi
        for b in list(self.bindings.values()):
            if not lo <= b.net <= hi:
                self.release(b, "pool_changed", now)
        self.rebuild(now)

    def in_pool(self, net: int) -> bool:
        return self.lo <= net <= self.hi and net != NET_SELF

    def is_excluded(self, net: int, now: float) -> bool:
        return net in self.scan or net in self.reserved or self.cooldown.get(net, 0) > now

    def rebuild(self, now: float | None = None):
        now = self.clock() if now is None else now
        cand = [n for n in range(self.lo, self.hi + 1) if n != NET_SELF and not self.is_excluded(n, now)]
        self.cand = _IndexedSet(cand)
        holds = self.holds
        self.free = _IndexedSet(n for n in cand if n not in holds)
        self.shared_nets = _IndexedSet(n for n, h in holds.items() if h.shared)

    def pool_size(self) -> int:
        if self.prefix is None:
            return 0
        size = self.hi - self.lo + 1
        if self.lo <= NET_SELF <= self.hi:
            size -= 1
        return size

    # ---- addresses -----------------------------------------------------------------

    def addr_of(self, net: int, iid: int) -> int:
        return self.prefix | (net << 64) | iid

    def new_addr(self, net: int, list_id: int) -> int:
        return self.addr_of(net, self.tagger.make_iid(list_id, self.rng.getrandbits))

    def net_of(self, addr: int) -> int | None:
        if self.prefix is None or (addr >> 80) != (self.prefix >> 80):
            return None
        return (addr >> 64) & 0xFFFF

    # ---- excluded transitions ------------------------------------------------------

    def _refresh_net(self, net: int, now: float):
        """Re-derive cand/free membership of one /64 after an excluded-source change."""
        self.dirty_nets.add(net)
        if not self.in_pool(net):
            return
        if self.is_excluded(net, now):
            if net in self.cand:
                self.cand.discard(net)
                self.free.discard(net)
                h = self.holds.get(net)
                if h is not None:
                    for b in list(h.binds):
                        self.release(b, "excluded", now)
                self.shared_nets.discard(net)
        elif net not in self.cand:
            self.cand.add(net)
            if net not in self.holds:
                self.free.add(net)

    def apply_scan(self, nets, complete: bool, scan_id, now: float, force: bool = False):
        """Excluded push from the agent's scan. Returns (excluded_count, removed_count).

        A scan-found /64 leaves only when every complete scan for at least
        SCAN_CONFIRM_SEC lacked it (so at least two complete scans >= 10 min apart).
        Any scan that lists it again, complete or not, restarts the count.
        Raises CtlRefused('excluded_shrink') when the confirmed removal is over 2 %
        of the scan entries (the additions of that push are kept)."""
        nets = {int(n) for n in nets if 0 <= int(n) < NET_SELF}
        if scan_id is not None and scan_id == self.last_scan_id:
            return self.excluded_count(now), 0
        for n in nets - self.scan:
            self.scan.add(n)
            self._refresh_net(n, now)
        missing = self.scan_missing
        for n in nets & missing.keys() if missing else ():
            del missing[n]
        removed = []
        if complete:
            gone = self.scan - nets
            for n in [n for n in missing if n not in gone]:
                del missing[n]  # cannot happen through scans, kept for safety
            for n in gone:
                first = missing.get(n)
                if first is None:
                    missing[n] = now
                elif now - first >= SCAN_CONFIRM_SEC:
                    removed.append(n)
            limit = max(1, int(SCAN_SHRINK_MAX * len(self.scan)))
            if len(removed) > limit and not force:
                self.last_scan_id = scan_id
                raise CtlRefused("excluded_shrink", wouldRemove=len(removed), limit=limit)
            for n in removed:
                del missing[n]
                self.scan.discard(n)
                self._refresh_net(n, now)
        self.last_scan_id = scan_id
        return self.excluded_count(now), len(removed)

    def excluded_count(self, now: float) -> int:
        return self.pool_size() - len(self.cand) if self.prefix is not None else len(self.scan)

    def reserve(self, count: int, ref: str, now: float, min_free: int, force: bool = False):
        """reserve_nets: count /64s for per-piece, idempotent per ref."""
        if ref in self.reservations:
            nets = self.reservations[ref]
            if len(nets) != count:
                raise CtlRefused("ref_conflict", nets=list(nets))
            return list(nets)
        if not 1 <= count <= RESERVE_MAX:
            raise CtlRefused("bad_request", detail="count must be 1..%d" % RESERVE_MAX)
        if not self.configured:
            raise CtlRefused("not_ready")
        if len(self.free) - count < min_free and not force:
            raise CtlRefused("capacity", free=len(self.free), minFree=min_free)
        picked = []
        chosen = set()
        too_recent = now - RESERVE_ROTATED_MIN_AGE
        last_used = self.last_used
        free = self.free
        for _ in range(count):
            best = None
            for _try in range(BEST_OF * 8):
                if len(free) <= len(chosen):
                    break
                n = free.pick(self.rng)
                if n in chosen or last_used[n] > too_recent:
                    continue
                if best is None or last_used[n] < last_used[best]:
                    best = n
                if _try >= BEST_OF - 1 and best is not None:
                    break
            if best is None:
                # sparse eligible set: one ordered pass over free
                for n in free.items:
                    if n not in chosen and last_used[n] <= too_recent:
                        best = n
                        break
            if best is None:
                raise CtlRefused("capacity", free=len(free), detail="recently_used")
            chosen.add(best)
            picked.append(best)
        for n in picked:
            self.reserved[n] = ref
            self.reserved_at[n] = now
            self._refresh_net(n, now)
        self.reservations[ref] = picked
        self.reservation_at[ref] = now
        self.dirty_refs.add(ref)
        return list(picked)

    def release_nets(self, nets, ref: str, now: float):
        """release_nets: per-piece hands /64s back; they rejoin after the cool-down."""
        if ref in self.releases:
            return self.releases[ref]
        until = now + COOLDOWN_SEC
        count = 0
        for raw in nets:
            n = int(raw)
            if not 0 <= n < NET_SELF:
                continue
            count += 1
            self.reserved.pop(n, None)
            self.reserved_at.pop(n, None)
            if self.cooldown.get(n, 0) < until:
                self.cooldown[n] = until
            self._refresh_net(n, now)
        self.releases[ref] = (count, until)
        self.dirty_refs.add("rel:" + ref)
        return count, until

    def expire_cooldowns(self, now: float):
        done = [n for n, until in self.cooldown.items() if until <= now]
        for n in done:
            del self.cooldown[n]
            self._refresh_net(n, now)
        return len(done)

    # ---- holds ---------------------------------------------------------------------

    def _hold_add(self, b: Binding):
        h = self.holds.get(b.net)
        if h is None:
            h = self.holds[b.net] = NetHold()
            self.free.discard(b.net)
        h.binds.append(b)
        c = h.accounts.get(b.account_id, 0) + 1
        h.accounts[b.account_id] = c
        if c == 2:
            h.dups += 1
            if h.dups == 1:
                self.same64 += 1
        if b.kind == STATIC:
            h.static += 1
            self.acct_static[b.account_id] = self.acct_static.get(b.account_id, 0) + 1
            self.n_static += 1
        else:
            self.n_sticky += 1
            self.acct_sticky[b.account_id] = self.acct_sticky.get(b.account_id, 0) + 1
            if not b.shared:
                self.acct_excl_sticky[b.account_id] = self.acct_excl_sticky.get(b.account_id, 0) + 1
        if b.shared and not h.shared:
            self._make_shared(b.net, h)

    def _make_shared(self, net: int, h: NetHold):
        h.shared = True
        self.shared_nets.add(net)
        for other in h.binds:
            if not other.shared:
                other.shared = True
                if other.kind == STICKY:
                    self._dec(self.acct_excl_sticky, other.account_id)
                self.dirty_bindings[other.key()] = other

    @staticmethod
    def _dec(d, k):
        v = d.get(k, 0) - 1
        if v > 0:
            d[k] = v
        else:
            d.pop(k, None)

    def _hold_remove(self, b: Binding, now: float):
        h = self.holds.get(b.net)
        if h is None:
            return
        h.binds.remove(b)
        c = h.accounts.get(b.account_id, 0)
        if c == 2:
            h.dups -= 1
            if h.dups == 0:
                self.same64 -= 1
        self._dec(h.accounts, b.account_id)
        if b.kind == STATIC:
            h.static -= 1
            self._dec(self.acct_static, b.account_id)
            self.n_static -= 1
        else:
            self.n_sticky -= 1
            self._dec(self.acct_sticky, b.account_id)
            if not b.shared:
                self._dec(self.acct_excl_sticky, b.account_id)
        if not h.binds:
            del self.holds[b.net]
            self.shared_nets.discard(b.net)
            if b.net in self.cand:
                self.free.add(b.net)
        self.last_used[b.net] = int(now)

    # ---- binding lifecycle ---------------------------------------------------------

    def _insert(self, b: Binding, event_reason: str | None, now: float):
        self.bindings[b.key()] = b
        self.by_list.setdefault(b.list_id, {})[b.slot] = b
        self._hold_add(b)
        self.dirty_bindings[b.key()] = b
        if b.kind == STICKY and b.expires_at is not None:
            heapq.heappush(self.sticky_heap, (b.expires_at, b.list_id, b.slot))
        if b.kind == STATIC and event_reason:
            self.events.append(("add", b.list_id, b.slot, b.addr, event_reason, now))

    def release(self, b: Binding, reason: str, now: float):
        key = b.key()
        if self.bindings.get(key) is not b:
            return
        del self.bindings[key]
        slots = self.by_list.get(b.list_id)
        if slots is not None:
            slots.pop(b.slot, None)
            if not slots:
                del self.by_list[b.list_id]
        self._hold_remove(b, now)
        self.dirty_bindings[key] = None
        if b.kind == STATIC:
            self.events.append(("release", b.list_id, b.slot, b.addr, reason, now))
        elif len(self.prev_net) < PREV_NET_MAX:
            self.prev_net[key] = (b.net, now + PREV_NET_TTL)
            self.prev_net.move_to_end(key)  # insertion order = expiry order

    def release_list(self, list_id: int, reason: str, now: float, kinds=(STATIC, STICKY)) -> int:
        slots = self.by_list.get(list_id)
        if not slots:
            return 0
        n = 0
        for b in list(slots.values()):
            if b.kind in kinds:
                self.release(b, reason, now)
                n += 1
        return n

    def load_binding(self, b: Binding, now: float) -> bool:
        """Re-insert a persisted binding at start-up (no events). False = dropped."""
        if b.key() in self.bindings or not self.in_pool(b.net) or self.is_excluded(b.net, now):
            return False
        if self.net_of(b.addr) != b.net:
            return False
        h = self.holds.get(b.net)
        if b.kind == STATIC and h is not None:
            return False
        if h is not None and h.static:
            return False
        if h is not None and not b.shared:
            b.shared = True  # a second binding on an "exclusive" /64: treat it as shared
        self.bindings[b.key()] = b
        self.by_list.setdefault(b.list_id, {})[b.slot] = b
        self._hold_add(b)
        if b.kind == STICKY and b.expires_at is not None:
            self.sticky_heap.append((b.expires_at, b.list_id, b.slot))
        return True

    def loaded(self):
        """End of start-up loading."""
        heapq.heapify(self.sticky_heap)

    # ---- picks ---------------------------------------------------------------------

    def _pick_exclusive(self, avoid=None):
        free = self.free
        if not len(free):
            return None
        last_used = self.last_used
        best = None
        for _ in range(BEST_OF):
            n = free.pick(self.rng)
            if n == avoid and len(free) > 1:
                continue
            if best is None or last_used[n] < last_used[best]:
                best = n
        if best is None or (best == avoid and len(free) > 1):
            for n in free.items:
                if n != avoid:
                    return n
        return best

    def _pick_shared(self, account_id, avoid, allow_free: bool):
        rng = self.rng
        holds = self.holds
        samples = []
        sn = self.shared_nets
        if len(sn) <= SHARED_SAMPLE:
            samples.extend(sn.items)
        else:
            samples.extend(sn.pick(rng) for _ in range(SHARED_SAMPLE))
        cand = self.cand
        if len(cand):
            samples.extend(cand.pick(rng) for _ in range(SHARED_SAMPLE))
        best, best_key = None, None
        for n in samples:
            if n == avoid:
                continue
            h = holds.get(n)
            if h is None:
                key = (1, 0) if allow_free else (4, 0)
            else:
                if h.static or account_id in h.accounts:
                    continue
                if h.shared:
                    key = (0, h.n) if h.n < SHARED_SOFT_MAX else (2, h.n)
                else:
                    key = (3, h.n)
            if best_key is None or key < best_key:
                best, best_key = n, key
        if best is not None:
            return best, False
        # nothing in the samples: one ordered pass over the candidates
        fallback_same = None
        for n in cand.items:
            if n == avoid:
                continue
            h = holds.get(n)
            if h is None:
                return n, False
            if h.static:
                continue
            if account_id not in h.accounts:
                return n, False
            if fallback_same is None:
                fallback_same = n
        if fallback_same is not None:
            return fallback_same, True
        return None, False

    def rotate_addr(self, list_id: int, now: float) -> int:
        free = self.free
        if len(free):
            # least recently used of a few random free /64s: rotation spreads evenly
            # and two connections in a row practically never share a /64
            rng = self.rng
            last_used = self.last_used
            n = free.pick(rng)
            for _ in range(ROTATE_BEST_OF - 1):
                c = free.pick(rng)
                if last_used[c] < last_used[n]:
                    n = c
        else:
            n = None
            cand = self.cand
            for _ in range(64):
                if not len(cand):
                    break
                c = cand.pick(self.rng)
                h = self.holds.get(c)
                if h is None or not h.static:
                    n = c
                    break
            if n is None:
                for c in cand.items:
                    h = self.holds.get(c)
                    if h is None or not h.static:
                        n = c
                        break
            if n is None:
                raise AllocError("capacity")
        self.last_used[n] = int(now)
        return self.new_addr(n, list_id)

    def _reserve_ok(self, pct: float) -> bool:
        return len(self.free) > pct / 100.0 * len(self.cand)

    def bind_sticky(self, list_id, slot, account_id, ttl, now, excl_cap, sticky_pct, static_pct=5) -> Binding:
        key = (list_id, slot)
        b = self.bindings.get(key)
        avoid = None
        if b is not None:
            if b.kind == STATIC:
                b.last_used_at = now
                return b
            new_exp = b.created_at + ttl
            if b.expires_at > now and new_exp > now:
                if new_exp != b.expires_at:
                    b.expires_at = new_exp
                    self.dirty_bindings[key] = b
                    heapq.heappush(self.sticky_heap, (new_exp, list_id, slot))
                b.last_used_at = now
                return b
            avoid = b.net
            self.release(b, "expired", now)
        else:
            prev = self.prev_net.get(key)
            if prev is not None and prev[1] > now:
                avoid = prev[0]
        if (
            len(self.bindings) >= self.max_bindings
            or self.acct_sticky.get(account_id, 0) >= self.max_sticky_per_account
        ):
            raise AllocError("capacity")
        shared = True
        n = None
        if self.acct_excl_sticky.get(account_id, 0) < excl_cap and self._reserve_ok(sticky_pct):
            n = self._pick_exclusive(avoid)
            shared = n is None
        same = False
        if n is None:
            n, same = self._pick_shared(account_id, avoid, allow_free=self._reserve_ok(sticky_pct))
        if n is None:
            raise AllocError("capacity")
        if same:
            self.same_account_events += 1
        nb = Binding(list_id, slot, STICKY, self.new_addr(n, list_id), n, account_id, shared, now, now + ttl, now)
        self._insert(nb, None, now)
        return nb

    def bind_static(self, list_id, slot, account_id, now, static_cap, static_pct) -> Binding:
        key = (list_id, slot)
        b = self.bindings.get(key)
        if b is not None and b.kind == STATIC:
            b.last_used_at = now
            return b
        if self.acct_static.get(account_id, 0) >= static_cap:
            raise AllocError("static_cap")
        if b is not None:
            h = self.holds.get(b.net)
            if not b.shared and h is not None and h.n == 1:
                # an exclusive sticky slot becomes static in place (same IP)
                self._hold_remove_soft(b)
                b.kind = STATIC
                b.expires_at = None
                b.last_used_at = now
                self._hold_add_soft(b)
                self.dirty_bindings[key] = b
                self.events.append(("add", b.list_id, b.slot, b.addr, "converted", now))
                return b
            self.release(b, "converted", now)
        if len(self.bindings) >= self.max_bindings:
            raise AllocError("capacity")
        if not len(self.free) or len(self.free) < static_pct / 100.0 * len(self.cand):
            raise AllocError("capacity")
        n = self._pick_exclusive()
        if n is None:
            raise AllocError("capacity")
        nb = Binding(list_id, slot, STATIC, self.new_addr(n, list_id), n, account_id, False, now, None, now)
        self._insert(nb, "first_use", now)
        return nb

    def _hold_remove_soft(self, b: Binding):
        """Counter part of a kind change (the /64 stays held)."""
        h = self.holds[b.net]
        if b.kind == STATIC:
            h.static -= 1
            self._dec(self.acct_static, b.account_id)
            self.n_static -= 1
        else:
            self.n_sticky -= 1
            self._dec(self.acct_sticky, b.account_id)
            if not b.shared:
                self._dec(self.acct_excl_sticky, b.account_id)

    def _hold_add_soft(self, b: Binding):
        h = self.holds[b.net]
        if b.kind == STATIC:
            h.static += 1
            self.acct_static[b.account_id] = self.acct_static.get(b.account_id, 0) + 1
            self.n_static += 1
        else:
            self.n_sticky += 1
            self.acct_sticky[b.account_id] = self.acct_sticky.get(b.account_id, 0) + 1
            if not b.shared:
                self.acct_excl_sticky[b.account_id] = self.acct_excl_sticky.get(b.account_id, 0) + 1

    def adopt_static(self, list_id: int, slot: str, account_id: int, addr: int, now: float) -> str:
        """Static merge rule (I5). Returns 'kept', 'adopted' or a refusal reason."""
        if (list_id, slot) in self.bindings:
            return "kept"
        n = self.net_of(addr)
        if n is None:
            return "outside_prefix"
        if not self.in_pool(n):
            return "outside_pool"
        if self.is_excluded(n, now):
            return "excluded"
        got, _r16, ok = self.tagger.decode(addr & ((1 << 64) - 1))
        if not ok or got != list_id:
            return "bad_tag"
        h = self.holds.get(n)
        if h is not None:
            if h.static:
                return "conflict"
            for b in list(h.binds):
                self.release(b, "static_adopt", now)
        nb = Binding(list_id, slot, STATIC, addr, n, account_id, False, now, None, now)
        self._insert(nb, "adopted", now)
        return "adopted"

    # ---- housekeeping --------------------------------------------------------------

    def expire_sticky(self, now: float) -> int:
        heap = self.sticky_heap
        n = 0
        while heap and heap[0][0] <= now:
            _exp, lid, slot = heapq.heappop(heap)
            b = self.bindings.get((lid, slot))
            if b is None or b.kind != STICKY or b.expires_at is None or b.expires_at > now:
                continue  # stale entry (released, converted or extended)
            self.release(b, "expired", now)
            n += 1
        if len(heap) > 2 * self.n_sticky + 4096:
            self.sticky_heap = [
                (b.expires_at, b.list_id, b.slot)
                for b in self.bindings.values()
                if b.kind == STICKY and b.expires_at is not None
            ]
            heapq.heapify(self.sticky_heap)
        pn = self.prev_net
        while pn:
            k, (_net, until) = next(iter(pn.items()))
            if until > now:
                break
            pn.popitem(last=False)
        return n

    def stats(self, now: float) -> dict:
        """O(1) apart from the cool-down count (exclusive /64s hold exactly one binding)."""
        bound_excl = len(self.holds) - len(self.shared_nets)
        bound_shared = self.n_static + self.n_sticky - bound_excl
        same64 = self.same64
        return {
            "sliceSize": self.pool_size(),
            "candidates": len(self.cand),
            "excluded": self.excluded_count(now),
            "free": len(self.free),
            "boundExclusive": bound_excl,
            "boundShared": bound_shared,
            "static": self.n_static,
            "sticky": self.n_sticky,
            "shared64": len(self.shared_nets),
            "sameAccount64": same64,
            "sameAccountEvents": self.same_account_events,
            "scanExcluded": len(self.scan),
            "reserved": len(self.reserved),
            "coolDown": sum(1 for u in self.cooldown.values() if u > now),
        }

    def check_invariants(self, now: float | None = None):
        """Consistency check used by the tests (raises AssertionError)."""
        now = self.clock() if now is None else now
        for n in self.free.items:
            assert n in self.cand.index and n not in self.holds, n
            assert self.in_pool(n) and not self.is_excluded(n, now), n
        for n in self.cand.items:
            assert self.in_pool(n) and not self.is_excluded(n, now), n
        counts = {}
        static_per_acct = {}
        excl_sticky = {}
        for b in self.bindings.values():
            assert b.net in self.holds, b.net
            assert b.net in self.cand.index, b.net
            assert self.net_of(b.addr) == b.net
            assert (b.addr & ((1 << 64) - 1)) >= (1 << 32)
            counts[b.net] = counts.get(b.net, 0) + 1
            if b.kind == STATIC:
                static_per_acct[b.account_id] = static_per_acct.get(b.account_id, 0) + 1
            elif not b.shared:
                excl_sticky[b.account_id] = excl_sticky.get(b.account_id, 0) + 1
        for n, h in self.holds.items():
            assert counts.get(n, 0) == h.n, (n, counts.get(n), h.n)
            assert h.static <= 1, n
            if h.static:
                assert h.n == 1, n
            if not h.shared:
                assert h.n == 1, n
        assert static_per_acct == self.acct_static, (static_per_acct, self.acct_static)
        assert excl_sticky == self.acct_excl_sticky, (excl_sticky, self.acct_excl_sticky)
        sticky_per_acct = {}
        for b in self.bindings.values():
            if b.kind == STICKY:
                sticky_per_acct[b.account_id] = sticky_per_acct.get(b.account_id, 0) + 1
                assert (b.expires_at, b.list_id, b.slot) in self.sticky_heap, b.key()
        assert sticky_per_acct == self.acct_sticky, (sticky_per_acct, self.acct_sticky)
        assert set(self.shared_nets.items) == {n for n, h in self.holds.items() if h.shared}
        same = sum(1 for h in self.holds.values() if any(c > 1 for c in h.accounts.values()))
        assert same == self.same64, (same, self.same64)
        for h in self.holds.values():
            assert h.dups == sum(1 for c in h.accounts.values() if c > 1)
