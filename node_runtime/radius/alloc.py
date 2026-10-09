"""Address allocator: the one allocator of record for the /64s of a per-GB pool.

Pool (amendment A1) = subnet ids lo..hi of the node's routed /48, never ffff
(the node's own /64). Default 0000-fffe.

excluded = /64s held by per-piece:
  - scan    : found by the agent's scan (cfg anchors, ipv6 lists, egress state).
              Shrink guard: additions apply at once; a /64 leaves only after two
              complete scans >= 10 min apart both lack it; an incomplete scan is
              add-only; a push that would remove more than 2 % is refused.
  - reserved: handed to per-piece through reserve_nets; only release_nets frees
              it, at once (A6: no cool-down; the orchestrator keeps the history).
candidates = pool - excluded. Per-GB holds nothing (A8): rotation, sticky,
static, timer and link lines of every customer draw from the candidates and the
same /64 (even the same address) may serve several customers at once.

Addresses (A8, A10, A11, A12). Host part = the I3 tag of the list (Feistel).
  - fresh (per_request, the rotate param): the least recently used of 4 random
    candidates (re-drawn up to 16 times to skip /64s the site refused, A12), a
    random tagged host; nothing stored;
  - per_request with the «липкая сессия» pause (A11): a busy line (new
    connections less than `pause` apart) keeps its address; the first
    connection after a quiet gap, or 120 s after the change was due, gets a new
    one;
  - timer: window w = floor((now - anchor) / ttl); the address is derived from
    (key, list, slot, ttl, w, link epochs); with the pause a busy line switches
    at its first quiet gap (at most 120 s late); the schedule never drifts;
  - link: derived from (key, list, slot, link epochs);
  - static: derived from (key, list, slot) — the same line always gets the same
    address while its /64 is not per-piece's; remembered (and persisted) so the
    orchestrator's mirror sees one add event, moved to the next probe when
    per-piece takes the /64;
  - sticky (a session param, or a ttl param outside timer lists): a random
    candidate (re-drawn up to 8 times to avoid the list's other /64s), kept for
    ttl from the first connection; persisted.
Derived picks probe i = 0, 1, ...: net_i = lo + H(k, kind, list, slot, extra, i)
mod (hi - lo + 1), skipping excluded /64s (static also skips, for up to 64
probes, /64s another static or sticky line of the same list uses). The host
part uses r16 = H_r(k, kind, list, slot, extra, j) for j = 0, 1, ... until the
interface id is >= 2^32; the IPv4 egress index (A7) is H_v4(...) mod N.
H = HMAC-SHA256 (see _derive).
"""

from __future__ import annotations

import heapq
import hmac
import os
import random
import time
from array import array
from collections import OrderedDict, deque

from tag import IID_MIN, Tagger, encrypt

NET_SELF = 0xFFFF
NET_COUNT = 1 << 16
SCAN_CONFIRM_SEC = 600  # two complete scans at least this far apart
SCAN_SHRINK_MAX = 0.02  # refuse a push that removes more than 2 % of scan entries
RESERVE_ROTATED_MIN_AGE = 60  # reserve_nets never returns a /64 used in the last 60 s
RESERVE_MAX = 5000
ROTATE_BEST_OF = 4
AVOID_TRIES = 16  # A12: re-draws to skip /64s the site refused
SPREAD_TRIES = 8  # A8: sticky re-draws to avoid the list's other /64s
SPREAD_PROBES = 64  # A8: static probes that skip the list's other /64s
DERIVE_MAX_PROBES = 4096
STICKY_MAX_DEFER = 120  # A11: PERGB_STICKY_MAX_DEFER_SEC
PREV_NET_TTL = 3600
PREV_NET_MAX = 200_000
MODE_LINE_IDLE = 600  # remembered timer/link/pause lines unused this long (beyond their window) are dropped
# Memory bounds (not customer limits, A8: never a reject): session names are
# customer-chosen, so live sticky sessions are bounded; beyond a bound the
# oldest session (of that account, or the one expiring first node-wide) is
# forgotten and its next connection gets a new address.
MAX_STICKY = 250_000
MAX_STICKY_PER_ACCOUNT = 20_000
MAX_MODE_LINES = 500_000
AVOID_MAX = 200_000  # A12: avoid entries; the soonest-expiring is evicted beyond it
STATIC = "static"
STICKY = "sticky"
TIMER = "timer"
LINK = "link"
PAUSE = "pr"  # per_request line held by the A11 pause

_LABEL_NET = b"netrun-pergb-pick\x00"
_LABEL_R16 = b"netrun-pergb-pick-r\x00"
_LABEL_V4 = b"netrun-pergb-pick-v4\x00"


class AllocError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class CtlRefused(Exception):
    def __init__(self, code: str, **extra):
        super().__init__(code)
        self.code = code
        self.extra = extra


class Line:
    """A remembered address of one line slot (static, sticky, or a timer/link/pause state)."""

    __slots__ = (
        "list_id",
        "slot",
        "kind",
        "addr",
        "net",
        "v4",
        "account_id",
        "created_at",
        "expires_at",
        "last_seen",
        "key",
        "pending_since",
    )

    def __init__(self, list_id, slot, kind, addr, net, v4, account_id, created_at, expires_at=None, key=None):
        self.list_id = list_id
        self.slot = slot
        self.kind = kind
        self.addr = addr
        self.net = net
        self.v4 = v4  # IPv4 egress choice (an index taken mod the number of egress IPv4s)
        self.account_id = account_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_seen = created_at
        self.key = key
        self.pending_since = None


# the old name, kept for callers that build persisted rows
Binding = Line


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


class _Window:
    """Event counts over the last hour in one-minute buckets."""

    __slots__ = ("buckets",)

    def __init__(self):
        self.buckets = {}

    def add(self, now: float, n: int = 1):
        m = int(now // 60)
        self.buckets[m] = self.buckets.get(m, 0) + n
        if len(self.buckets) > 70:
            for k in [k for k in self.buckets if k <= m - 60]:
                del self.buckets[k]

    def total(self, now: float) -> int:
        m = int(now // 60)
        return sum(v for k, v in self.buckets.items() if k > m - 60)


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
        self.reservations = {}  # ref -> [nets]
        self.reservation_at = {}  # ref -> ts
        self.releases = {}  # ref -> (count, at)
        self.scan_missing = {}  # scan-found net -> first complete scan that lacked it
        self.last_scan_id = None
        self.cand = _IndexedSet()
        self.last_used = _u32_array()
        # remembered lines
        self.static = {}  # (list_id, slot) -> Line
        self.sticky = {}  # (list_id, slot) -> Line
        self.mode = {}  # (list_id, slot) -> Line (timer / link / pause states; memory only)
        self.by_list = {}  # list_id -> set of (kind class, slot): kind class in static / sticky / mode
        self.list_nets = {}  # list_id -> {net: count} of its static and sticky lines
        self.net_index = {}  # net -> set of (kind, list_id, slot) of static and sticky lines
        self.sticky_heap = []  # (expires_at, list_id, slot); stale entries are skipped
        self.acct_fifo = {}  # account -> deque of (list_id, slot) of its sticky lines, oldest first
        self.acct_sticky = {}  # account -> live sticky count
        self.max_sticky = MAX_STICKY
        self.max_sticky_per_account = MAX_STICKY_PER_ACCOUNT
        self.max_mode_lines = MAX_MODE_LINES
        self.prev_net = OrderedDict()  # (list_id, slot) -> (net, until), oldest first
        self.evicted = 0
        self.moved = 0
        # A12 smart rotation
        self.avoid = {}  # site -> {net: until}
        self.avoid_n = 0
        self.avoid_heap = []  # (until, site, net); stale entries are skipped
        self.avoid_max = AVOID_MAX
        self.avoid_picks = _Window()
        self.avoid_exhausted = _Window()
        self.exhausted_sites = OrderedDict()  # site -> count (last 100 sites)
        # persistence journal, drained by the engine's flush
        self.dirty_lines = {}  # (kind, list_id, slot) -> Line | None
        self.events = []  # (op, list_id, slot, addr, reason, at)
        self.dirty_nets = set()
        self.dirty_refs = set()

    # ---- configuration -------------------------------------------------------------

    @property
    def configured(self) -> bool:
        return self.prefix is not None and self.tagger is not None

    @property
    def key(self) -> bytes:
        return self.tagger.key

    def configure(self, prefix: int, prefix_str: str, lo: int, hi: int, key: bytes, now: float | None = None):
        """Set the pool. A new prefix or key forgets every line; a smaller pool the outside ones."""
        now = self.clock() if now is None else now
        hi = min(hi, NET_SELF - 1)
        if lo < 0 or lo > hi:
            raise ValueError("bad pool range")
        if self.prefix is not None and prefix != self.prefix:
            self._forget_all("prefix_changed", now)
        elif self.tagger is not None and self.tagger.key != key:
            self._forget_all("key_changed", now)
        self.prefix = prefix
        self.prefix_str = prefix_str
        self.tagger = Tagger(key) if (self.tagger is None or self.tagger.key != key) else self.tagger
        self.lo, self.hi = lo, hi
        for ln in list(self.static.values()) + list(self.sticky.values()):
            if not lo <= ln.net <= hi:
                self.release(ln, "pool_changed", now)
        self.mode.clear()
        for kinds in self.by_list.values():
            for k in [k for k in kinds if k[0] == "mode"]:
                kinds.discard(k)
        self.rebuild(now)

    def _forget_all(self, reason: str, now: float):
        for ln in list(self.static.values()) + list(self.sticky.values()):
            self.release(ln, reason, now)
        self.mode.clear()
        self.by_list = {lid: {k for k in kinds if k[0] != "mode"} for lid, kinds in self.by_list.items()}
        self.by_list = {lid: kinds for lid, kinds in self.by_list.items() if kinds}

    def in_pool(self, net: int) -> bool:
        return self.lo <= net <= self.hi and net != NET_SELF

    def is_excluded(self, net: int, now: float | None = None) -> bool:
        return net in self.scan or net in self.reserved

    def rebuild(self, now: float | None = None):
        cand = [n for n in range(self.lo, self.hi + 1) if n != NET_SELF and not self.is_excluded(n)]
        self.cand = _IndexedSet(cand)

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

    @staticmethod
    def _seed(kind: str, list_id: int, slot: str, extra: str) -> bytes:
        return (
            kind.encode()
            + b"\x00"
            + list_id.to_bytes(4, "big")
            + slot.encode("utf-8")
            + b"\x00"
            + extra.encode("utf-8")
            + b"\x00"
        )

    def _derive(self, kind: str, list_id: int, slot: str, extra: str = "", spread: bool = False) -> int:
        """The deterministic /64 of a line (see the module doc); raises AllocError('capacity')."""
        key = self.key
        seed = _LABEL_NET + self._seed(kind, list_id, slot, extra)
        lo = self.lo
        size = self.hi - lo + 1
        cand = self.cand.index
        mine = self.list_nets.get(list_id) if spread else None
        first_ok = None
        clashes = 0
        for i in range(DERIVE_MAX_PROBES):
            d = hmac.digest(key, seed + i.to_bytes(4, "big"), "sha256")
            n = lo + int.from_bytes(d[:8], "big") % size
            if n not in cand:
                continue
            if mine and mine.get(n):
                if first_ok is None:
                    first_ok = n
                clashes += 1
                if clashes < SPREAD_PROBES:
                    continue
                return first_ok
            return n
        if first_ok is not None:
            return first_ok
        if len(self.cand):  # nearly the whole pool is per-piece's: any candidate
            return self.cand.items[int.from_bytes(hmac.digest(key, seed, "sha256")[:8], "big") % len(self.cand)]
        raise AllocError("capacity")

    def _derive_iid(self, kind: str, list_id: int, slot: str, extra: str = "") -> int:
        key = self.key
        seed = _LABEL_R16 + self._seed(kind, list_id, slot, extra)
        for j in range(64):
            d = hmac.digest(key, seed + j.to_bytes(4, "big"), "sha256")
            iid = encrypt(key, list_id, (d[0] << 8) | d[1])
            if iid >= IID_MIN:
                return iid
        return self.tagger.make_iid(list_id, self.rng.getrandbits)  # practically unreachable (2^-2048)

    def _derive_v4(self, kind: str, list_id: int, slot: str, extra: str = "") -> int:
        d = hmac.digest(self.key, _LABEL_V4 + self._seed(kind, list_id, slot, extra), "sha256")
        return int.from_bytes(d[:4], "big")

    def derived_line(self, kind: str, list_id: int, slot: str, extra: str = "", spread: bool = False):
        """(net, addr, v4) of a derived line."""
        n = self._derive(kind, list_id, slot, extra, spread)
        return (
            n,
            self.addr_of(n, self._derive_iid(kind, list_id, slot, extra)),
            self._derive_v4(kind, list_id, slot, extra),
        )

    # ---- excluded transitions ------------------------------------------------------

    def _refresh_net(self, net: int, now: float):
        """Re-derive the candidate membership of one /64 after an excluded-source change."""
        self.dirty_nets.add(net)
        if not self.in_pool(net):
            return
        if self.is_excluded(net):
            if net in self.cand:
                self.cand.discard(net)
                self._move_off(net, now)
        elif net not in self.cand:
            self.cand.add(net)

    def _move_off(self, net: int, now: float):
        """Per-piece took this /64: static lines move to their next probe, sticky ones are forgotten."""
        for kind, lid, slot in list(self.net_index.get(net, ())):
            if kind == STATIC:
                ln = self.static.get((lid, slot))
                if ln is None:
                    continue
                self._unindex(ln)
                old = ln.addr
                try:
                    n, addr, v4 = self.derived_line(STATIC, lid, slot, "", spread=True)
                except AllocError:
                    self.events.append(("release", lid, slot, old, "excluded", now))
                    self._drop(ln)
                    continue
                ln.net, ln.addr, ln.v4 = n, addr, v4
                self._index(ln)
                self.dirty_lines[(STATIC, lid, slot)] = ln
                self.events.append(("release", lid, slot, old, "excluded", now))
                self.events.append(("add", lid, slot, addr, "moved", now))
                self.moved += 1
            else:
                ln = self.sticky.get((lid, slot))
                if ln is not None:
                    self.release(ln, "excluded", now)

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

    def excluded_count(self, now: float | None = None) -> int:
        return self.pool_size() - len(self.cand) if self.prefix is not None else len(self.scan)

    def reserve(self, count: int, ref: str, now: float, min_free: int, force: bool = False):
        """reserve_nets: count /64s for per-piece, idempotent per ref.

        Random candidates not used by rotation in the last 60 s, preferring /64s no
        remembered per-GB line sits on (A8: per-GB holds nothing, so this is only
        to spare a static line a move)."""
        if ref in self.reservations:
            nets = self.reservations[ref]
            if len(nets) != count:
                raise CtlRefused("ref_conflict", nets=list(nets))
            return list(nets)
        if not 1 <= count <= RESERVE_MAX:
            raise CtlRefused("bad_request", detail="count must be 1..%d" % RESERVE_MAX)
        if not self.configured:
            raise CtlRefused("not_ready")
        cand = self.cand
        if len(cand) - count < min_free and not force:
            raise CtlRefused("capacity", free=len(cand), minFree=min_free)
        too_recent = now - RESERVE_ROTATED_MIN_AGE
        last_used = self.last_used
        lines = self.net_index
        picked = []
        chosen = set()
        while len(picked) < count:
            best = best_key = None
            for _try in range(64):
                n = cand.pick(self.rng)
                if n in chosen or last_used[n] > too_recent:
                    continue
                k = (len(lines.get(n, ())), last_used[n])
                if best is None or k < best_key:
                    best, best_key = n, k
                if _try >= 7 and best_key[0] == 0:
                    break
            if best is None:
                # most candidates were used in the last minute: the oldest eligible ones
                eligible = sorted(
                    (n for n in cand.items if n not in chosen and last_used[n] <= too_recent),
                    key=lambda n: (len(lines.get(n, ())), last_used[n]),
                )
                need = count - len(picked)
                if len(eligible) < need:
                    raise CtlRefused("capacity", free=len(cand), eligible=len(eligible), detail="recently_used")
                picked.extend(eligible[:need])
                break
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
        """release_nets: per-piece hands reserved /64s back; they rejoin the pool at once (A6).

        Released by net (the ref is a record of the call, idempotent per ref); a /64
        that is not reserved is a no-op (a scan-found one leaves through the scans)."""
        if ref in self.releases:
            return self.releases[ref][0]
        count = 0
        for raw in nets:
            n = int(raw)
            if not 0 <= n < NET_SELF or n not in self.reserved:
                continue
            count += 1
            del self.reserved[n]
            self.reserved_at.pop(n, None)
            self._refresh_net(n, now)
        self.releases[ref] = (count, now)
        self.dirty_refs.add("rel:" + ref)
        return count

    # ---- line bookkeeping ----------------------------------------------------------

    def _index(self, ln: Line):
        self.net_index.setdefault(ln.net, set()).add((ln.kind, ln.list_id, ln.slot))
        m = self.list_nets.setdefault(ln.list_id, {})
        m[ln.net] = m.get(ln.net, 0) + 1

    def _unindex(self, ln: Line):
        s = self.net_index.get(ln.net)
        if s is not None:
            s.discard((ln.kind, ln.list_id, ln.slot))
            if not s:
                del self.net_index[ln.net]
        m = self.list_nets.get(ln.list_id)
        if m is not None:
            c = m.get(ln.net, 0) - 1
            if c > 0:
                m[ln.net] = c
            else:
                m.pop(ln.net, None)
                if not m:
                    del self.list_nets[ln.list_id]

    def _table(self, kind):
        return self.static if kind == STATIC else self.sticky if kind == STICKY else self.mode

    @staticmethod
    def _cls(kind):
        return kind if kind in (STATIC, STICKY) else "mode"

    def _insert(self, ln: Line, event_reason: str | None, now: float):
        key = (ln.list_id, ln.slot)
        self._table(ln.kind)[key] = ln
        self.by_list.setdefault(ln.list_id, set()).add((self._cls(ln.kind), ln.slot))
        if ln.kind in (STATIC, STICKY):
            self._index(ln)
            self.dirty_lines[(ln.kind, ln.list_id, ln.slot)] = ln
        if ln.kind == STICKY:
            heapq.heappush(self.sticky_heap, (ln.expires_at, ln.list_id, ln.slot))
            live = self.acct_sticky.get(ln.account_id, 0) + 1
            self.acct_sticky[ln.account_id] = live
            dq = self.acct_fifo.setdefault(ln.account_id, deque())
            dq.append((ln.created_at, key))
            if len(dq) > 2 * live + 1024:  # drop the entries of sessions already gone
                sticky = self.sticky
                self.acct_fifo[ln.account_id] = deque(
                    (c, k) for c, k in dq if k in sticky and sticky[k].created_at == c
                )
        if ln.kind == STATIC and event_reason:
            self.events.append(("add", ln.list_id, ln.slot, ln.addr, event_reason, now))

    def _drop(self, ln: Line):
        """Forget a line (no event)."""
        key = (ln.list_id, ln.slot)
        table = self._table(ln.kind)
        if table.get(key) is not ln:
            return False
        del table[key]
        kinds = self.by_list.get(ln.list_id)
        if kinds is not None:
            kinds.discard((self._cls(ln.kind), ln.slot))
            if not kinds:
                del self.by_list[ln.list_id]
        if ln.kind in (STATIC, STICKY):
            self._unindex(ln)
            self.dirty_lines[(ln.kind, ln.list_id, ln.slot)] = None
        if ln.kind == STICKY:
            c = self.acct_sticky.get(ln.account_id, 0) - 1
            if c > 0:
                self.acct_sticky[ln.account_id] = c
            else:
                self.acct_sticky.pop(ln.account_id, None)
                self.acct_fifo.pop(ln.account_id, None)
        return True

    def release(self, ln: Line, reason: str, now: float):
        if not self._drop(ln):
            return
        if ln.kind == STATIC:
            self.events.append(("release", ln.list_id, ln.slot, ln.addr, reason, now))
        elif ln.kind == STICKY and len(self.prev_net) < PREV_NET_MAX:
            key = (ln.list_id, ln.slot)
            self.prev_net[key] = (ln.net, now + PREV_NET_TTL)
            self.prev_net.move_to_end(key)  # insertion order = expiry order

    def release_list(self, list_id: int, reason: str, now: float) -> int:
        kinds = self.by_list.get(list_id)
        if not kinds:
            return 0
        n = 0
        for cls, slot in list(kinds):
            table = self.static if cls == STATIC else self.sticky if cls == STICKY else self.mode
            ln = table.get((list_id, slot))
            if ln is not None:
                self.release(ln, reason, now)
                n += 1
        return n

    def forget_mode_lines(self, list_id: int):
        """The list's mode or epochs changed: its timer/link/pause states are recomputed."""
        kinds = self.by_list.get(list_id)
        if not kinds:
            return
        for _cls, slot in [k for k in kinds if k[0] == "mode"]:
            ln = self.mode.get((list_id, slot))
            if ln is not None:
                self._drop(ln)

    def load_line(self, ln: Line, now: float) -> bool:
        """Re-insert a persisted static or sticky line at start-up (no events). False = dropped."""
        key = (ln.list_id, ln.slot)
        if ln.kind not in (STATIC, STICKY) or key in self._table(ln.kind):
            return False
        if not self.in_pool(ln.net) or self.is_excluded(ln.net) or self.net_of(ln.addr) != ln.net:
            return False
        if (ln.addr & ((1 << 64) - 1)) < IID_MIN:
            return False
        if ln.kind == STICKY and (ln.expires_at is None or ln.expires_at <= now):
            return False
        self._table(ln.kind)[key] = ln
        self.by_list.setdefault(ln.list_id, set()).add((ln.kind, ln.slot))
        self._index(ln)
        if ln.kind == STICKY:
            self.sticky_heap.append((ln.expires_at, ln.list_id, ln.slot))
            self.acct_fifo.setdefault(ln.account_id, deque()).append((ln.created_at, key))
            self.acct_sticky[ln.account_id] = self.acct_sticky.get(ln.account_id, 0) + 1
        return True

    def load_rows(self, rows, now: float) -> list:
        """Bulk load_line for start-up (READY within 1 s with cap-sized state): rows are
        (list_id, slot, kind, addr16, net, v4, account_id, created, expires, last_used).
        Returns the rows that were dropped."""
        dropped = []
        static, sticky = self.static, self.sticky
        by_list, net_index, list_nets = self.by_list, self.net_index, self.list_nets
        heap, fifo, acct_sticky = self.sticky_heap, self.acct_fifo, self.acct_sticky
        lo, hi = self.lo, self.hi
        scan, reserved = self.scan, self.reserved
        top = self.prefix >> 80 if self.prefix is not None else None
        mask64 = (1 << 64) - 1
        for row in rows:
            list_id, slot, kind, addr16, net, v4, acct, created, expires, last_used = row
            addr = int.from_bytes(addr16, "big")
            if kind == STATIC:
                table = static
            elif kind == STICKY:
                table = sticky
                if expires is None or expires <= now:
                    dropped.append(row)
                    continue
            else:
                dropped.append(row)
                continue
            key = (list_id, slot)
            if (
                key in table
                or not lo <= net <= hi
                or net == NET_SELF
                or net in scan
                or net in reserved
                or addr >> 80 != top
                or (addr >> 64) & 0xFFFF != net
                or (addr & mask64) < IID_MIN
            ):
                dropped.append(row)
                continue
            ln = Line(list_id, slot, kind, addr, net, v4, acct, created, expires)
            ln.last_seen = last_used or created
            table[key] = ln
            kinds = by_list.get(list_id)
            if kinds is None:
                kinds = by_list[list_id] = set()
            kinds.add((kind, slot))
            s = net_index.get(net)
            if s is None:
                s = net_index[net] = set()
            s.add((kind, list_id, slot))
            m = list_nets.get(list_id)
            if m is None:
                m = list_nets[list_id] = {}
            m[net] = m.get(net, 0) + 1
            if table is sticky:
                heap.append((expires, list_id, slot))
                dq = fifo.get(acct)
                if dq is None:
                    dq = fifo[acct] = deque()
                dq.append((created, key))
                acct_sticky[acct] = acct_sticky.get(acct, 0) + 1
        return dropped

    def loaded(self):
        """End of start-up loading: the per-account FIFOs in creation order."""
        heapq.heapify(self.sticky_heap)
        for aid, dq in self.acct_fifo.items():
            self.acct_fifo[aid] = deque(sorted(dq))

    # ---- picks ---------------------------------------------------------------------

    def _draw(self) -> int:
        """The least recently used of a few random candidates."""
        cand = self.cand
        rng = self.rng
        last_used = self.last_used
        n = cand.pick(rng)
        for _ in range(ROTATE_BEST_OF - 1):
            c = cand.pick(rng)
            if last_used[c] < last_used[n]:
                n = c
        return n

    def pick_random(self, now: float, site: str | None = None) -> int:
        """A fresh /64 for a per_request pick: the least recently used of a few random
        candidates; A12: candidates this site refused are skipped, up to 16 draws."""
        cand = self.cand
        if not len(cand):
            raise AllocError("capacity")
        av = self.avoid.get(site) if site is not None else None
        if not av:
            n = self._draw()
        else:
            rng = self.rng
            last_used = self.last_used
            skipped = False
            n = None
            for _ in range(AVOID_TRIES):
                best = None
                for _ in range(ROTATE_BEST_OF):
                    c = cand.pick(rng)
                    until = av.get(c)
                    if until is not None and until > now:
                        skipped = True
                        continue
                    if best is None or last_used[c] < last_used[best]:
                        best = c
                if best is not None:
                    n = best
                    break
            if n is None:  # the site refuses (nearly) everything: take a draw anyway
                n = self._draw()
                self.avoid_exhausted.add(now)
                ex = self.exhausted_sites
                ex[site] = ex.pop(site, 0) + 1
                while len(ex) > 100:
                    ex.popitem(last=False)
            elif skipped:
                self.avoid_picks.add(now)
        self.last_used[n] = int(now)
        return n

    def rotate_addr(self, list_id: int, now: float, site: str | None = None) -> int:
        """A fresh tagged address (per_request, the rotate param, the probe)."""
        return self.new_addr(self.pick_random(now, site), list_id)

    def static_line(self, list_id: int, slot: str, account_id: int, now: float) -> Line:
        key = (list_id, slot)
        ln = self.static.get(key)
        if ln is not None:
            ln.last_seen = now
            return ln
        n, addr, v4 = self.derived_line(STATIC, list_id, slot, "", spread=True)
        ln = Line(list_id, slot, STATIC, addr, n, v4, account_id, now)
        self._insert(ln, "first_use", now)
        return ln

    def sticky_line(self, list_id: int, slot: str, account_id: int, ttl: int, now: float) -> Line:
        key = (list_id, slot)
        ln = self.sticky.get(key)
        avoid = None
        if ln is not None:
            new_exp = ln.created_at + ttl
            if ln.expires_at > now and new_exp > now:
                if new_exp != ln.expires_at:
                    ln.expires_at = new_exp
                    self.dirty_lines[(STICKY, list_id, slot)] = ln
                    heapq.heappush(self.sticky_heap, (new_exp, list_id, slot))
                ln.last_seen = now
                return ln
            avoid = ln.net
            self.release(ln, "expired", now)
        else:
            prev = self.prev_net.get(key)
            if prev is not None and prev[1] > now:
                avoid = prev[0]
        cand = self.cand
        if not len(cand):
            raise AllocError("capacity")
        mine = self.list_nets.get(list_id)
        n = None
        for _ in range(SPREAD_TRIES):
            c = cand.pick(self.rng)
            if c == avoid and len(cand) > 1:
                continue
            n = c
            if not mine or not mine.get(c):
                break
        if n is None:
            n = cand.pick(self.rng)
        ln = Line(
            list_id, slot, STICKY, self.new_addr(n, list_id), n, self.rng.getrandbits(32), account_id, now, now + ttl
        )
        self._insert(ln, None, now)
        self._bound_sticky(ln, now)
        return ln

    def _bound_sticky(self, fresh: Line, now: float):
        """Memory bounds: forget the account's oldest session, or the one expiring first."""
        aid = fresh.account_id
        if self.acct_sticky.get(aid, 0) > self.max_sticky_per_account:
            dq = self.acct_fifo.get(aid)
            while dq:
                created, k = dq.popleft()
                old = self.sticky.get(k)
                if old is not None and old is not fresh and old.account_id == aid and old.created_at == created:
                    self.release(old, "evicted", now)
                    self.evicted += 1
                    break
        while len(self.sticky) > self.max_sticky and self.sticky_heap:
            _exp, lid, slot = heapq.heappop(self.sticky_heap)
            old = self.sticky.get((lid, slot))
            if old is None or old is fresh or old.expires_at != _exp:
                continue
            self.release(old, "evicted", now)
            self.evicted += 1

    def _mode_line(self, list_id, slot, kind, key, account_id, now, extra, site=None) -> Line:
        if kind == PAUSE:
            n = self.pick_random(now, site)
            ln = Line(
                list_id, slot, PAUSE, self.new_addr(n, list_id), n, self.rng.getrandbits(32), account_id, now, key=key
            )
        else:
            n, addr, v4 = self.derived_line(kind, list_id, slot, extra)
            ln = Line(list_id, slot, kind, addr, n, v4, account_id, now, key=key)
        old = self.mode.get((list_id, slot))
        if old is not None:
            self._drop(old)
        elif len(self.mode) >= self.max_mode_lines:
            self.prune_mode_lines(now, force=True)
        self._insert(ln, None, now)
        return ln

    def timer_line(self, list_id, slot, account_id, ttl, anchor, epochs, now, pause=None) -> Line:
        """Timer mode (A10) with the optional A11 pause: busy lines switch at their first quiet gap."""
        w = int((now - anchor) // ttl)
        key = (TIMER, ttl, w) + tuple(epochs)
        ln = self.mode.get((list_id, slot))
        if ln is not None and ln.kind == TIMER:
            if ln.key == key:
                if ln.net in self.cand.index:
                    ln.last_seen = now
                    return ln
            elif (
                pause
                and ln.key[1] == ttl
                and ln.key[3:] == key[3:]  # a link change applies at once, never postponed
                and now - ln.last_seen < pause
                and ln.net in self.cand.index
            ):
                due = anchor + (ln.key[2] + 1) * ttl  # the tick that ended the window it uses
                if ln.pending_since is None:
                    ln.pending_since = min(due, now)
                if now - ln.pending_since < STICKY_MAX_DEFER:
                    ln.last_seen = now
                    return ln
        extra = "%d:%d:%s" % (ttl, w, ":".join(str(e) for e in epochs))
        return self._mode_line(list_id, slot, TIMER, key, account_id, now, extra)

    def link_line(self, list_id, slot, account_id, epochs, now) -> Line:
        key = (LINK,) + tuple(epochs)
        ln = self.mode.get((list_id, slot))
        if ln is not None and ln.kind == LINK and ln.key == key and ln.net in self.cand.index:
            ln.last_seen = now
            return ln
        return self._mode_line(list_id, slot, LINK, key, account_id, now, ":".join(str(e) for e in epochs))

    def pause_line(self, list_id, slot, account_id, pause, now, site=None) -> Line:
        """per_request with the A11 pause: a busy line keeps its address (at most 120 s past due)."""
        ln = self.mode.get((list_id, slot))
        if ln is not None and ln.kind == PAUSE and now - ln.last_seen < pause and ln.net in self.cand.index:
            if ln.pending_since is None:
                ln.pending_since = now
            if now - ln.pending_since < STICKY_MAX_DEFER:
                ln.last_seen = now
                return ln
        return self._mode_line(list_id, slot, PAUSE, (PAUSE,), account_id, now, "", site)

    def adopt_static(self, list_id: int, slot: str, account_id: int, addr: int, now: float) -> str:
        """Static merge rule (I5): 'kept', 'adopted' or a refusal reason."""
        ln = self.static.get((list_id, slot))
        if ln is not None:
            return "kept"
        n = self.net_of(addr)
        if n is None:
            return "outside_prefix"
        if not self.in_pool(n):
            return "outside_pool"
        if self.is_excluded(n):
            return "excluded"
        got, _r16, ok = self.tagger.decode(addr & ((1 << 64) - 1))
        if not ok or got != list_id or (addr & ((1 << 64) - 1)) < IID_MIN:
            return "bad_tag"
        ln = Line(list_id, slot, STATIC, addr, n, self._derive_v4(STATIC, list_id, slot), account_id, now)
        self._insert(ln, "adopted", now)
        return "adopted"

    # ---- A12 avoid set ---------------------------------------------------------------

    def avoid_apply(self, entries, removed, full: bool, now: float) -> int:
        """entries [(net, site, until)], removed [(net, site)]; full replaces the set."""
        if full:
            self.avoid = {}
            self.avoid_n = 0
            self.avoid_heap = []
        for net, site in removed:
            m = self.avoid.get(site)
            if m is not None and m.pop(net, None) is not None:
                self.avoid_n -= 1
                if not m:
                    del self.avoid[site]
        for net, site, until in entries:
            if until <= now or not self.in_pool(net):
                continue
            m = self.avoid.setdefault(site, {})
            if net not in m:
                self.avoid_n += 1
            m[net] = until
            heapq.heappush(self.avoid_heap, (until, site, net))
        self._avoid_trim(now)
        return self.avoid_n

    def _avoid_trim(self, now: float):
        heap = self.avoid_heap
        while heap and (heap[0][0] <= now or self.avoid_n > self.avoid_max):
            until, site, net = heapq.heappop(heap)
            m = self.avoid.get(site)
            if m is None or m.get(net) != until:
                continue  # stale (removed or extended)
            del m[net]
            self.avoid_n -= 1
            if not m:
                del self.avoid[site]
        if len(heap) > 2 * self.avoid_n + 4096:
            self.avoid_heap = [(u, s, n) for s, m in self.avoid.items() for n, u in m.items()]
            heapq.heapify(self.avoid_heap)

    def avoid_stats(self, now: float) -> dict:
        return {
            "avoidedPairs": self.avoid_n,
            "sites": len(self.avoid),
            "picksAvoided1h": self.avoid_picks.total(now),
            "exhausted1h": self.avoid_exhausted.total(now),
            "exhaustedSites": dict(list(self.exhausted_sites.items())[-10:]),
        }

    # ---- housekeeping --------------------------------------------------------------

    def expire_sticky(self, now: float) -> int:
        heap = self.sticky_heap
        n = 0
        while heap and heap[0][0] <= now:
            _exp, lid, slot = heapq.heappop(heap)
            ln = self.sticky.get((lid, slot))
            if ln is None or ln.expires_at > now:
                continue  # stale entry (released or extended)
            self.release(ln, "expired", now)
            n += 1
        if len(heap) > 2 * len(self.sticky) + 4096:
            self.sticky_heap = [(ln.expires_at, ln.list_id, ln.slot) for ln in self.sticky.values()]
            heapq.heapify(self.sticky_heap)
        pn = self.prev_net
        while pn:
            k, (_net, until) = next(iter(pn.items()))
            if until > now:
                break
            pn.popitem(last=False)
        self._avoid_trim(now)
        return n

    def prune_mode_lines(self, now: float, force: bool = False) -> int:
        """Drop timer/link/pause states nobody used lately (they are recomputed on use)."""
        idle = MODE_LINE_IDLE
        drop = []
        for ln in self.mode.values():
            age = now - ln.last_seen
            if ln.kind == PAUSE:
                if age > STICKY_MAX_DEFER + 60:
                    drop.append(ln)
            elif ln.kind == TIMER:
                if age > ln.key[1] + idle:
                    drop.append(ln)
            elif age > idle:
                drop.append(ln)
        if force and not drop and self.mode:
            drop = sorted(self.mode.values(), key=lambda x: x.last_seen)[: max(1, len(self.mode) // 10)]
        for ln in drop:
            self._drop(ln)
        return len(drop)

    def stats(self, now: float) -> dict:
        n_static, n_sticky = len(self.static), len(self.sticky)
        return {
            "sliceSize": self.pool_size(),
            "candidates": len(self.cand),
            "excluded": self.excluded_count(now),
            # A8: nothing is reserved for a per-GB customer, the pool is shared
            "free": len(self.cand),
            "boundExclusive": 0,
            "boundShared": n_static + n_sticky,
            "static": n_static,
            "sticky": n_sticky,
            "shared64": len(self.net_index),
            "sameAccount64": 0,
            "lines": len(self.mode),
            "stickyEvicted": self.evicted,
            "staticMoved": self.moved,
            "scanExcluded": len(self.scan),
            "reserved": len(self.reserved),
            "coolDown": 0,
        }

    def check_invariants(self, now: float | None = None):
        """Consistency check used by the tests (raises AssertionError)."""
        for n in self.cand.items:
            assert self.in_pool(n) and not self.is_excluded(n), n
        assert len(self.cand) == self.pool_size() - sum(
            1 for n in set(self.scan) | set(self.reserved) if self.in_pool(n)
        )
        idx = {}
        per_list = {}
        for table, kind in ((self.static, STATIC), (self.sticky, STICKY)):
            for (lid, slot), ln in table.items():
                assert ln.kind == kind and ln.list_id == lid and ln.slot == slot
                assert ln.net in self.cand.index, (kind, ln.net)
                assert self.net_of(ln.addr) == ln.net
                assert (ln.addr & ((1 << 64) - 1)) >= IID_MIN
                assert self.tagger.list_of(ln.addr & ((1 << 64) - 1)) == lid
                idx.setdefault(ln.net, set()).add((kind, lid, slot))
                m = per_list.setdefault(lid, {})
                m[ln.net] = m.get(ln.net, 0) + 1
                assert (kind, slot) in self.by_list.get(lid, ())
        assert idx == self.net_index, (idx, self.net_index)
        assert per_list == self.list_nets
        counts = {}
        for ln in self.sticky.values():
            counts[ln.account_id] = counts.get(ln.account_id, 0) + 1
            assert (ln.expires_at, ln.list_id, ln.slot) in self.sticky_heap
        assert counts == self.acct_sticky, (counts, self.acct_sticky)
        for lid, slot in self.mode:
            assert ("mode", slot) in self.by_list.get(lid, ())
        for lid, kinds in self.by_list.items():
            for cls, slot in kinds:
                table = self.static if cls == STATIC else self.sticky if cls == STICKY else self.mode
                assert (lid, slot) in table, (lid, cls, slot)
        assert self.avoid_n == sum(len(m) for m in self.avoid.values())
