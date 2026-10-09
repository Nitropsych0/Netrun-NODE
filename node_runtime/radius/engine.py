"""netrun-radius engine: in-memory state, the Access-Request path and the ctl operations.

Request path (plan §3.2):
  decode -> NAS-Port in [base, base+count) -> username (I1) -> probe? -> list, password,
  list status -> account state / expiry / local block -> deadman -> admission ->
  IPv4 family + IPv4 admission -> near-limit reservation -> mode/slot -> address.
Every refusal is a plain Access-Reject; the reason is counted per node and kept
per list (D17). Binding changes are queued for the writer thread.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from array import array

import proto
import username as uname
from alloc import STATIC, Allocator, AllocError, Binding, CtlRefused
from state import EVENT_RETENTION_SEC, Batch, log

REASONS = ("bad_login", "bad_params", "list_off", "account_off", "quota", "capacity", "static_cap")
ACCOUNT_STATES = ("active", "blocked", "released")
LIST_STATUSES = ("active", "blocked", "deleted")
MODES = ("rotate", "sticky", "static")
FAMILIES = ("dualstack", "ipv6_only")

DEFAULT_STATIC_CAP = 100
DEFAULT_STICKY_EXCL_CAP = 2000
DEFAULT_STATIC_PCT = 5.0
DEFAULT_STICKY_PCT = 15.0
DEFAULT_LOGDUMP = 262144
SPLICE_CHUNK = 65536
PROBE_RATE = 2.0  # probe Accepts per second (burst 2)
LAT_SAMPLES = 8192
REF_RETENTION_SEC = 7 * 86400
_LOGIN_ID_RE = re.compile(r"[a-z0-9]{5,12}\Z")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")


def _env_num(env, name, default, cast=float):
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        return cast(raw)
    except ValueError:
        log("ignoring bad %s=%r" % (name, raw))
        return default


def _bad(detail: str):
    return CtlRefused("bad_request", detail=detail)


def _int(d, key, lo=None, hi=None, default=None, required=True):
    v = d.get(key, default) if isinstance(d, dict) else default
    if v is None:
        if required:
            raise _bad("%s is required" % key)
        return None
    if isinstance(v, bool):
        raise _bad("%s must be an integer" % key)
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        v = int(v)
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    if not isinstance(v, int):
        raise _bad("%s must be an integer" % key)
    if (lo is not None and v < lo) or (hi is not None and v > hi):
        raise _bad("%s out of range" % key)
    return v


def _num(d, key, default=None):
    v = d.get(key, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise _bad("%s must be a number" % key)
    return float(v)


def _bool(d, key, default=False):
    v = d.get(key, default)
    if v is None:
        return default
    if not isinstance(v, bool):
        raise _bad("%s must be a boolean" % key)
    return v


def _subnet_id(v) -> int:
    if isinstance(v, bool):
        raise _bad("subnet id")
    if isinstance(v, str):
        v = int(v, 16)
    if not isinstance(v, int) or not 0 <= v <= 0xFFFF:
        raise _bad("subnet id out of range")
    return v


class Facts:
    __slots__ = (
        "raw",
        "base",
        "count",
        "geo",
        "family",
        "egress_v4",
        "egress_v4_str",
        "prefix",
        "prefix_str",
        "lo",
        "hi",
        "key",
        "probe_salt",
        "probe_hash",
        "canary",
        "static_pct",
        "sticky_pct",
        "logdump",
        "l_prime",
        "min_free_perpiece",
    )

    @classmethod
    def parse(cls, d: dict, env=None) -> Facts:
        env = os.environ if env is None else env
        if not isinstance(d, dict):
            raise _bad("facts must be an object")
        f = cls()
        f.raw = d
        f.base = _int(d, "base", 1, 65535)
        f.count = _int(d, "count", 1, 65535)
        if f.base + f.count - 1 > 65535:
            raise _bad("base+count beyond 65535")
        geo = d.get("geo")
        if geo is not None and (not isinstance(geo, str) or not re.match(r"[A-Za-z]{2}\Z", geo)):
            raise _bad("geo must be a 2-letter code")
        f.geo = geo.lower() if geo else None
        f.family = d.get("family") or "dualstack"
        if f.family not in FAMILIES:
            raise _bad("family")
        ev4 = d.get("egressIpv4")
        if ev4:
            try:
                a = ipaddress.IPv4Address(ev4)
            except (ipaddress.AddressValueError, ValueError):
                raise _bad("egressIpv4") from None
            f.egress_v4, f.egress_v4_str = a.packed, str(a)
        else:
            f.egress_v4, f.egress_v4_str = None, None
        try:
            net = ipaddress.IPv6Network(d.get("prefix"), strict=True)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError, TypeError):
            raise _bad("prefix must be an IPv6 /48") from None
        if net.prefixlen != 48:
            raise _bad("prefix must be an IPv6 /48")
        f.prefix, f.prefix_str = int(net.network_address), str(net)
        sub = d.get("subnets", [0, 0xFFFE])
        if isinstance(sub, str):
            sub = sub.split("-")
        if not isinstance(sub, (list, tuple)) or len(sub) != 2:
            raise _bad("subnets must be [lo, hi]")
        try:
            f.lo, f.hi = _subnet_id(sub[0]), min(_subnet_id(sub[1]), 0xFFFE)
        except ValueError:
            raise _bad("subnets") from None
        if f.lo > f.hi:
            raise _bad("subnets lo > hi")
        try:
            key = base64.b64decode(d.get("addrKey") or "", validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise _bad("addrKey must be base64") from None
        if len(key) != 32:
            raise _bad("addrKey must be 32 bytes")
        f.key = key
        f.probe_salt = f.probe_hash = None
        f.canary = frozenset()
        probe = d.get("probe")
        if probe is not None:
            if not isinstance(probe, dict):
                raise _bad("probe")
            salt, phash = probe.get("pwSalt"), probe.get("pwHash")
            if not (isinstance(salt, str) and _HEX_RE.match(salt) and isinstance(phash, str) and len(phash) == 64):
                raise _bad("probe pwSalt/pwHash")
            try:
                f.probe_salt, f.probe_hash = bytes.fromhex(salt), bytes.fromhex(phash)
            except ValueError:
                raise _bad("probe pwHash") from None
            canary = set()
            for item in probe.get("canary") or []:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise _bad("canary entries are [ip, port]")
                try:
                    ip = ipaddress.ip_address(item[0])
                except ValueError:
                    raise _bad("canary ip") from None
                port = _int({"p": item[1]}, "p", 1, 65535)
                canary.add((6 if ip.version == 6 else 4, ip.packed, port))
            f.canary = frozenset(canary)
        res = d.get("reserves") or {}
        if not isinstance(res, dict):
            raise _bad("reserves")
        f.static_pct = _num(res, "staticPct", DEFAULT_STATIC_PCT)
        f.sticky_pct = _num(res, "stickyPct", DEFAULT_STICKY_PCT)
        f.logdump = _int(d, "logdumpBytes", 0, 1 << 40, default=DEFAULT_LOGDUMP)
        f.l_prime = f.logdump + SPLICE_CHUNK
        env_min = _env_num(env, "PERGB_MIN_FREE64_FOR_PERPIECE", 5000, int)
        f.min_free_perpiece = _int(d, "minFree64ForPerpiece", 0, 65535, default=env_min)
        return f


class Account:
    __slots__ = ("id", "state", "expires_at", "limit", "static_cap", "sticky_excl_cap", "trial", "local_blocked")

    @classmethod
    def parse(cls, d) -> Account:
        if not isinstance(d, dict):
            raise _bad("account must be an object")
        a = cls()
        a.id = _int(d, "id", 0)
        a.state = d.get("state")
        if a.state not in ACCOUNT_STATES:
            raise _bad("account state")
        a.expires_at = _num(d, "expiresAt")
        lim = d.get("limit")
        if lim is not None and not isinstance(lim, dict):
            raise _bad("account limit")
        a.limit = lim
        a.static_cap = _int(d, "staticCap", 0, default=DEFAULT_STATIC_CAP)
        a.sticky_excl_cap = _int(d, "stickyExclCap", 0, default=DEFAULT_STICKY_EXCL_CAP)
        a.trial = _bool(d, "trial", False)
        a.local_blocked = False
        return a

    @classmethod
    def from_row(cls, row) -> Account:
        a = cls()
        a.id, a.state, a.expires_at, limit_json, a.static_cap, a.sticky_excl_cap, trial, lb = row
        a.limit = json.loads(limit_json) if limit_json else None
        a.trial, a.local_blocked = bool(trial), bool(lb)
        return a

    def row(self):
        return (
            self.id,
            self.state,
            self.expires_at,
            json.dumps(self.limit, sort_keys=True) if self.limit is not None else None,
            self.static_cap,
            self.sticky_excl_cap,
            int(self.trial),
            int(self.local_blocked),
        )

    def view(self) -> dict:
        exp = self.expires_at
        return {
            "id": self.id,
            "state": self.state,
            "expiresAt": int(exp) if exp is not None and float(exp).is_integer() else exp,
            "limit": self.limit,
            "staticCap": self.static_cap,
            "stickyExclCap": self.sticky_excl_cap,
            "trial": self.trial,
            "localBlocked": self.local_blocked,
        }


class PList:
    __slots__ = (
        "id",
        "login",
        "account_id",
        "pw_salt",
        "pw_hash",
        "pw_salt_hex",
        "pw_hash_hex",
        "pw_rev",
        "status",
        "mode",
        "ttl",
    )

    @classmethod
    def parse(cls, d) -> PList:
        if not isinstance(d, dict):
            raise _bad("list must be an object")
        p = cls()
        p.id = _int(d, "id", 0, 0xFFFFFFFF)
        login = d.get("login")
        if not isinstance(login, str):
            raise _bad("list login")
        login = login.strip().lower()
        if not login.startswith("netrun-"):
            login = "netrun-" + login
        lid = login[len("netrun-") :]
        if not _LOGIN_ID_RE.match(lid) or lid.startswith("svc"):
            raise _bad("list login %r" % login)
        p.login = login
        p.account_id = _int(d, "accountId", 0)
        salt, phash = d.get("pwSalt"), d.get("pwHash")
        if not (isinstance(salt, str) and _HEX_RE.match(salt)):
            raise _bad("pwSalt")
        if not (isinstance(phash, str) and len(phash) == 64 and _HEX_RE.match(phash)):
            raise _bad("pwHash")
        p.pw_salt_hex, p.pw_hash_hex = salt.lower(), phash.lower()
        p.pw_salt, p.pw_hash = bytes.fromhex(salt), bytes.fromhex(phash)
        p.pw_rev = _int(d, "pwRev", 0, default=1)
        p.status = d.get("status", "active")
        if p.status not in LIST_STATUSES:
            raise _bad("list status")
        p.mode = d.get("mode", "rotate")
        if p.mode not in MODES:
            raise _bad("list mode")
        p.ttl = _int(d, "ttlSec", uname.TTL_MIN, uname.TTL_MAX, required=False)
        return p

    @classmethod
    def from_row(cls, row) -> PList:
        p = cls()
        p.id, p.login, p.account_id, p.pw_salt_hex, p.pw_hash_hex, p.pw_rev, p.status, p.mode, p.ttl = row
        p.pw_salt, p.pw_hash = bytes.fromhex(p.pw_salt_hex), bytes.fromhex(p.pw_hash_hex)
        return p

    def row(self):
        return (
            self.id,
            self.login,
            self.account_id,
            self.pw_salt_hex,
            self.pw_hash_hex,
            self.pw_rev,
            self.status,
            self.mode,
            self.ttl,
        )

    def view(self) -> dict:
        return {
            "id": self.id,
            "login": self.login,
            "accountId": self.account_id,
            "status": self.status,
            "pwRev": self.pw_rev,
        }


def _addr_str(addr: int) -> str:
    return str(ipaddress.IPv6Address(addr))


class Engine:
    def __init__(self, store, secret: bytes | None = None, clock=time.time, rng=None, env=None):
        env = os.environ if env is None else env
        self.env = env
        self.store = store
        self.clock = clock
        self.lock = threading.Lock()
        self.ctl_lock = threading.Lock()
        self.alloc = Allocator(rng=rng, clock=clock)
        self.alloc.max_bindings = _env_num(env, "PERGB_BINDINGS_MAX", self.alloc.max_bindings, int)
        self.alloc.max_sticky_per_account = _env_num(
            env, "PERGB_STICKY_MAX_PER_ACCOUNT", self.alloc.max_sticky_per_account, int
        )
        self._pending_bindings = None
        self.secret = secret
        self.facts = None
        self.accounts = {}
        self.lists = {}
        self.by_login = {}
        self.by_account = {}
        self.epoch = 0
        self.seq = 0
        self.db_recovered = False
        self.adm_open = True
        self.adm_soft = frozenset()
        self.ipv4_open = True
        self.hb_at = None
        self.hb_recv = None
        self.near = {}
        self.near_reserved = {}
        self.near_since = {}
        self.near_ipv4 = {}
        self.deadman_after = _env_num(env, "PERGB_DEADMAN_AFTER_SEC", 15.0)
        self.deadman_rate = _env_num(env, "PERGB_DEADMAN_RATE", 50_000_000.0)
        self.reject_counts = dict.fromkeys(REASONS + ("not_ready",), 0)
        self.rejects = {}
        self.dirty_rejects = set()
        self.counters = {
            "requests": 0,
            "accepts": 0,
            "malformed": 0,
            "noSecret": 0,
            "badAuthenticator": 0,
            "noDst": 0,
            "probeAccepts": 0,
            "sendErrors": 0,
        }
        self.lat = array("d", bytes(8 * LAT_SAMPLES))
        self.lat_i = 0
        self.lat_n = 0
        self.dirty_meta = {}
        self.dirty_accounts = {}
        self.dirty_lists = {}
        self.pending = None
        self.probe_tokens = PROBE_RATE
        self.probe_t = 0.0
        self.started_at = clock()
        self.udp_alive = time.monotonic()

    # ---- load ----------------------------------------------------------------------

    def load(self):
        data = self.store.open()
        now = self.clock()
        self.db_recovered = self.store.recovered
        self.epoch, self.seq = data["epoch"], data["seq"]
        a = self.alloc
        for net, scan, ref, rat, cd in data["nets"]:
            if scan:
                a.scan.add(net)
            if ref is not None:
                a.reserved[net] = ref
                a.reserved_at[net] = rat or now
            if cd is not None:
                a.cooldown[net] = cd
        for ref, kind, nets_json, until, at in data["refs"]:
            if kind == "reserve":
                a.reservations[ref] = json.loads(nets_json)
                a.reservation_at[ref] = at
            elif kind == "release" and ref.startswith("rel:"):
                a.releases[ref[4:]] = (int(json.loads(nets_json)), until)
        guard = data.get("scan_guard")
        if guard:
            a.scan_missing = {int(k): float(v) for k, v in (guard.get("missing") or {}).items()}
            a.last_scan_id = guard.get("lastScanId")
        raw_facts = data.get("facts")
        if raw_facts:
            try:
                self._set_facts(Facts.parse(raw_facts, self.env), now)
            except (CtlRefused, ValueError) as e:
                log("stored facts are unusable (%s); waiting for the agent" % e)
        dropped = 0
        if a.configured:
            for list_id, slot, kind, addr, net, acct, shared, created, expires, last_used in data["bindings"]:
                b = Binding(
                    list_id,
                    slot,
                    kind,
                    int.from_bytes(addr, "big"),
                    net,
                    acct,
                    bool(shared),
                    created,
                    expires,
                    last_used,
                )
                if not a.load_binding(b, now):
                    dropped += 1
                    a.dirty_bindings[(list_id, slot)] = None
                    if kind == STATIC:
                        a.events.append(("release", list_id, slot, b.addr, "load_conflict", now))
        elif data["bindings"]:
            log("bindings kept on disk until facts arrive")
            self._pending_bindings = data["bindings"]
        a.loaded()
        if dropped:
            log("dropped %d inconsistent bindings at load" % dropped)
        a.dirty_nets.clear()
        a.dirty_refs.clear()
        for row in data["accounts"]:
            acct = Account.from_row(row)
            self.accounts[acct.id] = acct
        for row in data["lists"]:
            p = PList.from_row(row)
            self.lists[p.id] = p
        self._reindex()
        for list_id, reason, at, count in data["rejects"]:
            self.rejects[list_id] = [reason, at, count]
        hb = data.get("heartbeat")
        if hb:
            self.hb_at = hb.get("at")
            self.hb_recv = hb.get("recvAt")
            self.near = {int(k): int(v) for k, v in (hb.get("near") or {}).items()}
            since = hb.get("since") or {}
            self.near_since = {int(k): float(since.get(k, self.hb_recv or now)) for k in self.near}
        if self.db_recovered:
            log("state DB recovered: new epoch %d, broken copy %s" % (self.epoch, self.store.broken_path))

    def _reindex(self):
        self.by_login, self.by_account = self._indexes(self.lists)

    @staticmethod
    def _indexes(lists: dict):
        by_login = {p.login: p for p in lists.values()}
        by_acct = {}
        for p in lists.values():
            by_acct.setdefault(p.account_id, set()).add(p.id)
        return by_login, by_acct

    def _set_facts(self, f: Facts, now: float):
        self.alloc.configure(f.prefix, f.prefix_str, f.lo, f.hi, f.key, now)
        self.facts = f
        pend = getattr(self, "_pending_bindings", None)
        if pend:
            self._pending_bindings = None
            a = self.alloc
            for list_id, slot, kind, addr, net, acct, shared, created, expires, last_used in pend:
                b = Binding(
                    list_id,
                    slot,
                    kind,
                    int.from_bytes(addr, "big"),
                    net,
                    acct,
                    bool(shared),
                    created,
                    expires,
                    last_used,
                )
                if not a.load_binding(b, now):
                    a.dirty_bindings[(list_id, slot)] = None
                    if kind == STATIC:
                        a.events.append(("release", list_id, slot, b.addr, "load_conflict", now))
            a.loaded()

    # ---- request path --------------------------------------------------------------

    def handle(self, data: bytes) -> bytes | None:
        t0 = time.perf_counter()
        c = self.counters
        c["requests"] += 1
        try:
            req = proto.decode_request(data)
        except proto.ProtoError:
            c["malformed"] += 1
            return None
        if req.code != proto.ACCESS_REQUEST:
            c["malformed"] += 1
            return None
        secret = self.secret
        if not secret:
            c["noSecret"] += 1
            return None
        if req.msg_auth_offset >= 0 and not proto.message_authenticator_ok(req, secret):
            c["badAuthenticator"] += 1
            return None
        try:
            password = proto.decode_password(req.password_enc, secret, req.authenticator)
        except proto.ProtoError:
            password = None
        now = self.clock()
        with self.lock:
            reason, v6, v4 = self._authorize(req, password, now)
        if reason is None:
            c["accepts"] += 1
            out = proto.accept_v6(req, secret, v6) if v6 is not None else proto.accept_v4(req, secret, v4)
        else:
            out = proto.reject(req, secret)
        dt = time.perf_counter() - t0
        i = self.lat_i
        self.lat[i] = dt
        self.lat_i = (i + 1) % LAT_SAMPLES
        if self.lat_n < LAT_SAMPLES:
            self.lat_n += 1
        return out

    def _reject(self, reason: str, lst, now: float):
        self.reject_counts[reason] = self.reject_counts.get(reason, 0) + 1
        if lst is not None:
            r = self.rejects.get(lst.id)
            if r is None:
                self.rejects[lst.id] = [reason, now, 1]
            else:
                r[0], r[1], r[2] = reason, now, r[2] + 1
            self.dirty_rejects.add(lst.id)
        return reason, None, None

    def _authorize(self, req, password, now):
        f = self.facts
        if f is None or not self.alloc.configured:
            return self._reject("not_ready", None, now)
        if req.username is None:
            return self._reject("bad_login", None, now)
        try:
            login = uname.parse(req.username, f.geo)
        except uname.LoginError as e:
            return self._reject(e.reason, self.by_login.get(e.base) if e.base else None, now)
        fam = req.dst_family
        if fam == 0:
            self.counters["noDst"] += 1
            fam = 6
        if login.probe:
            return self._probe(req, password, fam, now)
        lst = self.by_login.get(login.base)
        port = req.nas_port
        if port is None or not f.base <= port < f.base + f.count:
            return self._reject("bad_params", lst, now)
        if lst is None:
            return self._reject("bad_login", None, now)
        if password is None or not hmac.compare_digest(hashlib.sha256(lst.pw_salt + password).digest(), lst.pw_hash):
            return self._reject("bad_login", lst, now)
        if lst.status != "active":
            return self._reject("list_off", lst, now)
        acct = self.accounts.get(lst.account_id)
        if acct is None or acct.state != "active" or (acct.expires_at is not None and now >= acct.expires_at):
            return self._reject("account_off", lst, now)
        if acct.local_blocked:
            return self._reject("quota", lst, now)
        aid = acct.id
        near = self.near.get(aid)
        if near is not None and self.hb_recv is not None:
            age = now - self.hb_recv
            if age > self.deadman_after and near - self.deadman_rate * age <= 0:
                return self._reject("quota", lst, now)
        if not self.adm_open or aid in self.adm_soft:
            return self._reject("capacity", lst, now)
        if fam == 4:
            if f.family == "ipv6_only" or f.egress_v4 is None:
                return self._reject("bad_params", lst, now)
            if not self.ipv4_open:
                return self._reject("capacity", lst, now)
        need = 2 * f.l_prime
        if near is not None and near - self.near_reserved.get(aid, 0) < need:
            return self._reject("quota", lst, now)
        v6 = v4 = None
        if fam == 4:
            v4 = f.egress_v4
        else:
            mode, ttl, slot = uname.resolve(login, port, f.base, lst.mode, lst.ttl)
            a = self.alloc
            try:
                if mode == "rotate":
                    addr = a.rotate_addr(lst.id, now)
                elif mode == "sticky":
                    cap = 0 if acct.trial else acct.sticky_excl_cap
                    addr = a.bind_sticky(lst.id, slot, aid, ttl, now, cap, f.sticky_pct).addr
                else:
                    addr = a.bind_static(lst.id, slot, aid, now, acct.static_cap, f.static_pct).addr
            except AllocError as e:
                return self._reject(e.reason, lst, now)
            v6 = addr.to_bytes(16, "big")
        if near is not None:
            self.near_reserved[aid] = self.near_reserved.get(aid, 0) + need
            if fam == 4:
                self.near_ipv4[aid] = self.near_ipv4.get(aid, 0) + 1
        return None, v6, v4

    def _probe(self, req, password, fam, now):
        f = self.facts
        if f.probe_hash is None or password is None:
            return self._reject("bad_login", None, now)
        if not hmac.compare_digest(hashlib.sha256(f.probe_salt + password).digest(), f.probe_hash):
            return self._reject("bad_login", None, now)
        if req.dst_addr is None or (req.dst_family, req.dst_addr, req.dst_port) not in f.canary:
            return self._reject("bad_params", None, now)
        tokens = min(PROBE_RATE, self.probe_tokens + (now - self.probe_t) * PROBE_RATE)
        self.probe_t = now
        if tokens < 1.0:
            self.probe_tokens = tokens
            return self._reject("capacity", None, now)
        self.probe_tokens = tokens - 1.0
        self.counters["probeAccepts"] += 1
        if fam == 4:
            if f.family == "ipv6_only" or f.egress_v4 is None:
                return self._reject("bad_params", None, now)
            return None, None, f.egress_v4
        try:
            addr = self.alloc.rotate_addr(0, now)
        except AllocError as e:
            return self._reject(e.reason, None, now)
        return None, addr.to_bytes(16, "big"), None

    # ---- persistence ---------------------------------------------------------------

    def _swap_batch(self) -> Batch:
        """Collect everything dirty (caller holds self.lock)."""
        b = Batch()
        b.meta, self.dirty_meta = self.dirty_meta, {}
        for k, acct in self.dirty_accounts.items():
            b.accounts[k] = acct.row() if acct is not None else None
        self.dirty_accounts = {}
        for k, p in self.dirty_lists.items():
            b.lists[k] = p.row() if p is not None else None
        self.dirty_lists = {}
        a = self.alloc
        for k, bd in a.dirty_bindings.items():
            b.bindings[k] = (
                None
                if bd is None
                else (
                    bd.list_id,
                    bd.slot,
                    bd.kind,
                    bd.addr.to_bytes(16, "big"),
                    bd.net,
                    bd.account_id,
                    int(bd.shared),
                    bd.created_at,
                    bd.expires_at,
                    bd.last_used_at,
                )
            )
        a.dirty_bindings = {}
        b.events = [(op, lid, slot, _addr_str(addr), reason, at) for op, lid, slot, addr, reason, at in a.events]
        a.events = []
        for lid in self.dirty_rejects:
            r = self.rejects.get(lid)
            b.rejects[lid] = tuple(r) if r is not None else None
        self.dirty_rejects = set()
        for n in a.dirty_nets:
            scan = n in a.scan
            ref = a.reserved.get(n)
            cd = a.cooldown.get(n)
            b.nets[n] = (
                None if (not scan and ref is None and cd is None) else (int(scan), ref, a.reserved_at.get(n), cd)
            )
        a.dirty_nets = set()
        for ref in a.dirty_refs:
            if ref.startswith("rel:"):
                r = a.releases.get(ref[4:])
                b.refs[ref] = None if r is None else ("release", json.dumps(r[0]), r[1], self.clock())
            else:
                nets = a.reservations.get(ref)
                b.refs[ref] = (
                    None
                    if nets is None
                    else ("reserve", json.dumps(nets), None, a.reservation_at.get(ref, self.clock()))
                )
        a.dirty_refs = set()
        return b

    def flush(self) -> bool:
        """Write everything dirty; True when it is durable."""
        store = self.store
        with store.lock:
            with self.lock:
                batch = self._swap_batch()
            if self.pending is not None:
                batch.merge_older(self.pending)
                self.pending = None
            if batch.empty():
                return True
            try:
                store.write(batch)
                return True
            except sqlite3.Error as e:
                self.pending = batch
                store.write_errors += 1
                store.last_write_error = "%s: %s" % (type(e).__name__, e)
                if isinstance(e, sqlite3.DatabaseError) and not isinstance(e, sqlite3.OperationalError):
                    store.corrupt = True
                log("state write failed: %s" % store.last_write_error)
                return False

    def _durable(self):
        if not self.flush():
            raise CtlRefused("db_write_failed", detail=self.store.last_write_error)

    # ---- housekeeping (thread D) ---------------------------------------------------

    def sweep(self, now: float | None = None):
        now = self.clock() if now is None else now
        with self.lock:
            expired = self.alloc.expire_sticky(now)
            back = self.alloc.expire_cooldowns(now)
            a = self.alloc
            old_refs = [
                r
                for r, at in a.reservation_at.items()
                if at < now - REF_RETENTION_SEC and not any(a.reserved.get(n) == r for n in a.reservations.get(r, ()))
            ]
            for r in old_refs:
                a.reservations.pop(r, None)
                a.reservation_at.pop(r, None)
                a.dirty_refs.add(r)
            old_rel = [r for r, (_c, until) in a.releases.items() if until < now - REF_RETENTION_SEC + 86400]
            for r in old_rel:
                del a.releases[r]
                a.dirty_refs.add("rel:" + r)
        return expired, back

    def prune_events(self, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        return self.store.prune_events(now - EVENT_RETENTION_SEC)

    def latency(self):
        n = self.lat_n
        if not n:
            return None, None
        s = sorted(self.lat[:n])
        return round(s[n // 2] * 1000, 4), round(s[min(n - 1, int(n * 0.99))] * 1000, 4)

    # ---- ctl operations ------------------------------------------------------------

    def op_status(self, req):
        now = self.clock()
        with self.lock:
            p50, p99 = self.latency()
            out = {
                "epoch": self.epoch,
                "seq": self.seq,
                "dbRecovered": self.db_recovered,
                "ready": self.facts is not None and self.alloc.configured,
                "secretLoaded": bool(self.secret),
                "counts": {
                    "lists": len(self.lists),
                    "accounts": len(self.accounts),
                    "sticky": self.alloc.n_sticky,
                    "static": self.alloc.n_static,
                },
                "alloc": self.alloc.stats(now),
                "latency": {"p50Ms": p50, "p99Ms": p99},
                "admission": {"open": self.adm_open, "soft": sorted(self.adm_soft)},
                "ipv4AdmissionOpen": self.ipv4_open,
                "deadman": {
                    "heartbeatAgeSec": None if self.hb_recv is None else round(now - self.hb_recv, 3),
                    "afterSec": self.deadman_after,
                    "active": self.hb_recv is not None and now - self.hb_recv > self.deadman_after,
                },
                "rejects": dict(self.reject_counts),
                "noDst": self.counters["noDst"],
                "counters": dict(self.counters),
                "db": {
                    "persistent": self.store.persistent,
                    "writeErrors": self.store.write_errors,
                    "lastWriteError": self.store.last_write_error,
                },
                "uptimeSec": round(now - self.started_at, 3),
            }
        if self.facts is not None:
            f = self.facts
            out["facts"] = {
                "base": f.base,
                "count": f.count,
                "geo": f.geo,
                "family": f.family,
                "egressIpv4": f.egress_v4_str,
                "prefix": f.prefix_str,
                "subnets": [f.lo, f.hi],
            }
        return out

    def op_facts(self, req):
        f = Facts.parse(req.get("facts"), self.env)
        with self.ctl_lock:
            with self.lock:
                self._set_facts(f, self.clock())
                self.dirty_meta["facts"] = json.dumps(f.raw, sort_keys=True)
            self._durable()
        return {"ok": True}

    def op_excluded(self, req):
        nets = req.get("nets")
        if not isinstance(nets, list):
            raise _bad("nets must be a list")
        try:
            nets = [_subnet_id(n) for n in nets]
        except ValueError:
            raise _bad("nets") from None
        complete = _bool(req, "complete", False)
        force = _bool(req, "force", False)
        scan_id = req.get("scanId")
        refused = None
        with self.ctl_lock:
            with self.lock:
                now = self.clock()
                a = self.alloc
                try:
                    count, removed = a.apply_scan(nets, complete, scan_id, now, force)
                except CtlRefused as e:
                    refused = e
                    count, removed = a.excluded_count(now), 0
                self.dirty_meta["scan_guard"] = json.dumps(
                    {"missing": {str(k): v for k, v in a.scan_missing.items()}, "lastScanId": a.last_scan_id}
                )
            self._durable()
        if refused is not None:
            out = {"error": refused.code, "excluded": count}
            out.update(refused.extra)
            return out
        return {"ok": True, "excluded": count, "removed": removed}

    def op_reserve_nets(self, req):
        count = _int(req, "count", 1, 5000)
        ref = req.get("ref")
        if not isinstance(ref, str) or not 1 <= len(ref) <= 200:
            raise _bad("ref must be a string of 1..200 chars")
        owner = req.get("owner", "perpiece")
        if owner != "perpiece":
            raise _bad("owner must be perpiece")
        force = _bool(req, "force", False)
        with self.ctl_lock:
            with self.lock:
                min_free = self.facts.min_free_perpiece if self.facts is not None else 5000
                nets = self.alloc.reserve(count, ref, self.clock(), min_free, force)
            self._durable()
        return {"nets": nets, "ref": ref}

    def op_release_nets(self, req):
        nets = req.get("nets")
        if not isinstance(nets, list):
            raise _bad("nets must be a list")
        try:
            nets = [_subnet_id(n) for n in nets]
        except ValueError:
            raise _bad("nets") from None
        ref = req.get("ref")
        if not isinstance(ref, str) or not 1 <= len(ref) <= 200:
            raise _bad("ref must be a string of 1..200 chars")
        with self.ctl_lock:
            with self.lock:
                count, until = self.alloc.release_nets(nets, ref, self.clock())
            self._durable()
        return {"released": count, "coolDownUntil": until}

    def _parse_state(self, req, with_static: bool):
        accounts = req.get("accounts") or []
        lists = req.get("lists") or []
        if not isinstance(accounts, list) or not isinstance(lists, list):
            raise _bad("accounts and lists must be lists")
        accs = [Account.parse(a) for a in accounts]
        lsts = [PList.parse(x) for x in lists]
        static = []
        if with_static:
            raw = req.get("static") or []
            if not isinstance(raw, list):
                raise _bad("static must be a list")
            for s in raw:
                if not isinstance(s, dict):
                    raise _bad("static entries are objects")
                lid = _int(s, "listId", 0, 0xFFFFFFFF)
                slot = s.get("slot")
                if not isinstance(slot, str) or not re.match(r"(p[0-9]{1,5}|s:[a-z0-9_]{1,32})\Z", slot):
                    raise _bad("static slot")
                try:
                    addr = int(ipaddress.IPv6Address(s.get("addr")))
                except (ipaddress.AddressValueError, ValueError, TypeError):
                    raise _bad("static addr") from None
                static.append((lid, slot, addr))
        return accs, lsts, static

    def _account_transition(self, old, new, out):
        if new.state != "active" and (old is None or old.state != new.state):
            out["accounts"].append({"id": new.id, "why": new.state})

    def _list_transition(self, old, new, out):
        if new.status != "active":
            if old is None or old.status != new.status:
                out["lists"].append({"id": new.id, "why": new.status})
        elif old is not None and new.pw_rev > old.pw_rev:
            out["lists"].append({"id": new.id, "why": "pw"})

    def _drop_released_static(self, acct_ids, now):
        for aid in acct_ids:
            for lid in self.by_account.get(aid, ()):
                self.alloc.release_list(lid, "account_released", now, kinds=(STATIC,))

    def op_snapshot(self, req):
        seq = _int(req, "seq", 0)
        accs, lsts, static = self._parse_state(req, True)
        new_accounts = {a.id: a for a in accs}
        new_lists = {}
        logins = {}
        deleted_ids = set()
        for p in lsts:
            if p.status == "deleted":
                deleted_ids.add(p.id)
                continue
            if p.login in logins and logins[p.login] != p.id:
                raise _bad("duplicate login %s" % p.login)
            logins[p.login] = p.id
            new_lists[p.id] = p
        with self.ctl_lock:
            # Only ctl ops (serialised by ctl_lock) change accounts and lists, so the
            # O(n) diff runs without the engine lock; the UDP thread keeps serving.
            old_accounts, old_lists = self.accounts, self.lists
            t = {"accounts": [], "lists": []}
            dirty_accounts, dirty_lists = {}, {}
            for a in new_accounts.values():
                old = old_accounts.get(a.id)
                if old is not None:
                    a.local_blocked = old.local_blocked
                self._account_transition(old, a, t)
                if old is None or old.row() != a.row():
                    dirty_accounts[a.id] = a
            for aid, old in old_accounts.items():
                if aid not in new_accounts:
                    dirty_accounts[aid] = None
                    if old.state != "released":
                        t["accounts"].append({"id": aid, "why": "released"})
            for p in new_lists.values():
                old = old_lists.get(p.id)
                self._list_transition(old, p, t)
                if old is None or old.row() != p.row():
                    dirty_lists[p.id] = p
            gone = [lid for lid in old_lists if lid not in new_lists]
            for lid in gone:
                dirty_lists[lid] = None
                t["lists"].append({"id": lid, "why": "deleted"})
            by_login, by_account = self._indexes(new_lists)
            released = {aid for aid, a in new_accounts.items() if a.state == "released"}
            with self.lock:
                now = self.clock()
                a = self.alloc
                for lid in [lid for lid in a.by_list if lid not in new_lists]:
                    a.release_list(lid, "list_deleted", now)
                for lid in gone:
                    if self.rejects.pop(lid, None) is not None:
                        self.dirty_rejects.add(lid)
                self.dirty_accounts.update(dirty_accounts)
                self.dirty_lists.update(dirty_lists)
                self.accounts, self.lists = new_accounts, new_lists
                self.by_login, self.by_account = by_login, by_account
                released.update(aid for aid in a.acct_static if aid not in new_accounts)
                self._drop_released_static(released, now)
                adopted = kept = 0
                refused = {}
                for lid, slot, addr in static:
                    p = new_lists.get(lid)
                    acct = new_accounts.get(p.account_id) if p is not None else None
                    if p is None:
                        r = "no_list"
                    elif acct is not None and acct.state == "released":
                        r = "released"
                    elif not a.configured:
                        r = "not_ready"
                    else:
                        r = a.adopt_static(lid, slot, p.account_id, addr, now)
                    if r == "adopted":
                        adopted += 1
                    elif r == "kept":
                        kept += 1
                    else:
                        refused[r] = refused.get(r, 0) + 1
                self._forget_accounts(set(self.near) - set(new_accounts))
                self.seq = seq
                self.dirty_meta["seq"] = str(seq)
            self._durable()
        return {
            "epoch": self.epoch,
            "seq": seq,
            "transitions": t,
            "static": {"adopted": adopted, "kept": kept, "refused": refused},
        }

    def _forget_accounts(self, ids):
        for aid in ids:
            self.near.pop(aid, None)
            self.near_reserved.pop(aid, None)
            self.near_since.pop(aid, None)
            self.near_ipv4.pop(aid, None)

    def op_apply(self, req):
        base_seq = _int(req, "baseSeq", 0)
        seq = _int(req, "seq", 0)
        accs, lsts, _ = self._parse_state(req, False)
        with self.ctl_lock:
            if base_seq != self.seq:
                raise CtlRefused("seq_mismatch", epoch=self.epoch, seq=self.seq)
            # validate against the merged state before changing anything
            batch_logins = {}
            for p in lsts:
                if p.status == "deleted":
                    continue
                holder = self.by_login.get(p.login)
                if (holder is not None and holder.id != p.id) or batch_logins.get(p.login, p.id) != p.id:
                    raise _bad("duplicate login %s" % p.login)
                batch_logins[p.login] = p.id
            t = {"accounts": [], "lists": []}
            released = []
            for a in accs:
                old = self.accounts.get(a.id)
                if old is not None:
                    a.local_blocked = old.local_blocked
                self._account_transition(old, a, t)
                if a.state == "released":
                    released.append(a.id)
            for p in lsts:
                old = self.lists.get(p.id)
                if p.status == "deleted":
                    if old is not None:
                        t["lists"].append({"id": p.id, "why": "deleted"})
                else:
                    self._list_transition(old, p, t)
            with self.lock:
                now = self.clock()
                for a in accs:
                    old = self.accounts.get(a.id)
                    self.accounts[a.id] = a
                    if old is None or old.row() != a.row():
                        self.dirty_accounts[a.id] = a
                for p in lsts:
                    old = self.lists.get(p.id)
                    if old is not None:
                        if self.by_login.get(old.login) is old:
                            del self.by_login[old.login]
                        ids = self.by_account.get(old.account_id)
                        if ids is not None:
                            ids.discard(p.id)
                            if not ids:
                                del self.by_account[old.account_id]
                    if p.status == "deleted":
                        if old is not None:
                            del self.lists[p.id]
                            self.dirty_lists[p.id] = None
                        self.alloc.release_list(p.id, "list_deleted", now)
                        if self.rejects.pop(p.id, None) is not None:
                            self.dirty_rejects.add(p.id)
                        continue
                    self.lists[p.id] = p
                    self.by_login[p.login] = p
                    self.by_account.setdefault(p.account_id, set()).add(p.id)
                    if old is None or old.row() != p.row():
                        self.dirty_lists[p.id] = p
                self._drop_released_static(released, now)
                self.seq = seq
                self.dirty_meta["seq"] = str(seq)
            self._durable()
        return {"epoch": self.epoch, "seq": seq, "transitions": t}

    def op_heartbeat(self, req):
        at = _num(req, "at")
        near = req.get("near") or {}
        if not isinstance(near, dict):
            raise _bad("near must be an object")
        parsed = {}
        for k, v in near.items():
            try:
                aid = int(k)
            except (TypeError, ValueError):
                raise _bad("near keys are account ids") from None
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise _bad("near values are byte counts")
            parsed[aid] = int(v)
        with self.lock:
            now = self.clock()
            for aid in set(self.near) - set(parsed):
                self.near_since.pop(aid, None)
                self.near_ipv4.pop(aid, None)
            for aid in parsed:
                if aid not in self.near:
                    self.near_since[aid] = now
                    self.near_ipv4[aid] = 0
            self.near = parsed
            self.near_reserved = {}
            self.hb_at = at
            self.hb_recv = now
            self.dirty_meta["heartbeat"] = json.dumps(
                {
                    "at": at,
                    "recvAt": now,
                    "near": {str(k): v for k, v in parsed.items()},
                    "since": {str(k): v for k, v in self.near_since.items()},
                }
            )
        return {"ok": True}

    def op_near_stats(self, req):
        with self.lock:
            return {
                "accounts": {
                    str(aid): {
                        "reserved": self.near_reserved.get(aid, 0),
                        "ipv4Accepts": self.near_ipv4.get(aid, 0),
                        "since": self.near_since.get(aid),
                        "headroom": h,
                    }
                    for aid, h in self.near.items()
                }
            }

    def op_local_block(self, req):
        aid = _int(req, "accountId", 0)
        blocked = _bool(req, "blocked", None)
        if blocked is None:
            raise _bad("blocked is required")
        with self.ctl_lock:
            with self.lock:
                acct = self.accounts.get(aid)
                if acct is None:
                    raise CtlRefused("unknown_account", accountId=aid)
                if acct.local_blocked != blocked:
                    acct.local_blocked = blocked
                    self.dirty_accounts[aid] = acct
            self._durable()
        return {"ok": True}

    def op_admission(self, req):
        open_ = _bool(req, "open", None)
        if open_ is None:
            raise _bad("open is required")
        soft = req.get("softAccounts") or []
        if not isinstance(soft, list):
            raise _bad("softAccounts must be a list")
        ids = frozenset(_int({"a": s}, "a", 0) for s in soft)
        with self.lock:
            self.adm_open = open_
            self.adm_soft = ids
        return {"ok": True}

    def op_ipv4_admission(self, req):
        open_ = _bool(req, "open", None)
        if open_ is None:
            raise _bad("open is required")
        with self.lock:
            self.ipv4_open = open_
        return {"ok": True}

    def op_bindings(self, req):
        after = _int(req, "after", 0, default=0)
        limit = _int(req, "limit", 1, 1000, default=1000)
        self.flush()
        rows = self.store.events_after(after, limit)
        items = [
            {"seq": s, "op": op, "listId": lid, "slot": slot, "addr": addr, "reason": reason, "at": at}
            for s, op, lid, slot, addr, reason, at in rows
        ]
        return {"items": items, "last": items[-1]["seq"] if items else after}

    # lists and accounts change only under ctl_lock: these views never block the UDP thread
    def op_logins(self, req):
        with self.ctl_lock:
            return {"lists": [p.view() for p in self.lists.values()]}

    def op_accounts(self, req):
        with self.ctl_lock:
            return {"accounts": [a.view() for a in self.accounts.values()]}

    def op_rejects(self, req):
        with self.lock:
            return {"lists": {str(k): {"reason": r[0], "at": r[1], "count": r[2]} for k, r in self.rejects.items()}}

    OPS = {
        "status": op_status,
        "facts": op_facts,
        "excluded": op_excluded,
        "snapshot": op_snapshot,
        "apply": op_apply,
        "heartbeat": op_heartbeat,
        "near_stats": op_near_stats,
        "local_block": op_local_block,
        "admission": op_admission,
        "ipv4_admission": op_ipv4_admission,
        "bindings": op_bindings,
        "logins": op_logins,
        "accounts": op_accounts,
        "rejects": op_rejects,
        "reserve_nets": op_reserve_nets,
        "release_nets": op_release_nets,
    }

    def dispatch(self, req) -> dict:
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return {"error": "bad_request", "detail": 'expected {"op": ...}'}
        fn = self.OPS.get(req["op"])
        if fn is None:
            return {"error": "unknown_op", "op": req["op"]}
        try:
            return fn(self, req)
        except CtlRefused as e:
            out = {"error": e.code}
            out.update(e.extra)
            return out
